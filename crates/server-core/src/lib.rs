//! Embedded SSH server entry point and module wiring.
//!
//! This module intentionally keeps the public surface small: `run_server` wires up the russh
//! configuration, while the heavy lifting lives in the submodules.

mod auth;
pub mod error;
mod handler;
mod relay;
mod remote_backend;
pub mod secrets;
mod server_manager;
mod tui;

use std::{sync::Arc, time::Duration};

use russh::{
    MethodKind, MethodSet, keys::{
        Algorithm, PrivateKey, ssh_key::{LineEnding, rand_core::OsRng}
    }, server::{self as ssh_server, Server as _}
};
use server_manager::ServerManager;
use sqlx::{Row, SqlitePool};
use ssh_core::crypto::legacy_preferred;
use state_store::{migrate_server, server_db};
use tracing::info;

use crate::error::{ServerError, ServerResult};

#[derive(Clone)]
pub struct ServerConfig {
    pub bind: String,
    pub port: u16,
    pub roll_hostkey: bool,
}

/// Launch the embedded SSH server using the parsed CLI configuration.
///
/// This configures russh with our crypto preferences, enables only password auth,
/// and defers to [`ServerManager`] (and ultimately [`handler::ServerHandler`]) for per-connection
/// state machines.
pub async fn run_server(config: ServerConfig) -> ServerResult<()> {
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();

    // Require at least one user to be present; avoid starting an unauthenticated server.
    let user_count = state_store::count_users(&pool).await?;
    if user_count == 0 {
        return Err(ServerError::InvalidConfig(
            "no users configured; add one with: rb-server --add-user --user <name> --password <pass>".to_string(),
        ));
    }

    if config.roll_hostkey {
        sqlx::query("DELETE FROM server_options WHERE key = 'server_hostkey'")
            .execute(&pool)
            .await?;
        info!("rolled server host key per --roll-hostkey request");
    }

    let host_key = load_or_create_host_key(&pool).await?;

    let mut server_config = ssh_server::Config {
        preferred: legacy_preferred(),
        auth_rejection_time: Duration::from_millis(250),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        nodelay: true,
        ..Default::default()
    };

    server_config.methods = MethodSet::empty();
    server_config.methods.push(MethodKind::Password);
    server_config.keys.push(host_key);

    let mut server = ServerManager;
    info!("starting embedded SSH server on {}:{}", config.bind, config.port);

    server
        .run_on_address(Arc::new(server_config), (config.bind.as_str(), config.port))
        .await?;
    Ok(())
}

pub async fn add_relay_host(endpoint: &str, name: &str) -> ServerResult<()> {
    let (ip, port) = parse_endpoint(endpoint)?;
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();
    sqlx::query(
        "INSERT INTO relay_hosts (name, ip, port) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET ip = excluded.ip, port = excluded.port",
    )
    .bind(name)
    .bind(&ip)
    .bind(port)
    .execute(&pool)
    .await?;
    info!(relay_host = name, ip, port, "relay host saved");

    // Attempt to fetch host key and optionally store it.
    if let Err(err) = fetch_and_optionally_store_hostkey(&pool, name, &ip, port as u16).await {
        tracing::warn!(?err, relay_host = name, "failed to fetch/store host key during add-host");
    }
    Ok(())
}

pub async fn grant_relay_access(name: &str, user: &str) -> ServerResult<()> {
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_name(&pool, name)
        .await?
        .ok_or_else(|| ServerError::not_found("relay host", name))?;
    let _uid = state_store::fetch_user_id_by_name(&pool, user)
        .await?
        .ok_or_else(|| ServerError::not_found("user", user))?;
    sqlx::query("INSERT OR IGNORE INTO relay_host_acl (username, relay_host_id) VALUES (?, ?)")
        .bind(user)
        .bind(host.id)
        .execute(&pool)
        .await?;
    info!(relay_host = name, user, "granted access to relay host");
    Ok(())
}

pub async fn set_relay_option(name: &str, key: &str, value: &str) -> ServerResult<()> {
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_name(&pool, name)
        .await?
        .ok_or_else(|| ServerError::not_found("relay host", name))?;
    let stored = crate::secrets::encrypt_string(value)?;
    sqlx::query(
        "INSERT INTO relay_host_options (relay_host_id, key, value) VALUES (?, ?, ?) \
         ON CONFLICT(relay_host_id, key) DO UPDATE SET value = excluded.value",
    )
    .bind(host.id)
    .bind(key)
    .bind(stored)
    .execute(&pool)
    .await?;
    info!(relay_host = name, key, "relay option set");
    Ok(())
}

pub async fn revoke_relay_access(name: &str, user: &str) -> ServerResult<()> {
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_name(&pool, name)
        .await?
        .ok_or_else(|| ServerError::not_found("relay host", name))?;
    let _uid = state_store::fetch_user_id_by_name(&pool, user)
        .await?
        .ok_or_else(|| ServerError::not_found("user", user))?;
    sqlx::query("DELETE FROM relay_host_acl WHERE username = ? AND relay_host_id = ?")
        .bind(user)
        .bind(host.id)
        .execute(&pool)
        .await?;
    info!(relay_host = name, user, "revoked access to relay host");
    Ok(())
}

pub async fn unset_relay_option(name: &str, key: &str) -> ServerResult<()> {
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_name(&pool, name)
        .await?
        .ok_or_else(|| ServerError::not_found("relay host", name))?;
    sqlx::query("DELETE FROM relay_host_options WHERE relay_host_id = ? AND key = ?")
        .bind(host.id)
        .bind(key)
        .execute(&pool)
        .await?;
    info!(relay_host = name, key, "relay option unset");
    Ok(())
}

async fn fetch_and_optionally_store_hostkey(pool: &sqlx::SqlitePool, name: &str, ip: &str, port: u16) -> ServerResult<()> {
    use std::{
        io::{self, Write}, sync::{Arc, Mutex}
    };

    use russh::{
        client, keys::{HashAlg, PublicKey}
    };

    struct CaptureHandler {
        key: Arc<Mutex<Option<PublicKey>>>,
    }
    impl russh::client::Handler for CaptureHandler {
        type Error = crate::ServerError;
        fn check_server_key(&mut self, key: &PublicKey) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
            let captured = self.key.clone();
            let key = key.clone();
            async move {
                *captured.lock().unwrap() = Some(key);
                Ok(true)
            }
        }
    }

    let captured = Arc::new(Mutex::new(None));
    let handler = CaptureHandler { key: captured.clone() };
    let cfg = std::sync::Arc::new(russh::client::Config {
        preferred: ssh_core::crypto::default_preferred(),
        ..Default::default()
    });
    let session = client::connect(cfg, (ip, port), handler).await?;
    // No auth; disconnect immediately after handshake.
    let _ = session.disconnect(russh::Disconnect::ByApplication, "", "").await;

    let Some(key) = captured.lock().unwrap().clone() else {
        return Ok(());
    };
    let fp = key.fingerprint(HashAlg::Sha256).to_string();
    let pem = key.to_openssh().map_err(|e| ServerError::Crypto(e.to_string()))?.to_string();

    // Prompt to store.
    println!("Discovered host key for {name} ({ip}:{port})");
    println!("Fingerprint (SHA256): {fp}");
    print!("Store this host key for relay host? [y/N]: ");
    io::stdout().flush().ok();
    let mut answer = String::new();
    io::stdin().read_line(&mut answer).ok();
    let yes = matches!(answer.trim().to_lowercase().as_str(), "y" | "yes");
    if yes {
        let host = state_store::fetch_relay_host_by_name(pool, name)
            .await?
            .ok_or_else(|| ServerError::Other("relay host disappeared during hostkey store".to_string()))?;
        let stored = crate::secrets::encrypt_string(&pem)?;
        sqlx::query(
            "INSERT INTO relay_host_options (relay_host_id, key, value) VALUES (?, ?, ?) \
             ON CONFLICT(relay_host_id, key) DO UPDATE SET value = excluded.value",
        )
        .bind(host.id)
        .bind("hostkey.openssh")
        .bind(stored)
        .execute(pool)
        .await?;
        info!(relay_host = name, "stored relay host key (OpenSSH format)");
    }
    Ok(())
}

pub async fn list_hosts() -> ServerResult<Vec<state_store::RelayHost>> {
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();
    let hosts = state_store::list_relay_hosts(&pool).await?;
    Ok(hosts)
}

pub async fn list_options(name: &str) -> ServerResult<Vec<(String, String)>> {
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_name(&pool, name)
        .await?
        .ok_or_else(|| ServerError::not_found("relay host", name))?;
    let map = state_store::fetch_relay_host_options(&pool, host.id).await?;
    // For CLI display, mask encrypted values to avoid leaking secrets.
    let mut items: Vec<(String, String)> = map
        .into_iter()
        .map(|(k, v)| {
            if crate::secrets::is_encrypted_marker(&v) {
                (k, "<encrypted>".to_string())
            } else {
                (k, v)
            }
        })
        .collect();
    items.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(items)
}

pub async fn list_access(name: &str) -> ServerResult<Vec<String>> {
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_name(&pool, name)
        .await?
        .ok_or_else(|| ServerError::not_found("relay host", name))?;
    let users = state_store::fetch_relay_access_usernames(&pool, host.id).await?;
    Ok(users)
}

pub async fn delete_relay_host(name: &str) -> ServerResult<()> {
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();
    sqlx::query("DELETE FROM relay_hosts WHERE name = ?")
        .bind(name)
        .execute(&pool)
        .await?;
    info!(relay_host = name, "relay host deleted");
    Ok(())
}

pub async fn refresh_target_hostkey(name: &str) -> ServerResult<()> {
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_name(&pool, name)
        .await?
        .ok_or_else(|| ServerError::not_found("relay host", name))?;
    // Wipe existing stored key if present
    sqlx::query("DELETE FROM relay_host_options WHERE relay_host_id = ? AND key = 'hostkey.openssh'")
        .bind(host.id)
        .execute(&pool)
        .await?;
    info!(relay_host = name, "refreshing relay host key");
    // Reuse the same flow as --add-host to fetch and optionally store the key
    fetch_and_optionally_store_hostkey(&pool, name, &host.ip, host.port as u16).await?;
    Ok(())
}

pub async fn add_user(user: &str, password: &str) -> ServerResult<()> {
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();
    let hash = crate::auth::hash_password(password)?;
    sqlx::query(
        "INSERT INTO users (username, password_hash) VALUES (?, ?) \
         ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash",
    )
    .bind(user)
    .bind(hash)
    .execute(&pool)
    .await?;
    info!(user, "user added/updated");
    Ok(())
}

pub async fn remove_user(user: &str) -> ServerResult<()> {
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();
    // Revoke all ACLs for this user
    sqlx::query("DELETE FROM relay_host_acl WHERE username = ?")
        .bind(user)
        .execute(&pool)
        .await?;
    // Remove user record
    sqlx::query("DELETE FROM users WHERE username = ?")
        .bind(user)
        .execute(&pool)
        .await?;
    info!(user, "user removed and access revoked");
    Ok(())
}

pub async fn list_users() -> ServerResult<Vec<String>> {
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();
    let users = state_store::list_usernames(&pool).await?;
    Ok(users)
}

pub async fn create_password_credential(name: &str, username: Option<&str>, password: &str) -> ServerResult<i64> {
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();
    let blob = crate::secrets::encrypt_secret(password.as_bytes())?;
    let meta = username.map(|u| serde_json::json!({"username": u}).to_string());
    let id =
        state_store::insert_relay_credential(&pool, name, "password", &blob.salt, &blob.nonce, &blob.ciphertext, meta.as_deref()).await?;
    info!(credential = name, kind = "password", "credential created/updated");
    Ok(id)
}

pub async fn create_ssh_key_credential(
    name: &str,
    username: Option<&str>,
    private_key_pem: &str,
    cert_openssh: Option<&str>,
    passphrase: Option<&str>,
) -> ServerResult<i64> {
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();
    // Store key+cert in encrypted JSON payload
    let mut secret_obj = serde_json::Map::new();
    secret_obj.insert("private_key".to_string(), serde_json::Value::String(private_key_pem.to_string()));
    if let Some(cert) = cert_openssh {
        secret_obj.insert("certificate".to_string(), serde_json::Value::String(cert.to_string()));
    }
    if let Some(pw) = passphrase {
        secret_obj.insert("passphrase".to_string(), serde_json::Value::String(pw.to_string()));
    }
    let secret_json = serde_json::Value::Object(secret_obj).to_string();
    let blob = crate::secrets::encrypt_secret(secret_json.as_bytes())?;
    let meta = username.map(|u| serde_json::json!({"username": u}).to_string());
    let id =
        state_store::insert_relay_credential(&pool, name, "ssh_key", &blob.salt, &blob.nonce, &blob.ciphertext, meta.as_deref()).await?;
    info!(credential = name, kind = "ssh_key", "credential created/updated");
    Ok(id)
}

pub async fn create_agent_credential(name: &str, username: Option<&str>, public_key_openssh: &str) -> ServerResult<i64> {
    use russh::keys::{HashAlg, PublicKey};
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();

    // Validate and fingerprint
    let pk = PublicKey::from_openssh(public_key_openssh).map_err(|e| ServerError::Crypto(format!("invalid OpenSSH public key: {e}")))?;
    let fingerprint = pk.fingerprint(HashAlg::Sha256).to_string();

    let secret = serde_json::json!({
        "public_key": public_key_openssh,
        "fingerprint": fingerprint,
    })
    .to_string();
    let blob = crate::secrets::encrypt_secret(secret.as_bytes())?;
    let meta = username.map(|u| serde_json::json!({"username": u}).to_string());
    let id = state_store::insert_relay_credential(&pool, name, "agent", &blob.salt, &blob.nonce, &blob.ciphertext, meta.as_deref()).await?;
    info!(credential = name, kind = "agent", "credential created/updated");
    Ok(id)
}

pub async fn delete_credential(name: &str) -> ServerResult<()> {
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();
    // Resolve credential id
    let cred = state_store::get_relay_credential_by_name(&pool, name)
        .await?
        .ok_or_else(|| ServerError::not_found("credential", name))?;
    // Guard: prevent deletion if in use by any relay host
    let rows = sqlx::query("SELECT relay_host_id, value FROM relay_host_options WHERE key = 'auth.id'")
        .fetch_all(&pool)
        .await?;
    let target_id_str = cred.id.to_string();
    for row in rows {
        let value: String = row.get("value");
        let resolved = if crate::secrets::is_encrypted_marker(&value) {
            match crate::secrets::decrypt_string_if_encrypted(&value) {
                Ok(s) => s,
                Err(_) => continue,
            }
        } else {
            value
        };
        if resolved == target_id_str {
            return Err(ServerError::not_permitted(
                format!("delete credential '{name}'"),
                "credential is assigned to at least one host; unassign it first (--unassign-credential --hostname <HOST>)",
            ));
        }
    }
    state_store::delete_relay_credential_by_name(&pool, name).await?;
    info!(credential = name, "credential deleted");
    Ok(())
}

pub async fn list_credentials() -> ServerResult<Vec<(i64, String, String)>> {
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();
    let rows = state_store::list_relay_credentials(&pool).await?;
    Ok(rows)
}

pub async fn rotate_secrets_key(old_input: &str, new_input: &str) -> ServerResult<()> {
    let old_master = crate::secrets::normalize_master_input(old_input);
    let new_master = crate::secrets::normalize_master_input(new_input);

    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();

    // Rotate credentials
    {
        let rows = sqlx::query("SELECT id, salt, nonce, secret FROM relay_credentials")
            .fetch_all(&pool)
            .await?;
        for row in rows {
            let id: i64 = row.get("id");
            let salt: Vec<u8> = row.get("salt");
            let nonce: Vec<u8> = row.get("nonce");
            let secret: Vec<u8> = row.get("secret");
            let pt = crate::secrets::decrypt_secret_with(&salt, &nonce, &secret, &old_master)?;
            let blob = crate::secrets::encrypt_secret_with(&pt, &new_master)?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            sqlx::query("UPDATE relay_credentials SET salt = ?, nonce = ?, secret = ?, updated_at = ? WHERE id = ?")
                .bind(&blob.salt)
                .bind(&blob.nonce)
                .bind(&blob.ciphertext)
                .bind(now)
                .bind(id)
                .execute(&pool)
                .await?;
        }
    }

    // Rotate relay_host_options values
    {
        let rows = sqlx::query("SELECT relay_host_id, key, value FROM relay_host_options")
            .fetch_all(&pool)
            .await?;
        for row in rows {
            let host_id: i64 = row.get("relay_host_id");
            let key: String = row.get("key");
            let value: String = row.get("value");
            // Decrypt with old if encrypted; otherwise treat as plaintext
            let plaintext = if crate::secrets::is_encrypted_marker(&value) {
                crate::secrets::decrypt_string_with(&value, &old_master)?
            } else {
                value
            };
            let reenc = crate::secrets::encrypt_string_with(&plaintext, &new_master)?;
            sqlx::query("UPDATE relay_host_options SET value = ? WHERE relay_host_id = ? AND key = ?")
                .bind(reenc)
                .bind(host_id)
                .bind(key)
                .execute(&pool)
                .await?;
        }
    }

    info!("secrets rotated for credentials and options");
    Ok(())
}

pub async fn assign_credential(hostname: &str, cred_name: &str) -> ServerResult<()> {
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();
    let cred = state_store::get_relay_credential_by_name(&pool, cred_name)
        .await?
        .ok_or_else(|| ServerError::not_found("credential", cred_name))?;
    let host = state_store::fetch_relay_host_by_name(&pool, hostname)
        .await?
        .ok_or_else(|| ServerError::not_found("relay host", hostname))?;
    // Write auth.source and auth.id; also record normalized method inferred from credential kind for convenience
    let enc_source = crate::secrets::encrypt_string("credential")?;
    let enc_id = crate::secrets::encrypt_string(&cred.id.to_string())?;
    // Normalize: map ssh_key-like kinds to publickey for relay auth.method
    let method_plain: &str = match cred.kind.as_str() {
        "ssh_key" | "ssh_cert_key" => "publickey",
        other => other,
    };
    let enc_method = crate::secrets::encrypt_string(method_plain)?;
    sqlx::query(
        "INSERT INTO relay_host_options (relay_host_id, key, value) VALUES (?, 'auth.source', ?) \
         ON CONFLICT(relay_host_id, key) DO UPDATE SET value = excluded.value",
    )
    .bind(host.id)
    .bind(enc_source)
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO relay_host_options (relay_host_id, key, value) VALUES (?, 'auth.id', ?) \
         ON CONFLICT(relay_host_id, key) DO UPDATE SET value = excluded.value",
    )
    .bind(host.id)
    .bind(enc_id)
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO relay_host_options (relay_host_id, key, value) VALUES (?, 'auth.method', ?) \
         ON CONFLICT(relay_host_id, key) DO UPDATE SET value = excluded.value",
    )
    .bind(host.id)
    .bind(enc_method)
    .execute(&pool)
    .await?;
    info!(relay_host = hostname, credential = cred_name, "credential assigned to host");
    Ok(())
}

pub async fn unassign_credential(hostname: &str) -> ServerResult<()> {
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_name(&pool, hostname)
        .await?
        .ok_or_else(|| ServerError::not_found("relay host", hostname))?;
    sqlx::query("DELETE FROM relay_host_options WHERE relay_host_id = ? AND key IN ('auth.source','auth.id','auth.method')")
        .bind(host.id)
        .execute(&pool)
        .await?;
    info!(relay_host = hostname, "credential unassigned from host");
    Ok(())
}

async fn load_or_create_host_key(pool: &SqlitePool) -> ServerResult<PrivateKey> {
    const KEY_NAME: &str = "server_hostkey";
    if let Some(row) = sqlx::query("SELECT value FROM server_options WHERE key = ?")
        .bind(KEY_NAME)
        .fetch_optional(pool)
        .await?
    {
        let pem: String = row.get("value");
        let key = PrivateKey::from_openssh(&pem).map_err(|e| ServerError::Crypto(e.to_string()))?;
        info!("loaded persisted server host key");
        Ok(key)
    } else {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).map_err(|e| ServerError::Crypto(e.to_string()))?;
        let pem = key
            .to_openssh(LineEnding::LF)
            .map_err(|e| ServerError::Crypto(e.to_string()))?
            .to_string();

        sqlx::query("INSERT OR REPLACE INTO server_options (key, value) VALUES (?, ?)")
            .bind(KEY_NAME)
            .bind(pem)
            .execute(pool)
            .await?;

        info!("generated new server host key and cached it in the state database");
        Ok(key)
    }
}

fn parse_endpoint(endpoint: &str) -> ServerResult<(String, i64)> {
    let (host, port_str) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| ServerError::InvalidEndpoint("relay hosts must be specified as ip:port".to_string()))?;
    let port = port_str
        .parse::<u16>()
        .map_err(|_| ServerError::InvalidEndpoint("invalid relay host port".to_string()))?;
    Ok((host.to_string(), port as i64))
}
