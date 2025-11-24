//! Embedded SSH server entry point and module wiring.
//!
//! This module intentionally keeps the public surface small: `run_server` wires up the russh
//! configuration, while the heavy lifting lives in the submodules.

pub mod auth;
pub mod error;
mod handler;
pub mod relay;
pub use relay::connect_to_relay_local;
pub mod secrets;
mod server_manager;

use std::{sync::Arc, time::Duration};

use base64::Engine;
use rb_types::{
    auth::ClaimType, web::{PrincipalKind, RelayAccessPrincipal}
};
use russh::{
    MethodKind, MethodSet, keys::{
        Algorithm, PrivateKey, ssh_key::{LineEnding, rand_core::OsRng}
    }, server::{self as ssh_server, Server as _}
};
use secrecy::ExposeSecret;
use server_manager::ServerManager;
use sqlx::{Row, SqlitePool};
use ssh_core::crypto::default_preferred;
use state_store::{
    add_user_to_group, create_group, delete_group_by_name, fetch_group_id_by_name, fetch_relay_access_principals, grant_relay_access_principal, list_group_members, list_groups as list_groups_db, list_user_groups, remove_user_from_group, revoke_relay_access_principal, server_db
};
use tracing::{info, warn};

use crate::error::{ServerError, ServerResult};

const FETCH_HOSTKEY_TIMEOUT_ENV: &str = "RB_FETCH_TIMEOUT";
const DEFAULT_FETCH_HOSTKEY_TIMEOUT_SECS: f64 = 2.0;
const MAX_FETCH_HOSTKEY_TIMEOUT_SECS: f64 = 5.0;

fn hostkey_fetch_timeout() -> ServerResult<Duration> {
    match std::env::var(FETCH_HOSTKEY_TIMEOUT_ENV) {
        Ok(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Ok(Duration::from_secs_f64(DEFAULT_FETCH_HOSTKEY_TIMEOUT_SECS));
            }
            let secs = trimmed.parse::<f64>().map_err(|e| {
                ServerError::InvalidConfig(format!(
                    "{FETCH_HOSTKEY_TIMEOUT_ENV} must be a positive number of seconds (e.g. \"1.5\"): {e}"
                ))
            })?;
            if secs <= 0.0 {
                return Err(ServerError::InvalidConfig(format!(
                    "{FETCH_HOSTKEY_TIMEOUT_ENV} must be greater than zero (got {secs})"
                )));
            }
            let normalized = secs.min(MAX_FETCH_HOSTKEY_TIMEOUT_SECS);
            if (normalized - secs).abs() > f64::EPSILON {
                tracing::warn!(
                    env = FETCH_HOSTKEY_TIMEOUT_ENV,
                    requested = secs,
                    used = normalized,
                    max = MAX_FETCH_HOSTKEY_TIMEOUT_SECS,
                    "RB_FETCH_TIMEOUT exceeded maximum and was clamped"
                );
            }
            Ok(Duration::from_secs_f64(normalized))
        }
        Err(std::env::VarError::NotPresent) => Ok(Duration::from_secs_f64(DEFAULT_FETCH_HOSTKEY_TIMEOUT_SECS)),
        Err(std::env::VarError::NotUnicode(_)) => Err(ServerError::InvalidConfig(format!(
            "{FETCH_HOSTKEY_TIMEOUT_ENV} contains invalid UTF-8"
        ))),
    }
}

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
pub async fn run_ssh_server(config: ServerConfig) -> ServerResult<()> {
    // Refuse to start without a non-empty master secret configured
    crate::secrets::require_master_secret()?;

    let db = server_db().await?;

    let pool = db.into_pool();

    // Require at least one user to be present; avoid starting an unauthenticated server.
    let user_count = state_store::count_users(&pool).await?;
    if user_count == 0 {
        return Err(ServerError::InvalidConfig(
            "no users configured; add one with: rb-server users add <name> --password <pass>".to_string(),
        ));
    }

    if config.roll_hostkey {
        sqlx::query("DELETE FROM server_options WHERE key = 'server_hostkey'")
            .execute(&pool)
            .await?;
        info!("rolled server host key per rb-server secrets rotate-key request");
    }

    let host_key = load_or_create_host_key(&pool).await?;

    let mut server_config = ssh_server::Config {
        // Inbound server connections must always run with secure defaults
        preferred: default_preferred(),
        auth_rejection_time: Duration::from_millis(250),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        nodelay: true,
        ..Default::default()
    };

    server_config.methods = MethodSet::empty();
    server_config.methods.push(MethodKind::Password);
    server_config.keys.push(host_key);

    let mut server = ServerManager;
    info!(bind = %config.bind, port = config.port, "starting embedded SSH server");

    server
        .run_on_address(Arc::new(server_config), (config.bind.as_str(), config.port))
        .await?;
    Ok(())
}

pub async fn add_relay_host(endpoint: &str, name: &str) -> ServerResult<()> {
    add_relay_host_inner(endpoint, name, true).await
}

/// Add a relay host without performing an immediate hostkey fetch/prompt.
/// This is used by rb-web, which presents a non-interactive hostkey review modal
/// after the host is created.
pub async fn add_relay_host_without_hostkey(endpoint: &str, name: &str) -> ServerResult<()> {
    add_relay_host_inner(endpoint, name, false).await
}

async fn add_relay_host_inner(endpoint: &str, name: &str, fetch_hostkey: bool) -> ServerResult<()> {
    let (ip, port) = parse_endpoint(endpoint)?;
    let db = server_db().await?;

    let pool = db.into_pool();

    // Check if name already exists
    if state_store::fetch_relay_host_by_name(&pool, name).await?.is_some() {
        return Err(ServerError::already_exists("relay host", name));
    }

    sqlx::query("INSERT INTO relay_hosts (name, ip, port) VALUES (?, ?, ?)")
        .bind(name)
        .bind(&ip)
        .bind(port)
        .execute(&pool)
        .await?;
    info!(relay_host = name, ip, port, "relay host saved");

    // Attempt to fetch host key and optionally store it.
    if fetch_hostkey && let Err(err) = fetch_and_optionally_store_hostkey(&pool, name, &ip, port as u16).await {
        tracing::warn!(?err, relay_host = name, "failed to fetch/store host key during add-host");
    }
    Ok(())
}

pub async fn grant_relay_access(name: &str, principal_kind: PrincipalKind, principal_name: &str) -> ServerResult<()> {
    let db = server_db().await?;

    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_name(&pool, name)
        .await?
        .ok_or_else(|| ServerError::not_found("relay host", name))?;
    grant_relay_access_principal(&pool, host.id, principal_kind.as_str(), principal_name).await?;
    info!(
        relay_host = name,
        principal_kind = principal_kind.as_str(),
        principal = principal_name,
        "granted access to relay host"
    );
    Ok(())
}

pub async fn set_relay_option(name: &str, key: &str, value: &str, is_secure: bool) -> ServerResult<()> {
    let db = server_db().await?;

    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_name(&pool, name)
        .await?
        .ok_or_else(|| ServerError::not_found("relay host", name))?;

    // Auto-determine if the option should be encrypted based on the key name
    // Only truly sensitive values should be encrypted
    let should_encrypt = match key {
        // These should always be encrypted
        "auth.password" | "auth.identity" | "auth.passphrase" | "hostkey.openssh" => true,
        // These can be plain text
        "auth.source"
        | "auth.id"
        | "auth.method"
        | "auth.username"
        | "auth.agent_socket"
        | "auth.agent_pubkey"
        | "auth.username_mode"
        | "auth.password_required" => false,
        // For any other keys, respect the caller's preference (default to secure)
        _ => is_secure,
    };

    let stored_value = if should_encrypt {
        crate::secrets::encrypt_string(crate::secrets::SecretString::new(Box::new(value.to_string())))?
    } else {
        value.to_string()
    };

    sqlx::query(
        "INSERT INTO relay_host_options (relay_host_id, key, value, is_secure) VALUES (?, ?, ?, ?) \
         ON CONFLICT(relay_host_id, key) DO UPDATE SET value = excluded.value, is_secure = excluded.is_secure",
    )
    .bind(host.id)
    .bind(key)
    .bind(stored_value)
    .bind(should_encrypt)
    .execute(&pool)
    .await?;
    info!(relay_host = name, key, is_secure = should_encrypt, "relay option set");
    Ok(())
}

pub async fn revoke_relay_access(name: &str, principal_kind: PrincipalKind, principal_name: &str) -> ServerResult<()> {
    let db = server_db().await?;

    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_name(&pool, name)
        .await?
        .ok_or_else(|| ServerError::not_found("relay host", name))?;
    revoke_relay_access_principal(&pool, host.id, &principal_kind, principal_name).await?;

    info!(
        relay_host = name,
        principal_kind = principal_kind.as_str(),
        principal = principal_name,
        "revoked access to relay host"
    );
    Ok(())
}

pub async fn unset_relay_option(name: &str, key: &str) -> ServerResult<()> {
    let db = server_db().await?;

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
        let stored = crate::secrets::encrypt_string(crate::secrets::SecretString::new(Box::new(pem)))?;
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

pub async fn list_hosts() -> ServerResult<Vec<rb_types::RelayInfo>> {
    let db = server_db().await?;

    let pool = db.into_pool();
    let hosts = state_store::list_relay_hosts(&pool, None).await?;
    Ok(hosts)
}

pub async fn list_options(name: &str) -> ServerResult<Vec<(String, String)>> {
    let db = server_db().await?;

    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_name(&pool, name)
        .await?
        .ok_or_else(|| ServerError::not_found("relay host", name))?;
    let map = state_store::fetch_relay_host_options(&pool, host.id).await?;
    // For CLI display, mask encrypted values to avoid leaking secrets.
    let mut items: Vec<(String, String)> = map
        .into_iter()
        .map(
            |(k, (v, is_secure))| {
                if is_secure { (k, "<encrypted>".to_string()) } else { (k, v) }
            },
        )
        .collect();
    items.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(items)
}

pub async fn list_access(name: &str) -> ServerResult<Vec<RelayAccessPrincipal>> {
    let db = server_db().await?;

    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_name(&pool, name)
        .await?
        .ok_or_else(|| ServerError::not_found("relay host", name))?;
    let principals = fetch_relay_access_principals(&pool, host.id).await?;
    Ok(principals
        .into_iter()
        .map(|p| RelayAccessPrincipal {
            kind: p.kind,
            name: p.name,
        })
        .collect())
}

pub async fn delete_relay_host(name: &str) -> ServerResult<()> {
    let db = server_db().await?;

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

    let pool = db.into_pool();

    // Check if user already exists
    if state_store::fetch_user_id_by_name(&pool, user).await?.is_some() {
        return Err(ServerError::already_exists("user", user));
    }

    let hash = crate::auth::hash_password(password)?;
    let result = sqlx::query("INSERT INTO users (username, password_hash) VALUES (?, ?)")
        .bind(user)
        .bind(hash)
        .execute(&pool)
        .await?;
    let user_id = result.last_insert_rowid();
    let promoted = maybe_promote_first_user(&pool, user, user_id).await?;
    info!(user, first_user = promoted, "user added");
    Ok(())
}

/// Grant elevated access if this is the first persisted user record.
async fn maybe_promote_first_user(pool: &SqlitePool, username: &str, user_id: i64) -> ServerResult<bool> {
    let earliest_id: i64 = sqlx::query_scalar("SELECT id FROM users ORDER BY id ASC LIMIT 1")
        .fetch_one(pool)
        .await?;
    if earliest_id != user_id {
        return Ok(false);
    }

    ensure_super_admin_privileges(pool, username).await?;
    Ok(true)
}

/// Best-effort helper that attaches the Super Admin role (or wildcard claim if the role hasn't been seeded yet).
async fn ensure_super_admin_privileges(pool: &SqlitePool, username: &str) -> ServerResult<()> {
    const SUPER_ADMIN_ROLE: &str = "Super Admin";
    match state_store::assign_role_to_user(pool, username, SUPER_ADMIN_ROLE).await {
        Ok(_) => {
            info!(user = username, role = SUPER_ADMIN_ROLE, "granted Super Admin role to first user");
            Ok(())
        }
        Err(state_store::DbError::GroupNotFound { .. }) => {
            warn!(
                user = username,
                role = SUPER_ADMIN_ROLE,
                "Super Admin role missing; granting wildcard claim directly"
            );
            let wildcard = ClaimType::Custom("*".to_string());
            state_store::add_claim_to_user(pool, username, &wildcard).await?;
            Ok(())
        }
        Err(err) => Err(err.into()),
    }
}

pub async fn remove_user(user: &str) -> ServerResult<()> {
    let db = server_db().await?;

    let pool = db.into_pool();
    // Revoke all ACLs for this user
    sqlx::query("DELETE FROM relay_host_acl WHERE principal_kind = 'user' AND principal_name = ?")
        .bind(user)
        .execute(&pool)
        .await?;
    // Remove user record (cascades user_groups)
    sqlx::query("DELETE FROM users WHERE username = ?")
        .bind(user)
        .execute(&pool)
        .await?;
    info!(user, "user removed and access revoked");
    Ok(())
}

pub async fn add_group(name: &str) -> ServerResult<()> {
    let db = server_db().await?;

    let pool = db.into_pool();

    if fetch_group_id_by_name(&pool, name).await?.is_some() {
        return Err(ServerError::already_exists("group", name));
    }

    create_group(&pool, name).await?;
    info!(group = name, "group added");
    Ok(())
}

pub async fn remove_group(name: &str) -> ServerResult<()> {
    let db = server_db().await?;

    let pool = db.into_pool();

    // Remove ACLs that reference this group
    sqlx::query("DELETE FROM relay_host_acl WHERE principal_kind = 'group' AND principal_name = ?")
        .bind(name)
        .execute(&pool)
        .await?;

    delete_group_by_name(&pool, name).await?;
    info!(group = name, "group removed and access revoked");
    Ok(())
}

pub async fn list_groups() -> ServerResult<Vec<String>> {
    let db = server_db().await?;

    let pool = db.into_pool();
    Ok(list_groups_db(&pool).await?)
}

pub async fn add_user_to_group_server(username: &str, group: &str) -> ServerResult<()> {
    let db = server_db().await?;

    let pool = db.into_pool();
    add_user_to_group(&pool, username, group).await?;
    info!(user = username, group, "user added to group");
    Ok(())
}

pub async fn remove_user_from_group_server(username: &str, group: &str) -> ServerResult<()> {
    let db = server_db().await?;

    let pool = db.into_pool();
    remove_user_from_group(&pool, username, group).await?;
    info!(user = username, group, "user removed from group");
    Ok(())
}

pub async fn list_user_groups_server(username: &str) -> ServerResult<Vec<String>> {
    let db = server_db().await?;

    let pool = db.into_pool();
    Ok(list_user_groups(&pool, username).await?)
}

pub async fn list_group_members_server(group: &str) -> ServerResult<Vec<String>> {
    let db = server_db().await?;

    let pool = db.into_pool();
    Ok(list_group_members(&pool, group).await?)
}

pub async fn list_users() -> ServerResult<Vec<String>> {
    let db = server_db().await?;

    let pool = db.into_pool();
    let users = state_store::list_usernames(&pool).await?;
    Ok(users)
}

pub async fn update_user(username: &str, new_password: Option<&str>) -> ServerResult<()> {
    let db = server_db().await?;

    let pool = db.into_pool();

    // Verify user exists
    let user_id = state_store::fetch_user_id_by_name(&pool, username)
        .await?
        .ok_or_else(|| ServerError::not_found("user", username))?;

    if let Some(npw) = new_password {
        let hash = crate::auth::hash_password(npw)?;
        sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
            .bind(&hash)
            .bind(user_id)
            .execute(&pool)
            .await?;
    }

    info!(user = username, "user updated");
    Ok(())
}

// -----------------------------
// RBAC: Roles & Claims
// -----------------------------

pub async fn create_role(name: &str, description: Option<&str>) -> ServerResult<()> {
    let db = server_db().await?;

    let pool = db.into_pool();
    state_store::create_role(&pool, name, description).await?;
    info!(role = name, "role created");
    Ok(())
}

pub async fn delete_role(name: &str) -> ServerResult<()> {
    let db = server_db().await?;

    let pool = db.into_pool();
    state_store::delete_role(&pool, name).await?;
    info!(role = name, "role deleted");
    Ok(())
}

pub async fn list_roles() -> ServerResult<Vec<state_store::Role>> {
    let db = server_db().await?;

    let pool = db.into_pool();
    Ok(state_store::list_roles(&pool).await?)
}

pub async fn assign_role(username: &str, role_name: &str) -> ServerResult<()> {
    let db = server_db().await?;

    let pool = db.into_pool();
    state_store::assign_role_to_user(&pool, username, role_name).await?;
    info!(user = username, role = role_name, "role assigned to user");
    Ok(())
}

pub async fn revoke_role(username: &str, role_name: &str) -> ServerResult<()> {
    let db = server_db().await?;

    let pool = db.into_pool();
    state_store::revoke_role_from_user(&pool, username, role_name).await?;
    info!(user = username, role = role_name, "role revoked from user");
    Ok(())
}

pub async fn add_role_claim(role_name: &str, claim: &ClaimType) -> ServerResult<()> {
    let db = server_db().await?;

    let pool = db.into_pool();
    state_store::add_claim_to_role(&pool, role_name, claim).await?;
    info!(role = role_name, claim = %claim, "claim added to role");
    Ok(())
}

pub async fn remove_role_claim(role_name: &str, claim: &ClaimType) -> ServerResult<()> {
    let db = server_db().await?;

    let pool = db.into_pool();
    state_store::remove_claim_from_role(&pool, role_name, claim).await?;
    info!(role = role_name, claim = %claim, "claim removed from role");
    Ok(())
}

pub async fn add_user_claim(username: &str, claim: &ClaimType) -> ServerResult<()> {
    let db = server_db().await?;

    let pool = db.into_pool();
    state_store::add_claim_to_user(&pool, username, claim).await?;
    info!(user = username, claim = %claim, "claim added to user");
    Ok(())
}

pub async fn remove_user_claim(username: &str, claim: &ClaimType) -> ServerResult<()> {
    let db = server_db().await?;

    let pool = db.into_pool();
    state_store::remove_claim_from_user(&pool, username, claim).await?;
    info!(user = username, claim = %claim, "claim removed from user");
    Ok(())
}

pub async fn add_group_claim(group_name: &str, claim: &ClaimType) -> ServerResult<()> {
    let db = server_db().await?;

    let pool = db.into_pool();
    state_store::add_claim_to_group(&pool, group_name, claim).await?;
    info!(group = group_name, claim = %claim, "claim added to group");
    Ok(())
}

pub async fn remove_group_claim(group_name: &str, claim: &ClaimType) -> ServerResult<()> {
    let db = server_db().await?;

    let pool = db.into_pool();
    state_store::remove_claim_from_group(&pool, group_name, claim).await?;
    info!(group = group_name, claim = %claim, "claim removed from group");
    Ok(())
}

pub async fn get_group_claims_server(group_name: &str) -> ServerResult<Vec<ClaimType>> {
    let db = server_db().await?;

    let pool = db.into_pool();
    Ok(state_store::get_group_claims(&pool, group_name).await?)
}

pub async fn create_password_credential(
    name: &str,
    username: Option<&str>,
    password: &str,
    username_mode: &str,
    password_required: bool,
) -> ServerResult<i64> {
    let db = server_db().await?;

    let pool = db.into_pool();
    let blob = crate::secrets::encrypt_secret(password.as_bytes())?;
    let meta = username.map(|u| serde_json::json!({"username": u}).to_string());
    let id = state_store::insert_relay_credential(
        &pool,
        name,
        "password",
        &blob.salt,
        &blob.nonce,
        &blob.ciphertext,
        meta.as_deref(),
        username_mode,
        password_required,
    )
    .await?;
    info!(credential = name, kind = "password", "credential created/updated");
    Ok(id)
}

pub async fn create_ssh_key_credential(
    name: &str,
    username: Option<&str>,
    key: &str,
    certificate: Option<&str>,
    passphrase: Option<&str>,
    username_mode: &str,
) -> ServerResult<i64> {
    let db = server_db().await?;

    let pool = db.into_pool();
    let mut secret_obj = serde_json::Map::new();
    secret_obj.insert("private_key".to_string(), serde_json::Value::String(key.to_string()));
    if let Some(c) = certificate {
        secret_obj.insert("certificate".to_string(), serde_json::Value::String(c.to_string()));
    }
    if let Some(p) = passphrase {
        secret_obj.insert("passphrase".to_string(), serde_json::Value::String(p.to_string()));
    }
    let secret_json = serde_json::Value::Object(secret_obj).to_string();
    let blob = crate::secrets::encrypt_secret(secret_json.as_bytes())?;
    let meta = username.map(|u| serde_json::json!({"username": u}).to_string());
    let id = state_store::insert_relay_credential(
        &pool,
        name,
        "ssh_key",
        &blob.salt,
        &blob.nonce,
        &blob.ciphertext,
        meta.as_deref(),
        username_mode,
        true, // password_required not applicable for ssh_key
    )
    .await?;
    info!(credential = name, kind = "ssh_key", "credential created/updated");
    Ok(id)
}

pub async fn create_agent_credential(name: &str, username: Option<&str>, public_key: &str, username_mode: &str) -> ServerResult<i64> {
    let db = server_db().await?;

    let pool = db.into_pool();
    // For agent, we store the public key fingerprint/content to match against agent keys
    // We'll store it as a JSON object in the secret
    let secret = serde_json::json!({
        "public_key": public_key,
        // We could also store fingerprint if we wanted to pre-calculate it
    })
    .to_string();
    let blob = crate::secrets::encrypt_secret(secret.as_bytes())?;
    let meta = username.map(|u| serde_json::json!({"username": u}).to_string());
    let id = state_store::insert_relay_credential(
        &pool,
        name,
        "agent",
        &blob.salt,
        &blob.nonce,
        &blob.ciphertext,
        meta.as_deref(),
        username_mode,
        true, // password_required not applicable for agent
    )
    .await?;
    info!(credential = name, kind = "agent", "credential created/updated");
    Ok(id)
}

pub async fn update_password_credential(
    id: i64,
    name: &str,
    username: Option<&str>,
    password: Option<&str>,
    username_mode: &str,
    password_required: bool,
) -> ServerResult<()> {
    let db = server_db().await?;

    let pool = db.into_pool();
    let (salt, nonce, secret) = if let Some(p) = password {
        let blob = crate::secrets::encrypt_secret(p.as_bytes())?;
        (blob.salt, blob.nonce, blob.ciphertext)
    } else {
        // Keep existing secret
        let current = state_store::get_relay_credential_by_id(&pool, id)
            .await?
            .ok_or_else(|| ServerError::not_found("credential", id.to_string()))?;
        (current.salt, current.nonce, current.secret)
    };
    let meta = username.map(|u| serde_json::json!({"username": u}).to_string());
    state_store::update_relay_credential(
        &pool,
        id,
        "password",
        &salt,
        &nonce,
        &secret,
        meta.as_deref(),
        username_mode,
        password_required,
    )
    .await?;
    info!(credential = name, kind = "password", "credential updated");
    Ok(())
}

pub async fn update_ssh_key_credential(
    id: i64,
    name: &str,
    username: Option<&str>,
    key: Option<&str>,
    certificate: Option<&str>,
    passphrase: Option<&str>,
    username_mode: &str,
) -> ServerResult<()> {
    let db = server_db().await?;

    let pool = db.into_pool();
    let (salt, nonce, secret) = if let Some(k) = key {
        let mut secret_obj = serde_json::Map::new();
        secret_obj.insert("private_key".to_string(), serde_json::Value::String(k.to_string()));
        if let Some(c) = certificate {
            secret_obj.insert("certificate".to_string(), serde_json::Value::String(c.to_string()));
        }
        if let Some(p) = passphrase {
            secret_obj.insert("passphrase".to_string(), serde_json::Value::String(p.to_string()));
        }
        let secret_json = serde_json::Value::Object(secret_obj).to_string();
        let blob = crate::secrets::encrypt_secret(secret_json.as_bytes())?;
        (blob.salt, blob.nonce, blob.ciphertext)
    } else {
        // Keep existing secret
        let current = state_store::get_relay_credential_by_id(&pool, id)
            .await?
            .ok_or_else(|| ServerError::not_found("credential", id.to_string()))?;
        (current.salt, current.nonce, current.secret)
    };
    let meta = username.map(|u| serde_json::json!({"username": u}).to_string());
    state_store::update_relay_credential(
        &pool,
        id,
        "ssh_key",
        &salt,
        &nonce,
        &secret,
        meta.as_deref(),
        username_mode,
        true, // password_required not applicable for ssh_key
    )
    .await?;
    info!(credential = name, kind = "ssh_key", "credential updated");
    Ok(())
}

pub async fn update_agent_credential(
    id: i64,
    name: &str,
    username: Option<&str>,
    public_key: Option<&str>,
    username_mode: &str,
) -> ServerResult<()> {
    let db = server_db().await?;

    let pool = db.into_pool();
    let (salt, nonce, secret) = if let Some(pk) = public_key {
        let secret = serde_json::json!({
            "public_key": pk,
        })
        .to_string();
        let blob = crate::secrets::encrypt_secret(secret.as_bytes())?;
        (blob.salt, blob.nonce, blob.ciphertext)
    } else {
        // Keep existing secret
        let current = state_store::get_relay_credential_by_id(&pool, id)
            .await?
            .ok_or_else(|| ServerError::not_found("credential", id.to_string()))?;
        (current.salt, current.nonce, current.secret)
    };
    let meta = username.map(|u| serde_json::json!({"username": u}).to_string());
    state_store::update_relay_credential(
        &pool,
        id,
        "agent",
        &salt,
        &nonce,
        &secret,
        meta.as_deref(),
        username_mode,
        true, // password_required not applicable for agent
    )
    .await?;
    info!(credential = name, kind = "agent", "credential updated");
    Ok(())
}

pub async fn delete_credential(name: &str) -> ServerResult<()> {
    let db = server_db().await?;

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
        let (resolved, is_legacy) = if crate::secrets::is_encrypted_marker(&value) {
            match crate::secrets::decrypt_string_if_encrypted(&value) {
                Ok((s, legacy)) => (s, legacy),
                Err(_) => continue,
            }
        } else {
            (crate::secrets::SecretString::new(Box::new(value)), false)
        };

        if is_legacy {
            warn!("Upgrading legacy v1 secret for relay option 'auth.id' (credential check)");
            let s: String = resolved.expose_secret().to_string();
            let b: Box<String> = Box::new(s);
            let ss: crate::secrets::SecretString = crate::secrets::SecretString::new(b);
            if let Ok(new_enc) = crate::secrets::encrypt_string(ss) {
                let _ = sqlx::query("UPDATE relay_host_options SET value = ? WHERE relay_host_id = ? AND key = 'auth.id'")
                    .bind(new_enc)
                    .bind(row.get::<i64, _>("relay_host_id"))
                    .execute(&pool)
                    .await;
            }
        }
        if resolved.expose_secret() == &target_id_str {
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

pub async fn list_credentials() -> ServerResult<Vec<(i64, String, String, Option<String>, String, bool)>> {
    let db = server_db().await?;

    let pool = db.into_pool();
    let rows = state_store::list_relay_credentials(&pool).await?;
    Ok(rows)
}

/// List credentials with assigned relay hosts
/// Returns (id, name, kind, username, username_mode, password_required, assigned_relays)
pub async fn list_credentials_with_assignments() -> ServerResult<Vec<(i64, String, String, Option<String>, String, bool, Vec<String>)>> {
    let db = server_db().await?;

    let pool = db.into_pool();

    let creds = state_store::list_relay_credentials(&pool).await?;
    let hosts = state_store::list_relay_hosts(&pool, None).await?;
    let host_map: std::collections::HashMap<i64, String> = hosts.into_iter().map(|h| (h.id, h.name)).collect();

    let opts_rows: Vec<(i64, String)> = sqlx::query_as("SELECT relay_host_id, value FROM relay_host_options WHERE key = 'auth.id'")
        .fetch_all(&pool)
        .await?;

    let mut assignments: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();

    for (host_id, value) in opts_rows {
        let (resolved, is_legacy) = if crate::secrets::is_encrypted_marker(&value) {
            match crate::secrets::decrypt_string_if_encrypted(&value) {
                Ok((s, legacy)) => (s, legacy),
                Err(_) => continue,
            }
        } else {
            (crate::secrets::SecretString::new(Box::new(value)), false)
        };

        if is_legacy {
            warn!("Upgrading legacy v1 secret for relay option 'auth.id' (list assignments)");
            if let Ok(new_enc) =
                crate::secrets::encrypt_string(secrecy::SecretBox::<String>::new(Box::new(resolved.expose_secret().to_string())))
            {
                let _ = sqlx::query("UPDATE relay_host_options SET value = ? WHERE relay_host_id = ? AND key = 'auth.id'")
                    .bind(new_enc)
                    .bind(host_id)
                    .execute(&pool)
                    .await;
            }
        }

        let cred_id_str = resolved.expose_secret().clone();
        if let Some(host_name) = host_map.get(&host_id) {
            assignments.entry(cred_id_str).or_default().push(host_name.clone());
        }
    }

    let mut result = Vec::new();
    for (id, name, kind, meta, username_mode, password_required) in creds {
        let username = meta
            .as_deref()
            .and_then(|m| serde_json::from_str::<serde_json::Value>(m).ok())
            .and_then(|v| v.get("username").and_then(|u| u.as_str().map(|s| s.to_string())));

        let mut assigned_relays = assignments.remove(&id.to_string()).unwrap_or_default();
        assigned_relays.sort();

        result.push((id, name, kind, username, username_mode, password_required, assigned_relays));
    }

    Ok(result)
}

pub async fn rotate_secrets_key(old_input: &str, new_input: &str) -> ServerResult<()> {
    // Trim inputs to match load_master_key behavior (prevents rotation failures with whitespace)
    let old_input = old_input.trim();
    let new_input = new_input.trim();

    // Derive master keys properly - if input looks like a passphrase, use Argon2id KDF
    let old_master = if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(old_input)
        && decoded.len() == 32
    {
        decoded
    } else {
        // It's a passphrase, derive using Argon2id (matches load_master_key)
        crate::secrets::derive_master_key_from_passphrase(old_input)?
    };

    let new_master = if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(new_input)
        && decoded.len() == 32
    {
        decoded
    } else {
        // It's a passphrase, derive using Argon2id (matches load_master_key)
        crate::secrets::derive_master_key_from_passphrase(new_input)?
    };

    let db = server_db().await?;

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
            let blob = crate::secrets::encrypt_secret_with(pt.expose_secret(), &new_master)?;
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

    // Rotate relay_host_options values. Respect the is_secure flag so plaintext
    // options remain plaintext and only sensitive rows are re-encrypted.
    {
        let rows = sqlx::query("SELECT relay_host_id, key, value, is_secure FROM relay_host_options")
            .fetch_all(&pool)
            .await?;
        for row in rows {
            let host_id: i64 = row.get("relay_host_id");
            let key: String = row.get("key");
            let value: String = row.get("value");
            let is_secure: bool = row.get("is_secure");

            // Only rotate entries explicitly marked secure; keep plaintext values untouched.
            if is_secure {
                // If a secure row somehow contains plaintext, treat it as such to avoid corrupting data.
                let plaintext = if crate::secrets::is_encrypted_marker(&value) {
                    crate::secrets::decrypt_string_with(&value, &old_master)?
                } else {
                    crate::secrets::SecretString::new(Box::new(value))
                };
                let reenc = crate::secrets::encrypt_string_with(plaintext, &new_master)?;
                sqlx::query("UPDATE relay_host_options SET value = ?, is_secure = 1 WHERE relay_host_id = ? AND key = ?")
                    .bind(reenc)
                    .bind(host_id)
                    .bind(key)
                    .execute(&pool)
                    .await?;
            } else if crate::secrets::is_encrypted_marker(&value) {
                // Data hygiene: if a non-secure row was encrypted previously, restore plaintext so consumers do not misinterpret it.
                let plaintext = crate::secrets::decrypt_string_with(&value, &old_master)?;
                sqlx::query("UPDATE relay_host_options SET value = ?, is_secure = 0 WHERE relay_host_id = ? AND key = ?")
                    .bind(plaintext.expose_secret().to_string())
                    .bind(host_id)
                    .bind(key)
                    .execute(&pool)
                    .await?;
            }
        }
    }

    info!("secrets rotated for credentials and options");
    Ok(())
}

pub async fn assign_credential(hostname: &str, cred_name: &str) -> ServerResult<()> {
    let db = server_db().await?;

    let pool = db.into_pool();
    let cred = state_store::get_relay_credential_by_name(&pool, cred_name)
        .await?
        .ok_or_else(|| ServerError::not_found("credential", cred_name))?;

    // Fetch host to get ID for clearing auth
    let host = state_store::fetch_relay_host_by_name(&pool, hostname)
        .await?
        .ok_or_else(|| ServerError::not_found("relay host", hostname))?;

    // Normalize: map ssh_key-like kinds to publickey for relay auth.method
    let method_plain: &str = match cred.kind.as_str() {
        "ssh_key" | "ssh_cert_key" => "publickey",
        other => other,
    };

    // Clear any existing auth first to ensure clean state
    sqlx::query("DELETE FROM relay_host_options WHERE relay_host_id = ? AND key LIKE 'auth.%'")
        .bind(host.id)
        .execute(&pool)
        .await?;

    // Use set_relay_option to benefit from automatic security determination
    // These will be stored as plain text per our security logic
    set_relay_option(hostname, "auth.source", "credential", true).await?;
    set_relay_option(hostname, "auth.id", &cred.id.to_string(), true).await?;
    set_relay_option(hostname, "auth.method", method_plain, true).await?;

    info!(relay_host = hostname, credential = cred_name, "credential assigned to host");
    Ok(())
}

pub async fn unassign_credential(hostname: &str) -> ServerResult<()> {
    let db = server_db().await?;

    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_name(&pool, hostname)
        .await?
        .ok_or_else(|| ServerError::not_found("relay host", hostname))?;
    sqlx::query("DELETE FROM relay_host_options WHERE relay_host_id = ? AND key LIKE 'auth.%'")
        .bind(host.id)
        .execute(&pool)
        .await?;
    info!(relay_host = hostname, "credential unassigned from host");
    Ok(())
}

/// Set custom password authentication for a relay (inline, not using a saved credential)
pub async fn set_custom_password_auth(
    hostname: &str,
    username: Option<&str>,
    password: &str,
    username_mode: &str,
    password_required: bool,
) -> ServerResult<()> {
    // Clear any existing auth first
    let db = server_db().await?;
    let pool = db.into_pool();
    if let Some(host) = state_store::fetch_relay_host_by_name(&pool, hostname).await? {
        sqlx::query("DELETE FROM relay_host_options WHERE relay_host_id = ? AND key LIKE 'auth.%'")
            .bind(host.id)
            .execute(&pool)
            .await?;
    }

    set_relay_option(hostname, "auth.source", "inline", true).await?;
    set_relay_option(hostname, "auth.method", "password", true).await?;
    if let Some(user) = username {
        set_relay_option(hostname, "auth.username", user, true).await?;
    }
    set_relay_option(hostname, "auth.password", password, true).await?;
    set_relay_option(hostname, "auth.username_mode", username_mode, true).await?;
    set_relay_option(
        hostname,
        "auth.password_required",
        if password_required { "true" } else { "false" },
        true,
    )
    .await?;
    info!(relay_host = hostname, "custom password auth configured");
    Ok(())
}

/// Set custom SSH key authentication for a relay (inline, not using a saved credential)
pub async fn set_custom_ssh_key_auth(
    hostname: &str,
    username: Option<&str>,
    private_key: &str,
    passphrase: Option<&str>,
    username_mode: &str,
) -> ServerResult<()> {
    // Clear any existing auth first
    let db = server_db().await?;
    let pool = db.into_pool();
    if let Some(host) = state_store::fetch_relay_host_by_name(&pool, hostname).await? {
        sqlx::query("DELETE FROM relay_host_options WHERE relay_host_id = ? AND key LIKE 'auth.%'")
            .bind(host.id)
            .execute(&pool)
            .await?;
    }

    set_relay_option(hostname, "auth.source", "inline", true).await?;
    set_relay_option(hostname, "auth.method", "publickey", true).await?;
    if let Some(user) = username {
        set_relay_option(hostname, "auth.username", user, true).await?;
    }
    set_relay_option(hostname, "auth.identity", private_key, true).await?;
    if let Some(pass) = passphrase {
        set_relay_option(hostname, "auth.passphrase", pass, true).await?;
    }
    set_relay_option(hostname, "auth.username_mode", username_mode, true).await?;
    info!(relay_host = hostname, "custom SSH key auth configured");
    Ok(())
}

/// Set custom SSH agent authentication for a relay (inline, not using a saved credential)
pub async fn set_custom_agent_auth(hostname: &str, username: Option<&str>, public_key: &str, username_mode: &str) -> ServerResult<()> {
    // Clear any existing auth first
    let db = server_db().await?;
    let pool = db.into_pool();
    if let Some(host) = state_store::fetch_relay_host_by_name(&pool, hostname).await? {
        sqlx::query("DELETE FROM relay_host_options WHERE relay_host_id = ? AND key LIKE 'auth.%'")
            .bind(host.id)
            .execute(&pool)
            .await?;
    }

    set_relay_option(hostname, "auth.source", "inline", true).await?;
    set_relay_option(hostname, "auth.method", "agent", true).await?;
    if let Some(user) = username {
        set_relay_option(hostname, "auth.username", user, true).await?;
    }
    set_relay_option(hostname, "auth.agent_pubkey", public_key, true).await?;
    set_relay_option(hostname, "auth.username_mode", username_mode, true).await?;
    info!(relay_host = hostname, "custom agent auth configured");
    Ok(())
}

/// Clear all authentication settings from a relay
pub async fn clear_all_auth(hostname: &str) -> ServerResult<()> {
    let db = server_db().await?;

    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_name(&pool, hostname)
        .await?
        .ok_or_else(|| ServerError::not_found("relay host", hostname))?;
    sqlx::query("DELETE FROM relay_host_options WHERE relay_host_id = ? AND key LIKE 'auth.%'")
        .bind(host.id)
        .execute(&pool)
        .await?;
    info!(relay_host = hostname, "all auth settings cleared");
    Ok(())
}

async fn load_or_create_host_key(pool: &SqlitePool) -> ServerResult<PrivateKey> {
    const KEY_NAME: &str = "server_hostkey";
    if let Some(row) = sqlx::query("SELECT value FROM server_options WHERE key = ?")
        .bind(KEY_NAME)
        .fetch_optional(pool)
        .await?
    {
        let raw: String = row.get("value");
        // Host key may be stored encrypted; decrypt if needed
        let (pem, is_legacy) = crate::secrets::decrypt_string_if_encrypted(&raw)?;
        if is_legacy {
            warn!("Upgrading legacy v1 server host key");
            let s: String = pem.expose_secret().to_string();
            let b: Box<String> = Box::new(s);
            let ss: secrecy::SecretBox<String> = secrecy::SecretBox::new(b);
            if let Ok(new_enc) = crate::secrets::encrypt_string(ss) {
                let _ = sqlx::query("INSERT OR REPLACE INTO server_options (key, value) VALUES (?, ?)")
                    .bind(KEY_NAME)
                    .bind(new_enc)
                    .execute(pool)
                    .await;
            }
        }
        // If it wasn't encrypted before and a master secret is configured, upgrade to encrypted at rest
        if !crate::secrets::is_encrypted_marker(&raw) {
            if let Ok(()) = crate::secrets::require_master_secret() {
                if let Ok(enc) = crate::secrets::encrypt_string(crate::secrets::SecretString::new(Box::new(pem.expose_secret().clone()))) {
                    let _ = sqlx::query("INSERT OR REPLACE INTO server_options (key, value) VALUES (?, ?)")
                        .bind(KEY_NAME)
                        .bind(enc)
                        .execute(pool)
                        .await;
                    tracing::info!("secured server host key with encryption");
                }
            } else {
                tracing::warn!(
                    "server host key is stored unencrypted; set RB_SERVER_SECRETS_KEY or RB_SERVER_SECRETS_PASSPHRASE to enable encryption"
                );
            }
        }
        let key = PrivateKey::from_openssh(pem.expose_secret()).map_err(|e| ServerError::Crypto(e.to_string()))?;
        info!("loaded persisted server host key");
        Ok(key)
    } else {
        // Ensure we have a usable master secret before generating so we don't persist unencrypted keys
        crate::secrets::require_master_secret()?;
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).map_err(|e| ServerError::Crypto(e.to_string()))?;
        let pem = key
            .to_openssh(LineEnding::LF)
            .map_err(|e| ServerError::Crypto(e.to_string()))?
            .to_string();

        // Encrypt before storing at rest
        let enc = crate::secrets::encrypt_string(crate::secrets::SecretString::new(Box::new(pem)))?;
        sqlx::query("INSERT OR REPLACE INTO server_options (key, value) VALUES (?, ?)")
            .bind(KEY_NAME)
            .bind(enc)
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

/// Create a ManagementApp with all relay hosts loaded from the database (admin view)
pub async fn create_management_app(
    review: Option<tui_core::apps::management::HostkeyReview>,
) -> ServerResult<tui_core::apps::ManagementApp> {
    create_management_app_with_tab(0, review).await
}

/// Create a ManagementApp with a specific tab selected
pub async fn create_management_app_with_tab(
    selected_tab: usize,
    review: Option<tui_core::apps::management::HostkeyReview>,
) -> ServerResult<tui_core::apps::ManagementApp> {
    let db = server_db().await?;

    let pool = db.into_pool();

    // Admin sees all relay hosts (no filtering)
    use tui_core::apps::relay_selector::RelayItem;
    let hosts = state_store::list_relay_hosts(&pool, None).await?;
    let relay_items: Vec<RelayItem> = hosts
        .into_iter()
        .map(|h| RelayItem {
            name: h.name,
            description: format!("{}:{}", h.ip, h.port),
            id: h.id,
        })
        .collect();

    // Credentials with counts
    let creds_rows = state_store::list_relay_credentials(&pool).await?;
    // Build assigned counts by scanning relay_host_options auth.id
    use secrecy::ExposeSecret as _;
    let mut counts: std::collections::HashMap<i64, i64> = std::collections::HashMap::new();
    let rows = sqlx::query("SELECT relay_host_id, value FROM relay_host_options WHERE key = 'auth.id'")
        .fetch_all(&pool)
        .await?;
    for row in rows {
        let value: String = row.get("value");
        let (id_str, is_legacy) = if crate::secrets::is_encrypted_marker(&value) {
            match crate::secrets::decrypt_string_if_encrypted(&value) {
                Ok((s, legacy)) => (s, legacy),
                Err(_) => continue,
            }
        } else {
            (crate::secrets::SecretString::new(Box::new(value)), false)
        };

        if is_legacy {
            warn!("Upgrading legacy v1 secret for relay option 'auth.id' (management app)");
            if let Ok(new_enc) =
                crate::secrets::encrypt_string(secrecy::SecretBox::<String>::new(Box::new(id_str.expose_secret().to_string())))
            {
                let _ = sqlx::query("UPDATE relay_host_options SET value = ? WHERE relay_host_id = ? AND key = 'auth.id'")
                    .bind(new_enc)
                    .bind(row.get::<i64, _>("relay_host_id"))
                    .execute(&pool)
                    .await;
            }
        }
        if let Ok(id) = id_str.expose_secret().parse::<i64>() {
            *counts.entry(id).or_insert(0) += 1;
        }
    }
    let credentials: Vec<tui_core::apps::management::CredentialItem> = creds_rows
        .into_iter()
        .map(
            |(id, name, kind, _meta, _username_mode, _password_required)| tui_core::apps::management::CredentialItem {
                id,
                name,
                kind,
                assigned: *counts.get(&id).unwrap_or(&0),
            },
        )
        .collect();

    // Build host->credential label mapping
    let mut host_creds: std::collections::HashMap<i64, String> = std::collections::HashMap::new();
    // Gather relevant options in one query
    let opt_rows = sqlx::query(
        "SELECT relay_host_id, key, value FROM relay_host_options WHERE key IN ('auth.source','auth.id','auth.identity','auth.password')",
    )
    .fetch_all(&pool)
    .await?;
    // Map host_id -> key -> resolved value
    let mut host_opts: std::collections::HashMap<i64, std::collections::HashMap<String, crate::secrets::SecretString>> =
        std::collections::HashMap::new();
    for row in opt_rows {
        let host_id: i64 = row.get("relay_host_id");
        let key: String = row.get("key");
        let raw: String = row.get("value");
        let resolved = if crate::secrets::is_encrypted_marker(&raw) {
            match crate::secrets::decrypt_string_if_encrypted(&raw) {
                Ok((s, _)) => s, // Skip upgrade - complex context without direct ID access
                Err(_) => continue,
            }
        } else {
            crate::secrets::SecretString::new(Box::new(raw))
        };
        host_opts.entry(host_id).or_default().insert(key, resolved);
    }
    // id -> name
    let mut cred_name_by_id: std::collections::HashMap<i64, String> = std::collections::HashMap::new();
    // rebuild from list (we had moved creds_rows)
    let creds_rows2 = state_store::list_relay_credentials(&pool).await?;
    for (id, name, _kind, _meta, _username_mode, _password_required) in creds_rows2 {
        cred_name_by_id.insert(id, name);
    }
    // Compute label
    for (hid, opts) in host_opts.iter() {
        let label = if let Some(src) = opts.get("auth.source") {
            if src.expose_secret() == "credential" {
                if let Some(id_str) = opts.get("auth.id") {
                    if let Ok(cid) = id_str.expose_secret().parse::<i64>() {
                        cred_name_by_id.get(&cid).cloned().unwrap_or_else(|| "<credential>".to_string())
                    } else {
                        "<credential>".to_string()
                    }
                } else {
                    "<credential>".to_string()
                }
            } else {
                "<custom>".to_string()
            }
        } else if opts.contains_key("auth.identity") || opts.contains_key("auth.password") {
            "<custom>".to_string()
        } else {
            "<none>".to_string()
        };
        host_creds.insert(*hid, label);
    }

    // Hostkey presence mapping
    let mut hostkeys: std::collections::HashMap<i64, bool> = std::collections::HashMap::new();
    let hk_rows = sqlx::query("SELECT relay_host_id FROM relay_host_options WHERE key = 'hostkey.openssh'")
        .fetch_all(&pool)
        .await?;
    for row in hk_rows {
        let hid: i64 = row.get("relay_host_id");
        hostkeys.insert(hid, true);
    }
    // Ensure entries exist for all hosts
    for item in &relay_items {
        hostkeys.entry(item.id).or_insert(false);
    }

    // Pending hostkey review (if any)
    let review_opt = review;
    let review_host = review_opt.as_ref().map(|r| r.host.clone());

    let mut app = tui_core::apps::ManagementApp::new(relay_items, host_creds, hostkeys, credentials, None, review_opt)
        .with_selected_tab(selected_tab);

    // If a hostkey review is being shown, ensure the background table selects that host
    if let Some(name) = review_host.as_deref() {
        app = app.with_selected_host_name(name);
    }

    Ok(app)
}

/// Build a TUI app by name for the given user context.
///
/// - name: "Management" or any other value (treated as relay selector)
/// - tab: optional tab index for Management
/// - user: optional username; when None or Some("admin"), full admin relay list is shown
pub async fn create_app_by_name(user: Option<&str>, name: &str, tab: Option<usize>) -> ServerResult<Box<dyn tui_core::TuiApp>> {
    match name {
        "Management" => {
            let app = if let Some(t) = tab {
                create_management_app_with_tab(t, None).await?
            } else {
                create_management_app(None).await?
            };
            Ok(Box::new(app))
        }
        _ => {
            let app = create_relay_selector_app(user).await?;
            Ok(Box::new(app))
        }
    }
}

/// Apply side effects for management-related AppActions (add/update/delete relay hosts).
/// Centralizing this logic avoids divergence between local and SSH TUI paths.
pub async fn handle_management_action(action: tui_core::AppAction) -> ServerResult<Option<tui_core::AppAction>> {
    match action {
        tui_core::AppAction::AddRelay(item) => {
            let (ip, port) = parse_endpoint(&item.description)?;
            let db = server_db().await?;

            let pool = db.into_pool();
            state_store::insert_relay_host(&pool, &item.name, &ip, port).await?;
        }
        tui_core::AppAction::UpdateRelay(item) => {
            let (ip, port) = parse_endpoint(&item.description)?;
            let db = server_db().await?;

            let pool = db.into_pool();
            state_store::update_relay_host(&pool, item.id, &item.name, &ip, port).await?;
        }
        tui_core::AppAction::DeleteRelay(id) => {
            let db = server_db().await?;

            let pool = db.into_pool();
            state_store::delete_relay_host_by_id(&pool, id).await?;
        }
        tui_core::AppAction::AddCredential(spec) => {
            use tui_core::apps::management::CredentialSpec as Spec;
            match spec {
                Spec::Password {
                    name,
                    username,
                    username_mode,
                    password_required,
                    password,
                } => {
                    let _ =
                        crate::create_password_credential(&name, username.as_deref(), &password, &username_mode, password_required).await?;
                }
                Spec::SshKey {
                    name,
                    username,
                    username_mode,
                    key_file: _,
                    value,
                    cert_file,
                    passphrase,
                } => {
                    // TUI provides inline key value; file path not used here
                    let key_data = if let Some(val) = value {
                        val
                    } else {
                        return Err(ServerError::Other("ssh_key requires key content".into()));
                    };
                    let cert_data = cert_file; // may be None
                    let _ = crate::create_ssh_key_credential(
                        &name,
                        username.as_deref(),
                        &key_data,
                        cert_data.as_deref(),
                        passphrase.as_deref(),
                        &username_mode,
                    )
                    .await?;
                }
                Spec::Agent {
                    name,
                    username,
                    username_mode,
                    public_key,
                } => {
                    let _ = crate::create_agent_credential(&name, username.as_deref(), &public_key, &username_mode).await?;
                }
            }
        }
        tui_core::AppAction::DeleteCredential(name) => crate::delete_credential(&name).await?,
        tui_core::AppAction::UnassignCredential(hostname) => crate::unassign_credential(&hostname).await?,
        tui_core::AppAction::AssignCredential { host, cred_name } => crate::assign_credential(&host, &cred_name).await?,
        tui_core::AppAction::FetchHostkey { id, name } => {
            info!(relay = %name, relay_id = id, "refreshing relay host key");
            // Fetch and stage hostkey for review
            let db = server_db().await?;

            let pool = db.into_pool();

            // Resolve host by id first to avoid stale name collisions
            let host = state_store::fetch_relay_host_by_id(&pool, id)
                .await?
                .ok_or_else(|| ServerError::not_found("relay host", id.to_string()))?;
            if host.name != name {
                tracing::warn!(
                    requested_name = %name,
                    actual_name = %host.name,
                    relay_id = id,
                    "relay name changed during hostkey fetch; using id match"
                );
            }

            use std::sync::{Arc, Mutex};

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
            let connect_timeout = hostkey_fetch_timeout()?;
            let session = tokio::time::timeout(connect_timeout, client::connect(cfg, (host.ip.as_str(), host.port as u16), handler))
                .await
                .map_err(|_| {
                    ServerError::Other(format!(
                        "timed out fetching host key from {}:{} after {:?}",
                        host.ip, host.port, connect_timeout
                    ))
                })??;
            let _ = session.disconnect(russh::Disconnect::ByApplication, "", "").await;
            let Some(new_key) = captured.lock().unwrap().clone() else {
                return Ok(None);
            };
            let new_fp = new_key.fingerprint(HashAlg::Sha256).to_string();
            let new_pem = new_key.to_openssh().map_err(|e| ServerError::Crypto(e.to_string()))?.to_string();
            let new_type = new_pem.split_whitespace().next().unwrap_or("").to_string();

            // Existing (optional)
            let mut old_fp: Option<String> = None;
            let mut old_type: Option<String> = None;
            if let Some(row) = sqlx::query("SELECT value FROM relay_host_options WHERE relay_host_id = ? AND key = 'hostkey.openssh'")
                .bind(host.id)
                .fetch_optional(&pool)
                .await?
            {
                let raw: String = row.get("value");
                let dec = if crate::secrets::is_encrypted_marker(&raw) {
                    match crate::secrets::decrypt_string_if_encrypted(&raw) {
                        Ok((s, _)) => s,
                        Err(_) => crate::secrets::SecretString::new(Box::new("".to_string())),
                    }
                } else {
                    crate::secrets::SecretString::new(Box::new(raw))
                };
                if !dec.expose_secret().is_empty()
                    && let Ok(pk) = PublicKey::from_openssh(dec.expose_secret())
                {
                    old_fp = Some(pk.fingerprint(HashAlg::Sha256).to_string());
                    // Extract type from stored content (prefix token)
                    old_type = Some(dec.expose_secret().split_whitespace().next().unwrap_or("").to_string());
                }
            }

            return Ok(Some(tui_core::AppAction::ReviewHostkey(
                tui_core::apps::management::HostkeyReview {
                    host_id: host.id,
                    host: host.name,
                    new_fingerprint: new_fp,
                    new_key_type: new_type,
                    old_fingerprint: old_fp,
                    old_key_type: old_type,
                    new_key_pem: new_pem,
                },
            )));
        }
        tui_core::AppAction::StoreHostkey { id, name: _name, key } => {
            let db = server_db().await?;

            let pool = db.into_pool();

            // Resolve host strictly by id to avoid races when names change mid-review
            let host = state_store::fetch_relay_host_by_id(&pool, id)
                .await?
                .ok_or_else(|| ServerError::not_found("relay host", id.to_string()))?;
            let stored = crate::secrets::encrypt_string(crate::secrets::SecretString::new(Box::new(key)))?;
            sqlx::query(
                "INSERT INTO relay_host_options (relay_host_id, key, value) VALUES (?, ?, ?) \
                 ON CONFLICT(relay_host_id, key) DO UPDATE SET value = excluded.value",
            )
            .bind(host.id)
            .bind("hostkey.openssh")
            .bind(stored)
            .execute(&pool)
            .await?;
            info!(relay = %host.name, relay_id = host.id, "relay host key accepted and stored");
        }
        tui_core::AppAction::CancelHostkey { .. } => {
            // No global state to clear
        }
        _ => {}
    }
    Ok(None)
}

/// Convenience wrapper for TUI callers: runs the management action and, on error,
/// sets a one-shot flash message so the Management UI can surface feedback.
// Format an error message suitable for display in the ManagementApp status area
pub fn format_action_error(action: &tui_core::AppAction, e: &ServerError) -> String {
    match action {
        tui_core::AppAction::AddRelay(item) => format!("Cannot add relay host '{}': {}", item.name, e),
        tui_core::AppAction::UpdateRelay(item) => format!("Cannot update relay host '{}': {}", item.name, e),
        tui_core::AppAction::DeleteRelay(id) => format!("Cannot delete relay host id {}: {}", id, e),
        tui_core::AppAction::AddCredential(spec) => match spec {
            tui_core::apps::management::CredentialSpec::Password { name, .. } => {
                format!("Cannot create password credential '{}': {}", name, e)
            }
            tui_core::apps::management::CredentialSpec::SshKey { name, .. } => {
                format!("Cannot create ssh_key credential '{}': {}", name, e)
            }
            tui_core::apps::management::CredentialSpec::Agent { name, .. } => format!("Cannot create agent credential '{}': {}", name, e),
        },
        tui_core::AppAction::DeleteCredential(name) => format!("Cannot delete credential '{}': {}", name, e),
        tui_core::AppAction::AssignCredential { host, cred_name } => {
            format!("Cannot set credential '{}' for '{}': {}", cred_name, host, e)
        }
        tui_core::AppAction::UnassignCredential(host) => {
            format!("Cannot clear credential for '{}': {}", host, e)
        }
        _ => format!("Operation failed: {}", e),
    }
}

/// Create a RelaySelectorApp with relay hosts loaded from the database
/// If username is Some, filters by access. If None (or "admin"), shows all relays with admin privileges.
pub async fn create_relay_selector_app(username: Option<&str>) -> ServerResult<tui_core::apps::RelaySelectorApp> {
    let db = server_db().await?;

    let pool = db.into_pool();

    let is_admin = username == Some("admin") || username.is_none();

    // Fetch relays. Admin view must bypass ACL filtering.
    use tui_core::apps::relay_selector::RelayItem;
    let filter_username = if is_admin { None } else { username };
    let hosts = state_store::list_relay_hosts(&pool, filter_username).await?;
    let relays: Vec<RelayItem> = hosts
        .into_iter()
        .map(|h| RelayItem {
            name: h.name,
            description: format!("{}:{}", h.ip, h.port),
            id: h.id,
        })
        .collect();

    Ok(if is_admin {
        tui_core::apps::RelaySelectorApp::new_for_admin(relays)
    } else {
        tui_core::apps::RelaySelectorApp::new(relays)
    })
}

/// Fetch relay hostkey for web UI review (returns tuple to avoid tui_core dependency)
/// Returns: (host_id, host_name, old_fp, old_type, new_fp, new_type, new_pem)
pub async fn fetch_relay_hostkey_for_web(id: i64) -> ServerResult<(i64, String, Option<String>, Option<String>, String, String, String)> {
    // Get host name first
    let db = server_db().await?;

    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_id(&pool, id)
        .await?
        .ok_or_else(|| ServerError::not_found("relay host", id.to_string()))?;

    let action = tui_core::AppAction::FetchHostkey { id, name: host.name };
    let result = handle_management_action(action).await?;

    match result {
        Some(tui_core::AppAction::ReviewHostkey(review)) => Ok((
            review.host_id,
            review.host,
            review.old_fingerprint,
            review.old_key_type,
            review.new_fingerprint,
            review.new_key_type,
            review.new_key_pem,
        )),
        _ => Err(ServerError::Other("Failed to fetch hostkey".to_string())),
    }
}

/// Store relay hostkey from web UI (avoids tui_core dependency)
pub async fn store_relay_hostkey_from_web(id: i64, key_pem: String) -> ServerResult<()> {
    let action = tui_core::AppAction::StoreHostkey {
        id,
        name: String::new(), // name is not used in StoreHostkey handler
        key: key_pem,
    };
    handle_management_action(action).await?;
    Ok(())
}

pub async fn delete_credential_by_id(id: i64) -> ServerResult<()> {
    let db = server_db().await?;

    let pool = db.into_pool();

    // Guard: prevent deletion if in use by any relay host
    let rows = sqlx::query("SELECT relay_host_id, value FROM relay_host_options WHERE key = 'auth.id'")
        .fetch_all(&pool)
        .await?;
    let target_id_str = id.to_string();
    for row in rows {
        let value: String = row.get("value");
        let (resolved, is_legacy) = if crate::secrets::is_encrypted_marker(&value) {
            match crate::secrets::decrypt_string_if_encrypted(&value) {
                Ok((s, legacy)) => (s, legacy),
                Err(_) => continue,
            }
        } else {
            (crate::secrets::SecretString::new(Box::new(value)), false)
        };

        if is_legacy {
            warn!("Upgrading legacy v1 secret for relay option 'auth.id' (credential check)");
            let s: String = resolved.expose_secret().to_string();
            let b: Box<String> = Box::new(s);
            let ss: crate::secrets::SecretString = crate::secrets::SecretString::new(b);
            if let Ok(new_enc) = crate::secrets::encrypt_string(ss) {
                let _ = sqlx::query("UPDATE relay_host_options SET value = ? WHERE relay_host_id = ? AND key = 'auth.id'")
                    .bind(new_enc)
                    .bind(row.get::<i64, _>("relay_host_id"))
                    .execute(&pool)
                    .await;
            }
        }
        if resolved.expose_secret() == &target_id_str {
            let host_id: i64 = row.get("relay_host_id");
            let host = state_store::fetch_relay_host_by_id(&pool, host_id).await?;
            let host_name = host.map(|h| h.name).unwrap_or_else(|| "unknown".to_string());
            return Err(ServerError::not_permitted(
                "delete_credential",
                format!("credential is in use by relay host '{}'", host_name),
            ));
        }
    }

    state_store::delete_relay_credential_by_id(&pool, id).await?;
    info!(id, "credential deleted");
    Ok(())
}
