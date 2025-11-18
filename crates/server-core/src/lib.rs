//! Embedded SSH server entry point and module wiring.
//!
//! This module intentionally keeps the public surface small: `run_server` wires up the russh
//! configuration, while the heavy lifting lives in the submodules.

mod handler;
mod auth;
mod relay;
mod remote_backend;
mod server_manager;
mod tui;

use std::{sync::Arc, time::Duration};

use anyhow::{Result, anyhow};
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
pub async fn run_server(config: ServerConfig) -> Result<()> {
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();

    // Require at least one user to be present; avoid starting an unauthenticated server.
    let user_count = state_store::count_users(&pool).await?;
    if user_count == 0 {
        return Err(anyhow!(
            "no users configured; add one with: rb-server --add-user --user <name> --password <pass>"
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

pub async fn add_relay_host(endpoint: &str, name: &str) -> Result<()> {
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

pub async fn grant_relay_access(name: &str, user: &str) -> Result<()> {
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_name(&pool, name)
        .await?
        .ok_or_else(|| anyhow!("unknown relay host: {name}"))?;
    let _uid = state_store::fetch_user_id_by_name(&pool, user)
        .await?
        .ok_or_else(|| anyhow!("unknown user: {user}"))?;
    sqlx::query(
        "INSERT OR IGNORE INTO relay_host_acl (username, relay_host_id) VALUES (?, ?)",
    )
    .bind(user)
    .bind(host.id)
    .execute(&pool)
    .await?;
    info!(relay_host = name, user, "granted access to relay host");
    Ok(())
}

pub async fn set_relay_option(name: &str, key: &str, value: &str) -> Result<()> {
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_name(&pool, name)
        .await?
        .ok_or_else(|| anyhow!("unknown relay host: {name}"))?;
    sqlx::query(
        "INSERT INTO relay_host_options (relay_host_id, key, value) VALUES (?, ?, ?) \
         ON CONFLICT(relay_host_id, key) DO UPDATE SET value = excluded.value",
    )
    .bind(host.id)
    .bind(key)
    .bind(value)
    .execute(&pool)
    .await?;
    info!(relay_host = name, key, "relay option set");
    Ok(())
}

pub async fn revoke_relay_access(name: &str, user: &str) -> Result<()> {
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_name(&pool, name)
        .await?
        .ok_or_else(|| anyhow!("unknown relay host: {name}"))?;
    let _uid = state_store::fetch_user_id_by_name(&pool, user)
        .await?
        .ok_or_else(|| anyhow!("unknown user: {user}"))?;
    sqlx::query(
        "DELETE FROM relay_host_acl WHERE username = ? AND relay_host_id = ?",
    )
    .bind(user)
    .bind(host.id)
    .execute(&pool)
    .await?;
    info!(relay_host = name, user, "revoked access to relay host");
    Ok(())
}

pub async fn unset_relay_option(name: &str, key: &str) -> Result<()> {
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_name(&pool, name)
        .await?
        .ok_or_else(|| anyhow!("unknown relay host: {name}"))?;
    sqlx::query(
        "DELETE FROM relay_host_options WHERE relay_host_id = ? AND key = ?",
    )
    .bind(host.id)
    .bind(key)
    .execute(&pool)
    .await?;
    info!(relay_host = name, key, "relay option unset");
    Ok(())
}

async fn fetch_and_optionally_store_hostkey(pool: &sqlx::SqlitePool, name: &str, ip: &str, port: u16) -> Result<()> {
    use russh::{client, keys::{PublicKey, HashAlg}};
    use std::{io::{self, Write}, sync::{Arc, Mutex}};

    struct CaptureHandler {
        key: Arc<Mutex<Option<PublicKey>>>,
    }
    impl russh::client::Handler for CaptureHandler {
        type Error = anyhow::Error;
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
    let cfg = std::sync::Arc::new(russh::client::Config { preferred: ssh_core::crypto::default_preferred(), ..Default::default() });
    let session = client::connect(cfg, (ip, port), handler).await?;
    // No auth; disconnect immediately after handshake.
    let _ = session.disconnect(russh::Disconnect::ByApplication, "", "").await;

    let Some(key) = captured.lock().unwrap().clone() else { return Ok(()); };
    let fp = key.fingerprint(HashAlg::Sha256).to_string();
    let pem = key.to_openssh()?.to_string();

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
            .ok_or_else(|| anyhow!("relay host disappeared during hostkey store"))?;
        sqlx::query(
            "INSERT INTO relay_host_options (relay_host_id, key, value) VALUES (?, ?, ?) \
             ON CONFLICT(relay_host_id, key) DO UPDATE SET value = excluded.value",
        )
        .bind(host.id)
        .bind("hostkey.openssh")
        .bind(pem)
        .execute(pool)
        .await?;
        info!(relay_host = name, "stored relay host key (OpenSSH format)");
    }
    Ok(())
}

pub async fn list_hosts() -> Result<Vec<state_store::RelayHost>> {
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();
    let hosts = state_store::list_relay_hosts(&pool).await?;
    Ok(hosts)
}

pub async fn list_options(name: &str) -> Result<Vec<(String, String)>> {
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_name(&pool, name)
        .await?
        .ok_or_else(|| anyhow!("unknown relay host: {name}"))?;
    let map = state_store::fetch_relay_host_options(&pool, host.id).await?;
    let mut items: Vec<(String, String)> = map.into_iter().collect();
    items.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(items)
}

pub async fn list_access(name: &str) -> Result<Vec<String>> {
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_name(&pool, name)
        .await?
        .ok_or_else(|| anyhow!("unknown relay host: {name}"))?;
    let users = state_store::fetch_relay_access_usernames(&pool, host.id).await?;
    Ok(users)
}

pub async fn refresh_target_hostkey(name: &str) -> Result<()> {
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_name(&pool, name)
        .await?
        .ok_or_else(|| anyhow!("unknown relay host: {name}"))?;
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

pub async fn add_user(user: &str, password: &str) -> Result<()> {
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

pub async fn remove_user(user: &str) -> Result<()> {
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

pub async fn list_users() -> Result<Vec<String>> {
    let db = server_db().await?;
    migrate_server(&db).await?;
    let pool = db.into_pool();
    let users = state_store::list_usernames(&pool).await?;
    Ok(users)
}

async fn load_or_create_host_key(pool: &SqlitePool) -> Result<PrivateKey> {
    const KEY_NAME: &str = "server_hostkey";
    if let Some(row) = sqlx::query("SELECT value FROM server_options WHERE key = ?")
        .bind(KEY_NAME)
        .fetch_optional(pool)
        .await?
    {
        let pem: String = row.get("value");
        let key = PrivateKey::from_openssh(&pem)?;
        info!("loaded persisted server host key");
        Ok(key)
    } else {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;
        let pem = key.to_openssh(LineEnding::LF)?.to_string();

        sqlx::query("INSERT OR REPLACE INTO server_options (key, value) VALUES (?, ?)")
            .bind(KEY_NAME)
            .bind(pem)
            .execute(pool)
            .await?;

        info!("generated new server host key and cached it in the state database");
        Ok(key)
    }
}

fn parse_endpoint(endpoint: &str) -> Result<(String, i64)> {
    let (host, port_str) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("relay hosts must be specified as ip:port"))?;
    let port = port_str.parse::<u16>().map_err(|_| anyhow!("invalid relay host port"))?;
    Ok((host.to_string(), port as i64))
}
