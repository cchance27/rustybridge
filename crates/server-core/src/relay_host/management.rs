use std::{env::VarError, time::Duration};

use rb_types::relay::RelayInfo;
use russh::{
    client, keys::{HashAlg, PublicKey}
};
use tracing::info;

use crate::{
    error::{ServerError, ServerResult}, secrets::{SecretBoxedString, encrypt_string}
};

const FETCH_HOSTKEY_TIMEOUT_ENV: &str = "RB_FETCH_TIMEOUT";
const DEFAULT_FETCH_HOSTKEY_TIMEOUT_SECS: f64 = 2.0;
const MAX_FETCH_HOSTKEY_TIMEOUT_SECS: f64 = 5.0;

pub fn hostkey_fetch_timeout() -> ServerResult<Duration> {
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
        Err(VarError::NotPresent) => Ok(Duration::from_secs_f64(DEFAULT_FETCH_HOSTKEY_TIMEOUT_SECS)),
        Err(VarError::NotUnicode(_)) => Err(ServerError::InvalidConfig(format!(
            "{FETCH_HOSTKEY_TIMEOUT_ENV} contains invalid UTF-8"
        ))),
    }
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
    let db = state_store::server_db().await?;

    let pool = db.into_pool();

    let mut tx = pool.begin().await.map_err(ServerError::Database)?;

    // Check if name already exists
    if state_store::fetch_relay_host_by_name(&mut *tx, name).await?.is_some() {
        return Err(ServerError::already_exists("relay host", name));
    }

    sqlx::query("INSERT INTO relay_hosts (name, ip, port) VALUES (?, ?, ?)")
        .bind(name)
        .bind(&ip)
        .bind(port)
        .execute(&mut *tx)
        .await?;

    tx.commit().await.map_err(ServerError::Database)?;

    info!(relay_host = name, ip, port, "relay host saved");

    // Attempt to fetch host key and optionally store it.
    if fetch_hostkey && let Err(err) = fetch_and_optionally_store_hostkey(&pool, name, &ip, port as u16).await {
        tracing::warn!(?err, relay_host = name, "failed to fetch/store host key during add-host");
    }
    Ok(())
}

async fn fetch_and_optionally_store_hostkey(pool: &sqlx::SqlitePool, name: &str, ip: &str, port: u16) -> ServerResult<()> {
    use std::{
        io::{self, Write}, sync::{Arc, Mutex}
    };

    struct CaptureHandler {
        key: Arc<Mutex<Option<PublicKey>>>,
    }
    impl russh::client::Handler for CaptureHandler {
        type Error = crate::error::ServerError;
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
        let stored = encrypt_string(SecretBoxedString::new(Box::new(pem)))?;
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

pub async fn list_hosts() -> ServerResult<Vec<RelayInfo>> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    let hosts = state_store::list_relay_hosts(&pool, None).await?;
    Ok(hosts)
}

pub async fn delete_relay_host_by_id(id: i64) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();
    sqlx::query("DELETE FROM relay_hosts WHERE id = ?").bind(id).execute(&pool).await?;
    info!(relay_host_id = id, "relay host deleted");
    Ok(())
}

pub async fn refresh_target_hostkey(name: &str) -> ServerResult<()> {
    let db = state_store::server_db().await?;

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

pub fn parse_endpoint(endpoint: &str) -> ServerResult<(String, i64)> {
    let (host, port_str) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| ServerError::InvalidEndpoint("relay hosts must be specified as ip:port".to_string()))?;
    let port = port_str
        .parse::<u16>()
        .map_err(|_| ServerError::InvalidEndpoint("invalid relay host port".to_string()))?;
    Ok((host.to_string(), port as i64))
}
