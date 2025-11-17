//! Embedded SSH server entry point and module wiring.
//!
//! This module intentionally keeps the public surface small: `run_server` wires up the russh
//! configuration, while the heavy lifting lives in the submodules.

mod handler;
mod remote_backend;
mod server_manager;
mod tui;

use std::{env, sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow};
use russh::{
    MethodKind, MethodSet,
    keys::{Algorithm, PrivateKey, ssh_key::LineEnding, ssh_key::rand_core::OsRng},
    server::{self as ssh_server, Server as _},
};
use server_manager::ServerManager;
use sqlx::{SqlitePool, migrate::Migrator, sqlite::SqlitePoolOptions};
use tracing::info;

use crate::{cli::ServerConfig, crypto::legacy_preferred};

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Launch the embedded SSH server using the parsed CLI configuration.
///
/// This configures russh with our crypto preferences, enables only password auth,
/// and defers to [`ServerManager`] (and ultimately [`handler::ServerHandler`]) for per-connection
/// state machines.
pub async fn run_server(config: ServerConfig) -> Result<()> {
    let db_url = state_db_url();
    let pool = init_state_store(&db_url).await?;
    MIGRATOR.run(&pool).await?;

    if config.roll_hostkey {
        sqlx::query!("DELETE FROM server_options WHERE key = 'server_hostkey'")
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
    info!(
        "starting embedded SSH server on {}:{} (credentials admin/admin)",
        config.bind, config.port
    );

    server
        .run_on_address(Arc::new(server_config), (config.bind.as_str(), config.port))
        .await?;
    Ok(())
}

fn state_db_url() -> String {
    match env::var("DATABASE_URL") {
        Ok(value) if value.starts_with("sqlite:") => value,
        Ok(value) => format!("sqlite://{value}"),
        Err(_) => "sqlite://rustybridge.db".to_string(),
    }
}

async fn init_state_store(db_url: &str) -> Result<SqlitePool> {
    let pool = SqlitePoolOptions::new()
        .max_connections(20)
        .connect(db_url)
        .await
        .with_context(|| format!("failed to open state database at {db_url}"))?;

    Ok(pool)
}

pub async fn add_relay_host(endpoint: &str, name: &str) -> Result<()> {
    let (ip, port) = parse_endpoint(endpoint)?;
    let db_url = state_db_url();
    let pool = init_state_store(&db_url).await?;
    MIGRATOR.run(&pool).await?;
    sqlx::query!(
        "INSERT INTO relay_hosts (name, ip, port) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET ip = excluded.ip, port = excluded.port",
        name,
        ip,
        port
    )
    .execute(&pool)
    .await?;
    info!(relay_host = name, ip, port, "relay host saved");
    Ok(())
}

async fn load_or_create_host_key(pool: &SqlitePool) -> Result<PrivateKey> {
    const KEY_NAME: &str = "server_hostkey";
    if let Some(row) = sqlx::query!("SELECT value FROM server_options WHERE key = ?", KEY_NAME)
        .fetch_optional(pool)
        .await?
    {
        let pem = row.value;
        let key = PrivateKey::from_openssh(&pem)?;
        info!("loaded persisted server host key");
        Ok(key)
    } else {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;
        let pem = key.to_openssh(LineEnding::LF)?.to_string();

        sqlx::query!("INSERT OR REPLACE INTO server_options (key, value) VALUES (?, ?)", KEY_NAME, pem)
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
