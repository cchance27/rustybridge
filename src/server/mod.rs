//! Embedded SSH server entry point and module wiring.
//!
//! This module intentionally keeps the public surface small: `run_server` wires up the russh
//! configuration, while the heavy lifting lives in the submodules.

mod handler;
mod remote_backend;
mod server_manager;
mod tui;

use std::{sync::Arc, time::Duration};

use anyhow::Result;
use russh::{
    MethodKind, MethodSet, keys::{Algorithm, PrivateKey, ssh_key::rand_core::OsRng}, server::{self as ssh_server, Server as _}
};
use server_manager::ServerManager;
use tracing::info;

use crate::{cli::ServerConfig, crypto::legacy_preferred};

/// Launch the embedded SSH server using the parsed CLI configuration.
///
/// This configures russh with our crypto preferences, enables only password auth,
/// and defers to [`ServerManager`] (and ultimately [`handler::ServerHandler`]) for per-connection
/// state machines.
pub async fn run_server(config: ServerConfig) -> Result<()> {
    let mut server_config = ssh_server::Config {
        preferred: legacy_preferred(),
        auth_rejection_time: Duration::from_millis(250),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        nodelay: true,
        ..Default::default()
    };

    server_config.methods = MethodSet::empty();
    server_config.methods.push(MethodKind::Password);
    server_config.keys.push(PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?);

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
