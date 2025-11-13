
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use russh::client;
use crate::session::{self, AcceptAllKeys, ShellOptions, run_command, run_shell};
use tracing::info;

use crate::cli::{ClientConfig};
use crate::crypto::legacy_preferred;

pub async fn run_client(args: ClientConfig) -> Result<()> {
    let ClientConfig {
        host,
        port,
        username,
        password,
        command,
        newline_mode,
        local_echo,
    } = args;
    let preferred = legacy_preferred();

    let config = russh::client::Config {
        preferred,
        nodelay: true,
        inactivity_timeout: None,
        ..Default::default()
    };
    let config = Arc::new(config);

    let handler = AcceptAllKeys;
    let target = format!("{host}:{port}");
    info!("connecting to {target}");
    let mut session = client::connect(config, (host.as_str(), port), handler)
        .await
        .context("failed to establish TCP connection")?;

    let auth = session
        .authenticate_password(username.clone(), password.clone())
        .await
        .context("password authentication failed")?;
    if !auth.success() {
        bail!("authentication rejected by server");
    }

    let outcome = if let Some(command) = &command {
        run_command(&mut session, command).await
    } else {
        let shell_opts = ShellOptions {
            newline_mode,
            local_echo,
        };
        run_shell(&mut session, shell_opts).await
    };

    session::disconnect(&mut session).await;
    outcome
}
