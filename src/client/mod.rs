mod hostkeys;

use std::{borrow::Cow, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use russh::client;
use tracing::{info, warn};

use crate::{
    cli::ClientConfig,
    crypto::legacy_preferred,
    session::{self, ShellOptions, run_command, run_shell},
};
use hostkeys::{HostKeyHandler, HostKeyPolicy, HostKeyVerifier};

pub async fn run_client(args: ClientConfig) -> Result<()> {
    let ClientConfig {
        host,
        port,
        username,
        password,
        command,
        newline_mode,
        local_echo,
        prefer_compression,
        rekey_interval,
        rekey_bytes,
        keepalive_interval,
        keepalive_max,
        accept_hostkey_once,
        accept_store_hostkey,
        replace_hostkey,
    } = args;
    let mut preferred = legacy_preferred();
    preferred.compression = if prefer_compression {
        Cow::Owned(vec![
            russh::compression::ZLIB,
            russh::compression::ZLIB_LEGACY,
            russh::compression::NONE,
        ])
    } else {
        Cow::Owned(vec![
            russh::compression::NONE,
            russh::compression::ZLIB,
            russh::compression::ZLIB_LEGACY,
        ])
    };

    let mut config = russh::client::Config {
        preferred,
        nodelay: true,
        inactivity_timeout: None,
        keepalive_interval: keepalive_interval.or(Some(Duration::from_secs(30))),
        keepalive_max: keepalive_max.unwrap_or(3),
        ..Default::default()
    };
    if let Some(interval) = rekey_interval {
        config.limits.rekey_time_limit = interval;
    }
    if let Some(limit) = rekey_bytes {
        config.limits.rekey_read_limit = limit;
        config.limits.rekey_write_limit = limit;
    }
    let hostkey_policy = if accept_store_hostkey {
        HostKeyPolicy::AcceptAndStore
    } else if accept_hostkey_once {
        HostKeyPolicy::AcceptOnce
    } else {
        HostKeyPolicy::Prompt
    };
    let authority = format!("{host}:{port}");
    let verifier = HostKeyVerifier::new(authority, hostkey_policy).await?;
    if replace_hostkey {
        verifier.clear().await?;
    }
    let handler = HostKeyHandler::new(verifier);
    let config = Arc::new(config);
    let target = format!("{host}:{port}");
    info!("connecting to {target}");
    let mut session = client::connect(config, (host.as_str(), port), handler).await?;

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
        let shell_opts = ShellOptions { newline_mode, local_echo };
        run_shell(&mut session, shell_opts).await
    };

    session::disconnect(&mut session).await;
    if let Err(err) = session.await {
        warn!(?err, "SSH session shutdown error");
    }
    outcome
}
