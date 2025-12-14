mod auth;
pub mod error;
mod hostkeys;

use auth::authenticate;
pub use error::{ClientError, ClientResult};
use hostkeys::{ClientHandler, HostKeyPolicy, HostKeyVerifier};
use rb_types::client::{AuthPreferences, ClientConfig};
use russh::client;
use ssh_core::{
    crypto::{default_preferred, legacy_preferred},
    forwarding::ForwardingManager,
    session::{self, ShellOptions, run_command, run_shell, run_subsystem},
};
use std::{borrow::Cow, sync::Arc, time::Duration};
use tracing::{info, warn};

pub async fn run_client(args: ClientConfig) -> ClientResult<()> {
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
        insecure,
        identities,
        allow_keyboard_interactive,
        agent_auth,
        forward_agent,
        ssh_agent_socket,
        prompt_password,
        password_prompt,
        forwarding,
    } = args;
    if forward_agent && ssh_agent_socket.is_none() {
        return Err(ClientError::Other("--forward-agent requires SSH_AUTH_SOCK to be set".to_string()));
    }
    let mut preferred = if insecure {
        warn!("insecure mode enabled: using legacy cipher suite");
        legacy_preferred()
    } else {
        default_preferred()
    };
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
    let forwarding = ForwardingManager::new(forwarding);
    let handler = ClientHandler::new(verifier, ssh_agent_socket.clone(), forward_agent, forwarding.clone());
    if forwarding.has_requests() {
        let summary = forwarding.descriptors();
        info!(targets = %summary.join(", "), "forwarding directives requested");
    }
    let config = Arc::new(config);
    let target = format!("{host}:{port}");
    info!(target = %target, "connecting to host");
    let mut session = client::connect(config, (host.as_str(), port), handler).await?;

    authenticate(
        &mut session,
        AuthPreferences {
            username: &username,
            password: password.as_ref(),
            prompt_password,
            password_prompt: password_prompt.as_deref(),
            identities: &identities,
            allow_keyboard_interactive,
            use_agent_auth: agent_auth,
            agent_socket: ssh_agent_socket.as_deref(),
        },
    )
    .await?;

    forwarding.start_remote_tcp_forwarders(&mut session).await?;
    forwarding.start_remote_unix_forwarders(&mut session).await?;
    let session = Arc::new(session);
    forwarding.start_local_tcp_forwarders(session.clone()).await?;
    forwarding.start_local_unix_forwarders(session.clone()).await?;
    forwarding.start_dynamic_socks(session.clone()).await?;

    let subsystem_names = forwarding
        .config()
        .subsystems
        .iter()
        .map(|sub| sub.name.clone())
        .collect::<Vec<_>>();

    let outcome = if !subsystem_names.is_empty() {
        for name in subsystem_names {
            info!(subsystem = %name, "requesting subsystem");
            run_subsystem(&session, &name, forward_agent, &forwarding).await?;
        }
        Ok(())
    } else if let Some(command) = command.as_deref() {
        run_command(&session, command, forward_agent, &forwarding).await
    } else {
        let shell_opts = ShellOptions {
            newline_mode,
            local_echo,
            forward_agent,
            forwarding: forwarding.clone(),
        };
        run_shell(&session, shell_opts).await
    };

    forwarding.shutdown(Some(session.clone())).await?;
    session::disconnect(&session).await;
    match Arc::try_unwrap(session) {
        Ok(handle) => {
            if let Err(err) = handle.await {
                warn!(?err, "ssh session shutdown error");
            }
        }
        Err(_) => warn!("ssh session handle still in use; skipping shutdown wait"),
    }
    Ok(outcome?)
}
