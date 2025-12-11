//! Connection handling for relay connections.
//!
//! This module handles establishing, managing, and bridging connections to relay hosts.

use std::{collections::HashMap, sync::Arc};

use rb_types::{
    auth::AuthPromptEvent, relay::RelayInfo, ssh::{ForwardingConfig, NewlineMode}
};
use russh::{ChannelMsg, client};
use secrecy::ExposeSecret;
use ssh_core::{crypto::default_preferred, forwarding::ForwardingManager, session::run_shell};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tracing::{info, warn};

use super::{auth::authenticate_relay_session, credential::fetch_and_resolve_credential, handler::SharedRelayHandler};
use crate::{
    error::{ServerError, ServerResult}, secrets::SecretBoxedString
};

// Internal Result type alias
type Result<T> = ServerResult<T>;

pub struct RelayHandle {
    pub session: russh::client::Handle<SharedRelayHandler>,
    pub channel_id: russh::ChannelId,
    pub input_tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl RelayHandle {
    pub fn send(&self, bytes: Vec<u8>) {
        let _ = self.input_tx.send(bytes);
    }
}

/// Build the client configuration for connecting to relay hosts.
pub(crate) fn build_client_config(options: &HashMap<String, SecretBoxedString>) -> Arc<client::Config> {
    let mut cfg = client::Config {
        preferred: default_preferred(),
        nodelay: true,
        keepalive_interval: Some(std::time::Duration::from_secs(30)),
        keepalive_max: 3,
        ..Default::default()
    };
    let insecure = options.get("insecure").map(|v| v.expose_secret() == "true").unwrap_or(false);
    if insecure {
        // Fallback to legacy crypto suite if requested
        cfg.preferred = ssh_core::crypto::legacy_preferred();
    }
    let prefer_compression = options.get("compression").map(|v| v.expose_secret() == "true").unwrap_or(false);
    cfg.preferred.compression = if prefer_compression {
        std::borrow::Cow::Owned(vec![
            russh::compression::ZLIB,
            russh::compression::ZLIB_LEGACY,
            russh::compression::NONE,
        ])
    } else {
        std::borrow::Cow::Owned(vec![
            russh::compression::NONE,
            russh::compression::ZLIB,
            russh::compression::ZLIB_LEGACY,
        ])
    };
    Arc::new(cfg)
}

/// Start an outbound SSH session to the relay host and return a RelayBackend for unified session management.
///
/// This is the new unified approach that returns a backend abstraction, allowing the same relay
/// connection to be shared between web and SSH clients.
///
/// # Arguments
/// * `relay` - Relay host information
/// * `base_username` - Username for authentication
/// * `initial_size` - Initial terminal size (cols, rows)
/// * `options` - Relay host options (credentials, hostkey, etc.)
/// * `prompt_tx` - Optional channel for sending auth prompts
/// * `auth_rx` - Optional channel for receiving auth responses
#[allow(clippy::too_many_arguments)]
pub async fn start_bridge_backend(
    relay: &RelayInfo,
    base_username: &str,
    initial_size: (u32, u32),
    options: &HashMap<String, SecretBoxedString>,
    prompt_tx: Option<UnboundedSender<AuthPromptEvent>>,
    auth_rx: Option<Arc<tokio::sync::Mutex<UnboundedReceiver<String>>>>,
) -> Result<crate::sessions::session_backend::RelayBackend> {
    use crate::sessions::session_backend::RelayBackend;

    // Build client config with secure defaults
    let cfg = build_client_config(options);

    // Bridge simple prompt events (for web) to AppAction channel expected by auth flow
    let (action_tx, mut action_rx_forward) = if prompt_tx.is_some() {
        let (tx, rx) = mpsc::unbounded_channel::<tui_core::AppAction>();
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    // Client handler that enforces host-key policy
    let handler = super::handler::SharedRelayHandler {
        expected_key: options.get("hostkey.openssh").map(|v| v.expose_secret().clone()),
        relay_name: relay.name.clone(),
        warning_callback: Arc::new(|msg| {
            Box::pin(async move {
                warn!("{}", msg);
            })
        }),
        action_tx: action_tx.clone(),
        auth_rx: auth_rx.clone(),
    };

    let target = format!("{}:{}", relay.ip, relay.port);
    info!(relay = %relay.name, target, "connecting to relay host for backend");

    let mut remote = client::connect(cfg, (relay.ip.as_str(), relay.port as u16), handler).await?;

    // If we're bridging prompts, forward AuthPrompt actions to the caller's channel
    if let (Some(mut rx), Some(ptx)) = (action_rx_forward.take(), prompt_tx) {
        tokio::spawn(async move {
            while let Some(action) = rx.recv().await {
                if let tui_core::AppAction::AuthPrompt { prompt, echo } = action {
                    let _ = ptx.send(AuthPromptEvent { prompt, echo });
                }
            }
        });
    }

    // Fetch and resolve credential once to avoid TOCTOU
    let resolved_cred = fetch_and_resolve_credential(options, base_username).await?;

    // Authenticate according to options
    authenticate_relay_session(
        &mut remote,
        options,
        base_username,
        resolved_cred.as_ref(),
        &action_tx,
        &auth_rx,
        None,
    )
    .await?;

    // Open channel + PTY + shell
    let rchan = remote.channel_open_session().await?;
    rchan.request_pty(true, "xterm", initial_size.0, initial_size.1, 0, 0, &[]).await?;
    rchan.request_shell(true).await?;
    info!(relay = %relay.name, cols = initial_size.0, rows = initial_size.1, "relay shell started");

    // Set up channels for the backend
    let (input_tx, mut input_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (resize_tx, mut resize_rx) = mpsc::channel::<(u32, u32)>(10);

    let relay_handle = RelayHandle {
        session: remote,
        channel_id: rchan.id(),
        input_tx: input_tx.clone(),
    };

    // Create the backend
    let backend = RelayBackend::new(relay_handle, resize_tx);
    let output_tx = backend.output_tx();
    let relay_name = relay.name.clone();

    // Spawn task to handle relay I/O and broadcast to all viewers
    tokio::spawn(async move {
        let mut rchan = rchan;
        loop {
            tokio::select! {
                // Relay output -> broadcast to all viewers
                msg = rchan.wait() => {
                    match msg {
                        Some(ChannelMsg::Data { data }) => {
                            let _ = output_tx.send(data.to_vec());
                        }
                        Some(ChannelMsg::ExtendedData { data, .. }) => {
                            let _ = output_tx.send(data.to_vec());
                        }
                        Some(ChannelMsg::ExitStatus { exit_status }) => {
                            info!(relay = %relay_name, status = exit_status, "relay channel exit status");
                            let _ = output_tx.send(Vec::new());
                            break;
                        }
                        Some(ChannelMsg::Eof) => {
                            info!(relay = %relay_name, "relay channel EOF");
                            let _ = output_tx.send(Vec::new());
                            break;
                        }
                        Some(ChannelMsg::Close) | None => {
                            info!(relay = %relay_name, "relay channel closed");
                            let _ = output_tx.send(Vec::new());
                            break;
                        }
                        _ => {}
                    }
                }
                // Client input -> relay
                Some(bytes) = input_rx.recv() => {
                    if bytes.is_empty() {
                        info!(relay = %relay_name, "relay input closed (EOF from backend)");
                        let _ = output_tx.send(Vec::new());
                        break;
                    }
                    let mut cursor = std::io::Cursor::new(bytes);
                    if rchan.data(&mut cursor).await.is_err() {
                        warn!(relay = %relay_name, "relay write failed, closing");
                        let _ = output_tx.send(Vec::new());
                        break;
                    }
                }
                // Resize events -> relay
                Some((cols, rows)) = resize_rx.recv() => {
                    if rchan.window_change(cols, rows, 0, 0).await.is_err() {
                        warn!(relay = %relay_name, cols, rows, "relay resize failed, closing");
                        let _ = output_tx.send(Vec::new());
                        break;
                    }
                    info!(relay = %relay_name, cols, rows, "relay resized");
                }
            }
        }
        // Cleanup on exit
        let _ = rchan.eof().await;
        let _ = rchan.close().await;
        let _ = output_tx.send(Vec::new());
        info!(relay = %relay_name, "relay loop terminated");
    });

    Ok(backend)
}

/// Connect to a relay by name and return a RelayBackend for unified session management.
///
/// This is a convenience wrapper around `start_bridge_backend` that fetches relay info
/// from the database. Used by web terminals and any code that needs a unified backend.
///
/// # Arguments
/// * `relay_name` - Name of the relay host to connect to
/// * `base_username` - Username for authentication
/// * `term_size` - Initial terminal size (cols, rows)
/// * `prompt_tx` - Optional channel for sending auth prompts
/// * `auth_rx` - Optional channel for receiving auth responses
pub async fn connect_to_relay_backend(
    relay_name: &str,
    base_username: &str,
    term_size: (u32, u32),
    prompt_tx: Option<UnboundedSender<AuthPromptEvent>>,
    auth_rx: Option<tokio::sync::Mutex<UnboundedReceiver<String>>>,
) -> Result<crate::sessions::session_backend::RelayBackend> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    let relay = state_store::fetch_relay_host_by_name(&pool, relay_name)
        .await?
        .ok_or_else(|| ServerError::not_found("relay host", relay_name))?;

    let options_map = state_store::fetch_relay_host_options(&pool, relay.id).await?;
    let mut options = HashMap::new();
    for (k, (v, is_secure)) in options_map {
        if is_secure {
            if let Ok((decrypted, is_legacy)) = crate::secrets::decrypt_string_if_encrypted(&v) {
                if is_legacy {
                    warn!(key = %k, "upgrading legacy v1 secret for relay option");
                    if let Ok(new_enc) =
                        crate::secrets::encrypt_string(SecretBoxedString::new(Box::new(decrypted.expose_secret().to_string())))
                    {
                        let _ = sqlx::query("UPDATE relay_host_options SET value = ? WHERE relay_host_id = ? AND key = ?")
                            .bind(new_enc)
                            .bind(relay.id)
                            .bind(&k)
                            .execute(&pool)
                            .await;
                    }
                }
                options.insert(k, decrypted);
            } else {
                options.insert(k, SecretBoxedString::new(Box::new(v)));
            }
        } else {
            options.insert(k, SecretBoxedString::new(Box::new(v)));
        }
    }

    let auth_rx = auth_rx.map(Arc::new);

    // Convert RelayHostRecord to RelayInfo
    let relay_info = RelayInfo {
        id: relay.id,
        name: relay.name,
        ip: relay.ip,
        port: relay.port,
    };

    start_bridge_backend(&relay_info, base_username, term_size, &options, prompt_tx, auth_rx).await
}

/// Connect to a relay host and return an open channel for external I/O handling.
/// This is used for WebSocket bridging where the caller manages the channel I/O.
pub async fn connect_to_relay_channel(
    relay_name: &str,
    base_username: &str,
    term_size: (u32, u32),
    prompt_tx: Option<UnboundedSender<AuthPromptEvent>>,
    auth_rx: Option<tokio::sync::Mutex<UnboundedReceiver<String>>>,
) -> Result<russh::Channel<russh::client::Msg>> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    let relay = state_store::fetch_relay_host_by_name(&pool, relay_name)
        .await?
        .ok_or_else(|| ServerError::not_found("relay host", relay_name))?;

    let options_map = state_store::fetch_relay_host_options(&pool, relay.id).await?;
    let mut options = HashMap::new();
    for (k, (v, is_secure)) in options_map {
        if is_secure {
            if let Ok((decrypted, is_legacy)) = crate::secrets::decrypt_string_if_encrypted(&v) {
                if is_legacy {
                    warn!(key = %k, "upgrading legacy v1 secret for relay option");
                    if let Ok(new_enc) =
                        crate::secrets::encrypt_string(SecretBoxedString::new(Box::new(decrypted.expose_secret().to_string())))
                    {
                        let _ = sqlx::query("UPDATE relay_host_options SET value = ? WHERE relay_host_id = ? AND key = ?")
                            .bind(new_enc)
                            .bind(relay.id)
                            .bind(&k)
                            .execute(&pool)
                            .await;
                    }
                }
                options.insert(k, decrypted);
            } else {
                options.insert(k, SecretBoxedString::new(Box::new(v)));
            }
        } else {
            options.insert(k, SecretBoxedString::new(Box::new(v)));
        }
    }

    let cfg = build_client_config(&options);

    let auth_rx = auth_rx.map(Arc::new);

    // Bridge simple prompt events (for web) to AppAction channel expected by auth flow
    let (action_tx, mut action_rx_forward) = if prompt_tx.is_some() {
        let (tx, rx) = mpsc::unbounded_channel::<tui_core::AppAction>();
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    let handler = super::handler::SharedRelayHandler {
        expected_key: options.get("hostkey.openssh").map(|v| v.expose_secret().clone()),
        relay_name: relay.name.clone(),
        warning_callback: std::sync::Arc::new(|msg| {
            Box::pin(async move {
                eprintln!("Warning: {}", msg);
            })
        }),
        action_tx: action_tx.clone(),
        auth_rx: auth_rx.clone(),
    };

    let mut session = client::connect(cfg, (relay.ip.as_str(), relay.port as u16), handler).await?;

    // If we're bridging prompts, forward AuthPrompt actions to the caller's channel.
    if let (Some(mut rx), Some(ptx)) = (action_rx_forward.take(), prompt_tx) {
        tokio::spawn(async move {
            while let Some(action) = rx.recv().await {
                if let tui_core::AppAction::AuthPrompt { prompt, echo } = action {
                    let _ = ptx.send(AuthPromptEvent { prompt, echo });
                }
            }
        });
    }

    // Fetch and resolve credential once to avoid TOCTOU
    let resolved_cred = fetch_and_resolve_credential(&options, base_username).await?;

    authenticate_relay_session(
        &mut session,
        &options,
        base_username,
        resolved_cred.as_ref(),
        &action_tx,
        &auth_rx,
        None,
    )
    .await?;

    let channel = session.channel_open_session().await?;
    channel.request_pty(true, "xterm", term_size.0, term_size.1, 0, 0, &[]).await?;
    channel.request_shell(true).await?;

    Ok(channel)
}

/// Connect to a relay host from the local machine (CLI) and bridge to stdio.
pub async fn connect_to_relay_local(relay_name: &str, base_username: &str) -> Result<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    let relay = state_store::fetch_relay_host_by_name(&pool, relay_name)
        .await?
        .ok_or_else(|| ServerError::not_found("relay host", relay_name))?;

    let options_map = state_store::fetch_relay_host_options(&pool, relay.id).await?;
    let mut options = HashMap::new();
    for (k, (v, is_secure)) in options_map {
        if is_secure {
            if let Ok((decrypted, is_legacy)) = crate::secrets::decrypt_string_if_encrypted(&v) {
                if is_legacy {
                    warn!(key = %k, "upgrading legacy v1 secret for relay option");
                    if let Ok(new_enc) =
                        crate::secrets::encrypt_string(SecretBoxedString::new(Box::new(decrypted.expose_secret().to_string())))
                    {
                        let _ = sqlx::query("UPDATE relay_host_options SET value = ? WHERE relay_host_id = ? AND key = ?")
                            .bind(new_enc)
                            .bind(relay.id)
                            .bind(&k)
                            .execute(&pool)
                            .await;
                    }
                }
                options.insert(k, decrypted);
            } else {
                // Fallback if decryption fails or it wasn't encrypted but marked secure
                options.insert(k, SecretBoxedString::new(Box::new(v)));
            }
        } else {
            // Plain text
            options.insert(k, SecretBoxedString::new(Box::new(v)));
        }
    }

    // Build client config
    let cfg = build_client_config(&options);

    let handler = super::handler::SharedRelayHandler {
        expected_key: options.get("hostkey.openssh").map(|v| v.expose_secret().clone()),
        relay_name: relay.name.clone(),
        warning_callback: std::sync::Arc::new(|msg| {
            Box::pin(async move {
                eprintln!("Warning: {}", msg);
            })
        }),
        action_tx: None,
        auth_rx: None,
    };

    let mut session = client::connect(cfg, (relay.ip.as_str(), relay.port as u16), handler).await?;

    // Fetch and resolve credential once to avoid TOCTOU
    let resolved_cred = fetch_and_resolve_credential(&options, base_username).await?;

    let no_action_tx: Option<UnboundedSender<tui_core::AppAction>> = None;
    let no_auth_rx: Option<std::sync::Arc<tokio::sync::Mutex<UnboundedReceiver<String>>>> = None;
    authenticate_relay_session(
        &mut session,
        &options,
        base_username,
        resolved_cred.as_ref(),
        &no_action_tx,
        &no_auth_rx,
        None,
    )
    .await?;

    // Run interactive shell bridging to stdio
    let shell_opts = ssh_core::session::ShellOptions {
        newline_mode: NewlineMode::default(),
        local_echo: false,
        forward_agent: false, // TODO: support forwarding agent if requested
        forwarding: ForwardingManager::new(ForwardingConfig::default()),
    };

    let session = Arc::new(session);
    run_shell(&session, shell_opts)
        .await
        .map_err(|e| ServerError::Other(e.to_string()))?;

    Ok(())
}
