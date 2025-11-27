//! Connection handling for relay connections.
//!
//! This module handles establishing, managing, and bridging connections to relay hosts.

use std::{collections::HashMap, sync::Arc};

use rb_types::{
    auth::AuthPromptEvent, relay::RelayInfo, ssh::{ForwardingConfig, NewlineMode}
};
use russh::{ChannelMsg, CryptoVec, client};
use secrecy::ExposeSecret;
use ssh_core::{crypto::default_preferred, forwarding::ForwardingManager, session::run_shell};
use tokio::sync::{
    mpsc::{self, UnboundedReceiver, UnboundedSender}, watch
};
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
fn build_client_config(options: &HashMap<String, SecretBoxedString>) -> Arc<client::Config> {
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

/// Start an outbound SSH session to the relay host and bridge IO between the remote channel and the inbound client channel.
///
/// - `server_handle` is used to send data back to the inbound client channel.
/// - `client_channel` is the inbound channel id on the embedded server.
/// - `pty_size_rx` emits window-size updates to propagate to the relay session.
/// - `options` is a key-value map from `relay_host_options`.
#[allow(clippy::too_many_arguments)]
pub async fn start_bridge(
    server_handle: russh::server::Handle,
    client_channel: russh::ChannelId,
    relay: &RelayInfo,
    base_username: &str,
    initial_size: (u16, u16),
    mut pty_size_rx: watch::Receiver<(u16, u16)>,
    options: &HashMap<String, SecretBoxedString>,
    peer_addr: Option<std::net::SocketAddr>,
    action_tx: Option<UnboundedSender<tui_core::AppAction>>,
    auth_rx: Option<tokio::sync::Mutex<UnboundedReceiver<String>>>,
    prompt_sink: Option<(russh::server::Handle, russh::ChannelId)>,
) -> Result<RelayHandle> {
    let auth_rx = auth_rx.map(Arc::new);

    // Build client config with secure defaults.
    let cfg = build_client_config(options);

    // Client handler that enforces host-key policy.
    let handler = super::handler::SharedRelayHandler {
        expected_key: options.get("hostkey.openssh").map(|v| v.expose_secret().clone()),
        relay_name: relay.name.clone(),
        warning_callback: Arc::new({
            let server_handle = server_handle.clone();
            let relay_name = relay.name.clone();
            move |msg| {
                let server_handle = server_handle.clone();
                let relay_name = relay_name.clone();
                Box::pin(async move {
                    warn!(relay = %relay_name, "{}", msg);
                    let mut payload = CryptoVec::new();
                    payload.extend(format!("[rustybridge] {}\r\n", msg).as_bytes());
                    let _ = server_handle.data(client_channel, payload).await;
                })
            }
        }),
        action_tx: action_tx.clone(),
        auth_rx: auth_rx.clone(),
    };

    let target = format!("{}:{}", relay.ip, relay.port);
    let peer = peer_addr.map(|a| a.to_string()).unwrap_or_else(|| "unknown".to_string());
    info!(relay = %relay.name, target, peer, "connecting to relay host");

    let mut remote = client::connect(cfg, (relay.ip.as_str(), relay.port as u16), handler).await?;

    // Fetch and resolve credential once to avoid TOCTOU
    let resolved_cred = fetch_and_resolve_credential(options, base_username).await?;

    // Authenticate according to options.
    let prompt_sink = prompt_sink.clone();
    authenticate_relay_session(
        &mut remote,
        options,
        base_username,
        resolved_cred.as_ref(),
        &action_tx,
        &auth_rx,
        prompt_sink,
    )
    .await?;

    // Open channel + PTY + shell
    let rchan = remote.channel_open_session().await?;
    let (cols, rows) = initial_size;
    rchan.request_pty(true, "xterm", cols as u32, rows as u32, 0, 0, &[]).await?;
    rchan.request_shell(true).await?;

    // Set up input channel for client->relay traffic.
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let server_handle_in = server_handle.clone();
    let client_channel_in = client_channel;
    let channel_id = rchan.id();

    // Single task handling relay->client, client->relay, and window resizes.
    tokio::spawn(async move {
        let mut rchan = rchan; // move into task
        loop {
            tokio::select! {
                msg = rchan.wait() => {
                    match msg {
                        Some(ChannelMsg::Data { data }) => {
                            let mut payload = CryptoVec::new();
                            payload.extend(&data);
                            if server_handle_in.data(client_channel_in, payload).await.is_err() {
                                break;
                            }
                        }
                        Some(ChannelMsg::ExtendedData { data, .. }) => {
                            let mut payload = CryptoVec::new();
                            payload.extend(&data);
                            if server_handle_in.data(client_channel_in, payload).await.is_err() {
                                break;
                            }
                        }
                        Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                            let _ = server_handle_in.close(client_channel_in).await;
                            break;
                        }
                        _ => {}
                    }
                }
                maybe_bytes = rx.recv() => {
                    match maybe_bytes {
                        Some(bytes) => {
                            if !bytes.is_empty() {
                                let mut cursor = std::io::Cursor::new(bytes);
                                if rchan.data(&mut cursor).await.is_err() {
                                    break;
                                }
                            }
                        }
                        None => {
                            let _ = rchan.eof().await;
                            let _ = rchan.close().await;
                            break;
                        }
                    }
                }
                changed = pty_size_rx.changed() => {
                    if changed.is_err() { break; }
                    let size = *pty_size_rx.borrow();
                    let cols = size.0.max(1) as u32;
                    let rows = size.1.max(1) as u32;
                    if rchan.window_change(cols, rows, 0, 0).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    Ok(RelayHandle {
        session: remote,
        channel_id,
        input_tx: tx,
    })
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
                    warn!("Upgrading legacy v1 secret for relay option '{}'", k);
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
                    warn!("Upgrading legacy v1 secret for relay option '{}'", k);
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
