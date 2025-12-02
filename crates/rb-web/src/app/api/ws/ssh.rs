#[cfg(feature = "server")]
use axum::http::HeaderMap;
#[cfg(feature = "server")]
use dioxus::fullstack::TypedWebsocket;
use dioxus::{
    fullstack::{JsonEncoding, WebSocketOptions, Websocket}, prelude::*
};
#[cfg(feature = "server")]
use rb_types::auth::AuthPromptEvent;
use rb_types::ssh::{SshClientMsg, SshServerMsg};
#[cfg(feature = "server")]
use russh::ChannelMsg;
use serde::{Deserialize, Serialize};
#[cfg(feature = "server")]
use server_core::relay::connect_to_relay_channel;
#[cfg(feature = "server")]
use server_core::sessions::{SessionRegistry, SshSession};
#[cfg(feature = "server")]
type SharedRegistry = std::sync::Arc<SessionRegistry>;
#[cfg(feature = "server")]
use state_store::{fetch_relay_host_by_name, user_has_relay_access};

#[cfg(feature = "server")]
use crate::server::auth::guards::{WebAuthSession, ensure_authenticated};

#[derive(Debug)]
pub enum SshAccessError {
    Unauthorized,
    RelayNotFound,
    RelayAccessDenied,
    Internal,
}

impl From<SshAccessError> for ServerFnError {
    fn from(err: SshAccessError) -> Self {
        ServerFnError::new(match err {
            SshAccessError::Unauthorized => "Unauthorized".to_string(),
            SshAccessError::RelayNotFound => "Relay not found".to_string(),
            SshAccessError::RelayAccessDenied => "Relay access denied".to_string(),
            SshAccessError::Internal => "Internal error".to_string(),
        })
    }
}

#[derive(Serialize, Deserialize)]
struct SshStatusResponse {
    ok: bool,
    message: String,
}

#[cfg(feature = "server")]
async fn ensure_relay_websocket_permissions(
    relay_name: &str,
    auth: &WebAuthSession,
    pool: &sqlx::SqlitePool,
) -> Result<(String, i64, i64), SshAccessError> {
    let user = ensure_authenticated(auth).map_err(|err| {
        tracing::warn!(relay = %relay_name, "Unauthenticated SSH WebSocket attempt: {err}");
        SshAccessError::Unauthorized
    })?;

    let relay = fetch_relay_host_by_name(pool, relay_name)
        .await
        .map_err(|err| {
            tracing::error!(relay = %relay_name, "Failed to fetch relay host: {err}");
            SshAccessError::Internal
        })?
        .ok_or_else(|| {
            tracing::warn!(relay = %relay_name, "Relay host not found");
            SshAccessError::RelayNotFound
        })?;

    let has_access = user_has_relay_access(pool, user.id, relay.id).await.map_err(|err| {
        tracing::error!(user = %user.username, relay = %relay_name, "Failed to check relay ACL: {err}");
        SshAccessError::Internal
    })?;

    if !has_access {
        tracing::warn!(user = %user.username, relay = %relay_name, "Relay ACL denied for user");
        return Err(SshAccessError::RelayAccessDenied);
    }

    Ok((user.username.clone(), user.id, relay.id))
}

pub type SshWebSocket = Websocket<SshClientMsg, SshServerMsg, JsonEncoding>;

#[cfg(feature = "server")]
async fn wait_for_client_ready(
    mut socket: TypedWebsocket<SshClientMsg, SshServerMsg, JsonEncoding>,
) -> Result<(TypedWebsocket<SshClientMsg, SshServerMsg, JsonEncoding>, bool), ()> {
    use rb_types::ssh::SshControl;
    let mut is_minimized = false;
    loop {
        match socket.recv().await {
            Ok(msg) => {
                if let Some(cmd) = msg.cmd {
                    match cmd {
                        SshControl::Ready => return Ok((socket, is_minimized)),
                        SshControl::Close => return Err(()),
                        SshControl::Minimize(val) => is_minimized = val,
                        SshControl::Resize { .. } => {}
                    }
                }
            }
            Err(_) => return Err(()),
        }
    }
}

#[get(
    "/api/ws/ssh_connection/{relay_name}?session_number",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>,
    registry: axum::Extension<SharedRegistry>,
    headers: HeaderMap
)]
pub async fn ssh_terminal_ws(
    relay_name: String,
    session_number: Option<u32>,
    options: WebSocketOptions,
) -> Result<SshWebSocket, ServerFnError> {
    // Extract state and auth
    let (username, user_id, relay_id) = match ensure_relay_websocket_permissions(&relay_name, &auth, &pool.0).await {
        Ok(res) => res,
        Err(err) => {
            tracing::error!("SSH Access Error: {:?}", err);
            return Err(ServerFnError::new(format!("Access denied: {:?}", err)));
        }
    };

    let relay_for_upgrade = relay_name.clone();
    let registry_inner: SharedRegistry = registry.0.clone();

    // If a session_number was provided, try to reattach to an existing session first.
    if let Some(num) = session_number
        && let Some(existing) = registry_inner.get_session(user_id, relay_id, num).await
    {
        tracing::info!(
            relay = %relay_for_upgrade,
            user = %username,
            session_number = num,
            "WebSocket SSH reattach requested"
        );

        return Ok(options.on_upgrade(move |socket| async move {
            tracing::info!(
                relay = %relay_for_upgrade,
                user = %username,
                session_number = num,
                "WebSocket upgrade callback started (reattach)"
            );
            if let Ok((socket, is_minimized)) = wait_for_client_ready(socket).await {
                let registry_for_upgrade = registry_inner.clone();
                handle_reattach(socket, existing, registry_for_upgrade, is_minimized).await;
            } else {
                tracing::info!(
                    relay = %relay_for_upgrade,
                    user = %username,
                    session_number = num,
                    "Client disconnected before Ready signal"
                );
            }
        }));
    }

    // Fallback: create a new session
    // Extract IP and User Agent from headers
    let ip_address = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .or_else(|| headers.get("x-real-ip").and_then(|v| v.to_str().ok()).map(|s| s.to_string()))
        .or_else(|| {
            // Fallback for localhost dev without proxy
            let host = headers.get("host").and_then(|v| v.to_str().ok()).unwrap_or("");
            if host.contains("localhost") || host.contains("127.0.0.1") {
                Some("127.0.0.1".to_string())
            } else {
                None
            }
        });

    let user_agent_str = headers.get("user-agent").and_then(|v| v.to_str().ok()).map(|s| s.to_string());

    Ok(options.on_upgrade(move |socket| async move {
        tracing::info!(relay = %relay_for_upgrade, user = %username, "WebSocket upgrade callback started (new session)");
        if let Ok((socket, is_minimized)) = wait_for_client_ready(socket).await {
            let registry_for_new = registry_inner.clone();
            handle_new_session(
                socket,
                registry_for_new,
                relay_for_upgrade,
                username,
                user_id,
                relay_id,
                ip_address,
                user_agent_str,
                is_minimized,
            )
            .await;
        } else {
            tracing::info!(
                relay = %relay_for_upgrade,
                user = %username,
                "Client disconnected before Ready signal (new session)"
            );
        }
    }))
}

#[get(
    "/api/ssh/{relay_name}/status", 
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn ssh_terminal_status(relay_name: String) -> Result<SshStatusResponse, ServerFnError> {
    let _ = ensure_relay_websocket_permissions(&relay_name, &auth, &pool.0).await?;

    Ok(SshStatusResponse {
        ok: true,
        message: "Authorized".to_string(),
    })
}

#[cfg(feature = "server")]
async fn handle_reattach(
    mut socket: TypedWebsocket<SshClientMsg, SshServerMsg, JsonEncoding>,
    session: std::sync::Arc<SshSession>,
    registry: SharedRegistry,
    initial_minimized: bool,
) {
    use rb_types::ssh::SshControl;

    // Track minimize state for this connection
    let mut is_minimized = initial_minimized;

    session.attach().await;

    // Replay scrollback history so a reattached client sees the existing shell state
    let history = session.get_history().await;
    if !history.is_empty() {
        info!("Replaying scrollback history for session {}", session.session_number);
        let _ = socket
            .send(SshServerMsg {
                data: history,
                eof: false,
                exit_status: None,
                session_id: None,
                relay_id: None,
            })
            .await;
    }

    // Subscribe to output
    let mut output_rx = session.output_tx.subscribe();
    let input_tx = session.input_tx.clone();
    let mut close_rx = session.close_tx.subscribe();

    // Increment connection count
    let conn_count = session.increment_connections().await;
    // Increment viewers only if not minimized
    if !is_minimized {
        session.increment_viewers().await;
    }

    tracing::info!(
        session_number = session.session_number,
        connections = conn_count,
        "Client attached to session"
    );

    // Send initial session ID confirmation
    let _ = socket
        .send(SshServerMsg {
            data: Vec::new(),
            eof: false,
            exit_status: None,
            session_id: Some(session.session_number),
            relay_id: Some(session.relay_id),
        })
        .await;

    let mut explicit_close = false;

    loop {
        tokio::select! {
            Ok(data) = output_rx.recv() => {
                let is_eof = data.is_empty();
                let msg = SshServerMsg {
                    data,
                    eof: is_eof,
                    exit_status: None,
                    session_id: None,
                    relay_id: None,
                };
                if socket.send(msg).await.is_err() {
                    break;
                }
                if is_eof {
                    // SSH closed, mark as explicit close
                    explicit_close = true;
                    break;
                }
            }
            ws_msg = socket.recv() => {
                match ws_msg {
                    Ok(client_msg) => {
                        if let Some(cmd) = &client_msg.cmd {
                            match cmd {
                                SshControl::Ready => {} // Already ready
                                SshControl::Close => {
                                    // User explicitly closed the shell
                                    explicit_close = true;
                                    session.close().await;
                                    break;
                                }
                                SshControl::Resize { .. } => {
                                    // TODO: implement resize
                                }
                                SshControl::Minimize(minimized) => {
                                    if *minimized != is_minimized {
                                        is_minimized = *minimized;
                                        if is_minimized {
                                            session.decrement_viewers().await;
                                        } else {
                                            session.increment_viewers().await;
                                        }
                                    }
                                }
                            }
                        }
                        if !client_msg.data.is_empty() {
                            let _ = input_tx.send(client_msg.data).await;
                        }
                    }
                    Err(_) => break,
                }
            }
            Ok(_) = close_rx.recv() => {
                // Session closed remotely (SSH EOF)
                explicit_close = true;
                break;
            }
        }
    }

    // Decrement connection count
    let remaining = session.decrement_connections().await;
    if !is_minimized {
        session.decrement_viewers().await;
    }

    tracing::info!(
        session_number = session.session_number,
        remaining_connections = remaining,
        explicit_close = explicit_close,
        "Client detached from session"
    );

    if explicit_close {
        // Explicit close (user clicked X or SSH closed)
        if remaining == 0 {
            // Last client with explicit close - clean up immediately
            tracing::info!(
                session_number = session.session_number,
                "Cleaning up session (explicit close, last client)"
            );
            registry
                .remove_session(session.user_id, session.relay_id, session.session_number)
                .await;
        } else {
            // Other clients still attached, they'll see the EOF
            tracing::info!(
                session_number = session.session_number,
                "Session closed but other clients still attached"
            );
        }
    } else {
        // Unexpected disconnect (refresh, network drop)
        if remaining == 0 {
            // No more clients - detach with timeout for reattachment
            tracing::info!(
                session_number = session.session_number,
                "All clients disconnected unexpectedly, detaching with timeout"
            );
            session.detach(std::time::Duration::from_secs(120)).await;
        } else {
            // Other clients still attached
            tracing::info!(session_number = session.session_number, "Client disconnected but others remain");
        }
    }
}

#[cfg(feature = "server")]
async fn handle_new_session(
    mut socket: TypedWebsocket<SshClientMsg, SshServerMsg, JsonEncoding>,
    registry: SharedRegistry,
    relay_name: String,
    username: String,
    user_id: i64,
    relay_id: i64,
    ip_address: Option<String>,
    user_agent: Option<String>,
    is_minimized: bool,
) {
    use tokio::sync::{Mutex, broadcast, mpsc, mpsc::unbounded_channel};

    // Channels for interactive auth prompts
    let (prompt_tx, mut prompt_rx) = unbounded_channel::<AuthPromptEvent>();
    let (auth_tx, auth_rx) = unbounded_channel::<String>();
    let auth_rx_mutex = Mutex::new(auth_rx);

    // Drive interactive auth prompts over the WebSocket while connecting
    let username_for_connect = username.clone();
    let mut connect_fut = Box::pin(connect_to_relay_channel(
        &relay_name,
        &username_for_connect,
        (80, 24),
        Some(prompt_tx.clone()),
        Some(auth_rx_mutex),
    ));

    // Prompt/response loop that runs until connect finishes
    struct PendingPrompt {
        buf: Vec<u8>,
        echo: bool,
    }
    let mut pending_prompt: Option<PendingPrompt> = None;
    // Track minimize state update if any arrived during handshake (unlikely given wait_for_client_ready)
    let mut current_minimized = is_minimized;

    let mut channel = loop {
        use rb_types::ssh::SshControl;

        tokio::select! {
            res = &mut connect_fut => {
                match res {
                    Ok(ch) => {
                        tracing::info!("Successfully connected to relay: {}", relay_name);
                        break ch;
                    }
                    Err(e) => {
                        tracing::error!("Failed to connect to relay {}: {}", relay_name, e);
                        let msg = SshServerMsg {
                            data: format!("Authentication failed: {}", e).into_bytes(),
                            eof: true,
                            exit_status: None,
                            session_id: None,
                            relay_id: None,
                        };
                        let _ = socket.send(msg).await;
                        return;
                    }
                }
            }
            Some(action) = prompt_rx.recv() => {
                let msg = SshServerMsg {
                    data: action.prompt.into_bytes(),
                    eof: false,
                    exit_status: None,
                    session_id: None,
                    relay_id: None,
                };
                let _ = socket.send(msg).await;
                pending_prompt = Some(PendingPrompt { echo: action.echo, buf: Vec::new() });
            }
            maybe_msg = socket.recv() => {
                match maybe_msg {
                    Ok(client_msg) => {
                        if let Some(cmd) = &client_msg.cmd {
                            match cmd {
                                SshControl::Close => return,
                                SshControl::Minimize(val) => current_minimized = *val,
                                _ => {}
                            }
                        }
                        if let Some(mut pending) = pending_prompt.take() {
                            let data = &client_msg.data;
                            pending.buf.extend_from_slice(data);
                            if pending.echo && !data.is_empty() {
                                let echo_msg = SshServerMsg {
                                    data: data.clone(),
                                    eof: false,
                                    exit_status: None,
                                    session_id: None,
                                    relay_id: None,
                                };
                                let _ = socket.send(echo_msg).await;
                            }
                            if let Some(pos) = pending.buf.iter().position(|b| *b == b'\n' || *b == b'\r') {
                                let line = pending.buf[..pos].to_vec();
                                let resp = String::from_utf8_lossy(&line).to_string();
                                let _ = auth_tx.send(resp);
                                if !pending.echo {
                                    let msg = SshServerMsg {
                                        data: b"\r\n\r\n".to_vec(),
                                        eof: false,
                                        exit_status: None,
                                        session_id: None,
                                        relay_id: None,
                                    };
                                    let _ = socket.send(msg).await;
                                }
                            } else {
                                pending_prompt = Some(pending);
                            }
                        }
                    }
                    Err(_) => return,
                }
            }
        }
    };

    // Connected! Create session channels
    let (input_tx, mut input_rx) = mpsc::channel::<Vec<u8>>(1024);
    let (output_tx, _) = broadcast::channel::<Vec<u8>>(1024);
    let (close_tx, _) = broadcast::channel::<()>(1);

    // Spawn SSH loop
    let relay_name_for_ssh = relay_name.clone();
    let close_tx_clone = close_tx.clone();

    // Register session and get session number
    let (session_number, session) = registry
        .create_next_session(
            user_id,
            relay_id,
            relay_name.clone(),
            username,
            input_tx.clone(),
            output_tx.clone(),
            close_tx,
            ip_address,
            user_agent,
        )
        .await;

    tracing::info!(session_number = session_number, relay = %relay_name, "Created new session");

    // Clone session for history appending and cleanup
    let session_for_history = session.clone();
    let registry_for_cleanup = registry.clone();
    let user_id_for_cleanup = user_id;
    let relay_id_for_cleanup = relay_id;
    let session_number_for_cleanup = session_number;

    // Update SSH loop to append to history
    let output_tx_for_history = output_tx.clone();
    tokio::spawn(async move {
        let mut close_rx = close_tx_clone.subscribe();
        loop {
            tokio::select! {
                Some(msg) = channel.wait() => {
                    match msg {
                        ChannelMsg::Data { ref data } => {
                            // Append to history
                            session_for_history.touch().await;
                            session_for_history.append_to_history(data).await;
                            if output_tx_for_history.send(data.to_vec()).is_err() { break; }
                        }
                        ChannelMsg::ExtendedData { ref data, .. } => {
                            // Append to history
                            session_for_history.touch().await;
                            session_for_history.append_to_history(data).await;
                            if output_tx_for_history.send(data.to_vec()).is_err() { break; }
                        }
                        ChannelMsg::ExitStatus { exit_status } => {
                            tracing::info!("SSH exit status: {}", exit_status);
                            session_for_history.close().await; // Mark session as closed
                            let _ = output_tx_for_history.send(Vec::new()); // EOF marker
                            break;
                        }
                        ChannelMsg::Eof | ChannelMsg::Close => {
                            tracing::info!("SSH closed");
                            session_for_history.close().await; // Mark session as closed
                            let _ = output_tx_for_history.send(Vec::new()); // EOF marker
                            break;
                        }
                        _ => {}
                    }
                }
                msg = input_rx.recv() => {
                    match msg {
                        Some(data) => {
                            let mut cursor = std::io::Cursor::new(data);
                            if channel.data(&mut cursor).await.is_err() { break; }
                        }
                        None => {
                            // Input closed (session closed)
                            let _ = channel.close().await;
                            break;
                        }
                    }
                }
                Ok(_) = close_rx.recv() => {
                    // Explicit close signal
                    let _ = channel.close().await;
                    break;
                }
            }
        }
        tracing::info!(relay = %relay_name_for_ssh, "ssh output history loop terminated");

        // Remove the session from the registry after shutdown so it disappears from admin/user lists.
        registry_for_cleanup
            .remove_session(user_id_for_cleanup, relay_id_for_cleanup, session_number_for_cleanup)
            .await;
    });

    // Send initial message with session number
    let _ = socket
        .send(SshServerMsg {
            data: Vec::new(),
            eof: false,
            exit_status: None,
            session_id: Some(session.session_number), // Reusing session_id field for session_number
            relay_id: Some(session.relay_id),
        })
        .await;

    // Hand off to reattach logic (which handles the WS loop)
    handle_reattach(socket, session, registry, current_minimized).await;
}
