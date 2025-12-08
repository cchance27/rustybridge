#[cfg(feature = "server")]
use axum::http::HeaderMap;
#[cfg(feature = "server")]
use dioxus::fullstack::TypedWebsocket;
use dioxus::{
    fullstack::{JsonEncoding, WebSocketOptions, Websocket}, prelude::*
};
use rb_types::ssh::{SshClientMsg, SshServerMsg};
#[cfg(feature = "server")]
use rb_types::{
    audit::{AuditContext, EventType}, auth::AuthPromptEvent
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "server")]
use server_core::sessions::{SessionRegistry, SshSession};
#[cfg(feature = "server")]
use server_core::{audit::log_event_from_context_best_effort, relay::connect_to_relay_backend};
#[cfg(feature = "server")]
type SharedRegistry = std::sync::Arc<SessionRegistry>;

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
async fn ensure_relay_websocket_permissions(relay_name: &str, auth: &WebAuthSession) -> Result<(String, i64, i64), SshAccessError> {
    let user = ensure_authenticated(auth).map_err(|err| {
        tracing::warn!(relay = %relay_name, "Unauthenticated SSH WebSocket attempt: {err}");
        SshAccessError::Unauthorized
    })?;

    let relay = server_core::api::fetch_relay_by_name(relay_name)
        .await
        .map_err(|err| {
            tracing::error!(relay = %relay_name, "Failed to fetch relay host: {err}");
            SshAccessError::Internal
        })?
        .ok_or_else(|| {
            tracing::warn!(relay = %relay_name, "Relay host not found");
            SshAccessError::RelayNotFound
        })?;

    let has_access = server_core::api::user_has_relay_access(user.id, relay.id).await.map_err(|err| {
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
) -> Result<(TypedWebsocket<SshClientMsg, SshServerMsg, JsonEncoding>, bool, (u32, u32)), ()> {
    use rb_types::ssh::SshControl;
    let mut is_minimized = false;
    loop {
        match socket.recv().await {
            Ok(msg) => {
                if let Some(cmd) = msg.cmd {
                    match cmd {
                        SshControl::Ready { cols, rows } => return Ok((socket, is_minimized, (cols, rows))),
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

// TODO(security): Migrate to UUID-based session identifiers
// Current implementation uses sequential integers which are easily guessable.
// This creates a potential attack vector for session enumeration.
#[allow(clippy::too_many_arguments)]
#[get(
    "/api/ws/ssh_connection/{relay_name}?session_number&target_user_id",
    auth: WebAuthSession,
    registry: axum::Extension<SharedRegistry>,
    headers: HeaderMap
)]
pub async fn ssh_terminal_ws(
    relay_name: String,
    session_number: Option<u32>,
    target_user_id: Option<i64>,
    options: WebSocketOptions,
) -> Result<SshWebSocket, ServerFnError> {
    // Extract state and auth
    let user = ensure_authenticated(&auth).map_err(|e| ServerFnError::new(e.to_string()))?;
    let authenticated_user_id = user.id;

    // Resolve relay
    let relay = server_core::api::fetch_relay_by_name(&relay_name)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .ok_or_else(|| ServerFnError::new("Relay not found"))?;

    // Determine target user ID (default to self)
    let target_id = target_user_id.unwrap_or(user.id);

    // Check permissions using centralized helper
    crate::server::auth::guards::check_session_attach_access(&auth, target_id, relay.id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let (effective_user_id, effective_username) = if user.id != target_id {
        // Admin attaching to another user
        let target_user = server_core::api::fetch_user_auth_record_by_id(target_id)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?
            .ok_or_else(|| ServerFnError::new("Target user not found"))?;
        (target_id, target_user.username)
    } else {
        // Attaching to self (or admin to self)
        (user.id, user.username.clone())
    };

    let username = effective_username;
    let user_id = effective_user_id;
    let relay_id = relay.id;
    let axum_session_id = auth.session.get_session_id();

    let relay_for_upgrade = relay_name.clone();
    let registry_inner: SharedRegistry = registry.0.clone();

    // Extract IP and User Agent from headers (needed for both reattach and new session)
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
            if let Ok((socket, is_minimized, _dims)) = wait_for_client_ready(socket).await {
                let registry_for_upgrade = registry_inner.clone();
                let is_admin_viewer = target_user_id.is_some();
                let admin_user_id_for_attach = if is_admin_viewer { Some(authenticated_user_id) } else { None };
                handle_reattach(
                    socket,
                    existing,
                    registry_for_upgrade,
                    is_minimized,
                    is_admin_viewer,
                    admin_user_id_for_attach,
                    ip_address.clone(),
                    user_agent_str.clone(),
                    None,
                    None,
                    Some(axum_session_id.clone()),
                )
                .await;
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
    // IP and UA already extracted above

    Ok(options.on_upgrade(move |socket| async move {
        tracing::info!(relay = %relay_for_upgrade, user = %username, "WebSocket upgrade callback started (new session)");
        if let Ok((socket, is_minimized, term_dims)) = wait_for_client_ready(socket).await {
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
                term_dims,
                Some(axum_session_id.clone()),
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
    auth: WebAuthSession
)]
pub async fn ssh_terminal_status(relay_name: String) -> Result<SshStatusResponse, ServerFnError> {
    let _ = ensure_relay_websocket_permissions(&relay_name, &auth).await?;

    Ok(SshStatusResponse {
        ok: true,
        message: "Authorized".to_string(),
    })
}

#[cfg(feature = "server")]
#[allow(clippy::too_many_arguments)]
async fn handle_reattach(
    mut socket: TypedWebsocket<SshClientMsg, SshServerMsg, JsonEncoding>,
    session: std::sync::Arc<SshSession>,
    registry: SharedRegistry,
    initial_minimized: bool,
    is_admin_viewer: bool,
    admin_user_id: Option<i64>,
    ip_address: Option<String>,
    user_agent: Option<String>,
    pre_subscribed_rx: Option<tokio::sync::broadcast::Receiver<Vec<u8>>>,
    override_connection_id: Option<String>,
    axum_session_id: Option<String>,
) {
    use rb_types::ssh::SshControl;
    use uuid::Uuid;

    // Generate a connection ID for this WebSocket session (or use provided)
    let connection_id = override_connection_id.unwrap_or_else(|| Uuid::now_v7().to_string());

    // Record the connection
    let registry_for_audit = registry.clone();
    let user_id_for_audit = if let Some(uid) = admin_user_id { uid } else { session.user_id };
    let ua_for_audit = user_agent.clone();
    let audit_ctx = AuditContext::web(
        user_id_for_audit,
        session.username.clone(),
        ip_address.clone().unwrap_or_else(|| "web".to_string()),
        connection_id.clone(),
        axum_session_id.clone(),
    );
    let audit_ctx_clone = audit_ctx.clone();

    let _session_started_at = std::time::Instant::now();

    tokio::spawn(async move {
        if let Err(e) =
            server_core::record_web_connection_with_context(&registry_for_audit, &audit_ctx_clone, ua_for_audit, axum_session_id).await
        {
            tracing::warn!("Failed to record web connection: {}", e);
        }
    });
    // Audit: relay connected (reattach or new viewer)
    log_event_from_context_best_effort(
        &audit_ctx,
        EventType::SessionRelayConnected {
            session_id: connection_id.clone(),
            relay_id: session.relay_id,
            relay_name: session.relay_name.clone(),
            username: session.username.clone(),
        },
    )
    .await;

    // Track minimize state for this connection
    let mut is_minimized = initial_minimized;

    session.attach().await;

    // Track admin viewer if this is an admin attachment
    if is_admin_viewer && let Some(admin_id) = admin_user_id {
        session.add_admin_viewer(admin_id).await;
        log_event_from_context_best_effort(
            &audit_ctx,
            EventType::AdminViewerAdded {
                session_id: connection_id.clone(),
                admin_username: session.username.clone(),
                admin_user_id: admin_id,
            },
        )
        .await;
    }

    // Subscribe to output via backend (or use pre-subscribed)
    let (mut output_rx, history_already_covered) = if let Some(rx) = pre_subscribed_rx {
        (rx, true)
    } else {
        (session.backend.subscribe(), false)
    };

    // Replay scrollback history so a reattached client sees the existing shell state
    // Skip if we have a pre-subscribed receiver (which covers the history from the start)
    if !history_already_covered {
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
    }

    let backend = session.backend.clone();

    // Increment connection count (web)
    let conn_count = session.increment_connection(rb_types::ssh::ConnectionType::Web).await;
    // Increment viewers only if not minimized
    if !is_minimized {
        session.increment_viewers(rb_types::ssh::ConnectionType::Web).await;
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
                    tracing::error!(
                        session_number = session.session_number,
                        "ssh_ws_send_failed_to_client; closing reattach loop"
                    );
                    break;
                }
                if is_eof {
                    // SSH/relay backend closed (EOF), mark as explicit close
                    tracing::info!(
                        session_number = session.session_number,
                        "ssh_ws_backend_eof; closing reattach loop"
                    );
                    explicit_close = true;
                    break;
                }
            }
            ws_msg = socket.recv() => {
                match ws_msg {
                    Ok(client_msg) => {
                        if let Some(cmd) = &client_msg.cmd {
                            match cmd {
                                SshControl::Ready { .. } => {} // Already ready
                                SshControl::Close => {
                                    // User explicitly closed the shell
                                    explicit_close = true;
                                    // Close backend for everyone and remove the session
                                    let _ = backend.close().await;
                                    session.close().await;
                                    registry
                                        .remove_session(session.user_id, session.relay_id, session.session_number)
                                        .await;
                                    break;
                                }
                                SshControl::Resize { cols, rows } => {
                                    let _ = backend.resize(*cols, *rows).await;
                                    log_event_from_context_best_effort(
                                        &audit_ctx,
                                        EventType::SessionResized {
                                            session_id: connection_id.clone(),
                                            relay_id: session.relay_id,
                                            cols: *cols,
                                            rows: *rows,
                                        },
                                    )
                                    .await;
                                }
                                SshControl::Minimize(minimized) => {
                                    if *minimized != is_minimized {
                                        is_minimized = *minimized;
                                        if is_minimized {
                                            session.decrement_viewers(rb_types::ssh::ConnectionType::Web).await;
                                        } else {
                                            session.increment_viewers(rb_types::ssh::ConnectionType::Web).await;
                                        }
                                    }
                                }
                            }
                        }
                        if !client_msg.data.is_empty() {
                            // Record input
                            let conn_id = connection_id.clone();
                            let data_vec = client_msg.data.clone();
                            let session_recorder = session.recorder.clone();
                            tokio::spawn(async move {
                                session_recorder.record_input(&data_vec, conn_id).await;
                            });

                            let _ = backend.send(client_msg.data).await;
                        }
                    }
                    Err(e) => {
                        tracing::info!(
                            session_number = session.session_number,
                            error = ?e,
                            "ssh_ws_client_recv_error; closing reattach loop"
                        );
                        break;
                    }
                }
            }
        }
    }

    // Decrement connection count (web)
    let remaining = session.decrement_connection(rb_types::ssh::ConnectionType::Web).await;

    // Record participant leave in relay_session_participants
    session.recorder.record_participant_leave(&connection_id).await;

    if !is_minimized {
        session.decrement_viewers(rb_types::ssh::ConnectionType::Web).await;
    }

    log_event_from_context_best_effort(
        &audit_ctx,
        EventType::SessionRelayDisconnected {
            session_id: connection_id.clone(),
            relay_id: session.relay_id,
            relay_name: session.relay_name.clone(),
            username: session.username.clone(),
        },
    )
    .await;
    let duration_ms = _session_started_at.elapsed().as_millis() as i64;
    log_event_from_context_best_effort(
        &audit_ctx,
        EventType::SessionEnded {
            session_id: connection_id.clone(),
            relay_name: session.relay_name.clone(),
            relay_id: session.relay_id,
            username: session.username.clone(),
            duration_ms,
        },
    )
    .await;

    // Remove admin viewer tracking if this was an admin attachment
    if is_admin_viewer && let Some(admin_id) = admin_user_id {
        session.remove_admin_viewer(admin_id).await;
        log_event_from_context_best_effort(
            &audit_ctx,
            EventType::AdminViewerRemoved {
                session_id: connection_id.clone(),
                admin_username: session.username.clone(),
                admin_user_id: admin_id,
            },
        )
        .await;
    }

    tracing::info!(
        session_number = session.session_number,
        remaining_connections = remaining,
        explicit_close = explicit_close,
        is_admin_viewer = is_admin_viewer,
        "Client detached from session"
    );

    // Admin viewers should never trigger session cleanup, even on explicit close
    if explicit_close && !is_admin_viewer {
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
        // Unexpected disconnect (refresh, network drop) OR admin detach
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
    // Record disconnection
    let registry_for_audit = registry.clone();
    let connection_id_clone = connection_id.clone();
    tokio::spawn(async move {
        if let Err(e) = server_core::record_connection_disconnection(&registry_for_audit, &connection_id_clone).await {
            tracing::warn!("Failed to record web disconnection: {}", e);
        }
    });
}

#[cfg(feature = "server")]
#[allow(clippy::too_many_arguments)]
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
    term_dims: (u32, u32),
    axum_session_id: Option<String>,
) {
    use server_core::sessions::session_backend::SessionBackend as _;
    use tokio::sync::{Mutex, mpsc::unbounded_channel};
    use uuid::Uuid;

    // Generate ID early to link session start and reattach events
    let connection_id = Uuid::now_v7().to_string();

    let audit_ctx = AuditContext::web(
        user_id,
        username.clone(),
        ip_address.clone().unwrap_or_else(|| "web".to_string()),
        connection_id.clone(),
        axum_session_id.clone(),
    );
    let username_for_audit = username.clone();

    // Channels for interactive auth prompts
    let (prompt_tx, mut prompt_rx) = unbounded_channel::<AuthPromptEvent>();
    let (auth_tx, auth_rx) = unbounded_channel::<String>();
    let auth_rx_mutex = Mutex::new(auth_rx);

    // Drive interactive auth prompts over the WebSocket while connecting
    let username_for_connect = username.clone();
    let mut connect_fut = Box::pin(connect_to_relay_backend(
        &relay_name,
        &username_for_connect,
        term_dims,
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

    let backend: server_core::sessions::session_backend::RelayBackend = loop {
        use rb_types::ssh::SshControl;

        tokio::select! {
            res = &mut connect_fut => {
                match res {
                    Ok(backend) => {
                        tracing::info!("Successfully connected to relay: {}", relay_name);
                        break backend;
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

    // Connected! Backend is already managing the relay I/O
    use std::sync::Arc;
    let backend = Arc::new(backend);

    // CRITICAL FIX: Subscribe NOW to capture any output that happens between now and appender start
    // This prevents first message loss (race condition)
    let initial_rx = backend.subscribe();

    // Record connection to ensure client_sessions entry exists for FK
    let registry_for_audit = registry.clone();
    let ua_for_audit = user_agent.clone();
    if let Err(e) =
        server_core::record_web_connection_with_context(&registry_for_audit, &audit_ctx, ua_for_audit, axum_session_id.clone()).await
    {
        tracing::warn!("Failed to record web connection (initial): {}", e);
    }

    // Register session and get session number
    let (session_number, session) = registry
        .create_next_session(
            user_id,
            relay_id,
            relay_name.clone(),
            username,
            backend.clone(),
            rb_types::ssh::SessionOrigin::Web { user_id },
            ip_address.clone(),
            user_agent.clone(),
            Some(term_dims),
            Some(connection_id.clone()),
        )
        .await;

    tracing::info!(session_number = session_number, relay = %relay_name, "Created new session with RelayBackend");
    // Audit: session started
    // We let handle_reattach log SessionRelayConnected with the same connection_id
    log_event_from_context_best_effort(
        &audit_ctx,
        EventType::SessionStarted {
            session_id: connection_id.clone(),
            relay_name: relay_name.clone(),
            relay_id,
            username: username_for_audit.clone(),
        },
    )
    .await;

    // Clone session for history appending
    let session_for_history = session.clone();
    let registry_for_cleanup = registry.clone();
    let user_id_for_cleanup = user_id;
    let relay_id_for_cleanup = relay_id;
    let session_number_for_cleanup = session_number;
    let relay_name_for_logging = relay_name.clone();

    // Spawn task to append backend output to session history
    tokio::spawn(async move {
        use server_core::sessions::session_backend::SessionBackend;
        let mut output_rx = backend.as_ref().subscribe();
        loop {
            match output_rx.recv().await {
                Ok(data) => {
                    if data.is_empty() {
                        // EOF marker
                        tracing::info!("SSH connection closed");
                        session_for_history.close().await;
                        break;
                    }
                    // Append to history
                    session_for_history.touch().await;
                    session_for_history.append_to_history(&data).await;
                }
                Err(_) => {
                    // Channel closed
                    tracing::info!("Backend output channel closed");
                    session_for_history.close().await;
                    break;
                }
            }
        }
        tracing::info!(relay = %relay_name_for_logging, "session history loop terminated");

        // Remove the session from the registry after shutdown
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
    // Pass initial_rx to avoid race condition, and connection_id to link audit events
    handle_reattach(
        socket,
        session,
        registry,
        current_minimized,
        false,
        None,
        ip_address,
        user_agent,
        Some(initial_rx),
        Some(connection_id),
        axum_session_id,
    )
    .await;
}
