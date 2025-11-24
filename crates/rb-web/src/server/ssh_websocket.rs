#[cfg(feature = "server")]
use axum::{
    Json, extract::{
        Path, ws::{Message, WebSocket, WebSocketUpgrade}
    }, http::StatusCode, response::{IntoResponse, Response}
};
#[cfg(feature = "server")]
use futures::{SinkExt, StreamExt};
#[cfg(feature = "server")]
use russh::ChannelMsg;
#[cfg(feature = "server")]
use serde::Serialize;
#[cfg(feature = "server")]
use server_core::relay::{AuthPromptEvent, connect_to_relay_channel};
#[cfg(feature = "server")]
use state_store::{fetch_relay_host_by_name, user_has_relay_access};

#[cfg(feature = "server")]
use crate::server::auth::guards::{WebAuthSession, ensure_authenticated};

#[cfg(feature = "server")]
#[derive(Debug)]
enum SshAccessError {
    Unauthorized,
    RelayNotFound,
    RelayAccessDenied,
    Internal,
}

#[cfg(feature = "server")]
impl SshAccessError {
    fn status_and_message(&self) -> (StatusCode, &'static str) {
        match self {
            SshAccessError::Unauthorized => (StatusCode::UNAUTHORIZED, "Authentication required"),
            SshAccessError::RelayNotFound => (StatusCode::NOT_FOUND, "Relay not found"),
            SshAccessError::RelayAccessDenied => (StatusCode::FORBIDDEN, "Relay access denied"),
            SshAccessError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"),
        }
    }

    fn into_http_response(self) -> Response {
        let (status, msg) = self.status_and_message();
        (status, msg).into_response()
    }

    fn into_status_response(self) -> Response {
        let (status, msg) = self.status_and_message();
        let body = SshStatusResponse {
            ok: false,
            message: msg.to_string(),
        };
        (status, Json(body)).into_response()
    }
}

#[cfg(feature = "server")]
#[derive(Serialize)]
struct SshStatusResponse {
    ok: bool,
    message: String,
}

#[cfg(feature = "server")]
async fn ensure_relay_websocket_permissions(
    relay_name: &str,
    auth: &WebAuthSession,
    pool: &sqlx::SqlitePool,
) -> Result<String, SshAccessError> {
    // Today any authenticated user may open relays they have been explicitly granted via ACLs.
    // If we decide to add a dedicated "relay access" claim in the future, this is the choke point.
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

    let has_access = user_has_relay_access(pool, &user.username, relay.id).await.map_err(|err| {
        tracing::error!(user = %user.username, relay = %relay_name, "Failed to check relay ACL: {err}");
        SshAccessError::Internal
    })?;

    if !has_access {
        tracing::warn!(user = %user.username, relay = %relay_name, "Relay ACL denied for user");
        return Err(SshAccessError::RelayAccessDenied);
    }

    Ok(user.username.clone())
}

// For attach addon, we use raw binary WebSocket (not Dioxus typed WebSocket)
// This is a plain axum handler, not a Dioxus server function
#[cfg(feature = "server")]
pub async fn ssh_terminal_ws(
    Path(relay_name): Path<String>,
    auth: WebAuthSession,
    axum::Extension(pool): axum::Extension<sqlx::SqlitePool>,
    ws: WebSocketUpgrade,
) -> Response {
    tracing::info!("WebSocket SSH connection requested for relay: {}", relay_name);

    let username = match ensure_relay_websocket_permissions(&relay_name, &auth, &pool).await {
        Ok(username) => username,
        Err(err) => return err.into_http_response(),
    };

    let relay_for_upgrade = relay_name.clone();

    ws.on_upgrade(move |socket| async move {
        tracing::info!(relay = %relay_for_upgrade, user = %username, "WebSocket upgrade callback started");
        handle_socket(socket, relay_for_upgrade, username).await
    })
}

#[cfg(feature = "server")]
pub async fn ssh_terminal_status(
    Path(relay_name): Path<String>,
    auth: WebAuthSession,
    axum::Extension(pool): axum::Extension<sqlx::SqlitePool>,
) -> Response {
    match ensure_relay_websocket_permissions(&relay_name, &auth, &pool).await {
        Ok(_) => {
            let body = SshStatusResponse {
                ok: true,
                message: "Authorized".to_string(),
            };
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(err) => err.into_status_response(),
    }
}

#[cfg(feature = "server")]
async fn handle_socket(socket: WebSocket, relay_name: String, username: String) {
    tracing::info!("handle_socket started for relay: {} user: {}", relay_name, username);

    let (mut ws_sender, mut ws_receiver) = socket.split();

    // Channels for interactive auth prompts
    let (prompt_tx, mut prompt_rx) = tokio::sync::mpsc::unbounded_channel::<AuthPromptEvent>();
    let (auth_tx, auth_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let auth_rx_mutex = tokio::sync::Mutex::new(auth_rx);

    // Drive interactive auth prompts over the WebSocket while connecting
    let mut connect_fut = Box::pin(connect_to_relay_channel(
        &relay_name,
        &username,
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
    let mut channel = loop {
        tokio::select! {
            res = &mut connect_fut => {
                match res {
                    Ok(ch) => {
                        tracing::info!("Successfully connected to relay: {}", relay_name);
                        break ch;
                    }
                    Err(e) => {
                        tracing::error!("Failed to connect to relay {}: {}", relay_name, e);
                        let _ = ws_sender.send(Message::Text(format!("Authentication failed: {}", e).into())).await;
                        let _ = ws_sender.send(Message::Close(None)).await;
                        return;
                    }
                }
            }
            Some(action) = prompt_rx.recv() => {
                // Send prompt to the web terminal; attach addon will render it as text
                let _ = ws_sender.send(Message::Text(action.prompt.clone().into())).await;
                pending_prompt = Some(PendingPrompt { echo: action.echo, buf: Vec::new() });
            }
            maybe_msg = ws_receiver.next() => {
                if let Some(Ok(msg)) = maybe_msg {
                    if let Some(mut pending) = pending_prompt.take() {
                        let mut handled = true;
                        let mut newly_received: Vec<u8> = Vec::new();
                        match msg {
                            Message::Text(txt) => {
                                newly_received.extend_from_slice(txt.as_bytes());
                                pending.buf.extend_from_slice(txt.as_bytes());
                            }
                            Message::Binary(data) => {
                                newly_received.extend_from_slice(&data);
                                pending.buf.extend_from_slice(&data);
                            }
                            _ => handled = false,
                        }

                        // Echo back only the newly received chunk if echo is enabled
                        if handled && pending.echo && !newly_received.is_empty() {
                            let _ = ws_sender.send(Message::Binary(newly_received.clone().into())).await;
                        }

                        if handled {
                            if let Some(pos) = pending
                                .buf
                                .iter()
                                .position(|b| *b == b'\n' || *b == b'\r')
                            {
                                let line = pending.buf[..pos].to_vec();
                                let resp = String::from_utf8_lossy(&line).to_string();
                                let _ = auth_tx.send(resp);
                                // Separate prompts from next output only after password prompts (echo == false)
                                if !pending.echo {
                                    let _ = ws_sender.send(Message::Binary(b"\r\n\r\n".to_vec().into())).await;
                                }
                            } else {
                                // No newline yet; continue accumulating
                                pending_prompt = Some(pending);
                            }
                        } else {
                            pending_prompt = Some(pending);
                        }
                    }
                } else {
                    tracing::warn!("WebSocket closed before relay authentication completed");
                    return;
                }
            }
        }
    };

    use tokio::sync::mpsc;
    // Use bounded channels to prevent OOM if one side is faster than the other
    let (input_tx, mut input_rx) = mpsc::channel::<Vec<u8>>(1024);
    let (output_tx, mut output_rx) = mpsc::channel::<Vec<u8>>(1024);

    // Task to handle SSH channel I/O
    let relay_name_for_ssh = relay_name.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                // Read from SSH channel
                Some(msg) = channel.wait() => {
                    match msg {
                        ChannelMsg::Data { ref data } => {
                            if output_tx.send(data.to_vec()).await.is_err() {
                                break;
                            }
                        }
                        ChannelMsg::ExtendedData { ref data, .. } => {
                            if output_tx.send(data.to_vec()).await.is_err() {
                                break;
                            }
                        }
                        ChannelMsg::ExitStatus { exit_status } => {
                            tracing::info!("SSH session exit status: {}", exit_status);
                            break;
                        }
                        ChannelMsg::Eof | ChannelMsg::Close => {
                            tracing::info!("SSH session closed");
                            break;
                        }
                        _ => {}
                    }
                }
                // Write input to SSH channel
                msg = input_rx.recv() => {
                    match msg {
                        Some(data) => {
                            let mut cursor = std::io::Cursor::new(data);
                            if channel.data(&mut cursor).await.is_err() {
                                break;
                            }
                        }
                        None => {
                            tracing::info!("Input channel closed (WebSocket disconnected), closing SSH channel");
                            let _ = channel.close().await;
                            break;
                        }
                    }
                }
            }
        }
        tracing::info!("SSH channel task exiting for relay: {}", relay_name_for_ssh);
    });

    // Task to send SSH output to WebSocket
    let relay_name_for_sender = relay_name.clone();
    tokio::spawn(async move {
        while let Some(data) = output_rx.recv().await {
            if ws_sender.send(Message::Binary(data.into())).await.is_err() {
                break;
            }
        }
        tracing::info!("WebSocket sender task exiting for relay: {}", relay_name_for_sender);
        let _ = ws_sender.close().await;
    });

    // Task to receive WebSocket input and send to SSH
    while let Some(msg) = ws_receiver.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                tracing::debug!("Received text from WebSocket: {} bytes", text.len());
                if input_tx.send(text.as_bytes().to_vec()).await.is_err() {
                    break;
                }
            }
            Ok(Message::Binary(data)) => {
                tracing::debug!("Received binary from WebSocket: {} bytes", data.len());
                if input_tx.send(data.to_vec()).await.is_err() {
                    break;
                }
            }
            Ok(Message::Close(_)) => {
                tracing::info!("WebSocket closed by client");
                break;
            }
            Err(e) => {
                tracing::warn!("WebSocket error: {:?}", e);
                break;
            }
            _ => {}
        }
    }
    tracing::info!("WebSocket receiver task exiting for relay: {}", relay_name);
}

// Client-side stub
#[cfg(not(feature = "server"))]
pub async fn ssh_terminal_ws() {}

// Client-side stub
#[cfg(not(feature = "server"))]
pub async fn ssh_terminal_status() {}
