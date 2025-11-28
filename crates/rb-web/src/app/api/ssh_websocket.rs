#[cfg(feature = "server")]
use dioxus::fullstack::TypedWebsocket;
use dioxus::{
    fullstack::{JsonEncoding, WebSocketOptions, Websocket}, prelude::*
};
#[cfg(feature = "server")]
use rb_types::auth::AuthPromptEvent;
#[cfg(feature = "server")]
use russh::ChannelMsg;
use serde::{Deserialize, Serialize};
#[cfg(feature = "server")]
use server_core::relay::connect_to_relay_channel;
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SshControl {
    Close,
    Resize { cols: u32, rows: u32 },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SshClientMsg {
    pub cmd: Option<SshControl>,
    pub data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SshServerMsg {
    pub data: Vec<u8>,
    pub eof: bool,
    pub exit_status: Option<i32>,
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

    let has_access = user_has_relay_access(pool, user.id, relay.id).await.map_err(|err| {
        tracing::error!(user = %user.username, relay = %relay_name, "Failed to check relay ACL: {err}");
        SshAccessError::Internal
    })?;

    if !has_access {
        tracing::warn!(user = %user.username, relay = %relay_name, "Relay ACL denied for user");
        return Err(SshAccessError::RelayAccessDenied);
    }

    Ok(user.username.clone())
}

pub type SshWebSocket = Websocket<SshClientMsg, SshServerMsg, JsonEncoding>;

// For attach addon, we use raw binary WebSocket (not Dioxus typed WebSocket)
// This is a plain axum handler, not a Dioxus server function
// Dioxus Server Function for SSH WebSocket
#[get("/api/ssh/{relay_name}")]
pub async fn ssh_terminal_ws(relay_name: String, options: WebSocketOptions) -> Result<SshWebSocket, ServerFnError> {
    // Extract state and auth
    let (auth, axum::Extension(pool)): (WebAuthSession, axum::Extension<sqlx::SqlitePool>) =
        FullstackContext::extract().await.map_err(|e| ServerFnError::new(e.to_string()))?;

    tracing::info!("WebSocket SSH connection requested for relay: {}", relay_name);

    let username = match ensure_relay_websocket_permissions(&relay_name, &auth, &pool).await {
        Ok(username) => username,
        Err(err) => {
            tracing::error!("SSH Access Error: {:?}", err);
            return Err(ServerFnError::new(format!("Access denied: {:?}", err)));
        }
    };

    let relay_for_upgrade = relay_name.clone();

    Ok(options.on_upgrade(move |socket| async move {
        tracing::info!(relay = %relay_for_upgrade, user = %username, "WebSocket upgrade callback started");
        handle_typed_socket(socket, relay_for_upgrade, username).await
    }))
}

#[get(
    "/api/ssh/{relay_name}/status", 
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn ssh_terminal_status(relay_name: String) -> Result<SshStatusResponse, ServerFnError> {
    let _ = ensure_relay_websocket_permissions(&relay_name, &auth, &pool).await?;

    Ok(SshStatusResponse {
        ok: true,
        message: "Authorized".to_string(),
    })
}

#[cfg(feature = "server")]
async fn handle_typed_socket(
    mut socket: TypedWebsocket<SshClientMsg, SshServerMsg, JsonEncoding>,
    relay_name: String,
    username: String,
) {
    use tokio::sync::{
        Mutex, mpsc::{self, unbounded_channel}
    };

    tracing::info!("handle_typed_socket started for relay: {} user: {}", relay_name, username);

    // Channels for interactive auth prompts
    let (prompt_tx, mut prompt_rx) = unbounded_channel::<AuthPromptEvent>();
    let (auth_tx, auth_rx) = unbounded_channel::<String>();
    let auth_rx_mutex = Mutex::new(auth_rx);

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
                        let msg = SshServerMsg {
                            data: format!("Authentication failed: {}", e).into_bytes(),
                            eof: true,
                            exit_status: None,
                        };
                        let _ = socket.send(msg).await;
                        // Socket will close when dropped
                        return;
                    }
                }
            }
            Some(action) = prompt_rx.recv() => {
                // Send prompt to the web terminal as server message
                let msg = SshServerMsg {
                    data: action.prompt.into_bytes(),
                    eof: false,
                    exit_status: None,
                };
                let _ = socket.send(msg).await;
                pending_prompt = Some(PendingPrompt { echo: action.echo, buf: Vec::new() });
            }
            maybe_msg = socket.recv() => {
                match maybe_msg {
                    Ok(client_msg) => {
                        // Handle control messages during auth (e.g. Close)
                        if let Some(cmd) = &client_msg.cmd {
                            match cmd {
                                SshControl::Close => {
                                    tracing::info!("Client requested close during auth");
                                    return;
                                }
                                SshControl::Resize { .. } => {
                                    // No-op during auth phase
                                }
                            }
                        }

                        if let Some(mut pending) = pending_prompt.take() {
                            let data = &client_msg.data;
                            pending.buf.extend_from_slice(data);

                            // Echo back if needed
                            if pending.echo && !data.is_empty() {
                                let echo_msg = SshServerMsg {
                                    data: data.clone(),
                                    eof: false,
                                    exit_status: None,
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
                                    };
                                    let _ = socket.send(msg).await;
                                }
                            } else {
                                pending_prompt = Some(pending);
                            }
                        }
                    }
                    Err(_) => {
                        tracing::warn!("WebSocket closed before relay authentication completed");
                        return;
                    }
                }
            }
        }
    };

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
                            let _ = output_tx.send(Vec::new()).await; // marker; handled below
                            // We log and break; websocket loop will see EOF when channel closes
                            break;
                        }
                        ChannelMsg::Eof | ChannelMsg::Close => {
                            tracing::info!("SSH session closed");
                            // Send EOF marker to websocket loop
                            let _ = output_tx.send(Vec::new()).await;
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
    let _relay_name_for_sender = relay_name.clone();

    loop {
        tokio::select! {
            // Receive from SSH output -> Send to WebSocket
            Some(data) = output_rx.recv() => {
                let is_eof = data.is_empty();
                let msg = SshServerMsg {
                    data,
                    eof: is_eof,
                    exit_status: None,
                };
                if socket.send(msg).await.is_err() {
                    break;
                }
                if is_eof {
                    break;
                }
            }
            // Receive from WebSocket -> Send to SSH input
            ws_msg = socket.recv() => {
                match ws_msg {
                    Ok(client_msg) => {
                        // Handle control commands
                        if let Some(cmd) = &client_msg.cmd {
                            match cmd {
                                SshControl::Close => {
                                    tracing::info!("Client requested SSH close");
                                    break;
                                }
                                SshControl::Resize { .. } => {
                                    // TODO: implement terminal resize
                                }
                            }
                        }

                        if !client_msg.data.is_empty() 
                            && input_tx.send(client_msg.data).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
        }
    }

    tracing::info!("WebSocket handler exiting for relay: {}", relay_name);
}
