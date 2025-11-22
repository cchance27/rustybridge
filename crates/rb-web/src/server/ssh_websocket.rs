#[cfg(feature = "server")]
use axum::{
    extract::{
        Path, ws::{Message, WebSocket, WebSocketUpgrade}
    }, response::Response
};
#[cfg(feature = "server")]
use futures::{SinkExt, StreamExt};
#[cfg(feature = "server")]
use russh::ChannelMsg;
#[cfg(feature = "server")]
use server_core::relay::connect_to_relay_channel;

// For attach addon, we use raw binary WebSocket (not Dioxus typed WebSocket)
// This is a plain axum handler, not a Dioxus server function
#[cfg(feature = "server")]
pub async fn ssh_terminal_ws(Path(relay_name): Path<String>, ws: WebSocketUpgrade) -> Response {
    tracing::info!("SERVER: WebSocket SSH connection requested for relay: {}", relay_name);

    ws.on_upgrade(move |socket| async move {
        tracing::info!("SERVER: WebSocket upgrade callback started for relay: {}", relay_name);
        handle_socket(socket, relay_name).await
    })
}

#[cfg(feature = "server")]
async fn handle_socket(socket: WebSocket, relay_name: String) {
    tracing::info!("SERVER: handle_socket started for relay: {}", relay_name);

    let (mut ws_sender, mut ws_receiver) = socket.split();

    // Get the username from the session (you'll need to extract this properly)
    let username = "admin"; // TODO: Extract from session

    // Connect to the relay
    let mut channel = match connect_to_relay_channel(&relay_name, username, (80, 24)).await {
        Ok(ch) => {
            tracing::info!("Successfully connected to relay: {}", relay_name);
            ch
        }
        Err(e) => {
            tracing::error!("Failed to connect to relay {}: {}", relay_name, e);
            let _ = ws_sender.send(Message::Text(format!("Failed to connect: {}", e).into())).await;
            return;
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
        tracing::info!("SERVER: WebSocket sender task exiting for relay: {}", relay_name_for_sender);
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
