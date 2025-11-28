# Dioxus 0.7.1 Streaming & WebSocket Implementation Plan

## Overview

This document outlines the implementation strategy for leveraging Dioxus 0.7.1's new streaming and WebSocket features to enhance the RustyBridge web interface. The plan focuses on two main phases: migrating the existing SSH WebSocket to the new typed WebSocket approach and implementing additional streaming features.

## Phase 1: SSH WebSocket Migration

### 1.1 Current Implementation Analysis

The current SSH WebSocket implementation uses:
- Raw Axum WebSocket extraction: `axum::extract::ws::{Message, WebSocket, WebSocketUpgrade}`
- Manual binary data handling with `Message::Binary(data.into())`
- Complex connection lifecycle management
- Interactive authentication prompt system

### CRITICAL: Be aware the proper way to use server functions in Dioxus 0.7.1 is now 

#[get(
    "/api/ssh/{relay_name}", 
    auth: WebAuthSession,
    axum::Extension(pool): axum::Extension<sqlx::SqlitePool>
)]
async fn ssh_terminal_ws(
    relay_name: String
    options: WebSocketOptions,
) -> Result<(), ServerFnError> {
}

Also their is no fullstack::prelude::*, you need to call the direct items you want to use no prelude for fullstack websocket items.

### 1.2 Migration to Dioxus Typed WebSocket

#### Server-side Migration

**Before (Current Implementation):**
```rust
// Current raw Axum WebSocket handler
#[cfg(feature = "server")]
pub async fn ssh_terminal_ws(
    Path(relay_name): Path<String>,
    auth: WebAuthSession,
    axum::Extension(pool): axum::Extension<sqlx::SqlitePool>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| async move {
        handle_socket(socket, relay_name, username).await
    })
}
```

**After (Dioxus Typed WebSocket):**
```rust
// New Dioxus typed WebSocket handler
#[get(
    "/api/ssh/{relay_name}", 
    auth: WebAuthSession,
    axum::Extension(pool): axum::Extension<sqlx::SqlitePool>
)]
async fn ssh_terminal_ws(
    relay_name: String
    options: WebSocketOptions,
) -> Result<Websocket<Vec<u8>, Vec<u8>, CborEncoding>> {
    // Ensure authentication and permissions (same logic as before)
    let username = ensure_relay_websocket_permissions(&relay_name, &auth, &pool).await?;
    
    Ok(options.on_upgrade(move |mut socket| async move {
        handle_typed_socket(socket, relay_name, username).await
    }))
}
```

#### Enhanced Connection Handling

```rust
#[cfg(feature = "server")]
async fn handle_typed_socket(
    mut socket: WebSocket<Vec<u8>, Vec<u8>, CborEncoding>,
    relay_name: String,
    username: String,
) {
    use tokio::sync::{Mutex, mpsc::{self, unbounded_channel}};
    
    // Auth prompt handling (similar to current implementation)
    let (prompt_tx, mut prompt_rx) = unbounded_channel::<AuthPromptEvent>();
    let (auth_tx, auth_rx) = unbounded_channel::<String>();
    let auth_rx_mutex = Mutex::new(auth_rx);
    
    // Connect to relay (same logic as before)
    let mut connect_fut = Box::pin(connect_to_relay_channel(
        &relay_name,
        &username,
        (80, 24),
        Some(prompt_tx.clone()),
        Some(auth_rx_mutex),
    ));
    
    // Interactive authentication loop
    let mut pending_prompt: Option<PendingPrompt> = None;
    let mut channel = loop {
        tokio::select! {
            res = &mut connect_fut => {
                match res {
                    Ok(ch) => break ch,
                    Err(e) => {
                        let _ = socket.send(format!("Authentication failed: {}", e).into_bytes()).await;
                        let _ = socket.close().await;
                        return;
                    }
                }
            }
            Some(action) = prompt_rx.recv() => {
                // Send prompt using typed WebSocket
                let _ = socket.send(action.prompt.into_bytes()).await;
                pending_prompt = Some(PendingPrompt { echo: action.echo, buf: Vec::new() });
            }
            Ok(data) = socket.recv() => {
                // Handle input using typed WebSocket (automatically deserializes)
                if let Some(mut pending) = pending_prompt.take() {
                    pending.buf.extend_from_slice(&data);
                    
                    // Echo back if needed
                    if pending.echo && !data.is_empty() {
                        let _ = socket.send(data).await;
                    }
                    
                    // Check for line completion
                    if let Some(pos) = pending.buf.iter().position(|b| *b == b'\n' || *b == b'\r') {
                        let line = pending.buf[..pos].to_vec();
                        let resp = String::from_utf8_lossy(&line).to_string();
                        let _ = auth_tx.send(resp);
                        if !pending.echo {
                            let _ = socket.send(b"\r\n\r\n".to_vec()).await;
                        }
                    } else {
                        pending_prompt = Some(pending);
                    }
                }
            }
        }
    };
    
    // Continue with SSH I/O (similar to current implementation)
    let (input_tx, mut input_rx) = mpsc::channel::<Vec<u8>>(1024);
    let (output_tx, mut output_rx) = mpsc::channel::<Vec<u8>>(1024);
    
    // SSH channel task (simplified)
    tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(msg) = channel.wait() => {
                    match msg {
                        ChannelMsg::Data { ref data } => {
                            if output_tx.send(data.to_vec()).await.is_err() {
                                break;
                            }
                        }
                        // Handle other message types...
                        _ => {}
                    }
                }
                Some(data) = input_rx.recv() => {
                    let mut cursor = std::io::Cursor::new(data);
                    let _ = channel.data(&mut cursor).await;
                }
            }
        }
    });
    
    // Output forwarding to WebSocket
    tokio::spawn(async move {
        while let Some(data) = output_rx.recv().await {
            if socket.send(data).await.is_err() {
                break;
            }
        }
    });
    
    // Input handling from WebSocket
    while let Ok(data) = socket.recv().await {
        if input_tx.send(data).await.is_err() {
            break;
        }
    }
}
```

#### Client-side Migration

**Before (Current Implementation):**
```rust
// Raw WebSocket connection in JavaScript
let ws_url = format!("{}://{}/api/ssh/{}", protocol, host, relay_name);
const socket = new WebSocket(ws_url);
socket.binaryType = 'arraybuffer';

// Use xterm AttachAddon
const attachAddon = new AttachAddon(socket);
term.loadAddon(attachAddon);
```

**After (Dioxus WebSocket Hook):**
```rust
#[component]
pub fn SshTerminal(props: TerminalProps) -> Element {
    let mut terminal_ref = use_signal(|| None);
    let mut socket = use_signal(|| None);
    let relay_name = props.relay_name.clone();
    
    // Initialize terminal (existing xterm.js integration)
    use_effect(move || {
        if let Some(relay) = &relay_name {
            // Use Dioxus typed WebSocket
            let ws_options = WebSocketOptions::new();
            let mut ws = use_websocket(|| ssh_terminal_ws(relay.clone(), ws_options));
            
            // Set up terminal connection
            socket.set(Some(ws));
            
            // Handle incoming data
            spawn(async move {
                while let Ok(data) = ws.recv().await {
                    if let Some(term) = terminal_ref() {
                        // Send binary data to xterm
                        write_to_terminal(&term, &data);
                    }
                }
            });
        }
    });
    
    // Handle terminal input
    let send_input = move |data: Vec<u8>| {
        if let Some(ws) = socket() {
            spawn(async move {
                ws.send(data).await.ok();
            });
        }
    };
    
    // Rest of component implementation...
}
```

### 1.3 Benefits of Migration

1. **Type Safety**: Compile-time guarantees for WebSocket message formats
2. **Better Integration**: Seamless Dioxus reactivity with `use_websocket` hook
3. **Performance**: CborEncoding provides better binary data efficiency than JSON
4. **Maintainability**: Cleaner server function approach vs raw Axum extraction
5. **Future Features**: Enables collaborative SSH sessions and advanced real-time features


### COMPLETED PHASE 1 NOTES BELOW

## Phase 1 Migration Notes 

We recently finished the “Phase 1” migration away from the legacy SSE hooks toward typed websockets in Dioxus 0.7.1. A few gotchas surfaced while bringing the SSH terminal online:

1. **Typed payloads are worth it.** We replaced the raw `Vec<u8>` websocket with:
   - `SshClientMsg { cmd: Option<SshControl>, data: Vec<u8> }`
   - `SshServerMsg { data: Vec<u8>, eof: bool, exit_status: Option<i32> }`
   This immediately gave us a clean channel for control messages (`Close`, `Resize`, future features) without touching the JS boundary.

2. **Gate client I/O on connection status.** Calling `.recv()` on the `use_websocket` handle *before* a relay is selected yields `WebSocket already closed` and can wedge the hook. We introduced a `connected` signal and only start the terminal bridge when it flips to `true`.

3. **Always dispatch a close event.** The dashboard listens for `window.dispatchEvent(new CustomEvent('ssh-connection-closed', …))` to reset `active_relay`. Make sure every exit path (SSH EOF, websocket error, manual disconnect) fires this event; otherwise the UI stays “connected” even though the socket died.

4. **Client-initiated close must use the typed channel.** Setting `socket.set(Err(..))` while the recv loop is running caused WASM `RuntimeError: unreachable`. Instead, send `SshControl::Close` over the websocket and let the server shut down the SSH channel; the hook will naturally observe the close.

5. **Surface EOF explicitly.** When the SSH session ends on the server we now push an empty chunk so the websocket emits `SshServerMsg { eof: true, … }`. The client reacts immediately, dispatching the close event without waiting for another keystroke.


## Phase 2: Additional Streaming Features Implementation

### 2.1 TextStream for Simple Notifications

TextStream is ideal for simple text-based notifications and status updates.

Not shown below but we'd likely need to use ensure_claims and bring auth in on the [get]'s where needed to secure things and use ensure claims or auth based on whats needed.

#### Server Connectivity Status
```rust
#[get("/api/server-status")]
async fn server_status() -> Result<TextStream> {
    Ok(TextStream::spawn(move |tx| async move {
        loop {
            let status = get_server_health().await;
            let message = match status {
                ServerHealth::Healthy => "Server: All systems operational",
                ServerHealth::Degraded => "Server: Performance degradation detected",
                ServerHealth::Down => "Server: Connection issues detected",
            };
            
            if tx.unbounded_send(message.to_string()).is_err() {
                break; // Client disconnected
            }
            
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        }
    }))
}
```

#### System Version Change Detection
```rust
#[get("/api/version-changes")]
async fn version_changes() -> Result<TextStream> {
    let mut last_version = get_current_version().await;
    
    Ok(TextStream::spawn(move |tx| async move {
        loop {
            let current_version = get_current_version().await;
            
            if current_version != last_version {
                let message = format!(
                    "Version update detected: {} -> {}. Please refresh the page for latest features.",
                    last_version, current_version
                );
                let _ = tx.unbounded_send(message).await;
                last_version = current_version;
            }
            
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        }
    }))
}
```

#### User Activity Notifications
```rust
#[get("/api/user-activity")]
async fn user_activity() -> Result<TextStream> {
    Ok(TextStream::spawn(move |tx| async move {
        // Listen for user activity events (simplified example)
        let mut activity_rx = get_user_activity_channel().await;
        
        while let Ok(activity) = activity_rx.recv().await {
            let message = match activity.event_type {
                ActivityEvent::Login => format!("User {} logged in", activity.username),
                ActivityEvent::Logout => format!("User {} logged out", activity.username),
                ActivityEvent::SshConnect => format!("User {} connected to SSH", activity.username),
                ActivityEvent::SshDisconnect => format!("User {} disconnected from SSH", activity.username),
            };
            
            if tx.unbounded_send(message).is_err() {
                break;
            }
        }
    }))
}
```

### 2.2 Streaming<T, JsonEncoding> for Complex Data

#### User Session Tracking
```rust
#[derive(Serialize, Deserialize, Debug)]
struct SessionEvent {
    event_type: SessionEventType,
    username: String,
    timestamp: chrono::DateTime<chrono::Utc>,
    session_id: String,
    ip_address: String,
}

#[derive(Serialize, Deserialize, Debug)]
enum SessionEventType {
    Login,
    Logout,
    SessionRenewed,
    AccessDenied,
}

#[get("/api/session-events")]
async fn session_events() -> Result<Streaming<SessionEvent, JsonEncoding>> {
    Ok(Streaming::spawn(|tx| async move {
        let mut session_rx = get_session_event_channel().await;
        
        while let Ok(event) = session_rx.recv().await {
            if tx.unbounded_send(event).is_err() {
                break;
            }
            
            // Rate limiting to prevent spam
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }))
}
```

#### SSH Session Monitoring
```rust
#[derive(Serialize, Deserialize, Debug)]
struct SshSessionData {
    session_id: String,
    username: String,
    relay_name: String,
    connected_at: chrono::DateTime<chrono::Utc>,
    last_activity: chrono::DateTime<chrono::Utc>,
    duration_minutes: u64,
    status: SshSessionStatus,
}

#[derive(Serialize, Deserialize, Debug)]
enum SshSessionStatus {
    Active,
    Authenticating,
    Idle,
    Disconnected,
}

#[get("/api/ssh-sessions")]
async fn ssh_sessions() -> Result<Streaming<SshSessionData, JsonEncoding>> {
    Ok(Streaming::spawn(|tx| async move {
        let mut sessions = HashMap::new();
        let mut update_interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        
        loop {
            update_interval.tick().await;
            
            // Update session data
            let current_sessions = get_active_ssh_sessions().await;
            
            for session in current_sessions {
                let existing = sessions.get(&session.session_id);
                if existing.map_or(true, |s| s.status != session.status) {
                    // Status changed, send update
                    if tx.unbounded_send(session.clone()).is_err() {
                        return;
                    }
                    sessions.insert(session.session_id.clone(), session);
                }
            }
            
            // Clean up disconnected sessions
            sessions.retain(|id, _| current_sessions.iter().any(|s| &s.session_id == id));
        }
    }))
}
```

#### Admin Dashboard - Real-time Metrics
```rust
#[derive(Serialize, Deserialize, Debug)]
struct SystemMetrics {
    timestamp: chrono::DateTime<chrono::Utc>,
    active_connections: u32,
    cpu_usage_percent: f32,
    memory_usage_mb: u64,
    ssh_sessions_active: u32,
    web_sessions_active: u32,
    relays_online: u32,
    relays_total: u32,
}

#[get("/api/system-metrics")]
async fn system_metrics() -> Result<Streaming<SystemMetrics, JsonEncoding>> {
    Ok(Streaming::spawn(|tx| async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10));
        
        loop {
            interval.tick().await;
            
            let metrics = SystemMetrics {
                timestamp: chrono::Utc::now(),
                active_connections: get_active_connection_count().await,
                cpu_usage_percent: get_cpu_usage().await,
                memory_usage_mb: get_memory_usage().await,
                ssh_sessions_active: get_ssh_session_count().await,
                web_sessions_active: get_web_session_count().await,
                relays_online: get_online_relay_count().await,
                relays_total: get_total_relay_count().await,
            };
            
            if tx.unbounded_send(metrics).is_err() {
                break;
            }
        }
    }))
}
```

### 2.3 Client-side Integration

#### Component Using TextStream
```rust
#[component]
pub fn ServerStatus() -> Element {
    let mut messages = use_signal(Vec::new);
    
    use_effect(move || {
        spawn(async move {
            let stream = server_status().await;
            while let Ok(msg) = stream.recv().await {
                messages.push(msg);
                
                // Auto-trim old messages
                if messages.len() > 50 {
                    messages.remove(0);
                }
            }
        });
    });
    
    rsx! {
        div {
            class: "server-status",
            h3 { "Server Status" },
            for (index, message) in messages.iter().enumerate() {
                div {
                    key: "{index}",
                    class: "status-message",
                    "{message}"
                }
            }
        }
    }
}
```

#### Component Using Streaming
```rust
#[component]
pub fn SshSessionMonitor() -> Element {
    let mut sessions = use_signal(HashMap::new);
    
    use_effect(move || {
        spawn(async move {
            let stream = ssh_sessions().await;
            while let Ok(session) = stream.recv().await {
                sessions.insert(session.session_id.clone(), session);
            }
        });
    });
    
    rsx! {
        div {
            class: "ssh-session-monitor",
            h3 { "Active SSH Sessions" },
            for (session_id, session) in sessions.iter() {
                div {
                    class: "session-item",
                    div {
                        "User: {session.username}"
                        "Relay: {session.relay_name}"
                        "Duration: {session.duration_minutes} minutes"
                        "Status: {format!("{:?}", session.status)}"
                    }
                }
            }
        }
    }
}
```

## Phase 3: Advanced Collaborative Features

### 3.1 Collaborative SSH Sessions

```rust
#[derive(Serialize, Deserialize, Debug)]
enum CollaborativeEvent {
    UserJoined { username: String },
    UserLeft { username: String },
    TerminalData { data: Vec<u8>, from_user: String },
    TerminalInput { data: Vec<u8>, from_user: String },
}

#[get("/api/ssh/collaborative/{session_id}")]
async fn collaborative_ssh(
    Path(session_id): Path<String>,
    username: String,
    options: WebSocketOptions,
) -> Result<Websocket<CollaborativeEvent, CollaborativeEvent, CborEncoding>> {
    Ok(options.on_upgrade(move |mut socket| async move {
        // Join collaborative session
        let session = join_collaborative_session(&session_id, &username).await;
        
        // Broadcast user join
        socket.send(CollaborativeEvent::UserJoined { username: username.clone() }).await;
        
        // Handle collaborative SSH logic
        // ... implementation details
        
        // Cleanup on disconnect
        leave_collaborative_session(&session_id, &username).await;
    }))
}
```

### 3.2 Real-time Admin Monitoring

```rust
#[derive(Serialize, Deserialize, Debug)]
struct AdminEvent {
    event_type: AdminEventType,
    details: serde_json::Value,
    timestamp: chrono::DateTime<chrono::Utc>,
}

#[get("/api/admin/events")]
async fn admin_events() -> Result<Streaming<AdminEvent, JsonEncoding>> {
    Ok(Streaming::spawn(|tx| async move {
        let mut admin_rx = get_admin_event_channel().await;
        
        while let Ok(event) = admin_rx.recv().await {
            if tx.unbounded_send(event).is_err() {
                break;
            }
        }
    }))
}
```

## Implementation Considerations

### Error Handling and Resilience
- Implement proper error handling for WebSocket disconnections
- Add reconnection strategies for client-side connections
- Handle backpressure in streaming endpoints

### Security
- Maintain existing authentication and authorization
- Validate WebSocket upgrade requests
- Rate limiting for streaming endpoints

### Performance
- Use appropriate streaming types (TextStream vs Streaming<T, E>)
- Implement connection pooling for WebSocket handlers
- Monitor resource usage of long-lived connections

### Scalability
- Design for multiple concurrent WebSocket connections
- Consider pub-sub patterns for broadcasting to multiple clients
- Implement proper cleanup for disconnected clients

## Conclusion

The migration to Dioxus 0.7.1's streaming and WebSocket features provides significant benefits:

1. **Phase 1** establishes a robust foundation by migrating SSH functionality to a type-safe and more maintainable approach
2. **Phase 2** introduces powerful real-time features that enhance administrative capabilities and user experience
3. **Phase 3** enables advanced collaborative features that were not previously feasible

This phased approach allows for incremental adoption while maintaining existing functionality and enabling new capabilities that significantly enhance the overall user experience. The SSH migration in Phase 1 provides the foundation for the advanced collaborative features in Phase 3, making it the logical starting point for the implementation.