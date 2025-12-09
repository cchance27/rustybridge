# Dioxus 0.7.1 Streaming & WebSocket Implementation Plan

## Additional Streaming Features Implementation

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