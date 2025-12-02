# Phase 4: Session Unification & Event Unification

Unify the SSH relay and web terminal session architectures to enable seamless session sharing between web and SSH clients, with trait-based event handling for resize, mouse events, and other terminal features.

## Background

Currently, RustyBridge has two separate paths for SSH sessions:

1. **Web Terminal Sessions** ([crates/rb-web/src/app/api/ws/ssh.rs](../crates/rb-web/src/app/api/ws/ssh.rs)):
   - WebSocket → `handle_new_session()` → `connect_to_relay_channel()` → manual I/O loops
   - Managed by `SshSession` in the session registry with broadcast channels
   - Supports multi-viewer, detach/reattach, history replay

2. **SSH Relay Sessions** ([crates/server-core/src/handler/relay.rs](../crates/server-core/src/handler/relay.rs)):
   - SSH Client → `connect_to_relay()` → `start_bridge()` → russh channel forwarding
   - Creates session entry in registry but uses separate I/O bridging
   - Cannot be attached to from web UI

**Problem**: These two paths are incompatible. Web sessions can't attach to SSH-originated sessions and vice versa, despite both ultimately connecting to the same relay hosts.

## Proposed Changes

### 1. Session Backend Abstraction

#### [NEW] [session_backend.rs](../crates/server-core/src/sessions/session_backend.rs)

Create trait-based abstraction for session I/O backends:

```rust
/// Trait for session I/O backends (Web, SSH, or unified)
pub trait SessionBackend: Send + Sync {
    /// Send data to the backend
    fn send(&self, data: Vec<u8>) -> Result<(), SessionError>;
    
    /// Subscribe to data from the backend
    fn subscribe(&self) -> broadcast::Receiver<Vec<u8>>;
    
    /// Send resize event
    fn resize(&self, cols: u32, rows: u32) -> Result<(), SessionError>;
    
    /// Send mouse event (for future use)
    fn mouse_event(&self, event: MouseEvent) -> Result<(), SessionError>;
    
    /// Close the backend
    fn close(&self) -> Result<(), SessionError>;
}

/// Unified backend that manages relay channel + broadcast
pub struct RelayBackend {
    relay_handle: RelayHandle,
    output_broadcast: broadcast::Sender<Vec<u8>>,
    resize_tx: mpsc::Sender<(u32, u32)>,
}

impl SessionBackend for RelayBackend {
    // Implementation bridges between relay channel and broadcast
}
```

**Purpose**: Provide a unified interface for session I/O that works for both web and SSH clients, abstracting away the underlying transport mechanism.

---

### 2. Relay Connection Refactoring  

#### [MODIFY] [relay/connection.rs](../crates/server-core/src/relay/connection.rs)

Refactor `start_bridge()` to return a `RelayBackend` instead of managing I/O directly:

```rust
pub async fn start_bridge_backend(
    relay: &RelayInfo,
    base_username: &str,
    initial_size: (u32, u32),
    options: &HashMap<String, SecretBoxedString>,
    prompt_tx: Option<UnboundedSender<AuthPromptEvent>>,
    auth_rx: Option<Arc<Mutex<UnboundedReceiver<String>>>>,
) -> Result<RelayBackend> {
    // Same connection logic as current start_bridge
    // Return RelayBackend wrapping the channel
}
```

Keep existing `start_bridge()` for SSH direct clients (backward compatibility):

```rust
pub async fn start_bridge(
    server_handle: russh::server::Handle,
    client_channel: russh::ChannelId,
    // ... existing params
) -> Result<RelayHandle> {
    // Call start_bridge_backend()
    // Spawn task to bridge RelayBackend <-> server_handle/client_channel
}
```

**Purpose**: Separate relay connection from I/O bridging, allowing the same relay connection to be shared between multiple attachment points.

---

### 3. Session Registry Enhancement

#### [MODIFY] [sessions.rs](../crates/server-core/src/sessions.rs)

Update `SshSession` to use `SessionBackend`:

```rust
pub struct SshSession {
    // ... existing fields ...
    
    // Replace input_tx/output_tx with backend
    pub backend: Arc<dyn SessionBackend>,
    
    // Keep these for multi-viewer broadcast
    pub close_tx: broadcast::Sender<()>,
    pub event_tx: broadcast::Sender<SessionEvent>,
}
```

Add session origin tracking:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionOrigin {
    Web { user_id: i64 },
    Ssh { user_id: i64 },
}

pub struct SshSession {
    // ... existing fields ...
    pub origin: SessionOrigin,
}
```

Update `SessionRegistry::create_next_session()` to accept `SessionBackend`:

```rust
pub async fn create_next_session(
    &self,
    user_id: i64,
    relay_id: i64,
    relay_name: String,
    username: String,
    backend: Arc<dyn SessionBackend>,
    origin: SessionOrigin,
    ip_address: Option<String>,
    user_agent: Option<String>,
) -> (u32, Arc<SshSession>) { ... }
```

**Purpose**: Make sessions transport-agnostic so they can be created from and attached to by both web and SSH clients.

---

### 4. Web Terminal Updates

#### [MODIFY] [rb-web/src/app/api/ws/ssh.rs](../crates/rb-web/src/app/api/ws/ssh.rs)

Update `handle_new_session()` to use `RelayBackend`:

```rust
async fn handle_new_session(
    mut socket: TypedWebsocket<...>,
    registry: SharedRegistry,
    // ... params ...
) {
    // Connect to relay
    let backend = start_bridge_backend(relay, username, (80, 24), options, ...).await?;
    
    // Create session with RelayBackend
    let (session_number, session) = registry.create_next_session(
        user_id,
        relay_id,
        relay_name,
        username,
        Arc::new(backend),
        SessionOrigin::Web { user_id },
        ip_address,
        user_agent,
    ).await;
    
    // Attach WebSocket to session backend
    handle_websocket_attachment(socket, session, initial_minimized).await;
}
```

Add resize handling to `SshControl`:

```rust
// In handle_reattach() and handle_new_session()
if let Some(SshControl::Resize { cols, rows }) = client_msg.cmd {
    session.backend.resize(cols, rows)?;
}
```

**Purpose**: Migrate web terminal sessions to use the unified backend abstraction.

---

### 5. SSH Handler Updates

#### [MODIFY] [handler/relay.rs](../crates/server-core/src/handler/relay.rs)

Update `connect_to_relay()` to use `RelayBackend`:

```rust
pub(super) async fn connect_to_relay(...) -> Result<(), russh::Error> {
    // ... auth logic ...
    
    // Create relay backend
    let backend = start_bridge_backend(relay, username, options, ...).await?;
    
    // Register session with backend
    let (session_number, session) = self.registry.create_next_session(
        user_id,
        host.id,
        host.name,
        username,
        Arc::new(backend),
        SessionOrigin::Ssh { user_id },
        ip_address,
        None, // no user_agent for SSH
    ).await;
    
    // Bridge session backend to SSH channel
    spawn_ssh_channel_bridge(session, server_handle, client_channel, size_rx);
}
```

Add helper to bridge `SessionBackend` to SSH channel:

```rust
fn spawn_ssh_channel_bridge(
    session: Arc<SshSession>,
    server_handle: russh::server::Handle,
    client_channel: russh::ChannelId,
    mut size_rx: watch::Receiver<(u16, u16)>,
) {
    tokio::spawn(async move {
        let mut output_rx = session.backend.subscribe();
        loop {
            tokio::select! {
                // Forward backend output to SSH channel
                Ok(data) = output_rx.recv() => {
                    let mut payload = CryptoVec::new();
                    payload.extend(&data);
                    if server_handle.data(client_channel, payload).await.is_err() {
                        break;
                    }
                }
                // Forward resize events
                changed = size_rx.changed() => {
                    if changed.is_ok() {
                        let (cols, rows) = *size_rx.borrow();
                        let _ = session.backend.resize(cols as u32, rows as u32);
                    }
                }
            }
        }
    });
}
```

**Purpose**: Enable SSH-originated sessions to be attachable from web UI by using the same backend abstraction.

---

### 6. Session Attachment Mechanism

#### [NEW] [rb-web/src/app/api/sessions.rs](../crates/rb-web/src/app/api/sessions.rs) - Add attach endpoint

Add API endpoint to attach to any session (web or SSH origin):

```rust
#[server(AttachToSession)]
pub async fn attach_to_session(
    user_id: i64,
    relay_id: i64,
    session_number: u32,
) -> Result<String, ServerFnError> {
    // Verify user has access to relay
    // Return WebSocket URL params for attachment
    Ok(format!("/api/ws/ssh_connection/{}?session_number={}", relay_id, session_number))
}
```

**Purpose**: Allow web UI to attach to sessions regardless of origin.

---

### 7. Web UI Updates

#### [MODIFY] [rb-web/src/app/pages/server/sessions.rs](../crates/rb-web/src/app/pages/server/sessions.rs)

Add "Attach" button to admin session list:

```rust
rsx! {
    button {
        class: "btn btn-sm btn-primary",
        onclick: move |_| {
            // Open web terminal attached to this session
            spawn(async move {
                let url = attach_to_session(user_id, relay_id, session_number).await?;
                // Trigger session open in SessionContext
            });
        },
        "Attach"
    }
}
```

#### [MODIFY] [rb-web/src/app/session/components/global_chrome.rs](../crates/rb-web/src/app/session/components/global_chrome.rs)

Update session drawer to show origin and allow attachment:

```rust
// In session list
for session in sessions {
    rsx! {
        div {
            class: "flex items-center justify-between",
            div {
                // Session name
                "{session.relay_name} #{session.session_number}"
                // Origin badge
                match session.origin {
                    SessionOrigin::Web => rsx! { span { class: "badge badge-info", "Web" } },
                    SessionOrigin::Ssh => rsx! { span { class: "badge badge-success", "SSH" } },
                }
            }
            // Attach button if not already attached
            if !is_attached(session) {
                button {
                    class: "btn btn-xs",
                    onclick: move |_| { attach_to_session(session.clone()) },
                    "Attach"
                }
            }
        }
    }
}
```

**Purpose**: Enable users to visually distinguish session origins and attach to any session they have access to.

---

### 8. Connection/Viewer Tracking Updates

#### [MODIFY] [rb-types/src/ssh.rs](../crates/rb-types/src/ssh.rs)

Add connection type tracking:

```rust
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ConnectionInfo {
    pub connection_type: ConnectionType,
    pub is_viewer: bool, // window open vs minimized
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ConnectionType {
    Web,
    Ssh,
}

pub struct UserSessionSummary {
    // ... existing fields ...
    pub web_connections: u32,
    pub ssh_connections: u32,
}
```

Update session increment/decrement methods:

```rust
impl SshSession {
    pub fn increment_web_connection(&self) -> u32 { ... }
    pub fn increment_ssh_connection(&self) -> u32 { ... }
    pub fn decrement_web_connection(&self) -> u32 { ... }
    pub fn decrement_ssh_connection(&self) -> u32 { ... }
}
```

**Purpose**: Provide granular visibility into which types of clients are connected to each session.

---

### 9. Resize Event Implementation

#### [MODIFY] [session_backend.rs](../crates/server-core/src/sessions/session_backend.rs)

Implement resize in `RelayBackend`:

```rust
impl RelayBackend {
    fn resize(&self, cols: u32, rows: u32) -> Result<(), SessionError> {
        self.resize_tx.send((cols, rows))
            .map_err(|_| SessionError::BackendClosed)?;
        Ok(())
    }
}
```

Update relay channel loop to handle resize:

```rust
// In relay/connection.rs bridge task
tokio::select! {
    // ... existing branches ...
    
    Some((cols, rows)) = resize_rx.recv() => {
        if rchan.window_change(cols, rows, 0, 0).await.is_err() {
            break;
        }
    }
}
```

#### [MODIFY] [rb-web/public/xterm-init.js](../crates/rb-web/public/xterm-init.js)

Send resize events to Rust:

```javascript
window.initRustyBridgeTerminal = function(termId, sendResizeCallback) {
    const term = terminals.get(termId);
    const fitAddon = fitAddons.get(termId);
    
    const resizeObserver = new ResizeObserver(() => {
        if (fitAddon && !isHidden(container)) {
            fitAddon.fit();
            const { cols, rows } = term;
            sendResizeCallback(cols, rows); // Call Rust callback
        }
    });
    
    resizeObserver.observe(container);
};
```

#### [MODIFY] [rb-web/src/app/components/terminal.rs](../crates/rb-web/src/app/components/terminal.rs)

Wire up resize callback:

```rust
let send_resize = move |cols: u32, rows: u32| {
    let socket = ws.clone();
    spawn(async move {
        let msg = SshClientMsg {
            cmd: Some(SshControl::Resize { cols, rows }),
            data: vec![],
        };
        let _ = socket.send(msg).await;
    });
};

eval(&format!(
    "window.initRustyBridgeTerminal('{}', (cols, rows) => {{ /* call send_resize */ }})",
    term_id
));
```

**Purpose**: Enable proper PTY resizing for both web and SSH clients.

---

## User Review Required

> [!IMPORTANT]
> This is a significant architectural refactoring that touches core session management.
> 
> **Key Decisions**:
> 1. **Trait-based abstraction**: Using `SessionBackend` trait allows clean separation but adds indirection
> 2. **Backward compatibility**: Keeping existing `start_bridge()` ensures SSH direct clients continue working
> 3. **Connection tracking**: Separating web/SSH connection counts provides better visibility but increases complexity
> 
> **Breaking Changes**: None expected for end users, but internal APIs change significantly

> [!WARNING]
> **Resize callback in JavaScript**: The JavaScript->Rust resize callback is non-trivial to implement in Dioxus. May need to use global callback registry or eval-based workaround.

---

## Verification Plan

### Automated Tests

#### 1. Session Backend Trait Tests
**Location**: `crates/server-core/src/sessions/session_backend.test.rs` (new file)

```bash
cargo test -p server-core session_backend
```

**What to test**:
- RelayBackend implements all SessionBackend methods
- Data flows correctly through broadcast channels
- Resize events are properly forwarded
- Close signals propagate to all subscribers

#### 2. Session Registry Tests
**Location**: Update `crates/server-core/src/sessions.test.rs`

```bash
cargo test -p server-core sessions::tests
```

**What to test**:
- Sessions can be created with different origins (Web/SSH)
- Sessions can be attached to multiple times
- Connection tracking works for web vs SSH
- Session cleanup works regardless of origin

#### 3. Relay Connection Tests
**Location**: `crates/server-core/src/relay/connection.test.rs` (new file)

```bash
cargo test -p server-core relay::connection
```

**What to test**:
- `start_bridge_backend()` returns functional backend
- Legacy `start_bridge()` still works
- Resize events propagate through backend

### Manual Verification

#### 1. Web Terminal Session Creation
1. Start server: `cargo run --bin rb-server`
2. Open web UI: `http://localhost:8080`
3. Open web terminal to a relay
4. Verify session appears in admin panel with "Web" origin badge
5. Resize browser window, verify terminal resizes correctly
6. Check server logs for resize events

#### 2. SSH Client Session Creation
1. SSH to bridge: `ssh username@localhost -p 2222`
2. Select relay from TUI
3. Verify session appears in admin panel with "SSH" origin badge
4. Resize terminal window, verify session resizes correctly

#### 3. Cross-Origin Attachment
1. Create SSH session (step 2 above)
2. Open web UI admin panel
3. Click "Attach" button on SSH-originated session
4. Verify web terminal opens and shows same session output
5. Type in web terminal, verify it appears in SSH client
6. Type in SSH client, verify it appears in web terminal
7. Close web terminal, verify SSH client continues working
8. Reattach from web, verify history replay works

#### 4. Connection Tracking
1. Open same session from 2 web browsers
2. Open same session from 1 SSH client
3. Check admin panel shows:
   - `web_connections: 2`
   - `ssh_connections: 1`
   - `active_connections: 3`
4. Minimize one web browser's terminal
5. Verify `active_viewers` decrements

#### 5. Session Lifecycle
1. Create web session
2. Attach from SSH
3. Close web session explicitly
4. Verify SSH session continues (no auto-close)
5. Disconnect SSH (Ctrl+D or exit)
6. Verify session enters Detached state
7. Wait 120 seconds
8. Verify session is cleaned up

### Compilation Verification

```bash
# Server-side code
cargo check -p server-core
cargo check -p rb-web --features server

# Web client code  
cargo check -p rb-web --features web --no-default-features --target wasm32-unknown-unknown

# Full build
cargo build --workspace
```
