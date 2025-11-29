# Web Shell Detach/Reattach Plan

## Goal
Enable SSH sessions to survive browser window refreshes and network interruptions by decoupling the SSH session lifetime from the WebSocket connection.

## Core Concepts

### 1. Session Registry
A central, thread-safe registry to manage active SSH sessions.
- **Location**: `crates/server-core/src/sessions.rs` (new module)
- **Structure**: `Arc<RwLock<HashMap<SessionId, Arc<SshSession>>>>`
- **SessionId**: UUID v4

### 2. SshSession Struct
Holds the state of a single SSH connection.
```rust
pub struct SshSession {
    pub id: SessionId,
    pub user_id: UserId,
    pub relay_id: RelayId,
    pub created_at: DateTime<Utc>,
    pub last_active_at: RwLock<DateTime<Utc>>,
    pub state: RwLock<SessionState>,
    // Channels to communicate with the SSH loop
    pub input_tx: mpsc::Sender<Vec<u8>>,
    // Broadcast channel to allow multiple listeners (reattach)
    pub output_tx: broadcast::Sender<Vec<u8>>,
    // The actual SSH channel handle (to close it eventually)
    pub ssh_channel: Mutex<Option<russh::client::Channel<SomeHandler>>>,
}

pub enum SessionState {
    Attached,
    Detached { detached_at: DateTime<Utc>, timeout: Duration },
    Closed,
}
```

### 3. Lifecycle

#### Creation
- User initiates connection via `ssh_terminal_ws`.
- Server creates a new `SshSession`, generates a `SessionId`.
- Server spawns the SSH loop (connects to relay).
- Session is added to `SessionRegistry`.
- WebSocket is attached to the session's input/output channels.

#### Detachment (Implicit - e.g., Refresh)
- WebSocket connection drops.
- Server detects WS close.
- Instead of closing SSH channel, session state transitions to `Detached`.
- `detached_at` is set to now.
- `timeout` is set to a default "short" TTL (e.g., 2 minutes) for refreshes.

#### Detachment (Explicit - Future)
- User clicks "Detach".
- Client sends "Detach" command.
- Server sets state to `Detached` with a longer TTL (e.g., 24 hours).
- WebSocket closes.

#### Reattachment
- User reloads page.
- Client sends `SessionId` (stored in `localStorage`) during WS handshake or as first message.
- Server looks up `SessionId` in `SessionRegistry`.
- **Security Check**: Server verifies that the `user_id` of the authenticated user matches the `user_id` of the `SshSession`.
    - If mismatch: Return "Unauthorized" and close.
- If found, active, and authorized:
    - Re-subscribes WS to `output_tx` (broadcast).
    - Updates state to `Attached`.
    - Replays recent history? (Optional: `output_tx` could be a `broadcast` channel with capacity to hold some history, or we maintain a separate circular buffer).
- If not found or expired:
    - Return error/close WS.

### 4. Multi-Session & Sharing
- **Multiple Viewers**: The `output_tx` is a `tokio::sync::broadcast::Sender`. This naturally supports multiple WebSocket connections (tabs/windows) subscribing to the same SSH session output.
- **Shared Input**: All attached WebSockets share the same `input_tx`. Input from any client is forwarded to the SSH channel.
- **Listing Sessions**: A new API endpoint `GET /api/ssh/sessions` will allow the client to list all active sessions for the current user, enabling a "Session Manager" UI in the future.

### 5. Security Considerations
- **Ownership Verification**: Reattachment MUST verify that `session.user_id == current_user.id`.
- **Session ID Entropy**: Use UUID v4 for `SessionId` to prevent guessing.
- **Transport Security**: All traffic over WSS (TLS).
- **Replay Attacks**: The `SessionId` is a handle to a live state, not a command replay. Reconnecting simply joins the live stream. Standard Web/Auth protections apply to the WebSocket upgrade request.

#### Cleanup
- Background task runs periodically (e.g., every minute).
- Checks `SessionRegistry` for `Detached` sessions where `detached_at + timeout < now`.
- Closes SSH channel.
- Removes from registry.

## Implementation Steps

### Phase 1: Core Infrastructure
1.  **Create `server-core/src/sessions.rs`**:
    - Define `SshSession`, `SessionState`, `SessionRegistry`.
    - Implement `SessionRegistry` methods: `create`, `get`, `remove`, `cleanup`.
2.  **Update `rb-web` State**:
    - Add `SessionRegistry` to `AppState` (or `Extension`).

### Phase 2: Refactor `ssh_websocket.rs`
1.  **Modify `ssh_terminal_ws`**:
    - Accept optional `session_id` query param.
    - If `session_id` provided, try to reattach.
    - If not, create new session.
2.  **Decouple SSH Loop**:
    - Move the SSH connection logic out of `handle_typed_socket` into a standalone task spawned by `SessionRegistry::create`.
    - `handle_typed_socket` becomes a bridge between WS and `SshSession` channels.
3.  **Handle Disconnects**:
    - When WS drops, notify `SshSession`.
    - `SshSession` decides whether to close SSH (if explicitly closed) or detach (if dropped).

### Phase 3: Client-Side (Dioxus)
1.  **Store Session ID**:
    - When session starts, server sends `SessionId`.
    - Client stores `SessionId` in `localStorage` (or `SessionProvider` state).
2.  **Reconnection Logic**:
    - On mount, check for existing `SessionId`.
    - If exists, try to connect with it.
    - Handle "Session Not Found" (clear ID, start new).

## Technical Details

### Output Buffering
To ensure the user sees what happened while they were gone (or at least the last screen), we need a buffer.
- **Option A**: `tokio::sync::broadcast` with a capacity. It keeps the last N messages.
- **Option B**: Explicit `RingBuffer` in `SshSession`.
- **Decision**: Start with `broadcast` channel with reasonable capacity (e.g., 100 messages or 64KB). For full scrollback, we'd need a more complex solution, but for "surviving refresh", a small buffer is usually enough to redraw the screen (especially if we trigger a redraw). *Actually, xterm.js might need a full redraw or we rely on the fact that we just reattach. If the shell sent data while detached, we need that data.*

### Thread Safety
- `SessionRegistry` needs `RwLock` for the map.
- `SshSession` needs internal locks for state updates.
- SSH Channel is `Send + Sync` usually, but we need to be careful about who owns it.

### Timeouts
- `REFRESH_TIMEOUT`: 2 minutes.
- `DETACH_TIMEOUT`: Configurable (future).

## Modules
- `crates/server-core/src/sessions.rs`: The registry and session logic.
- `crates/rb-web/src/app/api/ssh_websocket.rs`: The API endpoint and WS handling.
