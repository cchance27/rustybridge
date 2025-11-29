# AUTO_LOAD: Web Shell Auto-Restore Plan

## Goals

- Automatically (re)open SSH web-shell windows for all active user sessions when a browser connects or reloads.
- Sessions are keyed by `(user_id, relay_id, session_number)` rather than by browser-specific IDs.
- Support multiple browsers/devices attaching to the same SSH session concurrently.
- Distinguish between:
  - **Explicit closes** (user clicks X, or SSH exits/EOF) → session is cleaned up and **not** restored.
  - **Non-explicit disconnects** (browser refresh, tab closed, network drop) → session is detached but can be restored.

## Existing Building Blocks

- `server-core/src/sessions.rs`
  - `SessionRegistry` with `create_next_session`, `get_session`, `remove_session`, `list_sessions_for_user`, `cleanup_expired_sessions`.
  - `SshSession` with:
    - `session_number: u32`
    - `user_id: i64`, `relay_id: i64`
    - `state: SessionState::{Attached, Detached { detached_at, timeout }, Closed}`
    - `active_connections` counter + broadcast channels for multi-attach.
- `rb-web/src/app/api/ssh_websocket.rs`
  - `ssh_terminal_ws(relay_name, WebSocketOptions)` always creating a new session.
  - `handle_new_session` which creates the `SshSession`, spawns the SSH loop, and then calls `handle_reattach`.
  - `handle_reattach` that manages the WebSocket loop, increments/decrements `active_connections`, and sets `explicit_close` vs timeout-based detach.
- `rb-web` frontend
  - `SessionContext` / `Session` for window management.
  - `Terminal` Dioxus component handling the WebSocket bridge and xterm.js.

---

## Live session updates via WebSocket

To avoid polling and make session lists & attachment counts real-time:

- Add a dedicated WebSocket endpoint, e.g. `GET /api/ssh/sessions/ws`.
- It would send a stream of events for the current user:

  - `SessionAdded { relay_id, session_number, state, active_connections }`
  - `SessionUpdated { relay_id, session_number, state, active_connections }`
  - `SessionRemoved { relay_id, session_number }`

- The client would:
  - Maintain its `SessionContext` / session drawer based on these events.
  - Optionally auto-open/close windows as sessions are added/removed.

Server-side implementation ideas:

- Maintain a broadcast channel of session events in `SessionRegistry`.
- Whenever `create_next_session`, `attach`, `detach`, `close`, or `cleanup_expired_sessions` occur, send an event.
- The sessions WS endpoint would filter events for the current user and forward them.

Phase 2 is an optimization and UX improvement; Phase 1 (HTTP + auto-load on startup) is sufficient to validate the core behavior.
