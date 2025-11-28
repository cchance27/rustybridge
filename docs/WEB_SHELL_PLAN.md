# Web SSH Shells Plan (rb-web)

## Goal
Provide persistent, user-friendly SSH terminals in the web UI that survive page navigation (but not full refresh), with minimized sessions docked for quick restore, a hard client-side session cap, and a clear path to future reattachable sessions and server-enforced limits.

## Decisions (locked in)
- Persistence model: non-reattachable for now; sessions die on full page refresh. Documented as a limitation.
- Session cap: 4 concurrent SSH sessions, enforced client-side only (for now).
- Mini preview: Strategy A (static snapshot captured on minimize). Keep a toggle/flag to allow Strategy B (periodic refresh) later.
- Geometry persistence: store window position/size and dock-collapsed state in `localStorage` (no secrets).
- Tech: tailwind + daisyUI, pure CSS/JS for drag/resize.
- No frontend logging requirements yet; backend will handle auditing later.

## Current pain
- `Terminal` lives only in `DashboardPage`; unmounting on route change closes the SSH WebSocket.
- `RelayDrawer` scoped to dashboard; no global shell chrome.
- No session cap or minimized dock.

## MVP scope (this phase)
1) **App Shell / Provider**
   - Add `SessionProvider` above `Router` (in `app_root.rs`) to own all SSH session state.
   - Session model: `{ id, relay, title, status, minimized, fullscreen, position, size, started_at, thumbnail_data_url }`.
   - Actions: `open(relay)`, `close(id)`, `minimize(id)`, `focus(id)`, `toggle_fullscreen(id)`, `set_geometry(id, pos, size)`, `set_status(id, Connected|Connecting|Closed|Error)`, `set_thumbnail(id, data_url)`.
   - Enforce client cap (4): deny new `open` when at cap; emit toast.
   - Listen globally for `ssh-connection-closed` events and route to `set_status/close`.

2) **Global UI Chrome (always mounted)**
   - **Connection Drawer (left):** reuse relay list; launches `open(relay)`; disabled when cap reached.
   - **Session Dock/Rail (left):** shows chips/cards for sessions (status dot + elapsed); click to focus/restore; close/minimize controls.
  - **Session Windows:** floating panels (`position: fixed; pointer-events`) with draggable header and CSS `resize`; minimize hides via CSS (do not unmount); fullscreen stretches to viewport. Persist geometry per session to `localStorage`.
   - Z-order management: focused window moves to top; track `last_focused_at`.

3) **Terminal integration**
   - `Terminal` gets stable per-session `id` and callbacks: `on_connected`, `on_closed`, `on_error`.
   - Move the JS event listener (`ssh-connection-closed`) into `SessionProvider`.
   - On minimize: capture xterm canvas → data URL → store in session `thumbnail_data_url`; render in dock chip.
   - Cleanup only on explicit close; minimize keeps component mounted.

4) **User messaging**
   - Surface toast/tooltips when cap is hit.
   - Document limitation: full page refresh drops sessions; dock only protects intra-app navigation.

## Future roadmap (documented, not in this phase)
- Reattachable sessions:
  - Server session registry with `session_id`, TTL, user, relay, russh channel handle.
  - WS reconnect handshake to rebind a session after refresh.
  - Client restores sessions on load by querying active session list.
- Server-enforced limits:
  - `server_options` entries such as `max_active_ssh_sessions` (per-user and/or global).
  - Enforce in `ssh_terminal_status` / `ssh_terminal_ws` before upgrade; mirror limits to UI for better errors.
- Richer previews: Strategy B (periodic thumbnail refresh) or live canvas streaming; opt-in.
- Animations: consider adding framer-motion (or similar) later for dock/window transitions.

## Collaborative Sessions (future enhancement)
- **Multi-User Session Sharing:**
  - Allow multiple browser tabs/windows to connect to the same SSH session simultaneously
  - Session model extended: `{ ...collaborators: Vec<UserConnection>, viewer_count: u32, is_shared: bool }`
  - Display connection count in session dock chip (e.g., "2 viewers" or "Shared with 2 others")
  - Real-time collaborator presence indicators in session window header

- **Detach/Reattach Workflow:**
  - "Detach" button creates server-side session persistence with TTL
  - Generate one-time connection code format: `{user}:{detachment_code}@{server_ip}:2222`
  - Server keeps SSH tunnel alive in detached state (configurable timeout: 1hr, 6hr, 24hr)
  - Session remains in dock with "detached" status and reattach countdown

- **SSH Shell Bridge:**
  - Special SSH endpoint on port 2222 for session reattachment
  - Accept format: `user:specialcodefromdetachrequest@ip:2222`
  - Validates detachment code against active server session registry
  - Seamless handoff from web terminal to native SSH client
  - Reverse: Allow SSH session to be reattached from web (if still active)

- **Server-Side Session Registry:**
  - Enhanced beyond basic reattachable sessions
  - Store: `session_id`, `ssh_channel_handle`, `collaborators`, `owner`, `detachment_code`, `expires_at`
  - WebSocket multiplexing: route terminal I/O to multiple clients
  - Permission system: owner can invite/kick collaborators, or make session public/private

- **UI Enhancements for Collaboration:**
  - Session header shows: `[Owner] [Collaborator1] [Collaborator2] [Invite] [Detach] [Make Private/Public]`
  - "Share Session" modal with invitation link generation
  - Permission badges: "Owner", "Collaborator", "Viewer"
  - Conflict resolution: last writer wins for terminal input, visual indicators for concurrent typing

- **Security Considerations:**
  - Detachment codes are single-use, time-limited tokens
  - Session sharing respects existing RBAC - users can only share sessions they own or have access to
  - Audit logging for session joins/leaves and detach/reattach events
  - Rate limiting on invitation generation and detachment code requests

## Non-goals (this phase)
- Persistence across full browser refresh.
- Server-side session caps or auditing.
- Multi-tab coordination.

## Implementation outline (step-by-step)
1) Create `app/session/` module:
   - Types + context provider + hooks.
   - LocalStorage helpers for geometry/dock state.
2) Update `app_root.rs` to wrap `Router` with `SessionProvider` and render global overlays (dock, connection drawer, session windows).
3) Build components:
   - `connection_drawer.rs` (wrap current `relay_drawer.rs` logic, always mounted).
   - `session_dock.rs` (chips with status, thumbnail, timers, actions).
   - `session_window.rs` (floating, draggable, resizable; header controls).
4) Enhance `Terminal` props + callbacks; relocate WS close listener into provider; ensure cleanup only on close.
5) Thumbnail capture: add JS helper to extract xterm canvas to data URL on minimize; store in session.
6) UX polish: toasts for cap hit/errors; focus behavior; default window geometry; graceful empty states.
7) Documentation: add user-facing note (dashboard/help) about non-reattachable limitation and 4-session cap.

## Risks & mitigations
- Drag/resize jank: throttle pointer events; store only on mouseup.
- Thumbnail size/memory: constrain canvas snapshot (e.g., scale to width 220px) before storing data URL.
- Z-order bugs: centralize focus handling in provider.

## Config knobs (initial)
- `MAX_SESSIONS_CLIENT` = 4 (const, provider-level).
- `THUMBNAIL_MODE` flag: `"static-on-minimize"` (default) | `"periodic"` (future).