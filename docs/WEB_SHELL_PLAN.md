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

### ✅ PHASE 1 COMPLETE (Baseline Functionality)
1) [x] Create `app/session/` module:
   - [x] Types + context provider + hooks (`types.rs`, `provider.rs`)
   - [x] Session model with ID, status, geometry, timestamps
   - [x] 4-session cap enforcement (client-side)
   - [ ] **REMAINING**: LocalStorage helpers for geometry/dock state persistence
   
2) [x] Update `app_root.rs` to wrap `Router` with `SessionProvider` and render global overlays
   - [x] `SessionGlobalChrome` wraps Router and renders session windows
   - [x] Left drawer: Open sessions list with restore/focus actions
   - [x] Right drawer: Relay selection list
   - [x] Session dock: Quick access chips on left sidebar
   
3) [x] Build components (`app/session/components/`):
   - [x] `global_chrome.rs` - Main UI chrome with dual drawers, tabs, and mouse handlers
   - [x] `session_dock.rs` - Session chips with status indicators (minimized sessions)
   - [x] `session_window.rs` - Floating, draggable windows with header controls
   
4) [x] Enhance `Terminal` component and WebSocket integration:
   - [x] Migrated to Dioxus typed WebSocket (`SshClientMsg` / `SshServerMsg`)
   - [x] Added `on_close` callback prop for session cleanup
   - [x] Fix input capture race condition with retry loop
   - [x] Add explicit focus handling via `window.focusTerminal()`
   - [x] **CRITICAL FIX**: Spawn receiving loop in parallel with input setup loop to prevent blocking output
   - [x] Proper EOF handling with `eof: bool` flag in server messages
   
5) [x] Fix Window Management:
   - [x] Implement drag logic in `SessionProvider` (start_drag, update_drag, end_drag)
   - [x] Mouse handlers in `SessionGlobalChrome` for global drag/drop
   - [x] Z-index management via `last_focused_at` timestamps
   - [x] Fullscreen/windowed modes with proper fixed positioning
   - [x] Minimize/restore with visibility toggle (component stays mounted)
   
6) [x] JavaScript Bridge Updates (`xterm-init.js`):
   - [x] `window.writeToTerminal()` - Write data from Rust to xterm
   - [x] `window.setupTerminalInput()` - Setup input callback to Rust
   - [x] `window.focusTerminal()` - Explicit focus trigger
   - [x] `window.fitTerminal()` - Trigger fit addon
   - [x] ResizeObserver with visibility checks
   - [x] Removed legacy `attachWebSocketToTerminal()` (now handled in Rust)

### 🚧 PHASE 2 IN PROGRESS (Polish & Complete MVP)
7) [ ] **NEXT PRIORITY**: Detached Session management and LocalStorage Integration for sizes/locations of sessions
   - [ ] Admin panel that can show all sessions and all users and their current ssh session relays, right now i think we're only registering the web-shell sessions, but eventually we should also show ssh->relay->ssh sessions as well. Maybe we should also have this with ip info for the sessions, and other connection details. 
   - [ ] Profile page for our user should also show all their own active sessions. 
   - [ ] Need to support handling multi-session connected to the same ssh relay
   - [ ] Support for detaching sessions reattaching our webui.
   - [ ] Save/load window geometry per session (x, y, width, height) on local storage to handle if we refresh the page things end up where they were, also if they were in drawer or not.
   - [ ] Save/load dock collapsed state on local storage to handle if we refresh the page things end up where they were.
   - [ ] Security: Only store non-sensitive UI state, like geometry, dock state, and the id from the relay session as this is only needed for refresh reattach locations, and we should have this clear itself if the sessions aren't in our session registry.

8) [ ] **NEXT PRIORITY**: Session Sync for Registry improvements.
   - [ ] Transition from polling /api/ssh/sessions to a websocket or sse or something push based? so that we can handle sessione events, like if 1 connection of the user opens a new relay connection, the other connections should get that relay as well joined, and maybe minimized by default, but with a toast. 
   - [ ] do we have this as it's own ws endpoint, or should we finally spin up a server-client messaging endpoint to handle more than just ssh events, like server connection monitoring, server version change notices, and other things that we might want to handle with events from server->webui, we also would like to be able to track and see how many webui or ssh sessions a user has active at any time so that can be reported in their profile page, and in the admin session panels.

9) [ ] Handle missing resize and other shell events, like maybe adding click events so we can use TUI's remotely that accept the ssh mouse events? and others? we may want to handle. (see `SshClientMsg` and `SshServerMsg` for what we need to handle and maybe additionals we need to add for best practices).

10) [ ] Thumbnail Minimizing actions add JS helper to extract xterm canvas to data URL on minimize; store in session. (this will be based on our wip_genie_effect, but needs testing and modularization to make it easier to reuse, but we need to plan clean it up and improve first, check with designer.)

11) [ ] AUDITING: 
   - [ ] Right now we're only storing the recordings for sessions to replay them on reconnect, but all ssh sessions that are relayed should be actively stored so they can be replayed and reviewed but admins and users (with proper claims). 
   - [ ] Session connections should also record metadata for the connections, time, ip, duration, reconnect events, how the relay was initiated (ssh, web, etc), and any other metadata that we might want to record.

12) [ ] FUTURE CHANGES AND IMPROVEMENTS: 
   - [ ] **Support shell window resizing** with handles at edges, saved to local storage or something temporary for the specific session window temporarily for restoring from dock etc.
   - [ ] **New Shell Offsets**: Shells with no saved preferred location thats already in use.
   - [ ] **Toast notifications**: Show toast when session cap (4) is reached
   - [ ] **Disconnection handling**: show when we've lost connection to server, or when we lose our ssh/websocket connection and properly handle this if server tells us we lost a session after a reconnection.
   - [ ] **Error handling**: Toast for connection failures, authentication errors
   - [ ] **Focus behavior**: Tab order for keyboard navigation, Escape to minimize
   - [ ] **Default window geometry**: Cascade windows (offset by 30px x/y), center first window
   - [ ] **Bounds checking**: Prevent windows from being dragged off-screen
   - [ ] **Empty states**: ✅ Already done for drawers
   - [ ] **Session Counts**: Show counts as a small yellow banner at the top of the xterm window when more than 1 session is connected to the same relay by that user that says something like "x sessions connected to this relay session" or something like that.
   - [ ] **Session Sharing**: Add the ability to share a session with a onetime link that can be used to join a session, maybe with a password, and also read/type access or watch only access, ability to revoke and disconnect the user. 
   - [ ] **Settings for Session Restoration**: Server config and UX/UI for setting if sessions should be restored by user or by session, right now we use relay:user:# but we should allow for the server to override that and make it so its relay:user:#:sessionid so that users can either have the same sessions restored across all their browsers and computers, or if each one gets their own set based on localstorage or sessionstorage, also selectable for flexibiltiy, server config should allow this to be selected/enabled/disabled, but if multiple options are allowed, maybe each user in their profile (and edit for that user in access page) can have an override at the user level.

#### 🔧 REMAINING ISSUES
- **Bounds**: Windows can be dragged off-screen
- **LocalStorage**: Window geometry not persisted across page refreshes

## Risks & mitigations
- Drag/resize jank: throttle pointer events; store only on mouseup.

## Config knobs (initial)
- `MAX_SESSIONS_CLIENT` = 4 (const, provider-level), this should be moved to a config that can be edited at the server admin panel level that doesn't exist yet.