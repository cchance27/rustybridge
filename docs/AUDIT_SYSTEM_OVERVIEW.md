# RustyBridge Audit & Session Logging

## Status (December 2025)

- Core audit type system, persistence, and logging API are implemented and wired through server-core.
- Web, SSH/TUI, and CLI now emit strongly-typed events for user/group/relay/credential/ACL/session activity.
- **Audit Web UI**: Admin console for browsing/filtering events and a visual "Relay Session Timeline" for inspecting session lifecycle and connections.
- All state-changing operations in the management surfaces are moving to a **context-first** API that enforces attribution.
- **Hardening Complete**: The `server-core` crate uses a unified `audit!` macro for consistent logging. Write paths have been audited to ensure no sensitive operations bypass audit logging.
- **Retention & Cleanup**: Configurable cascading retention policies with background cleanup task and admin UI for managing session data and orphan events.

---

## Architecture

### High-Level Flow

```text
Web / CLI / SSH/TUI
  │
  │  (construct AuditContext at boundary)
  ▼
server-core business logic
  • functions take `&AuditContext`
  • log via `audit!(ctx, Event { ... })`
  ▼
state-store audit layer
  • `insert_audit_event` / `query_audit_events`
  ▼
SQLite `audit.db`
  • `system_events` table (typed events as JSON)
  • indexed for actor/category/session/time
```

### Key Modules

- `crates/rb-types/src/audit/`
  - `AuditContext` – web/ssh/server_cli/system attribution.
  - `EventCategory` – Authentication, UserManagement, GroupManagement, RoleManagement, RelayManagement, CredentialManagement, AccessControl, Session, Configuration, System.
  - `EventType` – strongly-typed union for all audit events (users, groups, relays, credentials, ACL, sessions, system).
  - `AuditEvent` – persisted event record (UUIDv7 id, timestamp ms, actor_id, category, event_type, resource_id, ip_address, session_id).
  - `EventFilter` – query filter struct (actor, category, time range, session, resource, limit/offset).

- `crates/state-store/src/audit/`
  - `connections.rs` – existing SSH/Web connection metadata.
  - `events.rs` – `insert_audit_event`, `query_audit_events`, `count_audit_events`.
  - `mod.rs` – migrator for audit DB, exposes `audit_db()` handle.

- `crates/server-core/src/audit/`
  - `logger.rs` – `log_event`, `log_event_simple_*`, `log_event_with_context_*`, `log_event_from_context_*`.
  - `query.rs` – helpers to query/filter events from server-core.
- `crates/server-core/src/macros.rs`:
    - `audit!` – Primary macro for logging events with context.

---

## AuditContext: How Attribution Works

```rust
use rb_types::audit::AuditContext;

// Web (rb-web)
let ctx = AuditContext::web(user_id, username, ip, session_id);

// SSH/TUI (server-core handler)
let ctx = AuditContext::ssh(user_id, username, ip, connection_id);

// Local CLI (rb-server)
let hostname = whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string());
let ctx = AuditContext::server_cli(None, hostname);

// System-initiated jobs
let ctx = AuditContext::system("database_migration");
```

Every business function that changes state now prefers a signature like:

```rust
pub async fn add_user(ctx: &AuditContext, username: &str, password: &str) -> ServerResult<()>;
```

and uses the `audit!` macro to record the corresponding `EventType`.

---

## Events Currently Emitted

### Authentication

Emitted from `server-core/src/handler/auth.rs`:

- `LoginSuccess { method: Password|PublicKey|Oidc, connection_id, username }`
- `LoginFailure { method, reason, username }`

### User Management

Emitted from `server-core/src/user.rs` and `server-core/src/api.rs`:

- `UserCreated { username }`
- `UserDeleted { username, user_id }`
- `UserPasswordChanged { username, user_id }`
- `UserSshKeyAdded { username, user_id, key_id, fingerprint }`
- `UserSshKeyRemoved { username, user_id, key_id }`
- `UserClaimAdded { username, user_id, claim }`
- `UserClaimRemoved { username, user_id, claim }`
- `OidcLinked { username, user_id, provider, subject }`
- `OidcUnlinked { username, user_id, provider }`

### Group Management

Emitted from `server-core/src/group.rs`:

- `GroupCreated { name }`
- `GroupDeleted { name, group_id }`
- `UserAddedToGroup { username, user_id, group_name, group_id }`
- `UserRemovedFromGroup { username, user_id, group_name, group_id }`
- `GroupClaimAdded { group_name, group_id, claim }`
- `GroupClaimRemoved { group_name, group_id, claim }`

### Role Management (RBAC)

Emitted from `server-core/src/api.rs`:

- `RoleCreated { name, description }`
- `RoleDeleted { name, role_id }`
- `RoleAssignedToUser { role_name, role_id, username, user_id }`
- `RoleRevokedFromUser { role_name, role_id, username, user_id }`
- `RoleAssignedToGroup { role_name, role_id, group_name, group_id }`
- `RoleRevokedFromGroup { role_name, role_id, group_name, group_id }`
- `RoleClaimAdded { role_name, role_id, claim }`
- `RoleClaimRemoved { role_name, role_id, claim }`

### Relay Hosts

Emitted from `server-core/src/relay_host/management.rs` and `relay_host/options.rs`:

- `RelayHostCreated { name, endpoint }`
- `RelayHostDeleted { name, relay_id, endpoint }`
- `RelayHostUpdated { relay_id, old_name, new_name, old_endpoint, new_endpoint }`
- `RelayHostKeyCaptured { name, relay_id, key_type, fingerprint }`
- `RelayHostKeyRefreshed { name, relay_id }`
- `RelayOptionSet { relay_name, relay_id, key, is_secure }`
- `RelayOptionCleared { relay_name, relay_id, key }`

Hostkey capture/refresh events are emitted from both the SSH/TUI path and the web hostkey review/store path.

### Credentials

Emitted from `server-core/src/credential.rs`:

- `CredentialCreated { name, kind }`
- `CredentialUpdated { name, cred_id, kind }`
- `CredentialDeleted { name, cred_id, kind }`
- `CredentialAssigned { cred_name, cred_id, relay_name, relay_id }`
- `CredentialUnassigned { relay_name, relay_id }`
- `SecretRotated { resource_type, resource_id }`

### Access Control (ACL)

Emitted from `server-core/src/relay_host/access.rs`:

- `AccessGranted { relay_name, relay_id, principal_kind, principal_name, principal_id }`
- `AccessRevoked { relay_name, relay_id, principal_kind, principal_name, principal_id }`

### Sessions & Relays

#### SSH/TUI (server-core)

From `server-core/src/handler/session.rs` and relay bridge:

- `SessionStarted { session_id, relay_name, relay_id, username }`
- `SessionEnded { session_id, relay_name, relay_id, username, duration_ms }`
- `SessionResized { session_id, relay_id, cols, rows }`
- `SessionRelayConnected { session_id, relay_id, relay_name, username }`
- `SessionRelayDisconnected { session_id, relay_id, relay_name, username }`

#### Web SSH (rb-web WS /api/ws/ssh_connection)

From `crates/rb-web/src/app/api/ws/ssh.rs`:

- On new web session:
  - `SessionStarted { session_id, relay_name, relay_id, username }`
  - `SessionRelayConnected { session_id, relay_id, relay_name, username }`
- On attach/reattach via WebSocket:
  - `SessionRelayConnected { session_id, relay_id, relay_name, username }`
- On resize:
  - `SessionResized { session_id, relay_id, cols, rows }`
- On disconnect:
  - `SessionRelayDisconnected { session_id, relay_id, relay_name, username }`
  - `SessionEnded { session_id, relay_name, relay_id, username, duration_ms }`
- Admin viewer tracking:
  - `AdminViewerAdded { session_id, admin_username, admin_user_id }`
  - `AdminViewerRemoved { session_id, admin_username, admin_user_id }`

### Configuration & System

Types exist for:

- `ServerHostKeyGenerated`
- `OidcConfigured { issuer }`
- `ServerStarted { version }`
- `ServerStopped`
- `DatabaseMigrated { database, version }`

Some are wired (e.g., migrations); others can be hooked into startup/shutdown flows as desired.

---

## Where Context Is Enforced

### Web (rb-web)

- `crates/rb-web/src/server/audit.rs` defines `WebAuditContext` – an Axum extractor that:
  - Pulls the authenticated `WebAuthSession`.
  - Extracts client IP from `ConnectInfo<SocketAddr>`.
  - Uses the session store ID as `session_id`.
  - Builds an `AuditContext::Web` that is passed into server-core.

- Management endpoints (`crates/rb-web/src/app/api/*.rs`) now:
  - Require both `auth: WebAuthSession` and `audit: WebAuditContext` for mutating operations.
  - Call server-core functions with `&audit.0` so every change is audit-enforced.

### SSH/TUI (server-core)

- `ServerHandler` maintains:
  - `user_id`, `username`, `peer_addr`, `connection_session_id`.
  - `ssh_audit_context()` builds an `AuditContext::Ssh` as needed.
- TUI management actions (`handle_management_action`) and relay host key flows use this context for all audit events.

### CLI (rb-cli rb-server)

- `crates/rb-cli/src/bin/rb-server.rs`:
  - Creates a single `AuditContext::server_cli(None, hostname)` per process.
  - Passes `&ctx` into all management operations (users, groups, relays, credentials, ACL, relay options).

---

## Audit UI & Visualization

### Audit Events Explorer (`/admin/audit`)
- **Virtualized list** of all audit events.
- **Filter by Category**: Authentication, User Management, Sessions, etc.
- **Group by Actor/Session**: "Drill-down" view to see all events initiated by a specific user or occurring within a specific session.
- **JSON Inspection**: View full raw event data (e.g., `client_type`, `user_agent`, custom details).

### Relay Session Timeline
- **Visual multi-track timeline** for every session.
- **Tracks**:
    - **Session Lifecycle**: Start/End duration.
    - **Relay Connections**: Visualization of when the different "legs" of the session were active (Web vs SSH).
    - **Admin Viewers**: Bars showing when admins shadowed the session, with duration and client type.
    - **Events**: Point markers for events like `Resize`, `Clipboard`, or `Input` (future).
- **Auto-refresh**: Live updating for active sessions.

---

## Retention & Cleanup

The audit system includes configurable retention policies with **cascading cleanup** to maintain referential integrity across tables.

### Retention Policies

Two policy groups are configurable via the Server Settings admin UI:

1. **Session Data Policy** - Controls all session-related data:
   - `relay_sessions` (session metadata)
   - `session_chunks` (terminal recordings)
   - `relay_session_participants` (viewer tracking)
   - `client_sessions` (SSH/Web connections)
   - `system_events` linked to sessions

2. **Orphan Events Policy** - Controls system events not tied to any session:
   - Server startup/shutdown
   - User/group/role management events
   - Configuration changes

Each policy supports:
- **Max Age (days)**: Delete data older than N days
- **Max Size (KB)**: Iteratively delete oldest data until under size limit
- **Enabled toggle**: Enable/disable automatic cleanup

### Cascading Cleanup Logic

When a `relay_session` is deleted, all related data is cleaned up in the correct order to maintain referential integrity:

1. **Find related client_sessions** (initiator + all participants)
2. **Delete system_events** tied to those client sessions or the relay session
3. **Delete relay_session** (chunks and participants cascade via FK)
4. **Delete orphaned client_sessions** (only if not referenced by other relay_sessions)

This ensures no foreign key violations and no orphaned records.

### Size-Based Cleanup

When `max_size_kb` is exceeded:
1. Get total size of session data (or orphan events)
2. If over limit, delete the **oldest** relay_session (cascading)
3. Re-check size, repeat until under limit
4. Uses `tokio::task::yield_now()` to prevent blocking

### Background Cleanup Task

A periodic background task runs retention cleanup automatically:
- Interval configurable via `cleanup_interval_secs` (default: 1 hour)
- Runs at server startup for immediate cleanup
- Logs `AuditRetentionRun` events with detailed stats

### Admin UI (Server Settings)

The `/admin/settings` page provides:
- **Policy Configuration**: Enable/disable, max age, max size for each policy group
- **Database Stats**: Size breakdown per table with row counts
  - Recordings (chunks), Sessions, Connections, Participants, Session Events, Orphan Events
- **Manual Cleanup**: "Run Cleanup Now" button with toast notification showing detailed results
- **Real-time feedback**: Save button appears immediately as values change

### Audit Events

- `AuditRetentionRun` - Logged after each cleanup with:
  - `sessions_deleted`, `client_sessions_deleted`, `session_events_deleted`, `orphan_events_deleted`
  - `duration_ms`, `is_automated` (background vs manual)


---

## How to Extend

1. Add a new variant to `EventType` in `rb-types/src/audit/event.rs`.
2. Map it to an `EventCategory` and an `action_type()` string.
3. Log it from server-core using `crate::audit!(ctx, UserCreated { username });`.
4. (Optional) Add filtering support in any UIs that should expose it.

This keeps all audit logic centralized, type-safe, and easy to evolve as the platform grows.


## Future Improvements

### Export Feature (TODO)
- Optional export path (JSON/CSV) for external SIEM ingestion
- Reusable across all audit tables
- Export based on current filters/grouping from history view
- Non-blocking implementation to avoid performance impact

### Refactoring Considerations
- **Event Type Verbosity**: The `EventType` enum is currently very verbose. While this provides excellent type safety and clarity, consider refactoring into a more modular structure or using macros/codegen as the system grows.
- **Session ID Migration**: Some places still use `session_number` (u32). This should be migrated to `session_id` (UUIDv7) strictly to prevent session enumeration.
