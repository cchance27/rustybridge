pub mod session_backend;
pub mod web;

use std::{
    collections::{HashMap, VecDeque}, sync::{
        Arc, atomic::{AtomicBool, AtomicI64, AtomicU32, Ordering}
    }, time::Duration
};

use chrono::{DateTime, Utc};
use rb_types::ssh::{
    ConnectionAmounts, ConnectionType, SessionEvent, SessionKind, SessionOrigin, SessionStateSummary, TUIApplication, UserSessionSummary, WebSessionMeta
};
use session_backend::SessionBackend;
use tokio::sync::{RwLock, broadcast};

use crate::session_recorder::SessionRecorder;

#[derive(Debug, Clone)]
pub enum SessionState {
    Attached,
    Detached { detached_at: DateTime<Utc>, timeout: Duration },
    Closed,
}

impl From<&SessionState> for SessionStateSummary {
    fn from(state: &SessionState) -> Self {
        match state {
            SessionState::Attached => SessionStateSummary::Attached,
            SessionState::Detached { .. } => SessionStateSummary::Detached,
            SessionState::Closed => SessionStateSummary::Closed,
        }
    }
}

pub struct SshSession {
    pub session_number: u32,
    pub user_id: i64,
    pub relay_id: i64,
    pub relay_name: String,
    pub username: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    last_active_broadcast_ms: AtomicI64,
    last_activity_ms: AtomicI64,
    pub idle_notified: AtomicBool,
    pub state: RwLock<SessionState>,
    // Active TUI app name (if any)
    pub active_app: RwLock<Option<TUIApplication>>,
    // Scrollback history buffer (64KB)
    pub history: RwLock<VecDeque<u8>>,
    // Number of active WebSocket connections
    pub active_connections: AtomicU32,
    // Number of connections with the window OPEN (not minimized)
    pub active_viewers: AtomicU32,
    // Connection counts by type
    pub web_connections: AtomicU32,
    pub ssh_connections: AtomicU32,
    pub web_viewers: AtomicU32,
    pub ssh_viewers: AtomicU32,
    // Initial connection ID (used for SessionStarted/Ended matching)
    pub initial_connection_id: Option<String>,
    // Session origin (Web or SSH)
    pub origin: SessionOrigin,
    // Backend for I/O operations (unified interface)
    pub backend: Arc<dyn SessionBackend>,
    // Admin viewers (user IDs of admins attached via server:attach_any)
    pub admin_viewers: RwLock<std::collections::HashSet<i64>>,
    // Close signal
    pub close_tx: broadcast::Sender<()>,
    // Event channel
    pub event_tx: broadcast::Sender<SessionEvent>,
    // Session Recorder
    pub recorder: Arc<SessionRecorder>,
}

impl SshSession {
    const ACTIVE_PULSE_MS: i64 = 5_000; // keep "active now" fresh without spamming
    const IDLE_THRESHOLD_MS: i64 = 30_000; // treat as idle after 30s
    #[allow(clippy::too_many_arguments)]
    //FIXME: too many args we should probably make this a struct?
    pub fn new(
        session_number: u32,
        user_id: i64,
        relay_id: i64,
        relay_name: String,
        username: String,
        backend: Arc<dyn SessionBackend>,
        origin: SessionOrigin,
        close_tx: broadcast::Sender<()>,
        event_tx: broadcast::Sender<SessionEvent>,
        ip_address: Option<String>,
        user_agent: Option<String>,
        initial_connection_id: Option<String>,
        recorder: Arc<SessionRecorder>,
    ) -> Self {
        let now_ms = Utc::now().timestamp_millis();
        Self {
            session_number,
            user_id,
            relay_id,
            relay_name,
            username,
            ip_address,
            user_agent,
            created_at: Utc::now(),
            last_active_broadcast_ms: AtomicI64::new(now_ms),
            last_activity_ms: AtomicI64::new(now_ms),
            idle_notified: AtomicBool::new(false),
            state: RwLock::new(SessionState::Attached),
            active_app: RwLock::new(None),
            history: RwLock::new(VecDeque::with_capacity(65536)), // 64KB
            active_connections: AtomicU32::new(0),
            active_viewers: AtomicU32::new(0),
            web_connections: AtomicU32::new(0),
            ssh_connections: AtomicU32::new(0),
            web_viewers: AtomicU32::new(0),
            ssh_viewers: AtomicU32::new(0),
            initial_connection_id,
            origin,
            backend,
            admin_viewers: RwLock::new(std::collections::HashSet::new()),
            close_tx,
            event_tx,
            recorder,
        }
    }

    pub async fn to_summary(&self) -> UserSessionSummary {
        let current_state = self.state.read().await;
        let state = SessionStateSummary::from(&*current_state);
        let detached_at = if let SessionState::Detached { detached_at, .. } = *current_state {
            Some(detached_at)
        } else {
            None
        };

        let kind = if self.relay_id == 0 { SessionKind::TUI } else { SessionKind::Relay };

        UserSessionSummary {
            relay_id: self.relay_id,
            relay_name: self.relay_name.clone(),
            session_number: self.session_number,
            kind,
            ip_address: self.ip_address.clone(),
            user_agent: self.user_agent.clone(),
            state,
            active_recent: self.is_active_recent(),
            detached_at,
            detached_timeout_secs: None, // TODO: Implement timeout config
            active_app: self.active_app.read().await.clone(),
            connections: ConnectionAmounts {
                web: self.web_connections.load(Ordering::Relaxed),
                ssh: self.ssh_connections.load(Ordering::Relaxed),
            },
            viewers: ConnectionAmounts {
                web: self.web_viewers.load(Ordering::Relaxed),
                ssh: self.ssh_viewers.load(Ordering::Relaxed),
            },
            created_at: self.created_at,
            last_active_at: self.last_active_at(),
            admin_viewers: self.admin_viewers.read().await.iter().copied().collect(),
        }
    }

    pub async fn set_active_app(&self, app_name: Option<TUIApplication>) {
        let mut app = self.active_app.write().await;
        *app = app_name;
        drop(app);
        let _ = self.event_tx.send(SessionEvent::Updated(self.user_id, self.to_summary().await));
    }

    fn is_active_recent(&self) -> bool {
        let now_ms = Utc::now().timestamp_millis();
        let last_activity_ms = self.last_activity_ms.load(Ordering::Relaxed);
        now_ms.saturating_sub(last_activity_ms) < Self::IDLE_THRESHOLD_MS
    }

    fn last_active_at(&self) -> DateTime<Utc> {
        let last_activity_ms = self.last_activity_ms.load(Ordering::Relaxed);
        DateTime::from_timestamp_millis(last_activity_ms).unwrap_or_default()
    }

    pub async fn increment_connection(&self, conn_type: ConnectionType) -> u32 {
        let conn_kind = match conn_type {
            ConnectionType::Web => "web",
            ConnectionType::Ssh => "ssh",
        };
        match conn_type {
            ConnectionType::Web => {
                self.web_connections.fetch_add(1, Ordering::SeqCst);
            }
            ConnectionType::Ssh => {
                self.ssh_connections.fetch_add(1, Ordering::SeqCst);
            }
        }

        let count = self.active_connections.fetch_add(1, Ordering::SeqCst) + 1;
        tracing::debug!(
            user_id = self.user_id,
            relay_id = self.relay_id,
            session_number = self.session_number,
            conn_type = conn_kind,
            active_connections = count,
            web_connections = self.web_connections.load(Ordering::SeqCst),
            ssh_connections = self.ssh_connections.load(Ordering::SeqCst),
            "session_connection_incremented"
        );
        // Broadcast the updated connection count to all listeners
        if let Err(e) = self.event_tx.send(SessionEvent::Updated(self.user_id, self.to_summary().await)) {
            // Only warn if there are subscribers (otherwise it's expected)
            if self.event_tx.receiver_count() > 0 {
                tracing::warn!(
                    session_number = self.session_number,
                    error = ?e,
                    "Failed to broadcast connection count increment"
                );
            }
        }
        count
    }

    pub async fn decrement_connection(&self, conn_type: ConnectionType) -> u32 {
        let conn_kind = match conn_type {
            ConnectionType::Web => "web",
            ConnectionType::Ssh => "ssh",
        };
        match conn_type {
            ConnectionType::Web => {
                // Prevent underflow: only decrement if > 0
                self.web_connections
                    .fetch_update(
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                        |cur| {
                            if cur > 0 { Some(cur - 1) } else { Some(0) }
                        },
                    )
                    .ok();
            }
            ConnectionType::Ssh => {
                self.ssh_connections
                    .fetch_update(
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                        |cur| {
                            if cur > 0 { Some(cur - 1) } else { Some(0) }
                        },
                    )
                    .ok();
            }
        }

        // Prevent underflow on the total active count as well.
        let old_count = self
            .active_connections
            .fetch_update(
                Ordering::SeqCst,
                Ordering::SeqCst,
                |cur| {
                    if cur > 0 { Some(cur - 1) } else { Some(0) }
                },
            )
            .unwrap_or_else(|cur| cur); // unwrap_or_else gives us the last observed value

        let count = if old_count > 0 { old_count - 1 } else { 0 };

        tracing::debug!(
            user_id = self.user_id,
            relay_id = self.relay_id,
            session_number = self.session_number,
            conn_type = conn_kind,
            active_connections = count,
            web_connections = self.web_connections.load(Ordering::SeqCst),
            ssh_connections = self.ssh_connections.load(Ordering::SeqCst),
            "session_connection_decremented"
        );
        // Broadcast the updated connection count to all listeners
        if let Err(e) = self.event_tx.send(SessionEvent::Updated(self.user_id, self.to_summary().await)) {
            // Only warn if there are subscribers (otherwise it's expected)
            if self.event_tx.receiver_count() > 0 {
                tracing::warn!(
                    session_number = self.session_number,
                    error = ?e,
                    "Failed to broadcast connection count decrement"
                );
            }
        }
        count
    }

    pub async fn increment_viewers(&self, conn_type: ConnectionType) -> u32 {
        let count = self.active_viewers.fetch_add(1, Ordering::SeqCst) + 1;
        let conn_kind = match conn_type {
            ConnectionType::Web => "web",
            ConnectionType::Ssh => "ssh",
        };
        match conn_type {
            ConnectionType::Web => {
                let _ = self.web_viewers.fetch_add(1, Ordering::SeqCst);
            }
            ConnectionType::Ssh => {
                let _ = self.ssh_viewers.fetch_add(1, Ordering::SeqCst);
            }
        }
        tracing::debug!(
            user_id = self.user_id,
            relay_id = self.relay_id,
            session_number = self.session_number,
            conn_type = conn_kind,
            active_viewers = count,
            web_viewers = self.web_viewers.load(Ordering::SeqCst),
            ssh_viewers = self.ssh_viewers.load(Ordering::SeqCst),
            "session_viewers_incremented"
        );
        // Broadcast updates
        if let Err(e) = self.event_tx.send(SessionEvent::Updated(self.user_id, self.to_summary().await)) {
            // Only warn if there are subscribers (otherwise it's expected)
            if self.event_tx.receiver_count() > 0 {
                tracing::warn!(
                    session_number = self.session_number,
                    error = ?e,
                    "Failed to broadcast viewer count increment"
                );
            }
        }
        count
    }

    pub async fn decrement_viewers(&self, conn_type: ConnectionType) -> u32 {
        // Prevent underflow on viewer totals and per-type counts.
        let old_count = self
            .active_viewers
            .fetch_update(
                Ordering::SeqCst,
                Ordering::SeqCst,
                |cur| {
                    if cur > 0 { Some(cur - 1) } else { Some(0) }
                },
            )
            .unwrap_or_else(|cur| cur);

        let count = if old_count > 0 { old_count - 1 } else { 0 };

        let conn_kind = match conn_type {
            ConnectionType::Web => "web",
            ConnectionType::Ssh => "ssh",
        };
        match conn_type {
            ConnectionType::Web => {
                self.web_viewers
                    .fetch_update(
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                        |cur| {
                            if cur > 0 { Some(cur - 1) } else { Some(0) }
                        },
                    )
                    .ok();
            }
            ConnectionType::Ssh => {
                self.ssh_viewers
                    .fetch_update(
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                        |cur| {
                            if cur > 0 { Some(cur - 1) } else { Some(0) }
                        },
                    )
                    .ok();
            }
        }
        tracing::debug!(
            user_id = self.user_id,
            relay_id = self.relay_id,
            session_number = self.session_number,
            conn_type = conn_kind,
            active_viewers = count,
            web_viewers = self.web_viewers.load(Ordering::SeqCst),
            ssh_viewers = self.ssh_viewers.load(Ordering::SeqCst),
            "session_viewers_decremented"
        );
        // Broadcast updates
        if let Err(e) = self.event_tx.send(SessionEvent::Updated(self.user_id, self.to_summary().await)) {
            // Only warn if there are subscribers (otherwise it's expected)
            if self.event_tx.receiver_count() > 0 {
                tracing::warn!(
                    session_number = self.session_number,
                    error = ?e,
                    "Failed to broadcast viewer count decrement"
                );
            }
        }
        count
    }

    pub fn connection_count(&self) -> u32 {
        self.active_connections.load(Ordering::SeqCst)
    }

    pub fn web_connection_count(&self) -> u32 {
        self.web_connections.load(Ordering::SeqCst)
    }

    pub fn ssh_connection_count(&self) -> u32 {
        self.ssh_connections.load(Ordering::SeqCst)
    }

    pub fn web_viewer_count(&self) -> u32 {
        self.web_viewers.load(Ordering::SeqCst)
    }

    pub fn ssh_viewer_count(&self) -> u32 {
        self.ssh_viewers.load(Ordering::SeqCst)
    }

    /// Add an admin viewer to this session
    pub async fn add_admin_viewer(&self, admin_user_id: i64) {
        let mut admin_viewers = self.admin_viewers.write().await;
        admin_viewers.insert(admin_user_id);
        tracing::info!(
            session_number = self.session_number,
            admin_user_id,
            admin_count = admin_viewers.len(),
            "Admin viewer added to session"
        );
        // Broadcast session update with new admin viewer
        drop(admin_viewers); // Release lock before broadcasting
        if let Err(e) = self.event_tx.send(SessionEvent::Updated(self.user_id, self.to_summary().await))
            && self.event_tx.receiver_count() > 0
        {
            tracing::warn!(
                session_number = self.session_number,
                error = ?e,
                "Failed to broadcast admin viewer addition"
            );
        }
    }

    /// Remove an admin viewer from this session
    pub async fn remove_admin_viewer(&self, admin_user_id: i64) {
        let mut admin_viewers = self.admin_viewers.write().await;
        admin_viewers.remove(&admin_user_id);
        tracing::info!(
            session_number = self.session_number,
            admin_user_id,
            admin_count = admin_viewers.len(),
            "Admin viewer removed from session"
        );
        // Broadcast session update with removed admin viewer
        drop(admin_viewers); // Release lock before broadcasting
        if let Err(e) = self.event_tx.send(SessionEvent::Updated(self.user_id, self.to_summary().await))
            && self.event_tx.receiver_count() > 0
        {
            tracing::warn!(
                session_number = self.session_number,
                error = ?e,
                "Failed to broadcast admin viewer removal"
            );
        }
    }

    /// Get list of admin viewer user IDs
    pub async fn get_admin_viewers(&self) -> Vec<i64> {
        self.admin_viewers.read().await.iter().copied().collect()
    }

    pub async fn append_to_history(&self, data: &[u8]) {
        self.recorder.record_output(data).await;
        let mut history = self.history.write().await;
        for &byte in data {
            if history.len() >= 65536 {
                history.pop_front();
            }
            history.push_back(byte);
        }
    }

    pub async fn get_history(&self) -> Vec<u8> {
        let history = self.history.read().await;
        history.iter().copied().collect()
    }

    pub async fn touch(&self) {
        let now_ms = Utc::now().timestamp_millis();
        self.last_activity_ms.store(now_ms, Ordering::Relaxed);

        // If we were idle, broadcast once on transition to active
        let last_ms = self.last_active_broadcast_ms.load(Ordering::Relaxed);
        let idle_for = now_ms.saturating_sub(last_ms);
        if idle_for >= Self::IDLE_THRESHOLD_MS {
            self.idle_notified.store(false, Ordering::Relaxed);
            if self
                .last_active_broadcast_ms
                .compare_exchange(last_ms, now_ms, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                let _ = self.event_tx.send(SessionEvent::Updated(self.user_id, self.to_summary().await));
            }
            return;
        }

        // While active, rate-limit pulses
        let elapsed = now_ms.saturating_sub(last_ms);
        if elapsed >= Self::ACTIVE_PULSE_MS
            && self
                .last_active_broadcast_ms
                .compare_exchange(last_ms, now_ms, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            let _ = self.event_tx.send(SessionEvent::Updated(self.user_id, self.to_summary().await));
        }
    }

    pub async fn detach(&self, timeout: Duration) {
        let mut state = self.state.write().await;
        *state = SessionState::Detached {
            detached_at: Utc::now(),
            timeout,
        };
        drop(state);
        let _ = self.event_tx.send(SessionEvent::Updated(self.user_id, self.to_summary().await));
    }

    pub async fn idle_watch(self: Arc<Self>) {
        use tokio::time::{Duration as TokioDuration, sleep};
        loop {
            sleep(TokioDuration::from_millis(5_000)).await;

            if matches!(*self.state.read().await, SessionState::Closed) {
                break;
            }

            let now_ms = Utc::now().timestamp_millis();
            let last_activity = self.last_activity_ms.load(Ordering::Relaxed);
            let idle_for = now_ms.saturating_sub(last_activity);

            if idle_for >= Self::IDLE_THRESHOLD_MS && !self.idle_notified.swap(true, Ordering::Relaxed) {
                let _ = self.event_tx.send(SessionEvent::Updated(self.user_id, self.to_summary().await));
            }
        }
    }

    pub async fn attach(&self) {
        let mut state = self.state.write().await;
        *state = SessionState::Attached;
        // IMPORTANT: Drop the write lock BEFORE calling touch().
        // touch() calls to_summary() which attempts to acquire a read lock.
        // If we hold the write lock here, it causes a deadlock.
        drop(state);

        self.touch().await;
        let _ = self.event_tx.send(SessionEvent::Updated(self.user_id, self.to_summary().await));
    }

    pub async fn close(&self) {
        let mut state = self.state.write().await;
        *state = SessionState::Closed;
        let _ = self.close_tx.send(());
        drop(state);
        self.recorder.close().await;
        let _ = self.event_tx.send(SessionEvent::Updated(self.user_id, self.to_summary().await));
    }
}

// FIXME: This is a disgusting type to manage sessions, but it will do for now.
// Could definitly be made into a proper struct not random i64/u32 tuples for key, especially when we move to uuid ids.
#[derive(Clone)]
pub struct SessionRegistry {
    #[allow(clippy::type_complexity)]
    sessions: Arc<RwLock<HashMap<(i64, i64, u32), Arc<SshSession>>>>,
    web_connections: Arc<RwLock<HashMap<i64, Vec<WebSessionMeta>>>>,
    pub event_tx: broadcast::Sender<SessionEvent>,
    next_session_id: Arc<AtomicU32>,
    pub audit_db: rb_types::state::DbHandle,
}

impl SessionRegistry {
    pub fn new(audit_db: rb_types::state::DbHandle) -> Self {
        let (event_tx, _) = broadcast::channel(100);

        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            web_connections: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            next_session_id: Arc::new(AtomicU32::new(1)),
            audit_db,
        }
    }

    pub async fn register_web_session(&self, user_id: i64, meta: WebSessionMeta) {
        let mut conns = self.web_connections.write().await;
        let list = conns.entry(user_id).or_default();
        if let Some(existing) = list.iter_mut().find(|m| m.id == meta.id) {
            // Update metadata for an existing tab instead of duplicating it
            *existing = meta;
        } else {
            list.push(meta);
        }
        let current_list = list.clone();
        drop(conns);

        let _ = self.event_tx.send(SessionEvent::Presence(user_id, current_list));
    }

    pub async fn unregister_web_session(&self, user_id: i64, session_id: &str) {
        let mut conns = self.web_connections.write().await;
        if let Some(list) = conns.get_mut(&user_id) {
            list.retain(|s| s.id != session_id);
            let current_list = list.clone();
            // Clean up empty entries? Maybe not strictly necessary but good for memory
            if list.is_empty() {
                conns.remove(&user_id);
            }
            drop(conns);
            let _ = self.event_tx.send(SessionEvent::Presence(user_id, current_list));
        }
    }

    pub async fn get_web_sessions(&self, user_id: i64) -> Vec<WebSessionMeta> {
        self.web_connections.read().await.get(&user_id).cloned().unwrap_or_default()
    }

    // FIXME: we should use rusts type system to make things unrepresentable at the type level
    // IP Addresses should be validated on creation and storage not just by length, useragents to, usernames too, etc. as well as any generic "string" that isnt really just a string

    /// Validate and sanitize metadata fields before storing in the database.
    /// Caps field lengths to prevent oversized values from bloating rows.
    fn validate_metadata_fields(
        ip_address: Option<String>,
        user_agent: Option<String>,
        username: String,
        relay_name: String,
    ) -> (Option<String>, Option<String>, String, String) {
        const MAX_IP_LEN: usize = 256;
        const MAX_USER_AGENT_LEN: usize = 2048;
        const MAX_USERNAME_LEN: usize = 256;
        const MAX_RELAY_NAME_LEN: usize = 256;

        let ip_address = ip_address.map(|s| {
            if s.len() > MAX_IP_LEN {
                tracing::warn!(original_len = s.len(), "IP address exceeds max length, truncating");
                s.chars().take(MAX_IP_LEN).collect()
            } else {
                s
            }
        });

        let user_agent = user_agent.map(|s| {
            if s.len() > MAX_USER_AGENT_LEN {
                tracing::warn!(original_len = s.len(), "User agent exceeds max length, truncating");
                s.chars().take(MAX_USER_AGENT_LEN).collect()
            } else {
                s
            }
        });

        let username = if username.len() > MAX_USERNAME_LEN {
            tracing::warn!(original_len = username.len(), "Username exceeds max length, truncating");
            username.chars().take(MAX_USERNAME_LEN).collect()
        } else {
            username
        };

        let relay_name = if relay_name.len() > MAX_RELAY_NAME_LEN {
            tracing::warn!(original_len = relay_name.len(), "Relay name exceeds max length, truncating");
            relay_name.chars().take(MAX_RELAY_NAME_LEN).collect()
        } else {
            relay_name
        };

        (ip_address, user_agent, username, relay_name)
    }

    #[allow(clippy::too_many_arguments)]
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
        term_dims: Option<(u32, u32)>,
        connection_id: Option<String>,
    ) -> (u32, Arc<SshSession>) {
        let mut sessions = self.sessions.write().await;

        // Use atomic counter for O(1) ID generation
        let session_number = self.next_session_id.fetch_add(1, Ordering::Relaxed);

        let (close_tx, _) = broadcast::channel(1);

        // Validate and sanitize metadata fields
        let (ip_address, user_agent, username, relay_name) = Self::validate_metadata_fields(ip_address, user_agent, username, relay_name);

        let metadata = {
            let mut base = serde_json::json!({
                "ip_address": ip_address,
                "user_agent": user_agent,
                "origin": origin,
                "username": username,
                "relay_name": relay_name,
            });

            if let Some((cols, rows)) = term_dims {
                base["terminal"] = serde_json::json!({
                    "cols": cols,
                    "rows": rows,
                });
            }

            base
        };

        let recorder = SessionRecorder::new(
            self.audit_db.clone(),
            user_id,
            relay_id,
            session_number,
            metadata,
            connection_id.clone(),
        )
        .await;

        let session = Arc::new(SshSession::new(
            session_number,
            user_id,
            relay_id,
            relay_name,
            username,
            backend,
            origin,
            close_tx,
            self.event_tx.clone(),
            ip_address,
            user_agent,
            connection_id.clone(),
            recorder,
        ));

        sessions.insert((user_id, relay_id, session_number), session.clone());
        let _ = self.event_tx.send(SessionEvent::Created(user_id, session.to_summary().await));

        // Spawn idle watcher to emit idle->active transitions without client polling
        let session_clone = session.clone();
        tokio::spawn(async move { session_clone.idle_watch().await });

        (session_number, session)
    }

    pub async fn get_session(&self, user_id: i64, relay_id: i64, session_number: u32) -> Option<Arc<SshSession>> {
        self.sessions.read().await.get(&(user_id, relay_id, session_number)).cloned()
    }

    pub async fn remove_session(&self, user_id: i64, relay_id: i64, session_number: u32) {
        if self.sessions.write().await.remove(&(user_id, relay_id, session_number)).is_some() {
            let _ = self.event_tx.send(SessionEvent::Removed {
                user_id,
                relay_id,
                session_number,
            });
        }
    }

    pub async fn list_sessions_for_user(&self, user_id: i64) -> Vec<Arc<SshSession>> {
        let sessions = self.sessions.read().await;
        sessions
            .iter()
            .filter(|((uid, _, _), _)| *uid == user_id)
            .map(|(_, session)| session.clone())
            .collect()
    }

    pub async fn list_all_sessions(&self) -> Vec<Arc<SshSession>> {
        let sessions = self.sessions.read().await;
        sessions.values().cloned().collect()
    }

    pub async fn list_all_web_sessions(&self) -> Vec<WebSessionMeta> {
        let conns = self.web_connections.read().await;
        conns.values().flatten().cloned().collect()
    }

    pub async fn list_web_sessions_for_user(&self, user_id: i64) -> Vec<WebSessionMeta> {
        self.web_connections.read().await.get(&user_id).cloned().unwrap_or_default()
    }

    pub async fn cleanup_expired_sessions(&self) {
        // First pass: collect keys to remove without holding the write lock for the entire duration
        // and without holding the write lock while awaiting individual session locks.
        // Also collect session data needed for audit logging.
        let candidates: Vec<((i64, i64, u32), String)> = {
            let sessions = self.sessions.read().await;
            let now = Utc::now();
            let mut candidates = Vec::new();

            for (key, session) in sessions.iter() {
                // We need to read the state. This awaits a RwLock read, which is fine as long as we don't hold the global write lock.
                let state = session.state.read().await;
                let reason = match *state {
                    SessionState::Detached { detached_at, timeout } => {
                        if now > detached_at + timeout {
                            // Signal close - it's okay if we signal close and then don't remove (e.g. race),
                            // the session will just handle the close signal (which might be ignored if attached).
                            let _ = session.close_tx.send(());
                            Some("detach_timeout".to_string())
                        } else {
                            None
                        }
                    }
                    SessionState::Closed => Some("already_closed".to_string()),
                    SessionState::Attached => {
                        // Zombie check: if attached but no activity for 24 hours, kill it
                        let last_active = session.last_active_at();
                        if now.signed_duration_since(last_active).num_seconds() > 86400 {
                            let _ = session.close_tx.send(());
                            Some("zombie_cleanup".to_string())
                        } else {
                            None
                        }
                    }
                };

                if let Some(r) = reason {
                    candidates.push((*key, r));
                }
            }
            candidates
        };

        if !candidates.is_empty() {
            // Struct to hold session data needed for cleanup after removal
            struct SessionCleanupData {
                session: Arc<SshSession>,
                key: (i64, i64, u32),
                reason: String,
                duration_ms: i64,
            }

            let mut to_cleanup: Vec<SessionCleanupData> = Vec::new();
            let now = Utc::now();

            // Hold write lock only long enough to check conditions and remove sessions
            {
                let mut sessions = self.sessions.write().await;

                for (key, reason) in candidates {
                    // Re-check condition to avoid race where session became active between read and write lock
                    let should_remove = if let Some(session) = sessions.get(&key) {
                        let state = session.state.read().await;
                        match *state {
                            SessionState::Detached { detached_at, timeout } => now > detached_at + timeout,
                            SessionState::Closed => true,
                            SessionState::Attached => {
                                let last_active = session.last_active_at();
                                now.signed_duration_since(last_active).num_seconds() > 86400
                            }
                        }
                    } else {
                        // Already removed
                        false
                    };

                    if should_remove {
                        // Remove session and collect data for cleanup outside lock
                        if let Some(session) = sessions.remove(&key) {
                            let duration_ms = (now - session.created_at).num_milliseconds();
                            to_cleanup.push(SessionCleanupData {
                                session,
                                key,
                                reason,
                                duration_ms,
                            });

                            // Broadcast removal event
                            let (uid, rid, snum) = key;
                            let _ = self.event_tx.send(SessionEvent::Removed {
                                user_id: uid,
                                relay_id: rid,
                                session_number: snum,
                            });
                        }
                    }
                }
            } // Write lock released here

            // Now perform async close operations and audit logging WITHOUT holding the lock
            for cleanup_data in to_cleanup {
                let session = cleanup_data.session;
                let key = cleanup_data.key;
                let reason = cleanup_data.reason;
                let duration_ms = cleanup_data.duration_ms;

                let session_id = session.recorder.session_id().to_string();
                let relay_name = session.relay_name.clone();
                let relay_id = session.relay_id;
                let username = session.username.clone();
                let user_id = session.user_id;

                // Close session to update end_time in DB (no lock held)
                session.close().await;

                // Log SessionTimedOut audit event ONLY for actual timeouts.
                if reason != "already_closed" {
                    let session_id_clone = session_id.clone();
                    let relay_name_clone = relay_name.clone();
                    let username_clone = username.clone();
                    let reason_clone = reason.clone();
                    tokio::spawn(async move {
                        let ctx = rb_types::audit::AuditContext::system(format!("session_cleanup:{}", session_id_clone));
                        crate::audit::log_event_from_context_best_effort(
                            &ctx,
                            rb_types::audit::EventType::SessionTimedOut {
                                session_id: session_id_clone,
                                relay_name: relay_name_clone,
                                relay_id,
                                username: username_clone,
                                duration_ms,
                                reason: reason_clone,
                            },
                        )
                        .await;
                    });
                }

                tracing::info!(
                    user_id,
                    relay_id,
                    session_number = key.2,
                    reason = %reason,
                    "Session timed out and removed"
                );
            }
        }
    }

    /// Cleanup stale web sessions that haven't been seen in a while (e.g., browser crashed)
    pub async fn cleanup_stale_web_sessions(&self, timeout_secs: i64) {
        let mut conns = self.web_connections.write().await;
        let now = Utc::now();
        let mut changed_users = Vec::new();

        for (user_id, list) in conns.iter_mut() {
            let before_count = list.len();
            list.retain(|meta| {
                let age = now.signed_duration_since(meta.last_seen).num_seconds();
                age < timeout_secs
            });
            if list.len() != before_count {
                changed_users.push((*user_id, list.clone()));
            }
        }

        // Remove empty entries
        conns.retain(|_, list| !list.is_empty());
        drop(conns);

        // Broadcast presence updates for affected users
        for (user_id, list) in changed_users {
            let _ = self.event_tx.send(SessionEvent::Presence(user_id, list));
        }
    }

    /// Update last_seen timestamp for a web session (heartbeat)
    pub async fn heartbeat_web_session(&self, user_id: i64, session_id: &str) {
        let mut conns = self.web_connections.write().await;
        if let Some(list) = conns.get_mut(&user_id)
            && let Some(meta) = list.iter_mut().find(|m| m.id == session_id)
        {
            meta.last_seen = Utc::now();
        }
    }
}
