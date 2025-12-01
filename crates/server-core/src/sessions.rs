use std::{
    collections::{HashMap, VecDeque}, sync::{
        Arc, atomic::{AtomicU32, Ordering}
    }, time::Duration
};

use chrono::{DateTime, Utc};
use rb_types::ssh::{SessionEvent, SessionStateSummary, UserSessionSummary, WebSessionMeta};
use tokio::sync::{RwLock, broadcast, mpsc};

#[derive(Debug, Clone)]
pub enum SessionState {
    Attached,
    Detached { detached_at: DateTime<Utc>, timeout: Duration },
    Closed,
}

pub struct SshSession {
    pub session_number: u32,
    pub user_id: i64,
    pub relay_id: i64,
    pub relay_name: String,
    pub created_at: DateTime<Utc>,
    pub last_active_at: RwLock<DateTime<Utc>>,
    pub state: RwLock<SessionState>,
    // Scrollback history buffer (64KB)
    pub history: RwLock<VecDeque<u8>>,
    // Number of active WebSocket connections
    pub active_connections: AtomicU32,
    // Number of connections with the window OPEN (not minimized)
    pub active_viewers: AtomicU32,
    // Channel to send input to the SSH loop
    pub input_tx: mpsc::Sender<Vec<u8>>,
    // Broadcast channel to send output to attached WebSockets
    pub output_tx: broadcast::Sender<Vec<u8>>,
    // Close signal
    pub close_tx: broadcast::Sender<()>,
    // Event channel
    pub event_tx: broadcast::Sender<SessionEvent>,
}

impl SshSession {
    #[allow(clippy::too_many_arguments)]
    //FIXME: too many args we should probably make this a struct?
    pub fn new(
        session_number: u32,
        user_id: i64,
        relay_id: i64,
        relay_name: String,
        input_tx: mpsc::Sender<Vec<u8>>,
        output_tx: broadcast::Sender<Vec<u8>>,
        close_tx: broadcast::Sender<()>,
        event_tx: broadcast::Sender<SessionEvent>,
    ) -> Self {
        Self {
            session_number,
            user_id,
            relay_id,
            relay_name,
            created_at: Utc::now(),
            last_active_at: RwLock::new(Utc::now()),
            state: RwLock::new(SessionState::Attached),
            history: RwLock::new(VecDeque::with_capacity(65536)), // 64KB
            active_connections: AtomicU32::new(0),
            active_viewers: AtomicU32::new(0),
            input_tx,
            output_tx,
            close_tx,
            event_tx,
        }
    }

    pub async fn to_summary(&self) -> UserSessionSummary {
        let state = self.state.read().await;
        let state_summary = match *state {
            SessionState::Attached => SessionStateSummary::Attached,
            SessionState::Detached { .. } => SessionStateSummary::Detached,
            SessionState::Closed => SessionStateSummary::Closed,
        };
        UserSessionSummary {
            relay_id: self.relay_id,
            relay_name: self.relay_name.clone(),
            session_number: self.session_number,
            state: state_summary,
            active_connections: self.active_connections.load(Ordering::SeqCst),
            active_viewers: self.active_viewers.load(Ordering::SeqCst),
            created_at: self.created_at,
            last_active_at: *self.last_active_at.read().await,
        }
    }

    pub async fn increment_connections(&self) -> u32 {
        let count = self.active_connections.fetch_add(1, Ordering::SeqCst) + 1;
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

    pub async fn decrement_connections(&self) -> u32 {
        let count = self.active_connections.fetch_sub(1, Ordering::SeqCst).saturating_sub(1);
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

    pub async fn increment_viewers(&self) -> u32 {
        let count = self.active_viewers.fetch_add(1, Ordering::SeqCst) + 1;
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

    pub async fn decrement_viewers(&self) -> u32 {
        let count = self.active_viewers.fetch_sub(1, Ordering::SeqCst).saturating_sub(1);
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

    pub async fn append_to_history(&self, data: &[u8]) {
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
        *self.last_active_at.write().await = Utc::now();
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

    pub async fn attach(&self) {
        let mut state = self.state.write().await;
        *state = SessionState::Attached;
        self.touch().await;
        drop(state);
        let _ = self.event_tx.send(SessionEvent::Updated(self.user_id, self.to_summary().await));
    }

    pub async fn close(&self) {
        let mut state = self.state.write().await;
        *state = SessionState::Closed;
        let _ = self.close_tx.send(());
        drop(state);
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
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionRegistry {
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(100);
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            web_connections: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
        }
    }

    pub async fn register_web_session(&self, user_id: i64, meta: WebSessionMeta) {
        let mut conns = self.web_connections.write().await;
        let list = conns.entry(user_id).or_default();
        list.push(meta);
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

    pub async fn create_next_session(
        &self,
        user_id: i64,
        relay_id: i64,
        relay_name: String,
        input_tx: mpsc::Sender<Vec<u8>>,
        output_tx: broadcast::Sender<Vec<u8>>,
        close_tx: broadcast::Sender<()>,
    ) -> (u32, Arc<SshSession>) {
        let mut sessions = self.sessions.write().await;

        // Find next session number
        let session_number = (1u32..).find(|&n| !sessions.contains_key(&(user_id, relay_id, n))).unwrap_or(1);

        let session = Arc::new(SshSession::new(
            session_number,
            user_id,
            relay_id,
            relay_name,
            input_tx,
            output_tx,
            close_tx,
            self.event_tx.clone(),
        ));

        sessions.insert((user_id, relay_id, session_number), session.clone());
        let _ = self.event_tx.send(SessionEvent::Created(user_id, session.to_summary().await));
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

    pub async fn cleanup_expired_sessions(&self) {
        let mut sessions = self.sessions.write().await;
        let now = Utc::now();
        let mut to_remove = Vec::new();

        for (key, session) in sessions.iter() {
            let state = session.state.read().await;
            match *state {
                SessionState::Detached { detached_at, timeout } => {
                    if now > detached_at + timeout {
                        to_remove.push(*key);
                        // Signal close
                        let _ = session.close_tx.send(());
                    }
                }
                SessionState::Closed => {
                    to_remove.push(*key);
                }
                _ => {}
            }
        }

        for key in to_remove {
            sessions.remove(&key);
        }
    }
}

#[cfg(test)]
#[path = "sessions.test.rs"]
mod tests;
