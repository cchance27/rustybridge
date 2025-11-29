use chrono::{DateTime, Utc};
use dioxus::prelude::*;

use crate::app::{
    auth::hooks::use_auth, session::types::{Session, SessionStatus, WindowGeometry}, storage::{BrowserStorage, StorageType}
};

const MAX_SESSIONS: usize = 4;

#[derive(Clone, Copy)]
pub struct SessionContext {
    sessions: Signal<Vec<Session>>,
    drag_state: Signal<Option<DragState>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DragState {
    pub session_id: String,
    pub start_x: i32,
    pub start_y: i32,
    pub initial_x: i32,
    pub initial_y: i32,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SessionStorageData {
    geometry: WindowGeometry,
    minimized: bool,
}

pub fn use_session_provider() -> SessionContext {
    let sessions = use_signal(Vec::new);
    let drag_state = use_signal(|| None);
    let context = SessionContext { sessions, drag_state };
    use_context_provider(|| context);
    context
}

pub fn use_session() -> SessionContext {
    use_context::<SessionContext>()
}

impl SessionContext {
    pub fn sessions(&self) -> Signal<Vec<Session>> {
        self.sessions
    }

    fn get_storage(&self) -> BrowserStorage {
        BrowserStorage::new(StorageType::Local)
    }

    fn get_current_user_id(&self) -> Option<i64> {
        let auth = use_auth();
        auth.read().user.as_ref().map(|u| u.id)
    }

    fn get_session_storage_key(&self, user_id: i64, relay_id: i64, session_number: u32) -> String {
        format!("rb-session-{}-{}-{}", user_id, relay_id, session_number)
    }

    fn save_session_state(&self, user_id: i64, relay_id: i64, session_number: u32, geometry: WindowGeometry, minimized: bool) {
        let key = self.get_session_storage_key(user_id, relay_id, session_number);
        let data = SessionStorageData { geometry, minimized };
        let _ = self.get_storage().set_json(&key, &data);
    }

    fn load_session_state(&self, user_id: i64, relay_id: i64, session_number: u32) -> Option<SessionStorageData> {
        let key = self.get_session_storage_key(user_id, relay_id, session_number);
        self.get_storage().get_json(&key)
    }

    fn remove_session_storage(&self, user_id: i64, relay_id: i64, session_number: u32) {
        let key = self.get_session_storage_key(user_id, relay_id, session_number);
        let _ = self.get_storage().remove(&key);
    }

    #[cfg(not(feature = "web"))]
    fn validate_geometry_on_screen(&self, geometry: WindowGeometry) -> WindowGeometry {
        // For non-web builds, return the geometry as is
        geometry
    }

    #[cfg(feature = "web")]
    fn validate_geometry_on_screen(&self, mut geometry: WindowGeometry) -> WindowGeometry {
        // Get screen dimensions from JavaScript
        use web_sys;

        // Get the window dimensions
        let window = web_sys::window();
        if let Some(window) = window {
            use web_sys::wasm_bindgen::JsValue;

            let screen_width = window.inner_width().unwrap_or(JsValue::from_f64(1200.0)).as_f64().unwrap_or(1200.0) as i32;
            let screen_height = window.inner_height().unwrap_or(JsValue::from_f64(800.0)).as_f64().unwrap_or(800.0) as i32;

            // Ensure minimum dimensions
            let min_width = 200;
            let min_height = 150;

            // Cap the window dimensions to screen size
            if geometry.width > screen_width {
                geometry.width = screen_width.min(800); // reasonable default
            }
            if geometry.height > screen_height {
                geometry.height = screen_height.min(600); // reasonable default
            }

            // Ensure minimum dimensions
            geometry.width = geometry.width.max(min_width);
            geometry.height = geometry.height.max(min_height);

            // Ensure the window is within screen bounds
            if geometry.x < 0 {
                geometry.x = 0;
            }
            if geometry.y < 0 {
                geometry.y = 0;
            }

            // Ensure the window doesn't go off the right/bottom of screen
            if geometry.x + geometry.width > screen_width {
                geometry.x = (screen_width - geometry.width).max(0);
            }
            if geometry.y + geometry.height > screen_height {
                geometry.y = (screen_height - geometry.height).max(0);
            }
        }

        geometry
    }

    pub fn open(&self, relay_name: String) {
        let mut sessions = self.sessions;

        // Check cap
        if sessions.read().len() >= MAX_SESSIONS {
            #[cfg(feature = "web")]
            {
                web_sys::console::warn_1(&"Session cap reached (4)".into());
                // Dispatch event for UI feedback
                let _ = dioxus::document::eval(
                    r#"
                     window.dispatchEvent(new CustomEvent('rb-session-cap-reached', {
                         detail: { max: 4, message: 'Maximum 4 concurrent SSH sessions allowed' }
                     }));
                 "#,
                );
            }
            return;
        }

        let mut new_session = Session::new(relay_name);

        // Default geometry is already set in Session::new()
        // We don't load from storage for new sessions as they don't have a session_number yet

        // Set z-index for new session (will be recalculated on first focus)
        let current_count = sessions.read().len();
        new_session.z_index = 60 + current_count;

        sessions.write().push(new_session);

        // Recalculate z-indexes for all sessions
        self.recalculate_z_indexes();
    }

    /// Open a session window bound to an existing SSH session number.
    /// If a matching window already exists for this relay+session_number, do nothing.
    pub fn open_restored(&self, relay_name: String, relay_id: i64, session_number: u32) {
        let mut sessions = self.sessions;

        // Avoid duplicates: check for existing session with same relay and session number
        if sessions
            .read()
            .iter()
            .any(|s| s.relay_name == relay_name && s.session_number == Some(session_number))
        {
            return;
        }

        let mut new_session = Session::new(relay_name);
        new_session.session_number = Some(session_number);
        new_session.relay_id = Some(relay_id);

        // Load saved state if available
        if let Some(user_id) = self.get_current_user_id() 
            && let Some(saved_state) = self.load_session_state(user_id, relay_id, session_number) {
                // Validate geometry is within screen bounds
                new_session.geometry = self.validate_geometry_on_screen(saved_state.geometry);
                new_session.minimized = saved_state.minimized;
        }

        let current_count = sessions.read().len();
        new_session.z_index = 60 + current_count;

        sessions.write().push(new_session);

        self.recalculate_z_indexes();
    }

    pub fn close(&self, id: &str) {
        let mut sessions = self.sessions;

        // Clean up storage if session has relay_id and session_number
        if let Some(session) = sessions.read().iter().find(|s| s.id == id) 
            && let (Some(user_id), Some(relay_id), Some(session_number)) =
                (self.get_current_user_id(), session.relay_id, session.session_number)
            {
                self.remove_session_storage(user_id, relay_id, session_number);
            
        }

        sessions.write().retain(|s| s.id != id);
    }

    /// Close a session window and send explicit close command to server
    /// This should be used when the user explicitly closes a window (e.g., clicking X)
    pub fn close_with_command(&self, id: &str) {
        #[cfg(feature = "web")]
        {
            let id_owned = id.to_string();
            let sessions_signal = self.sessions;

            spawn(async move {
                use crate::app::api::ssh_websocket::{SshClientMsg, SshControl};

                web_sys::console::log_1(&format!("Attempting to send explicit close command for session {}", id_owned).into());

                // Try to send close command via eval to the Terminal's WebSocket
                // The Terminal component stores its socket in a signal, but we don't have direct access
                // So we'll use a global event that the Terminal can listen for
                let term_id = format!("term-{}", id_owned);
                let _ = dioxus::document::eval(&format!(
                    r#"
                    window.dispatchEvent(new CustomEvent('terminal-close-requested', {{
                        detail: {{ termId: '{}' }}
                    }}));
                    "#,
                    term_id
                ))
                .await;

                // Small delay to let the message send
                gloo_timers::future::TimeoutFuture::new(100).await;
            });

            // On web: do not close the window immediately. The server will receive
            // the explicit close command, send EOF, and the Terminal component's
            // on_close handler will call SessionContext::close for this id.
            return;
        }

        // Non-web builds: fall back to immediately closing the window
        self.close(id);
    }

    pub fn minimize(&self, id: &str) {
        let mut sessions = self.sessions;
        if let Some(session) = sessions.write().iter_mut().find(|s| s.id == id) {
            session.minimized = true;

            // Save state
            if let (Some(user_id), Some(relay_id), Some(session_number)) =
                (self.get_current_user_id(), session.relay_id, session.session_number)
            {
                self.save_session_state(user_id, relay_id, session_number, session.geometry.clone(), true);
            }
        }
    }

    pub fn restore(&self, id: &str) {
        let mut sessions = self.sessions;
        if let Some(session) = sessions.write().iter_mut().find(|s| s.id == id) {
            session.minimized = false;
            session.last_focused_at = Utc::now();

            // Save state
            if let (Some(user_id), Some(relay_id), Some(session_number)) =
                (self.get_current_user_id(), session.relay_id, session.session_number)
            {
                self.save_session_state(user_id, relay_id, session_number, session.geometry.clone(), false);
            }
        }
    }

    pub fn focus(&self, id: &str) {
        let mut sessions = self.sessions;
        if let Some(session) = sessions.write().iter_mut().find(|s| s.id == id) {
            session.last_focused_at = Utc::now();
            if session.minimized {
                session.minimized = false;
            }
        }

        // Recalculate z-indexes after focus change
        self.recalculate_z_indexes();
    }

    pub fn toggle_fullscreen(&self, id: &str) {
        let mut sessions = self.sessions;
        if let Some(session) = sessions.write().iter_mut().find(|s| s.id == id) {
            session.fullscreen = !session.fullscreen;
        }
    }

    pub fn set_geometry(&self, id: &str, geometry: WindowGeometry) {
        let mut sessions = self.sessions;
        if let Some(session) = sessions.write().iter_mut().find(|s| s.id == id) {
            // Validate geometry is within screen bounds before setting
            let validated_geometry = self.validate_geometry_on_screen(geometry.clone());
            session.geometry = validated_geometry.clone();

            // Save state
            if let (Some(user_id), Some(relay_id), Some(session_number)) =
                (self.get_current_user_id(), session.relay_id, session.session_number)
            {
                self.save_session_state(user_id, relay_id, session_number, validated_geometry, session.minimized);
            }
        }
    }

    pub fn set_status(&self, id: &str, status: SessionStatus) {
        let mut sessions = self.sessions;
        if let Some(session) = sessions.write().iter_mut().find(|s| s.id == id) {
            session.status = status;
        }
    }

    pub fn set_thumbnail(&self, id: &str, data_url: String) {
        let mut sessions = self.sessions;
        if let Some(session) = sessions.write().iter_mut().find(|s| s.id == id) {
            session.thumbnail_data_url = Some(data_url);
        }
    }

    /// Associate a backend SSH session number with a window given its terminal DOM id ("term-<session.id>").
    pub fn set_session_number_from_term_id(&self, term_id: &str, session_number: u32, relay_id: Option<i64>) {
        // term_id is expected to be "term-<session.id>"
        let prefix = "term-";
        if !term_id.starts_with(prefix) {
            return;
        }

        let window_id = &term_id[prefix.len()..];
        let mut sessions = self.sessions;
        if let Some(session) = sessions.write().iter_mut().find(|s| s.id == window_id) {
            session.session_number = Some(session_number);
            if let Some(rid) = relay_id {
                session.relay_id = Some(rid);

                // Save initial state now that we have all identifiers
                if let Some(user_id) = self.get_current_user_id() {
                    self.save_session_state(user_id, rid, session_number, session.geometry.clone(), session.minimized);
                }
            }
        }
    }

    // Dragging logic
    pub fn start_drag(&self, session_id: String, start_x: i32, start_y: i32) {
        let sessions = self.sessions.read();
        if let Some(session) = sessions.iter().find(|s| s.id == session_id) {
            let mut drag_state = self.drag_state;
            drag_state.set(Some(DragState {
                session_id,
                start_x,
                start_y,
                initial_x: session.geometry.x,
                initial_y: session.geometry.y,
            }));
        }
    }

    pub fn update_drag(&self, current_x: i32, current_y: i32) {
        // Early return if no drag is active - this prevents unnecessary work on every mouse move
        let drag_state_signal = self.drag_state;
        let state = match drag_state_signal.read().as_ref() {
            Some(s) => s.clone(),
            None => return, // No drag in progress, do nothing
        };

        let dx = current_x - state.start_x;
        let dy = current_y - state.start_y;

        // Get current geometry to preserve width/height
        let sessions = self.sessions.read();
        if let Some(session) = sessions.iter().find(|s| s.id == state.session_id) {
            let new_geometry = WindowGeometry {
                x: state.initial_x + dx,
                y: state.initial_y + dy,
                width: session.geometry.width,
                height: session.geometry.height,
            };

            // Drop the read lock before calling set_geometry
            drop(sessions);

            self.set_geometry(&state.session_id, new_geometry);
        }
    }

    pub fn end_drag(&self) {
        let mut drag_state = self.drag_state;
        drag_state.set(None);
    }

    /// Recalculate z-indexes for all sessions based on last_focused_at
    /// This is called when focus changes or sessions are added/removed
    fn recalculate_z_indexes(&self) {
        let mut sessions = self.sessions;
        let mut all_sessions = sessions.write();

        // Create a sorted list of (index, last_focused_at) pairs
        let mut indexed: Vec<(usize, DateTime<Utc>)> = all_sessions.iter().enumerate().map(|(i, s)| (i, s.last_focused_at)).collect();

        // Sort by last_focused_at
        indexed.sort_by_key(|(_, ts)| *ts);

        // Assign z-indexes based on sorted order
        for (z_order, (original_idx, _)) in indexed.iter().enumerate() {
            all_sessions[*original_idx].z_index = 60 + z_order;
        }
    }

    pub fn session_count(&self) -> usize {
        self.sessions.read().len()
    }

    pub fn at_capacity(&self) -> bool {
        self.sessions.read().len() >= MAX_SESSIONS
    }

    pub async fn restore_sessions_from_backend(&self) {
        use crate::app::api::ssh_websocket::{SessionStateSummary, ssh_list_sessions};

        #[cfg(feature = "web")]
        web_sys::console::log_1(&"Restoring sessions from backend...".into());

        match ssh_list_sessions().await {
            Ok(sessions) => {
                #[cfg(feature = "web")]
                web_sys::console::log_1(&format!("Found {} sessions from backend", sessions.len()).into());

                let mut active_session_keys = std::collections::HashSet::new();
                let mut restored_relay_names = Vec::new();

                for session_summary in sessions {
                    // Only restore active sessions
                    if let SessionStateSummary::Closed = session_summary.state { continue }

                    // Track active session keys for cleanup
                    if let Some(user_id) = self.get_current_user_id() {
                        let key = self.get_session_storage_key(user_id, session_summary.relay_id, session_summary.session_number);
                        active_session_keys.insert(key);
                    }

                    self.open_restored(
                        session_summary.relay_name.clone(),
                        session_summary.relay_id,
                        session_summary.session_number,
                    );

                    restored_relay_names.push(session_summary.relay_name);
                }

                // FIXME: Do we really like this method for toasts? Normally it's better to pop multiple toast methods, but we should think abotu handlign that globally and having a toast system fully typed as a dioxus system leveraging rust where we can.
                // Show toast notification for number of reattached sessions
                #[cfg(feature = "web")]
                {
                    if !restored_relay_names.is_empty() {
                        let count = restored_relay_names.len();
                        let message = if count == 1 {
                            format!("Reattached to 1 SSH session ({})", restored_relay_names[0])
                        } else {
                            format!("Reattached to {} SSH sessions", count)
                        };

                        let escaped_message = message.replace("\\", "\\\\").replace("'", "\\'").replace("\"", "\\\"");
                        let _ = dioxus::document::eval(&format!(
                            r#"
                            try {{
                                console.log('Dispatching rb-toast-notification for {} sessions');
                                window.dispatchEvent(new CustomEvent('rb-toast-notification', {{
                                    detail: {{
                                        message: '{}',
                                        type: 'info'
                                    }}
                                }}));
                            }} catch (e) {{
                                console.error('Error dispatching toast event:', e);
                            }}
                            "#,
                            count,
                            escaped_message
                        ))
                        .await;
                    }
                }

                // Cleanup stale sessions
                // Note: This is a bit tricky because we can't easily iterate all keys in localStorage
                // that match our pattern without a keys() method on BrowserStorage.
                // I added keys() to BrowserStorage, so we can use it.
                if let Some(user_id) = self.get_current_user_id() {
                    let storage = self.get_storage();
                    let all_keys = storage.keys();
                    let prefix = format!("rb-session-{}-", user_id);

                    for key in all_keys {
                        if key.starts_with(&prefix) && !active_session_keys.contains(&key) {
                            let _ = storage.remove(&key);
                        }
                    }
                }
            }
            Err(_e) => {
                #[cfg(feature = "web")]
                web_sys::console::error_1(&format!("Failed to list sessions: {}", _e).into());
            }
        }
    }
}
