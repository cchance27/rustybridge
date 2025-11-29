use chrono::{DateTime, Utc};
use dioxus::prelude::*;

use crate::app::session::types::{Session, SessionStatus, WindowGeometry};

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

pub fn use_session_provider() -> SessionContext {
    let sessions = use_signal(Vec::new);
    let drag_state = use_signal(|| None);
    let context = SessionContext { sessions, drag_state };
    use_context_provider(|| context);

    // Listen for global SSH connection closed events
    // This is needed because the Terminal component might dispatch this event
    // when the websocket closes unexpectedly or EOF is received.
    // In the new architecture, the Terminal component will still handle the WS,
    // but we want to update the session status here.

    // Note: We can't easily pass the context into the event listener closure if it's
    // a window event listener set up via web_sys or eval.
    // However, the Terminal component itself will call callbacks on the session provider.
    // So maybe we don't need a global listener here if we update Terminal to use the provider.

    context
}

pub fn use_session() -> SessionContext {
    use_context::<SessionContext>()
}

impl SessionContext {
    pub fn sessions(&self) -> Signal<Vec<Session>> {
        self.sessions
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

        // TODO: Load geometry from local storage

        // Set z-index for new session (will be recalculated on first focus)
        let current_count = sessions.read().len();
        new_session.z_index = 60 + current_count;

        sessions.write().push(new_session);

        // Recalculate z-indexes for all sessions
        self.recalculate_z_indexes();
    }

    /// Open a session window bound to an existing SSH session number.
    /// If a matching window already exists for this relay+session_number, do nothing.
    pub fn open_restored(&self, relay_name: String, session_number: u32) {
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

        let current_count = sessions.read().len();
        new_session.z_index = 60 + current_count;

        sessions.write().push(new_session);

        self.recalculate_z_indexes();
    }

    pub fn close(&self, id: &str) {
        let mut sessions = self.sessions;
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
            // Minimize implies we might want to focus another window?
            // Or just let it minimize.
        }
    }

    pub fn restore(&self, id: &str) {
        let mut sessions = self.sessions;
        if let Some(session) = sessions.write().iter_mut().find(|s| s.id == id) {
            session.minimized = false;
            session.last_focused_at = Utc::now();
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
            session.geometry = geometry;
            // TODO: Save to local storage
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
    pub fn set_session_number_from_term_id(&self, term_id: &str, session_number: u32) {
        // term_id is expected to be "term-<session.id>"
        let prefix = "term-";
        if !term_id.starts_with(prefix) {
            return;
        }

        let window_id = &term_id[prefix.len()..];
        let mut sessions = self.sessions;
        if let Some(session) = sessions
            .write()
            .iter_mut()
            .find(|s| s.id == window_id)
        {
            session.session_number = Some(session_number);
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
}
