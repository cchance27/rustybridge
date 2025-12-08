use std::collections::HashSet;

use chrono::{DateTime, Utc};
use dioxus::{fullstack::use_websocket, prelude::*};
use rb_types::ssh::{SessionEvent, SessionStateSummary, UserSessionSummary, WebSessionMeta};

use crate::app::{
    auth::hooks::use_auth, session::types::{Session, SessionStatus, WindowGeometry}, storage::{BrowserStorage, StorageType}
};

const MAX_SESSIONS: usize = 4;

#[derive(Clone, Copy)]
pub struct SessionContext {
    sessions: Signal<Vec<Session>>,
    drag_state: Signal<Option<DragState>>,
    resize_state: Signal<Option<ResizeState>>,
    pub snap_preview: Signal<Option<WindowGeometry>>,
    pub snap_to_navbar: Signal<bool>, // true = snap below navbar, false = snap to screen edge
    pub active_web_sessions: Signal<Vec<WebSessionMeta>>,
    pub current_client_id: Signal<String>,
    #[cfg(feature = "web")]
    toast: Option<crate::app::components::toast::ToastContext>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DragState {
    pub session_id: String,
    pub start_x: i32,
    pub start_y: i32,
    pub initial_x: i32,
    pub initial_y: i32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResizeState {
    pub session_id: String,
    pub start_x: i32,
    pub start_y: i32,
    pub initial_geometry: WindowGeometry,
    pub direction: ResizeDirection,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ResizeDirection {
    TopLeft,
    Top,
    TopRight,
    Right,
    BottomRight,
    Bottom,
    BottomLeft,
    Left,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SessionStorageData {
    geometry: WindowGeometry,
    minimized: bool,
}

pub fn use_session_provider() -> SessionContext {
    // Try to get existing context first - if it exists, return it immediately
    if let Some(existing_context) = try_consume_context::<SessionContext>() {
        #[cfg(feature = "web")]
        web_sys::console::log_1(&"SessionProvider: Reusing existing context".into());
        return existing_context;
    }

    #[cfg(feature = "web")]
    web_sys::console::log_1(&"SessionProvider: Creating NEW context and WebSocket connections".into());

    let sessions = use_signal(Vec::new);
    let drag_state = use_signal(|| None);
    let resize_state = use_signal(|| None);
    let snap_preview = use_signal(|| None);
    let active_web_sessions = use_signal(Vec::new);

    // Generate or retrieve persistent client ID for this browser tab
    // Use sessionStorage so it persists across page refreshes but not across tabs
    let current_client_id = use_signal(|| {
        let storage = BrowserStorage::new(StorageType::Session);
        if let Some(existing_id) = storage.get("rb-client-id") {
            #[cfg(feature = "web")]
            web_sys::console::log_1(&format!("Reusing existing client ID: {}", existing_id).into());
            existing_id
        } else {
            let new_id = uuid::Uuid::new_v4().to_string();
            let _ = storage.set("rb-client-id", &new_id);
            #[cfg(feature = "web")]
            web_sys::console::log_1(&format!("Generated new client ID: {}", new_id).into());
            new_id
        }
    });

    // Load snap_to_navbar preference from localStorage (default: true = snap below navbar)
    let snap_to_navbar = use_signal(|| {
        let storage = BrowserStorage::new(StorageType::Local);
        storage.get_json::<bool>("rb-snap-to-navbar").unwrap_or(true)
    });
    let pending_restores = use_signal(|| Option::<Vec<UserSessionSummary>>::None);

    use dioxus::fullstack::WebSocketOptions;

    use crate::app::api::ws::session_events::ssh_web_events;
    #[cfg(feature = "web")]
    use crate::app::components::use_toast;
    #[cfg(feature = "web")]
    let toast = use_toast();

    let mut context = SessionContext {
        sessions,
        drag_state,
        resize_state,
        snap_preview,
        snap_to_navbar,
        active_web_sessions,
        current_client_id,
        #[cfg(feature = "web")]
        toast: None,
    };
    #[cfg(feature = "web")]
    {
        use web_sys::window;
        // Check if we are on the SSH success page
        if let Some(win) = window() {
            if let Ok(path) = win.location().pathname() {
                if path == "/auth/ssh-success" {
                    // Start an empty context without WebSocket or restoration logic
                    context.toast = None; // Disable toasts explicitly though it shouldn't matter with empty logic
                    use_context_provider(|| context);
                    return context;
                }
            }
        }
        context.toast = Some(toast);
    }
    use_context_provider(|| context);

    let auth = use_auth();

    // When auth becomes ready after initial mount, restore any sessions we deferred
    // Use a memo to track if restoration is in progress to prevent duplicate attempts
    let restoration_in_progress = use_signal(|| false);

    {
        let mut pending_restores = pending_restores;
        let mut restoration_in_progress = restoration_in_progress;
        let context = context;
        #[cfg(feature = "web")]
        let toast = toast;

        use_effect(move || {
            // Direct reads - proper reactive tracking without intermediate variables
            let pending = pending_restores.read().clone();
            let user = auth.read().user.clone();
            let in_progress = *restoration_in_progress.read();

            // Only proceed if we have both pending sessions and auth, and not already restoring
            if let (Some(summaries), Some(user)) = (pending, user)
                && !in_progress
            {
                // Mark as in progress and clear pending
                restoration_in_progress.set(true);
                pending_restores.set(None);

                let context = context;
                #[cfg(feature = "web")]
                let toast = toast;
                let mut restoration_in_progress = restoration_in_progress;

                spawn(async move {
                    let mut restored_relay_names = Vec::new();
                    let mut active_session_keys = HashSet::new();

                    for session_summary in summaries {
                        if let SessionStateSummary::Closed = session_summary.state {
                            continue;
                        }

                        #[cfg(feature = "web")]
                        web_sys::console::log_1(
                            &format!(
                                "Restoring (deferred) session: relay_id={}, session_number={}, user_id={}",
                                session_summary.relay_id, session_summary.session_number, user.id
                            )
                            .into(),
                        );

                        // Track active session keys for cleanup
                        let key = context.get_session_storage_key(user.id, session_summary.relay_id, session_summary.session_number);
                        active_session_keys.insert(key);

                        // Relay sessions (web or ssh origin) are attachable; TUI/web presence are not
                        let attachable = matches!(session_summary.kind, rb_types::ssh::SessionKind::Relay);
                        context.open_restored(
                            user.id,
                            session_summary.relay_name.clone(),
                            session_summary.relay_id,
                            session_summary.session_number,
                            false,
                            session_summary.connections,
                            session_summary.viewers,
                            attachable,
                            None,
                            None,
                        );
                        restored_relay_names.push(session_summary.relay_name);
                    }

                    #[cfg(feature = "web")]
                    {
                        if !restored_relay_names.is_empty() {
                            let count = restored_relay_names.len();
                            let message = if count == 1 {
                                format!("Reattached to 1 SSH session ({})", restored_relay_names[0])
                            } else {
                                format!("Reattached to {} SSH sessions", count)
                            };
                            toast.info(&message);
                        }
                    }

                    // Cleanup stale sessions
                    let storage = context.get_storage();
                    let all_keys = storage.keys();
                    let prefix = format!("rb-session-{}-", user.id);

                    for key in all_keys {
                        if key.starts_with(&prefix) && !active_session_keys.contains(&key) {
                            let _ = storage.remove(&key);
                        }
                    }

                    // Mark restoration as complete
                    restoration_in_progress.set(false);
                });
            }
        });
    }
    // WebSocket connection with proper lifecycle management
    let client_id_val = current_client_id.peek().clone();
    let mut ws = use_websocket(move || {
        let client_id = client_id_val.clone();
        #[cfg(feature = "web")]
        web_sys::console::log_1(&format!("Opening WebSocket connection with client_id: {}", client_id).into());
        async move { ssh_web_events(client_id, None, WebSocketOptions::new()).await }
    });

    // Log component lifecycle for debugging
    use_effect(move || {
        #[cfg(feature = "web")]
        web_sys::console::log_1(&"SessionProvider mounted, WebSocket connection active".into());
    });

    let auth = use_auth();

    let mut pending_restores_clone = pending_restores;
    use_coroutine(move |_rx: UnboundedReceiver<()>| async move {
        let mut success = false;
        while let Ok(event) = ws.recv().await {
            success = true;
            match event {
                SessionEvent::Presence(_, list) => {
                    context.active_web_sessions.set(list);
                }
                SessionEvent::Created(_, summary) => {
                    // Check if we already have this session and update it, or create new
                    let mut sessions = context.sessions.write();

                    // First check: do we have a session with matching relay_id + session_number?
                    let found_by_ids = sessions
                        .iter_mut()
                        .find(|s| s.relay_id == Some(summary.relay_id) && s.session_number == Some(summary.session_number));

                    if let Some(existing) = found_by_ids {
                        // Session already exists in this browser - just update counts
                        existing.connections = summary.connections;
                        existing.viewers = summary.viewers;
                    } else {
                        // Second check: do we have a session that's still connecting (no session_number yet)
                        // for the same relay name? This handles the race where SessionEvent::Created arrives
                        // before the Terminal's WebSocket receives the session_id
                        let found_by_name = sessions.iter_mut().find(|s| {
                            s.relay_name == summary.relay_name
                                && s.session_number.is_none()
                                && matches!(s.status, SessionStatus::Connecting)
                        });

                        if let Some(existing) = found_by_name {
                            // This is our session that's still connecting - update it with the IDs
                            existing.relay_id = Some(summary.relay_id);
                            existing.session_number = Some(summary.session_number);
                            existing.connections = summary.connections;
                            existing.viewers = summary.viewers;
                            existing.status = SessionStatus::Connected;

                            #[cfg(feature = "web")]
                            web_sys::console::log_1(
                                &format!(
                                    "Updated connecting session {} with session_number {}",
                                    existing.id, summary.session_number
                                )
                                .into(),
                            );
                        } else {
                            // Drop the write lock before calling open_restored
                            drop(sessions);

                            // Get user_id from auth context
                            if let Some(user) = auth.read().user.as_ref() {
                                // This is a new session created elsewhere - open minimized
                                let attachable = matches!(summary.kind, rb_types::ssh::SessionKind::Relay);
                                context.open_restored(
                                    user.id,
                                    summary.relay_name.clone(),
                                    summary.relay_id,
                                    summary.session_number,
                                    true,
                                    summary.connections,
                                    summary.viewers,
                                    attachable,
                                    None,
                                    None,
                                );
                            }

                            // Show toast
                            #[cfg(feature = "web")]
                            {
                                toast.info(&format!("New session synced: {}", summary.relay_name));
                            }
                        }
                    }
                }
                SessionEvent::Updated(_, summary) => {
                    // Update session state and active_connections count
                    let mut sessions = context.sessions.write();
                    if let Some(session) = sessions
                        .iter_mut()
                        .find(|s| s.relay_id == Some(summary.relay_id) && s.session_number == Some(summary.session_number))
                    {
                        // Update active connections and viewers count
                        session.connections = summary.connections;
                        session.viewers = summary.viewers;

                        // Update status based on state
                        if let SessionStateSummary::Closed = summary.state {
                            session.status = SessionStatus::Closed;
                        }
                    }
                }
                SessionEvent::Removed {
                    user_id: _,
                    relay_id,
                    session_number,
                } => {
                    // Remove session
                    let mut sessions = context.sessions.write();
                    if let Some(pos) = sessions
                        .iter()
                        .position(|s| s.relay_id == Some(relay_id) && s.session_number == Some(session_number))
                    {
                        sessions.remove(pos);
                    }
                    drop(sessions); // Drop the lock before calling other methods

                    // Also remove storage
                    if let Some(user) = auth.read().user.as_ref() {
                        context.remove_session_storage(user.id, relay_id, session_number);
                    }
                }
                SessionEvent::List(summaries) => {
                    #[cfg(feature = "web")]
                    web_sys::console::log_1(&format!("Received {} sessions from WebSocket", summaries.len()).into());

                    // If auth not ready yet, stash for immediate restore when it arrives
                    if auth.read().user.is_none() {
                        pending_restores_clone.set(Some(summaries));
                        continue;
                    }

                    // Check if restoration is already in progress - prevent duplicate restoration
                    if *restoration_in_progress.read() {
                        #[cfg(feature = "web")]
                        web_sys::console::log_1(&"Session restoration already in progress, skipping duplicate List event".into());
                        continue;
                    }

                    let user = auth.read().user.clone().unwrap();
                    let context = context;
                    #[cfg(feature = "web")]
                    let toast = toast;
                    let mut restoration_in_progress_clone = restoration_in_progress;

                    // Mark restoration as in progress
                    restoration_in_progress_clone.set(true);

                    spawn(async move {
                        let mut restored_relay_names = Vec::new();
                        let mut active_session_keys = HashSet::new();

                        for session_summary in summaries {
                            // Only restore active sessions
                            if let SessionStateSummary::Closed = session_summary.state {
                                continue;
                            }

                            #[cfg(feature = "web")]
                            {
                                web_sys::console::log_1(
                                    &format!(
                                        "Restoring session: relay_id={}, session_number={}, user_id={}",
                                        session_summary.relay_id, session_summary.session_number, user.id
                                    )
                                    .into(),
                                );
                            }

                            // Track active session keys for cleanup
                            let key = context.get_session_storage_key(user.id, session_summary.relay_id, session_summary.session_number);
                            active_session_keys.insert(key);

                            // Restore the session with proper user_id
                            let attachable = matches!(session_summary.kind, rb_types::ssh::SessionKind::Relay);
                            context.open_restored(
                                user.id,
                                session_summary.relay_name.clone(),
                                session_summary.relay_id,
                                session_summary.session_number,
                                false, // Don't force minimized on restore
                                session_summary.connections,
                                session_summary.viewers,
                                attachable,
                                None,
                                None,
                            );
                            restored_relay_names.push(session_summary.relay_name);
                        }

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
                                toast.info(&message);
                            }
                        }

                        // Cleanup stale sessions
                        let storage = context.get_storage();
                        let all_keys = storage.keys();
                        let prefix = format!("rb-session-{}-", user.id);

                        for key in all_keys {
                            if key.starts_with(&prefix) && !active_session_keys.contains(&key) {
                                let _ = storage.remove(&key);
                            }
                        }

                        // Mark restoration as complete
                        restoration_in_progress_clone.set(false);
                    });
                }
            }
        }
        if !success {
            #[cfg(feature = "web")]
            web_sys::console::error_1(&format!("Failed to connect to WebSocket").into());
        }
    });

    context
}

pub fn use_session() -> SessionContext {
    use_context::<SessionContext>()
}

impl SessionContext {
    #[cfg(feature = "web")]
    fn toast(&self) -> Option<crate::app::components::toast::ToastContext> {
        self.toast
    }

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
        let result: std::option::Option<SessionStorageData> = self.get_storage().get_json(&key);

        #[cfg(feature = "web")]
        {
            web_sys::console::log_1(
                &format!(
                    "load_session_state: user_id={}, relay_id={}, session_number={}, key={}, found={}",
                    user_id,
                    relay_id,
                    session_number,
                    key,
                    result.is_some()
                )
                .into(),
            );
            if let Some(ref data) = result {
                web_sys::console::log_1(
                    &format!(
                        "  Loaded geometry: x={}, y={}, w={}, h={}, minimized={}",
                        data.geometry.x, data.geometry.y, data.geometry.width, data.geometry.height, data.minimized
                    )
                    .into(),
                );
            }
        }

        result
    }

    pub fn remove_session_storage(&self, user_id: i64, relay_id: i64, session_number: u32) {
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
                if let Some(toast) = self.toast() {
                    toast.warning("Maximum 4 concurrent SSH sessions allowed");
                }
            }
            return;
        }

        let mut new_session = Session::new(relay_name);

        // Use cascading geometry for new windows
        new_session.geometry = self.calculate_default_geometry();

        // Set z-index for new session (will be recalculated on first focus)
        let current_count = sessions.read().len();
        new_session.z_index = 60 + current_count;

        #[cfg(feature = "web")]
        let new_session_id = new_session.id.clone();
        sessions.write().push(new_session);

        // Recalculate z-indexes for all sessions
        self.recalculate_z_indexes();

        // Trigger focus for the new session
        #[cfg(feature = "web")]
        {
            let term_id = format!("term-{}", new_session_id);
            spawn(async move {
                // Wait for terminal to mount and init
                gloo_timers::future::TimeoutFuture::new(300).await;
                let _ = dioxus::document::eval(&format!("if (window.focusTerminal) window.focusTerminal('{}')", term_id)).await;
            });
        }
    }

    /// Open a session window bound to an existing SSH session number.
    /// If a matching window already exists for this relay+session_number, do nothing.
    /// If it exists, update its active_connections count instead.
    //FIXME: too many args we should probably make this a struct?
    #[allow(clippy::too_many_arguments)]
    pub fn open_restored(
        &self,
        user_id: i64,
        relay_name: String,
        relay_id: i64,
        session_number: u32,
        force_minimized: bool,
        connections: rb_types::ssh::ConnectionAmounts,
        viewers: rb_types::ssh::ConnectionAmounts,
        attachable: bool,
        target_user_id: Option<i64>,
        attached_to_username: Option<String>,
    ) {
        let mut sessions = self.sessions;

        // Check for existing session with same relay_id and session_number
        {
            let mut sessions_write = sessions.write();
            if let Some(existing) = sessions_write
                .iter_mut()
                .find(|s| s.relay_id == Some(relay_id) && s.session_number == Some(session_number))
            {
                // Session already exists - just update counts
                existing.connections = connections;
                existing.viewers = viewers;
                return;
            }
        }

        let mut new_session = Session::new(relay_name);
        new_session.session_number = Some(session_number);
        new_session.relay_id = Some(relay_id);
        new_session.connections = connections;
        new_session.viewers = viewers;
        new_session.attachable = attachable;
        new_session.target_user_id = target_user_id;
        new_session.is_admin_attached = target_user_id.is_some();
        new_session.attached_to_username = attached_to_username;

        // Load saved state if available
        if let Some(saved_state) = self.load_session_state(user_id, relay_id, session_number) {
            // Validate geometry is within screen bounds
            new_session.geometry = self.validate_geometry_on_screen(saved_state.geometry);
            new_session.minimized = saved_state.minimized;
        }

        if force_minimized {
            new_session.minimized = true;
        }

        let current_count = sessions.read().len();
        new_session.z_index = 60 + current_count;

        #[cfg(feature = "web")]
        let new_session_id = new_session.id.clone();
        sessions.write().push(new_session);

        self.recalculate_z_indexes();

        // Trigger focus for the restored session if not minimized
        if !force_minimized {
            #[cfg(feature = "web")]
            {
                let term_id = format!("term-{}", new_session_id);
                spawn(async move {
                    // Wait for terminal to mount and init
                    gloo_timers::future::TimeoutFuture::new(300).await;
                    let _ = dioxus::document::eval(&format!("if (window.focusTerminal) window.focusTerminal('{}')", term_id)).await;
                });
            }
        }
    }

    pub fn close(&self, id: &str) {
        let mut sessions = self.sessions;

        // Cancel any drag operation for this session
        if let Some(drag) = self.drag_state.read().as_ref()
            && drag.session_id == id
        {
            self.end_drag();
        }

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
            let _sessions_signal = self.sessions;

            spawn(async move {
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
        }

        #[cfg(not(feature = "web"))]
        {
            // Non-web builds: fall back to immediately closing the window
            self.close(id);
        }
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
    /// Only sets the session number if not already set (to avoid race with SessionEvent::Created).
    pub fn set_session_number_from_term_id(&self, term_id: &str, session_number: u32, relay_id: Option<i64>) {
        // term_id is expected to be "term-<session.id>"
        let prefix = "term-";
        if !term_id.starts_with(prefix) {
            return;
        }

        let window_id = &term_id[prefix.len()..];
        let mut sessions = self.sessions;
        if let Some(session) = sessions.write().iter_mut().find(|s| s.id == window_id) {
            // Only set if not already set (to avoid race with SessionEvent::Created)
            if session.session_number.is_none() {
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

    pub fn update_drag(&mut self, current_x: i32, current_y: i32) {
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

        // Snapping logic
        #[cfg(feature = "web")]
        {
            if let Some(window) = web_sys::window() {
                if let (Ok(inner_width), Ok(inner_height)) = (window.inner_width(), window.inner_height()) {
                    if let (Some(screen_width), Some(screen_height)) = (inner_width.as_f64(), inner_height.as_f64()) {
                        let screen_width = screen_width as i32;
                        let screen_height = screen_height as i32;

                        // Define snap zones (e.g. 20px from edge)
                        let snap_margin = 20;
                        let nav_height = 64; // Approximate nav bar height

                        // Use nav_height if snap_to_navbar is true, otherwise use 0
                        let top_offset = if self.snap_to_navbar.read().clone() { nav_height } else { 0 };

                        let mut preview = None;

                        if current_x < snap_margin {
                            // Left edge
                            if current_y < snap_margin {
                                // Top-Left Corner (1/4)
                                preview = Some(WindowGeometry {
                                    x: 0,
                                    y: top_offset,
                                    width: screen_width / 2,
                                    height: (screen_height - top_offset) / 2,
                                });
                            } else if current_y > screen_height - snap_margin {
                                // Bottom-Left Corner (1/4)
                                preview = Some(WindowGeometry {
                                    x: 0,
                                    y: top_offset + (screen_height - top_offset) / 2,
                                    width: screen_width / 2,
                                    height: (screen_height - top_offset) / 2,
                                });
                            } else {
                                // Left Half
                                preview = Some(WindowGeometry {
                                    x: 0,
                                    y: top_offset,
                                    width: screen_width / 2,
                                    height: screen_height - top_offset,
                                });
                            }
                        } else if current_x > screen_width - snap_margin {
                            // Right edge
                            if current_y < snap_margin {
                                // Top-Right Corner (1/4)
                                preview = Some(WindowGeometry {
                                    x: screen_width / 2,
                                    y: top_offset,
                                    width: screen_width / 2,
                                    height: (screen_height - top_offset) / 2,
                                });
                            } else if current_y > screen_height - snap_margin {
                                // Bottom-Right Corner (1/4)
                                preview = Some(WindowGeometry {
                                    x: screen_width / 2,
                                    y: top_offset + (screen_height - top_offset) / 2,
                                    width: screen_width / 2,
                                    height: (screen_height - top_offset) / 2,
                                });
                            } else {
                                // Right Half
                                preview = Some(WindowGeometry {
                                    x: screen_width / 2,
                                    y: top_offset,
                                    width: screen_width / 2,
                                    height: screen_height - top_offset,
                                });
                            }
                        } else if current_y < snap_margin {
                            // Top Edge (Full width, half height)
                            preview = Some(WindowGeometry {
                                x: 0,
                                y: top_offset,
                                width: screen_width,
                                height: (screen_height - top_offset) / 2,
                            });
                        } else if current_y > screen_height - snap_margin {
                            // Bottom Edge (Full width, half height)
                            preview = Some(WindowGeometry {
                                x: 0,
                                y: top_offset + (screen_height - top_offset) / 2,
                                width: screen_width,
                                height: (screen_height - top_offset) / 2,
                            });
                        }

                        self.snap_preview.set(preview);
                    }
                }
            }
        }
    }

    pub fn end_drag(&self) {
        let mut drag_state = self.drag_state;
        let mut snap_preview = self.snap_preview;

        // Apply snap if preview exists
        if let Some(preview) = snap_preview.read().clone()
            && let Some(state) = drag_state.read().as_ref()
        {
            self.set_geometry(&state.session_id, preview);
        }

        // Save state
        if let Some(state) = drag_state.read().as_ref() {
            let sessions = self.sessions.read();
            if let Some(session) = sessions.iter().find(|s| s.id == state.session_id)
                && let (Some(user_id), Some(relay_id), Some(session_number)) =
                    (self.get_current_user_id(), session.relay_id, session.session_number)
            {
                self.save_session_state(user_id, relay_id, session_number, session.geometry.clone(), session.minimized);
            }
        }

        snap_preview.set(None);
        drag_state.set(None);
    }

    // Resizing logic
    pub fn start_resize(&self, session_id: String, start_x: i32, start_y: i32, direction: ResizeDirection) {
        let sessions = self.sessions.read();
        if let Some(session) = sessions.iter().find(|s| s.id == session_id) {
            let mut resize_state = self.resize_state;
            resize_state.set(Some(ResizeState {
                session_id,
                start_x,
                start_y,
                initial_geometry: session.geometry.clone(),
                direction,
            }));
        }
    }

    pub fn update_resize(&mut self, current_x: i32, current_y: i32) {
        let resize_state_signal = self.resize_state;
        let state = match resize_state_signal.read().as_ref() {
            Some(s) => s.clone(),
            None => return,
        };

        let dx = current_x - state.start_x;
        let dy = current_y - state.start_y;

        let mut sessions_write = self.sessions.write();

        if let Some(session) = sessions_write.iter_mut().find(|s| s.id == state.session_id) {
            let mut new_geo = state.initial_geometry.clone();
            let min_width = 200;
            let min_height = 150;

            match state.direction {
                ResizeDirection::Right => {
                    new_geo.width = (state.initial_geometry.width + dx).max(min_width);
                }
                ResizeDirection::Bottom => {
                    new_geo.height = (state.initial_geometry.height + dy).max(min_height);
                }
                ResizeDirection::BottomRight => {
                    new_geo.width = (state.initial_geometry.width + dx).max(min_width);
                    new_geo.height = (state.initial_geometry.height + dy).max(min_height);
                }
                ResizeDirection::Left => {
                    let new_width = (state.initial_geometry.width - dx).max(min_width);
                    new_geo.x = state.initial_geometry.x + (state.initial_geometry.width - new_width);
                    new_geo.width = new_width;
                }
                ResizeDirection::BottomLeft => {
                    let new_width = (state.initial_geometry.width - dx).max(min_width);
                    new_geo.x = state.initial_geometry.x + (state.initial_geometry.width - new_width);
                    new_geo.width = new_width;
                    new_geo.height = (state.initial_geometry.height + dy).max(min_height);
                }
                ResizeDirection::Top => {
                    let new_height = (state.initial_geometry.height - dy).max(min_height);
                    new_geo.y = state.initial_geometry.y + (state.initial_geometry.height - new_height);
                    new_geo.height = new_height;
                }
                ResizeDirection::TopRight => {
                    new_geo.width = (state.initial_geometry.width + dx).max(min_width);
                    let new_height = (state.initial_geometry.height - dy).max(min_height);
                    new_geo.y = state.initial_geometry.y + (state.initial_geometry.height - new_height);
                    new_geo.height = new_height;
                }
                ResizeDirection::TopLeft => {
                    let new_width = (state.initial_geometry.width - dx).max(min_width);
                    new_geo.x = state.initial_geometry.x + (state.initial_geometry.width - new_width);
                    new_geo.width = new_width;

                    let new_height = (state.initial_geometry.height - dy).max(min_height);
                    new_geo.y = state.initial_geometry.y + (state.initial_geometry.height - new_height);
                    new_geo.height = new_height;
                }
            }

            session.geometry = new_geo;
        }
    }

    pub fn end_resize(&self) {
        let mut resize_state = self.resize_state;

        // Save the final state
        if let Some(state) = resize_state.read().as_ref() {
            let sessions = self.sessions.read();
            if let Some(session) = sessions.iter().find(|s| s.id == state.session_id)
                && let (Some(user_id), Some(relay_id), Some(session_number)) =
                    (self.get_current_user_id(), session.relay_id, session.session_number)
            {
                self.save_session_state(user_id, relay_id, session_number, session.geometry.clone(), session.minimized);
            }
        }

        resize_state.set(None);
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

    pub fn set_active_connections(&self, id: &str, web: u32, ssh: u32) {
        let mut sessions = self.sessions;
        if let Some(session) = sessions.write().iter_mut().find(|s| s.id == id) {
            session.connections = rb_types::ssh::ConnectionAmounts { web, ssh };
        }
    }

    /// Calculate default geometry for a new window with cascading offset
    fn calculate_default_geometry(&self) -> WindowGeometry {
        let sessions = self.sessions.read();
        let existing_count = sessions.len();

        // Base position for first window (centered)
        let base_x = 100;
        let base_y = 100;

        // Cascade offset (30px each direction)
        let offset = 30 * existing_count as i32;

        WindowGeometry {
            x: base_x + offset,
            y: base_y + offset,
            width: 800,
            height: 600,
        }
    }
}
