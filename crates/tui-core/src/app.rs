use ratatui::Frame;
use rb_types::relay::HostkeyReview;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusKind {
    Info,
    Success,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusLine {
    pub text: String,
    pub kind: StatusKind,
}

use crate::TuiResult;

/// Core trait that all TUI applications must implement.
///
/// This trait provides a clean interface for interactive terminal applications
/// that can run both over SSH (remote) and standalone (local terminal).
pub trait TuiApp: Send {
    /// Handle raw input bytes from the user.
    fn handle_input(&mut self, input: &[u8]) -> TuiResult<AppAction>;

    /// Render the app's current state to the provided frame.
    ///
    /// This is called during the render cycle and should use ratatui's
    /// widget API to draw the UI.
    ///
    /// `uptime` is the duration since the session started.
    fn render(&mut self, frame: &mut Frame, uptime: std::time::Duration);

    /// Optional periodic tick handler for time-based updates.
    fn tick(&mut self) -> TuiResult<AppAction> {
        Ok(AppAction::Continue)
    }

    /// Check if the app has requested to exit.
    /// Deprecated: Use AppAction::Exit return value instead.
    fn should_exit(&self) -> bool {
        false
    }

    /// Get a human-readable name for this app (for logging/debugging).
    fn name(&self) -> &str {
        "TuiApp"
    }

    /// Optional: Set a session-scoped status/flash message for this app instance.
    /// Defaults to no-op; apps can override to display a message.
    fn set_status(&mut self, _status: Option<StatusLine>) {}

    /// Back-compat helper if callers only have text (defaults to Error style).
    fn set_status_message(&mut self, msg: Option<String>) {
        if let Some(m) = msg {
            self.set_status(Some(StatusLine {
                text: m,
                kind: StatusKind::Error,
            }));
        } else {
            self.set_status(None);
        }
    }
}

/// Result of an app operation indicating the next step
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppAction {
    /// Do nothing, wait for next event
    Continue,
    /// Trigger a re-render
    Render,
    /// Exit the application
    Exit,
    /// Switch to another application by name
    SwitchTo(String),
    /// Connect to a specific relay
    ConnectToRelay { id: i64, name: String },
    /// Add a new relay host
    AddRelay(crate::apps::relay_selector::RelayItem),
    /// Update an existing relay host
    UpdateRelay(crate::apps::relay_selector::RelayItem),
    /// Delete a relay host by ID
    DeleteRelay(i64),
    /// Add a new credential
    AddCredential(crate::apps::management::CredentialSpec),
    /// Delete a credential by ID
    DeleteCredential(i64),
    /// Unassign a shared credential from a relay host by host ID
    UnassignCredential(i64),
    /// Assign a shared credential to a relay host by IDs
    AssignCredential { host_id: i64, cred_id: i64 },
    /// Fetch the current host key from the selected relay host (no store yet)
    FetchHostkey { id: i64, name: String },
    /// Store the last fetched host key for the selected relay host (replace if exists)
    StoreHostkey { id: i64, name: String, key: String },
    /// Cancel any pending hostkey review for the selected relay host
    CancelHostkey { id: i64, name: String },
    /// Propagate an error message to the UI
    Error(String),
    /// Review a fetched hostkey
    ReviewHostkey(HostkeyReview),
    /// Display an authentication prompt to the user (for keyboard-interactive auth)
    AuthPrompt { prompt: String, echo: bool },
    /// Opaque backend event (used for internal signaling like connection completion)
    BackendEvent(BackendEventPayload),
}

#[derive(Debug, Clone)]
pub struct BackendEventPayload(pub std::sync::Arc<dyn std::any::Any + Send + Sync>);

impl PartialEq for BackendEventPayload {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for BackendEventPayload {}

// Backward compatibility constants (deprecated)
pub const CONTINUE: AppAction = AppAction::Continue;
pub const RE_RENDER: AppAction = AppAction::Render;
