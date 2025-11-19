use ratatui::Frame;

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
    /// Delete a credential by name
    DeleteCredential(String),
    /// Unassign a shared credential from a relay host by hostname
    UnassignCredential(String),
    /// Assign a shared credential to a relay host by hostname
    AssignCredential { host: String, cred_name: String },
}

// Backward compatibility constants (deprecated)
pub const CONTINUE: AppAction = AppAction::Continue;
pub const RE_RENDER: AppAction = AppAction::Render;
