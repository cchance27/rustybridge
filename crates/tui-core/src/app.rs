use ratatui::Frame;

use crate::TuiResult;

/// Core trait that all TUI applications must implement.
/// 
/// This trait provides a clean interface for interactive terminal applications
/// that can run both over SSH (remote) and standalone (local terminal).
pub trait TuiApp: Send {
    /// Handle raw input bytes from the user.
    /// 
    /// Returns `true` if the input was handled and should trigger a re-render,
    /// `false` if the input was ignored.
    fn handle_input(&mut self, input: &[u8]) -> TuiResult<bool>;
    
    /// Render the app's current state to the provided frame.
    /// 
    /// This is called during the render cycle and should use ratatui's
    /// widget API to draw the UI.
    fn render(&self, frame: &mut Frame);
    
    /// Optional periodic tick handler for time-based updates.
    /// 
    /// Returns `true` if the tick resulted in a state change that requires re-render.
    fn tick(&mut self) -> TuiResult<bool> {
        Ok(false)
    }
    
    /// Check if the app has requested to exit.
    fn should_exit(&self) -> bool;
    
    /// Get a human-readable name for this app (for logging/debugging).
    fn name(&self) -> &str {
        "TuiApp"
    }
}

/// Result of an app operation indicating whether re-render is needed
pub type AppAction = bool;

pub const CONTINUE: AppAction = false;
pub const RE_RENDER: AppAction = true;
