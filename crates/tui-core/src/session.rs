// Session management for TUI apps over SSH

use std::time::Instant;

use ratatui::{Terminal, backend::Backend, layout::Rect};

use crate::{TuiApp, TuiResult};

/// Manages a TUI app session including rendering and lifecycle
pub struct AppSession<B: Backend> {
    app: Box<dyn TuiApp>,
    terminal: Terminal<B>,
    connected_at: Instant,
    last_render: Instant,
}

impl<B: Backend> AppSession<B> {
    /// Create a new app session with the given app and backend
    pub fn new(app: Box<dyn TuiApp>, backend: B) -> TuiResult<Self> {
        let terminal = Terminal::new(backend)?;
        Ok(Self {
            app,
            terminal,
            connected_at: Instant::now(),
            last_render: Instant::now(),
        })
    }

    /// Replace the active app while keeping the same terminal/back-end context.
    pub fn set_app(&mut self, app: Box<dyn TuiApp>) -> TuiResult<()> {
        self.app = app;
        self.connected_at = Instant::now();
        self.last_render = Instant::now();
        Ok(())
    }

    /// Handle window resize
    pub fn resize(&mut self, area: Rect) -> TuiResult<()> {
        self.terminal.resize(area)?;
        Ok(())
    }

    /// Handle user input
    pub fn handle_input(&mut self, data: &[u8]) -> TuiResult<crate::AppAction> {
        self.app.handle_input(data)
    }

    /// Handle periodic tick
    pub fn tick(&mut self) -> TuiResult<crate::AppAction> {
        self.app.tick()
    }

    /// Render the app
    pub fn render(&mut self) -> TuiResult<()> {
        let uptime = self.connected_at.elapsed();
        self.terminal.draw(|frame| {
            self.app.render(frame, uptime);
        })?;
        self.last_render = Instant::now();
        Ok(())
    }

    /// Set a session-scoped status/flash message on the current app (if supported)
    pub fn set_status_message(&mut self, msg: Option<String>) {
        self.app.set_status_message(msg);
    }

    /// Set a typed status on the current app (if supported)
    pub fn set_status(&mut self, status: Option<crate::app::StatusLine>) {
        self.app.set_status(status);
    }

    /// Clear the terminal screen
    pub fn clear(&mut self) -> TuiResult<()> {
        self.terminal.clear()?;
        Ok(())
    }

    /// Check if app should exit
    pub fn should_exit(&self) -> bool {
        self.app.should_exit()
    }

    /// Get elapsed time since session started
    pub fn uptime(&self) -> std::time::Duration {
        self.connected_at.elapsed()
    }

    pub fn backend(&self) -> &B {
        self.terminal.backend()
    }

    pub fn backend_mut(&mut self) -> &mut B {
        self.terminal.backend_mut()
    }
}
