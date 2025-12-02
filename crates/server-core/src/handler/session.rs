//! Terminal session and TUI management.

use std::sync::Arc;

use rb_types::{relay::HostkeyReview, ssh::TUIApplication};
use russh::{ChannelId, Pty, server::Session};
use tokio::sync::{broadcast, mpsc};
use tracing::info;
use tui_core::{AppSession, backend::RemoteBackend, utils::desired_rect};

use super::ServerHandler;
use crate::{create_app_by_name, create_management_app, create_management_app_with_tab, create_relay_selector_app};

impl ServerHandler {
    /// Send the closing sequence, tear down terminal state, and emit disconnect logs.
    pub(super) fn handle_exit(&mut self, session: &mut Session, channel: ChannelId) -> Result<(), russh::Error> {
        self.drop_terminal();
        if self.alt_screen {
            self.leave_alt_screen(session, channel)?;
        }

        self.send_line(session, channel, "Bye!")?;
        session.exit_status_request(channel, 0)?;
        session.close(channel)?;
        self.channel = None;

        // Clear active app presence (fire-and-forget)
        self.set_active_app_on_session(None);

        // Remove session from registry
        if let Some(session_number) = self.session_number
            && let Some(user_id) = self.user_id
        {
            let relay_id = self.active_relay_id.unwrap_or(0);
            let registry = self.registry.clone();
            tokio::spawn(async move {
                // Check if session is detached before removing
                let should_remove = if let Some(session) = registry.get_session(user_id, relay_id, session_number).await {
                    let state = session.state.read().await;
                    !matches!(*state, crate::sessions::SessionState::Detached { .. })
                } else {
                    true
                };

                if should_remove {
                    if let Some(session) = registry.get_session(user_id, relay_id, session_number).await {
                        session.close().await;
                    }
                    registry.remove_session(user_id, relay_id, session_number).await;
                }
            });
        }

        self.log_disconnect("client requested exit");
        Ok(())
    }

    /// Initialise the shell, including a fresh TUI instance and remote terminal.
    pub(super) async fn init_shell(&mut self) -> Result<(), russh::Error> {
        // FIXME: this feels like it should be a helper  that we can call from anywhere since its useful for TUI and Web, etc
        // Check for management access via claims
        let username = self.username.as_deref().unwrap_or("unknown");
        let (can_manage, user_id) = Self::check_management_access(username).await;
        self.user_id = user_id;

        let (app, app_name, active_app): (Box<dyn tui_core::TuiApp>, &str, Option<TUIApplication>) = if can_manage {
            (
                Box::new(
                    create_management_app(None)
                        .await
                        .map_err(|e| russh::Error::IO(std::io::Error::other(e)))?,
                ),
                "ManagementApp",
                Some(TUIApplication::Management),
            )
        } else {
            (
                Box::new(
                    create_relay_selector_app(self.username.as_deref())
                        .await
                        .map_err(|e| russh::Error::IO(std::io::Error::other(e)))?,
                ),
                "RelaySelectorApp",
                Some(TUIApplication::RelaySelector),
            )
        };

        let username = self.username.as_deref().unwrap_or("unknown");
        let peer_addr = if let Some(peer_addr) = self.peer_addr {
            format!("{:?}", peer_addr)
        } else {
            "unknown".to_string()
        };
        info!(app_name, username, peer_addr, "tui launched");

        // Register the session
        // Create channels for the TUI session
        let (input_tx, _input_rx) = mpsc::channel(100);
        let (output_tx, _output_rx) = broadcast::channel(100);

        // Use legacy backend for TUI sessions (relay_id = 0)
        let backend = Arc::new(crate::sessions::session_backend::LegacyChannelBackend::new(input_tx, output_tx));

        let user_id_value = user_id.unwrap_or(0);
        let ip_address = self.peer_addr.map(|addr| addr.ip().to_string());

        let (session_number, _session) = self
            .registry
            .create_next_session(
                user_id_value,
                0, // relay_id = 0 for TUI sessions
                "Management".to_string(),
                username.to_string(),
                backend,
                rb_types::ssh::SessionOrigin::Ssh { user_id: user_id_value },
                ip_address,
                None,
            )
            .await;
        self.session_number = Some(session_number);
        self.tui_session_number = Some(session_number);
        self.active_relay_id = Some(0);

        // Surface the active TUI app to observers
        if let Some(app_kind) = active_app {
            self.set_active_app_on_session(Some(app_kind));
        }

        let rect = desired_rect(self.view_size());
        let backend = RemoteBackend::new(rect);
        let session = AppSession::new(app, backend).map_err(|e| russh::Error::IO(std::io::Error::other(e)))?;
        self.app_session = Some(session);
        self.last_was_cr = false;
        Ok(())
    }

    /// Render the TUI and forward any emitted bytes to the SSH client.
    pub(super) fn render_terminal(&mut self, session: &mut Session, channel: ChannelId) -> Result<(), russh::Error> {
        let rect = desired_rect(self.view_size());
        if let Some(app_session) = self.app_session.as_mut() {
            if app_session.backend().area() != rect {
                app_session.backend_mut().set_size(rect);
                app_session.resize(rect).map_err(|e| russh::Error::IO(std::io::Error::other(e)))?;
            }
            app_session.render().map_err(|e| russh::Error::IO(std::io::Error::other(e)))?;
            self.flush_terminal(session, channel)?;
        }
        Ok(())
    }

    pub(super) fn show_status_line(
        &mut self,
        status: tui_core::app::StatusLine,
        session: &mut Session,
        channel: ChannelId,
    ) -> Result<(), russh::Error> {
        if let Some(app_session) = self.app_session.as_mut() {
            app_session.set_status(Some(status));
            self.render_terminal(session, channel)?;
        }
        Ok(())
    }

    pub(super) async fn switch_app(&mut self, app_name: &str, session: &mut Session, channel: ChannelId) -> Result<(), russh::Error> {
        let username = self.username.as_deref().unwrap_or("unknown");
        let peer_addr = if let Some(peer_addr) = self.peer_addr {
            format!("{:?}", peer_addr)
        } else {
            "unknown".to_string()
        };
        info!(app_name, username, peer_addr, "tui switched");

        let result = self.show_app_by_name(app_name, None, session, channel).await;
        if result.is_ok() {
            self.set_active_app_on_session(Self::map_app_name(app_name));
        }
        result
    }

    pub(super) async fn reload_management_app(
        &mut self,
        session: &mut Session,
        channel: ChannelId,
        tab: usize,
        review: Option<HostkeyReview>,
    ) -> Result<(), russh::Error> {
        let app = create_management_app_with_tab(tab, review)
            .await
            .map_err(|e| russh::Error::IO(std::io::Error::other(e)))?;
        if let Some(app_session) = self.app_session.as_mut() {
            let _ = app_session.set_app(Box::new(app));
            self.render_terminal(session, channel)?;
        }
        Ok(())
    }

    /// Helper: set the current TUI app and render+flush, reusing the existing session if present.
    pub(super) fn set_and_render_app(
        &mut self,
        app: Box<dyn tui_core::TuiApp>,
        session: &mut Session,
        channel: ChannelId,
    ) -> Result<(), russh::Error> {
        if let Some(app_session) = self.app_session.as_mut() {
            app_session.set_app(app).map_err(|e| russh::Error::IO(std::io::Error::other(e)))?;
            app_session.render().map_err(|e| russh::Error::IO(std::io::Error::other(e)))?;
            self.flush_terminal(session, channel)?;
            Ok(())
        } else {
            let rect = desired_rect(self.view_size());
            let backend = RemoteBackend::new(rect);
            let mut new_session = AppSession::new(app, backend).map_err(|e| russh::Error::IO(std::io::Error::other(e)))?;
            new_session.render().map_err(|e| russh::Error::IO(std::io::Error::other(e)))?;
            self.app_session = Some(new_session);
            self.flush_terminal(session, channel)?;
            Ok(())
        }
    }

    /// Helper: build an app by name (Management or RelaySelector for current user) and show it.
    pub(super) async fn show_app_by_name(
        &mut self,
        name: &str,
        selected_tab: Option<usize>,
        session: &mut Session,
        channel: ChannelId,
    ) -> Result<(), russh::Error> {
        let app = create_app_by_name(self.username.as_deref(), name, selected_tab)
            .await
            .map_err(|e| russh::Error::IO(std::io::Error::other(e)))?;
        let result = self.set_and_render_app(app, session, channel);
        if result.is_ok() {
            self.set_active_app_on_session(Self::map_app_name(name));
        }
        result
    }

    /// Push accumulated escape sequences toward the remote SSH channel.
    pub(super) fn flush_terminal(&mut self, session: &mut Session, channel: ChannelId) -> Result<(), russh::Error> {
        if let Some(app_session) = self.app_session.as_ref() {
            let bytes = app_session.backend().drain_bytes();
            if !bytes.is_empty() {
                self.send_bytes(session, channel, &bytes)?;
            }
        }
        Ok(())
    }

    pub(super) fn drop_terminal(&mut self) {
        self.app_session = None;
    }

    fn set_active_app_on_session(&self, app: Option<TUIApplication>) {
        if let (Some(user_id), Some(session_number)) = (self.user_id, self.session_number) {
            let relay_id = self.active_relay_id.unwrap_or(0);
            let registry = self.registry.clone();
            tokio::spawn(async move {
                if let Some(session) = registry.get_session(user_id, relay_id, session_number).await {
                    session.set_active_app(app).await;
                }
            });
        }
    }

    fn map_app_name(name: &str) -> Option<TUIApplication> {
        match name {
            "Management" | "ManagementApp" => Some(TUIApplication::Management),
            "RelaySelector" | "RelaySelectorApp" => Some(TUIApplication::RelaySelector),
            _ => None,
        }
    }

    /// Remove the TUI session from the registry (fire-and-forget).
    pub(super) fn end_tui_session(&mut self) {
        if let (Some(user_id), Some(tui_number)) = (self.user_id, self.tui_session_number) {
            // TUI sessions always use relay_id 0
            let registry = self.registry.clone();
            self.tui_session_number = None;
            tokio::spawn(async move {
                if let Some(session) = registry.get_session(user_id, 0, tui_number).await {
                    session.close().await;
                }
                registry.remove_session(user_id, 0, tui_number).await;
            });
        }
    }

    /// Switch the remote PTY into the alternate screen buffer once per session.
    pub(super) fn enter_alt_screen(&mut self, session: &mut Session, channel: ChannelId) -> Result<(), russh::Error> {
        if !self.alt_screen {
            self.send_bytes(session, channel, b"\x1b[?1049h\x1b[2J\x1b[H")?;
            self.alt_screen = true;
        }
        Ok(())
    }

    /// Restore the remote PTY to the main screen when the session ends.
    pub(super) fn leave_alt_screen(&mut self, session: &mut Session, channel: ChannelId) -> Result<(), russh::Error> {
        if self.alt_screen {
            self.send_bytes(session, channel, b"\x1b[?1049l")?;
            self.alt_screen = false;
        }
        Ok(())
    }

    /// Return the most recently negotiated PTY size (falling back to 80x24).
    pub(super) fn view_size(&self) -> (u16, u16) {
        self.pty_size.unwrap_or((80, 24))
    }

    /// Persist the PTY size reported by the client, clamping to reasonable bounds.
    pub(super) fn set_pty_size(&mut self, cols: u32, rows: u32) {
        let cols = cols.clamp(1, u16::MAX as u32) as u16;
        let rows = rows.clamp(1, u16::MAX as u32) as u16;
        self.pty_size = Some((cols, rows));
        let _ = self.size_updates.send((cols, rows));
    }

    pub(super) async fn handle_shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), russh::Error> {
        session.channel_success(channel)?;
        self.channel = Some(channel);
        if let Some(relay_name) = self.relay_target.clone() {
            // Permission check and connection scaffold
            self.connect_to_relay(session, channel, &relay_name).await
        } else {
            self.init_shell().await?;
            self.enter_alt_screen(session, channel)?;
            self.render_terminal(session, channel)
        }
    }

    pub(super) async fn handle_exec_request(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), russh::Error> {
        session.channel_success(channel)?;
        self.channel = Some(channel);
        if !data.is_empty() {
            let cmd = String::from_utf8_lossy(data).trim().to_string();
            if !cmd.is_empty() {
                let response = format!("exec received: {cmd}");
                self.send_line(session, channel, &response)?;
            }
        }
        self.handle_exit(session, channel)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn handle_pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        self.set_pty_size(col_width, row_height);
        session.channel_success(channel)?;
        self.render_terminal(session, channel)
    }

    pub(super) async fn handle_window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        self.set_pty_size(col_width, row_height);
        session.channel_success(channel)?;
        if self.relay_handle.is_some() {
            // Relay mode: size updates are propagated asynchronously by the bridge task.
            Ok(())
        } else {
            self.render_terminal(session, channel)
        }
    }

    pub(super) async fn handle_channel_close(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), russh::Error> {
        if Some(channel) == self.channel {
            self.relay_handle = None;
            if self.app_session.is_some() {
                self.leave_alt_screen(session, channel)?;
            }

            self.drop_terminal();
            self.channel = None;
            self.set_active_app_on_session(None);
            // Mark session closed for observers
            if let (Some(user_id), Some(session_number)) = (self.user_id, self.session_number) {
                let relay_id = self.active_relay_id.unwrap_or(0);
                let registry = self.registry.clone();
                tokio::spawn(async move {
                    if let Some(session) = registry.get_session(user_id, relay_id, session_number).await {
                        session.close().await;
                    }
                    registry.remove_session(user_id, relay_id, session_number).await;
                });
            }
            self.log_disconnect("channel closed");
        }
        Ok(())
    }
}
