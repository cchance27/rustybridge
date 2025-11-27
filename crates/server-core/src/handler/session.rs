//! Terminal session and TUI management.

use rb_types::relay::HostkeyReview;
use russh::{ChannelId, Pty, server::Session};
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
        self.log_disconnect("client requested exit");
        Ok(())
    }

    /// Initialise the shell, including a fresh TUI instance and remote terminal.
    pub(super) async fn init_shell(&mut self) -> Result<(), russh::Error> {
        let username = self.username.as_deref().unwrap_or("unknown");

        // FIXME: this feels like it should be a helper  that we can call from anywhere since its useful for TUI and Web, etc
        // Check for management access via claims
        // Users with any *:view claim or wildcard get management access
        let can_manage = if let Ok(handle) = state_store::server_db().await {
            let pool = handle.into_pool();
            if let Ok(claims) = state_store::get_user_claims(&pool, username).await {
                claims.iter().any(|c| {
                    let claim_str = c.to_string();
                    claim_str == "*" || claim_str.ends_with(":view")
                })
            } else {
                false
            }
        } else {
            false
        };

        let (app, app_name): (Box<dyn tui_core::TuiApp>, &str) = if can_manage {
            (
                Box::new(
                    create_management_app(None)
                        .await
                        .map_err(|e| russh::Error::IO(std::io::Error::other(e)))?,
                ),
                "ManagementApp",
            )
        } else {
            (
                Box::new(
                    create_relay_selector_app(self.username.as_deref())
                        .await
                        .map_err(|e| russh::Error::IO(std::io::Error::other(e)))?,
                ),
                "RelaySelectorApp",
            )
        };

        let username = self.username.as_deref().unwrap_or("unknown");
        let peer_addr = if let Some(peer_addr) = self.peer_addr {
            format!("{:?}", peer_addr)
        } else {
            "unknown".to_string()
        };
        info!(app_name, username, peer_addr, "tui launched");

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

        self.show_app_by_name(app_name, None, session, channel).await
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
        self.set_and_render_app(app, session, channel)
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
            self.log_disconnect("channel closed");
        }
        Ok(())
    }
}
