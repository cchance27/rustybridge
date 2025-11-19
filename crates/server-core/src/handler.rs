//! SSH handler implementation that drives per-connection state and the echo TUI.

use std::{net::SocketAddr, time::Instant};

use russh::{
    Channel, ChannelId, CryptoVec, Pty, server::{self as ssh_server, Auth, Session}
};
use tokio::sync::watch;
use tracing::{info, warn};
use tui_core::{AppAction, AppSession, backend::RemoteBackend, utils::desired_rect};

use crate::auth::{self, AuthDecision, LoginTarget, parse_login_target};

/// Tracks the lifecycle of a single SSH session, including authentication, PTY events, and TUI I/O.
pub(super) struct ServerHandler {
    pub(super) peer_addr: Option<SocketAddr>,
    username: Option<String>,
    relay_target: Option<String>,
    relay_handle: Option<crate::relay::RelayHandle>,
    channel: Option<ChannelId>,
    closed: bool,
    connected_at: Instant,
    app_session: Option<AppSession<RemoteBackend>>,
    last_was_cr: bool,
    pty_size: Option<(u16, u16)>,
    alt_screen: bool,
    size_updates: watch::Sender<(u16, u16)>,
}

impl ServerHandler {
    /// Create a handler bound to the connecting client's socket address.
    pub(super) fn new(peer_addr: Option<SocketAddr>) -> Self {
        let (size_updates, _) = watch::channel((80, 24));
        Self {
            peer_addr,
            username: None,
            relay_target: None,
            relay_handle: None,
            channel: None,
            closed: false,
            connected_at: Instant::now(),
            app_session: None,
            last_was_cr: false,
            pty_size: None,
            alt_screen: false,
            size_updates,
        }
    }

    fn send_bytes(&self, session: &mut Session, channel: ChannelId, bytes: &[u8]) -> Result<(), russh::Error> {
        let mut payload = CryptoVec::new();
        payload.extend(bytes);
        session.data(channel, payload)
    }

    fn send_line(&self, session: &mut Session, channel: ChannelId, line: &str) -> Result<(), russh::Error> {
        let mut payload = CryptoVec::new();
        payload.extend(line.as_bytes());
        payload.extend(b"\r\n");
        session.data(channel, payload)
    }

    fn log_disconnect(&mut self, reason: &str) {
        if self.closed {
            return;
        }
        self.closed = true;

        let elapsed = self.connected_at.elapsed();
        info!(
            peer = %display_addr(self.peer_addr),
            user = %self.username.as_deref().unwrap_or("<unauthenticated>"),
            duration = ?elapsed,
            reason,
            "client disconnected",
        );
    }

    /// Send the closing sequence, tear down terminal state, and emit disconnect logs.
    fn handle_exit(&mut self, session: &mut Session, channel: ChannelId) -> Result<(), russh::Error> {
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

    /// Initialise the echo shell, including a fresh TUI instance and remote terminal.
    async fn init_shell(&mut self) -> Result<(), russh::Error> {
        let (app, app_name): (Box<dyn tui_core::TuiApp>, &str) = if self.username.as_deref() == Some("admin") {
            (
                Box::new(
                    crate::create_management_app()
                        .await
                        .map_err(|e| russh::Error::IO(std::io::Error::other(e)))?,
                ),
                "ManagementApp",
            )
        } else {
            (
                Box::new(
                    crate::create_relay_selector_app(self.username.as_deref())
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
    fn render_terminal(&mut self, session: &mut Session, channel: ChannelId) -> Result<(), russh::Error> {
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

    async fn switch_app(&mut self, app_name: &str, session: &mut Session, channel: ChannelId) -> Result<(), russh::Error> {
        let username = self.username.as_deref().unwrap_or("unknown");
        let peer_addr = if let Some(peer_addr) = self.peer_addr {
            format!("{:?}", peer_addr)
        } else {
            "unknown".to_string()
        };
        info!(app_name, username, peer_addr, "tui switched");

        let app: Box<dyn tui_core::TuiApp> = match app_name {
            "Management" => Box::new(
                crate::create_management_app()
                    .await
                    .map_err(|e| russh::Error::IO(std::io::Error::other(e)))?,
            ),
            _ => Box::new(
                crate::create_relay_selector_app(self.username.as_deref())
                    .await
                    .map_err(|e| russh::Error::IO(std::io::Error::other(e)))?,
            ),
        };

        let rect = desired_rect(self.view_size());
        let backend = RemoteBackend::new(rect);
        let mut new_session = AppSession::new(app, backend).map_err(|e| russh::Error::IO(std::io::Error::other(e)))?;

        new_session.clear().map_err(|e| russh::Error::IO(std::io::Error::other(e)))?;
        new_session.render().map_err(|e| russh::Error::IO(std::io::Error::other(e)))?;

        self.app_session = Some(new_session);
        self.flush_terminal(session, channel)?;
        Ok(())
    }

    /// Push accumulated escape sequences toward the remote SSH channel.
    fn flush_terminal(&mut self, session: &mut Session, channel: ChannelId) -> Result<(), russh::Error> {
        if let Some(app_session) = self.app_session.as_ref() {
            let bytes = app_session.backend().drain_bytes();
            if !bytes.is_empty() {
                self.send_bytes(session, channel, &bytes)?;
            }
        }
        Ok(())
    }

    fn drop_terminal(&mut self) {
        self.app_session = None;
    }

    /// Switch the remote PTY into the alternate screen buffer once per session.
    fn enter_alt_screen(&mut self, session: &mut Session, channel: ChannelId) -> Result<(), russh::Error> {
        if !self.alt_screen {
            self.send_bytes(session, channel, b"\x1b[?1049h\x1b[2J\x1b[H")?;
            self.alt_screen = true;
        }
        Ok(())
    }

    /// Restore the remote PTY to the main screen when the session ends.
    fn leave_alt_screen(&mut self, session: &mut Session, channel: ChannelId) -> Result<(), russh::Error> {
        if self.alt_screen {
            self.send_bytes(session, channel, b"\x1b[?1049l")?;
            self.alt_screen = false;
        }
        Ok(())
    }

    /// Return the most recently negotiated PTY size (falling back to 80x24).
    fn view_size(&self) -> (u16, u16) {
        self.pty_size.unwrap_or((80, 24))
    }

    /// Persist the PTY size reported by the client, clamping to reasonable bounds.
    fn set_pty_size(&mut self, cols: u32, rows: u32) {
        let cols = cols.clamp(1, u16::MAX as u32) as u16;
        let rows = rows.clamp(1, u16::MAX as u32) as u16;
        self.pty_size = Some((cols, rows));
        let _ = self.size_updates.send((cols, rows));
    }

    async fn connect_to_relay(&mut self, session: &mut Session, channel: ChannelId, relay_name: &str) -> Result<(), russh::Error> {
        use state_store::{fetch_relay_host_by_name, fetch_relay_host_options, server_db, user_has_relay_access};
        let username = self.username.clone().unwrap_or_else(|| "<unknown>".into());
        match server_db().await {
            Ok(handle) => {
                let pool = handle.into_pool();
                match fetch_relay_host_by_name(&pool, relay_name).await {
                    Ok(Some(host)) => {
                        match user_has_relay_access(&pool, &username, host.id).await {
                            Ok(true) => {
                                let _ = self.send_line(
                                    session,
                                    channel,
                                    &format!("user authenticated; connecting to relay host '{}'...", relay_name),
                                );
                                let options = match fetch_relay_host_options(&pool, host.id).await {
                                    Ok(raw) => {
                                        // Decrypt any encrypted option values.
                                        let mut out = std::collections::HashMap::with_capacity(raw.len());
                                        for (k, v) in raw.into_iter() {
                                            match crate::secrets::decrypt_string_if_encrypted(&v) {
                                                Ok(val) => {
                                                    out.insert(k, val);
                                                }
                                                Err(err) => {
                                                    let _ = self.send_line(
                                                        session,
                                                        channel,
                                                        &format!("internal error decrypting option '{k}': {err}"),
                                                    );
                                                    return self.handle_exit(session, channel);
                                                }
                                            }
                                        }
                                        out
                                    }
                                    Err(err) => {
                                        let _ = self.send_line(session, channel, &format!("internal error loading relay options: {err}"));
                                        return self.handle_exit(session, channel);
                                    }
                                };
                                let server_handle = session.handle();
                                let size_rx = self.size_updates.subscribe();
                                let initial_size = self.view_size();
                                match crate::relay::start_bridge(
                                    server_handle,
                                    channel,
                                    &host,
                                    &username,
                                    initial_size,
                                    size_rx,
                                    &options,
                                    self.peer_addr,
                                )
                                .await
                                {
                                    Ok(handle) => {
                                        self.relay_handle = Some(handle);
                                        Ok(())
                                    }
                                    Err(err) => {
                                        let _ = self.send_line(session, channel, &format!("failed to start relay: {err}"));
                                        self.handle_exit(session, channel)
                                    }
                                }
                            }
                            Ok(false) => {
                                warn!(
                                    peer = %display_addr(self.peer_addr),
                                    user = %username,
                                    relay = %relay_name,
                                    "relay access denied for user"
                                );
                                let _ = self.send_line(
                                    session,
                                    channel,
                                    &format!("access denied: user '{}' is not permitted to connect to '{}'", username, relay_name),
                                );
                                self.handle_exit(session, channel)
                            }
                            Err(err) => {
                                let _ = self.send_line(session, channel, &format!("internal error checking access: {err}"));
                                self.handle_exit(session, channel)
                            }
                        }
                    }
                    Ok(None) => {
                        warn!(
                            peer = %display_addr(self.peer_addr),
                            user = %username,
                            relay = %relay_name,
                            "relay host not found"
                        );
                        let _ = self.send_line(session, channel, &format!("unknown relay host '{}'", relay_name));
                        self.handle_exit(session, channel)
                    }
                    Err(err) => {
                        let _ = self.send_line(session, channel, &format!("internal error resolving relay host: {err}"));
                        self.handle_exit(session, channel)
                    }
                }
            }
            Err(err) => {
                let _ = self.send_line(session, channel, &format!("internal error opening server database: {err}"));
                self.handle_exit(session, channel)
            }
        }
    }
}

impl Drop for ServerHandler {
    fn drop(&mut self) {
        if !self.closed {
            self.log_disconnect("connection dropped");
        }
    }
}

impl ssh_server::Handler for ServerHandler {
    type Error = russh::Error;

    async fn channel_open_session(&mut self, channel: Channel<ssh_server::Msg>, _session: &mut Session) -> Result<bool, Self::Error> {
        self.channel = Some(channel.id());
        Ok(true)
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        let login: LoginTarget = parse_login_target(user);
        let decision = auth::authenticate_password(&login, password)
            .await
            .map_err(|e| russh::Error::IO(std::io::Error::other(e)))?;

        match decision {
            AuthDecision::Accept => {
                self.username = Some(login.username.clone());
                self.relay_target = login.relay.clone();
                info!(
                    peer = %display_addr(self.peer_addr),
                    user = %login.username,
                    relay = %login.relay.as_deref().unwrap_or("<none>"),
                    "password authentication accepted"
                );
                Ok(Auth::Accept)
            }
            AuthDecision::Reject => {
                warn!(
                    peer = %display_addr(self.peer_addr),
                    user = %login.username,
                    "password authentication rejected"
                );
                Ok(Auth::reject())
            }
        }
    }

    async fn auth_succeeded(&mut self, _session: &mut Session) -> Result<(), Self::Error> {
        info!(
            peer = %display_addr(self.peer_addr),
            user = %self.username.as_deref().unwrap_or("<unknown>"),
            "user authenticated"
        );
        Ok(())
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
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

    async fn exec_request(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
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

    async fn data(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        if Some(channel) != self.channel {
            return Ok(());
        }

        if let Some(relay) = self.relay_handle.as_ref() {
            if !data.is_empty() {
                relay.send(data.to_vec());
            }
            return Ok(());
        }

        if let Some(app_session) = self.app_session.as_mut() {
            let action = app_session
                .handle_input(data)
                .map_err(|e| russh::Error::IO(std::io::Error::other(e)))?;
            match action {
                AppAction::Exit => {
                    self.handle_exit(session, channel)?;
                }
                AppAction::Render => {
                    self.render_terminal(session, channel)?;
                }
                AppAction::SwitchTo(app_name) => {
                    self.switch_app(&app_name, session, channel).await?;
                }
                AppAction::ConnectToRelay { id: _, name } => {
                    self.relay_target = Some(name.clone());
                    self.drop_terminal(); // Stop TUI
                    self.leave_alt_screen(session, channel)?; // Leave alt screen
                    self.connect_to_relay(session, channel, &name).await?; // Now Connect
                }
                AppAction::Continue => {}
            }
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.set_pty_size(col_width, row_height);
        session.channel_success(channel)?;
        self.render_terminal(session, channel)
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.set_pty_size(col_width, row_height);
        session.channel_success(channel)?;
        if self.relay_handle.is_some() {
            // Relay mode: size updates are propagated asynchronously by the bridge task.
            Ok(())
        } else {
            self.render_terminal(session, channel)
        }
    }

    async fn channel_close(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
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

/// Display helper used for tracing; keeps logging concise when the socket address is unavailable.
pub(super) fn display_addr(addr: Option<SocketAddr>) -> String {
    addr.map(|a| a.to_string()).unwrap_or_else(|| "<unknown>".into())
}
