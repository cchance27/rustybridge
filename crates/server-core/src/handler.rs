//! SSH handler implementation that drives per-connection state and the echo TUI.

use std::{
    net::SocketAddr, time::{Duration, Instant}
};

use russh::{
    Channel, ChannelId, CryptoVec, Pty, server::{self as ssh_server, Auth, Session}
};
use tokio::{sync::watch, task::JoinHandle, time};
use tracing::{info, warn};
use tui_core::{
    AppSession,
    apps::echo::{EchoApp, desired_rect, status_tick_sequence},
    backend::RemoteBackend,
};

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
    tick_shutdown: Option<watch::Sender<bool>>,
    tick_task: Option<JoinHandle<()>>,
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
            tick_shutdown: None,
            tick_task: None,
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
        self.stop_tick_task();
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
        self.stop_tick_task();
        self.send_line(session, channel, "Bye!")?;
        session.exit_status_request(channel, 0)?;
        session.close(channel)?;
        self.channel = None;
        self.log_disconnect("client requested exit");
        Ok(())
    }

    /// Initialise the echo shell, including a fresh TUI instance and remote terminal.
    fn init_shell(&mut self) -> Result<(), russh::Error> {
        let app = Box::new(EchoApp::new());
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
            app_session.resize(rect).map_err(|e| russh::Error::IO(std::io::Error::other(e)))?;
            app_session.render().map_err(|e| russh::Error::IO(std::io::Error::other(e)))?;
            self.flush_terminal(session, channel)?;
        }
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

    /// Spawn a lightweight task that refreshes the status timer once per second.
    fn start_tick_task(&mut self, session: &Session, channel: ChannelId) {
        if self.tick_task.is_some() {
            return;
        }
        let handle = session.handle();
        let size_rx = self.size_updates.subscribe();
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        self.tick_shutdown = Some(shutdown_tx);
        let connected_at = self.connected_at;
        self.tick_task = Some(tokio::spawn(async move {
            let mut ticker = time::interval(Duration::from_secs(1));
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let size = *size_rx.borrow();
                        let elapsed = connected_at.elapsed();
                        if let Some(bytes) = status_tick_sequence(size, elapsed) {
                            let mut payload = CryptoVec::new();
                            payload.extend(&bytes);
                            if handle.data(channel, payload).await.is_err() {
                                break;
                            }
                        }
                    }
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        }));
    }

    /// Stop the refresh task and drop any pending handle.
    fn stop_tick_task(&mut self) {
        if let Some(tx) = self.tick_shutdown.take() {
            let _ = tx.send(true);
        }
        if let Some(handle) = self.tick_task.take() {
            handle.abort();
        }
    }
}

impl Drop for ServerHandler {
    fn drop(&mut self) {
        if !self.closed {
            self.log_disconnect("connection dropped");
        }
        self.stop_tick_task();
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
            use state_store::{fetch_relay_host_by_name, fetch_relay_host_options, server_db, user_has_relay_access};
            let username = self.username.clone().unwrap_or_else(|| "<unknown>".into());
            match server_db().await {
                Ok(handle) => {
                    let pool = handle.into_pool();
                    match fetch_relay_host_by_name(&pool, &relay_name).await {
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
                                            let _ =
                                                self.send_line(session, channel, &format!("internal error loading relay options: {err}"));
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
        } else {
            self.init_shell()?;
            self.enter_alt_screen(session, channel)?;
            self.start_tick_task(session, channel);
            self.render_terminal(session, channel)
        }
    }

    async fn exec_request(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        self.channel = Some(channel);
        // For exec, we don't use the TUI app, just simple echo
        // Or we could use EchoApp in non-interactive mode?
        // The original implementation just echoed the command.
        // Let's keep it simple as before.
        use tui_core::apps::echo::{HELLO_BANNER, INSTRUCTIONS};
        self.send_line(session, channel, HELLO_BANNER)?;
        self.send_line(session, channel, INSTRUCTIONS)?;
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

        let should_render = if let Some(app_session) = self.app_session.as_mut() {
            app_session.handle_input(data).map_err(|e| russh::Error::IO(std::io::Error::other(e)))?
        } else {
            false
        };

        if should_render {
            self.render_terminal(session, channel)?;
        }

        if let Some(app_session) = self.app_session.as_ref() {
            if app_session.should_exit() {
                self.handle_exit(session, channel)?;
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
            self.stop_tick_task();
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
