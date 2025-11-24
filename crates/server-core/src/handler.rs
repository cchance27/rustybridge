//! SSH handler implementation that drives per-connection state and the echo TUI.

use std::{net::SocketAddr, sync::Arc, time::Instant};

use russh::{
    Channel, ChannelId, CryptoVec, Pty, server::{self as ssh_server, Auth, Session}
};
use secrecy::ExposeSecret;
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
    pending_relay: Option<
        tokio::sync::oneshot::Receiver<Result<(crate::relay::RelayHandle, tokio::sync::mpsc::UnboundedSender<String>), russh::Error>>,
    >,
    prompt_sink_active: bool,
    channel: Option<ChannelId>,
    closed: bool,
    connected_at: Instant,
    app_session: Option<AppSession<RemoteBackend>>,
    last_was_cr: bool,
    pty_size: Option<(u16, u16)>,
    alt_screen: bool,
    size_updates: watch::Sender<(u16, u16)>,
    // Channel for background tasks (e.g., hostkey fetch) to inject actions
    action_tx: tokio::sync::mpsc::UnboundedSender<AppAction>,
    action_rx: tokio::sync::mpsc::UnboundedReceiver<AppAction>,
    // Interactive auth plumbing
    auth_tx: Option<tokio::sync::mpsc::UnboundedSender<String>>,
    pending_auth: Option<AuthPromptState>,
}

struct AuthPromptState {
    buffer: Vec<u8>,
    echo: bool,
}

impl ServerHandler {
    /// Create a handler bound to the connecting client's socket address.
    pub(super) fn new(peer_addr: Option<SocketAddr>) -> Self {
        let (size_updates, _) = watch::channel((80, 24));
        let (action_tx, action_rx) = tokio::sync::mpsc::unbounded_channel();
        Self {
            peer_addr,
            username: None,
            relay_target: None,
            relay_handle: None,
            pending_relay: None,
            prompt_sink_active: false,
            channel: None,
            closed: false,
            connected_at: Instant::now(),
            app_session: None,
            last_was_cr: false,
            pty_size: None,
            alt_screen: false,
            size_updates,
            action_tx,
            action_rx,
            auth_tx: None,
            pending_auth: None,
        }
    }

    fn send_bytes(&self, session: &mut Session, channel: ChannelId, bytes: &[u8]) -> Result<(), russh::Error> {
        if bytes.is_empty() {
            return Ok(());
        }
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

    /// Initialise the shell, including a fresh TUI instance and remote terminal.
    async fn init_shell(&mut self) -> Result<(), russh::Error> {
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
                    crate::create_management_app(None)
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

    fn show_status_line(
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

    async fn switch_app(&mut self, app_name: &str, session: &mut Session, channel: ChannelId) -> Result<(), russh::Error> {
        let username = self.username.as_deref().unwrap_or("unknown");
        let peer_addr = if let Some(peer_addr) = self.peer_addr {
            format!("{:?}", peer_addr)
        } else {
            "unknown".to_string()
        };
        info!(app_name, username, peer_addr, "tui switched");

        self.show_app_by_name(app_name, None, session, channel).await
    }

    async fn reload_management_app(
        &mut self,
        session: &mut Session,
        channel: ChannelId,
        tab: usize,
        review: Option<tui_core::apps::management::HostkeyReview>,
    ) -> Result<(), russh::Error> {
        let app = crate::create_management_app_with_tab(tab, review)
            .await
            .map_err(|e| russh::Error::IO(std::io::Error::other(e)))?;
        if let Some(app_session) = self.app_session.as_mut() {
            let _ = app_session.set_app(Box::new(app));
            self.render_terminal(session, channel)?;
        }
        Ok(())
    }

    /// Helper: set the current TUI app and render+flush, reusing the existing session if present.
    fn set_and_render_app(
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
    async fn show_app_by_name(
        &mut self,
        name: &str,
        selected_tab: Option<usize>,
        session: &mut Session,
        channel: ChannelId,
    ) -> Result<(), russh::Error> {
        let app = crate::create_app_by_name(self.username.as_deref(), name, selected_tab)
            .await
            .map_err(|e| russh::Error::IO(std::io::Error::other(e)))?;
        self.set_and_render_app(app, session, channel)
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
                                        for (k, (v, is_secure)) in raw.into_iter() {
                                            if is_secure {
                                                match crate::secrets::decrypt_string_if_encrypted(&v) {
                                                    Ok((val, is_legacy)) => {
                                                        if is_legacy {
                                                            warn!("Upgrading legacy v1 secret for relay option '{}'", k);
                                                            if let Ok(new_enc) =
                                                                crate::secrets::encrypt_string(crate::secrets::SecretString::new(Box::new(
                                                                    val.expose_secret().to_string(),
                                                                )))
                                                            {
                                                                let _ = sqlx::query("UPDATE relay_host_options SET value = ? WHERE relay_host_id = ? AND key = ?")
                                                                    .bind(new_enc)
                                                                    .bind(host.id)
                                                                    .bind(&k)
                                                                    .execute(&pool)
                                                                    .await;
                                                            }
                                                        }
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
                                            } else {
                                                out.insert(k, crate::secrets::SecretString::new(Box::new(v)));
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
                                let server_handle_for_prompt = server_handle.clone();
                                let server_handle_for_error = server_handle.clone();
                                let size_rx = self.size_updates.subscribe();
                                let initial_size = self.view_size();
                                let (auth_tx, auth_rx) = tokio::sync::mpsc::unbounded_channel();
                                self.auth_tx = Some(auth_tx.clone());
                                let action_tx = self.action_tx.clone();
                                let peer = self.peer_addr;
                                let options_arc = Arc::new(options);
                                let host_clone = host.clone();
                                let username_clone = username.clone();

                                // Spawn background connect; result delivered via oneshot
                                let (tx_done, rx_done) = tokio::sync::oneshot::channel();
                                tokio::spawn(async move {
                                    let res = crate::relay::start_bridge(
                                        server_handle,
                                        channel,
                                        &host_clone,
                                        &username_clone,
                                        initial_size,
                                        size_rx,
                                        options_arc.as_ref(),
                                        peer,
                                        Some(action_tx),
                                        Some(tokio::sync::Mutex::new(auth_rx)),
                                        Some((server_handle_for_prompt, channel)),
                                    )
                                    .await
                                    .map(|h| (h, auth_tx));

                                    match res {
                                        Ok(ok) => {
                                            let _ = tx_done.send(Ok(ok));
                                        }
                                        Err(e) => {
                                            // Inform client immediately
                                            let mut payload = CryptoVec::new();
                                            payload.extend(format!("failed to start relay: {e}\r\n").as_bytes());
                                            let _ = server_handle_for_error.data(channel, payload).await;
                                            let _ = server_handle_for_error.close(channel).await;
                                            let _ = tx_done.send(Err(russh::Error::IO(std::io::Error::other(e))));
                                        }
                                    }
                                });

                                self.prompt_sink_active = true;
                                self.pending_relay = Some(rx_done);

                                // Drain any immediate AuthPrompt actions queued during connect spawn
                                while let Ok(action) = self.action_rx.try_recv() {
                                    if let AppAction::AuthPrompt { prompt, echo } = action {
                                        if !self.prompt_sink_active {
                                            let _ = self.send_bytes(session, channel, prompt.as_bytes());
                                            if echo {
                                                let _ = self.send_bytes(session, channel, b" ");
                                            }
                                        }
                                        self.pending_auth = Some(AuthPromptState { buffer: Vec::new(), echo });
                                    } else {
                                        // re-queue other actions by pushing back into action_rx? drop for now
                                    }
                                }
                                Ok(())
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

        // Process any queued background actions (e.g., results from hostkey fetch)
        while let Ok(action) = self.action_rx.try_recv() {
            self.process_action(action, session, channel).await?;
        }

        // If a relay connect is pending, poll its completion
        if let Some(rx) = self.pending_relay.as_mut() {
            match rx.try_recv() {
                Ok(Ok((handle, auth_tx))) => {
                    self.relay_handle = Some(handle);
                    self.auth_tx = Some(auth_tx);
                    self.pending_relay = None;
                    self.prompt_sink_active = false; // relay established; prompts will come from remote shell now
                }
                Ok(Err(err)) => {
                    let _ = self.send_line(session, channel, &format!("failed to start relay: {}", err));
                    self.pending_relay = None;
                    return self.handle_exit(session, channel);
                }
                Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
                Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                    let _ = self.send_line(session, channel, "failed to start relay: channel closed");
                    self.pending_relay = None;
                    return self.handle_exit(session, channel);
                }
            }
        }

        // If an auth prompt is active, capture input directly and bypass TUI apps
        if self.pending_auth.is_some() {
            let mut done = false;
            let mut response_to_send: Option<String> = None;
            let mut echo_out: Vec<u8> = Vec::new();
            let _echo_enabled = {
                let auth = self.pending_auth.as_mut().unwrap();
                let echo_flag = auth.echo;
                for b in data {
                    match *b {
                        0x03 => {
                            // Ctrl+C: cancel prompt and close session
                            let _ = self.send_bytes(session, channel, b"\r\n^C\r\n");
                            self.pending_auth = None;
                            return self.handle_exit(session, channel);
                        }
                        0x04 => {
                            // Ctrl+D: treat like cancel/EOF
                            let _ = self.send_bytes(session, channel, b"\r\n^D\r\n");
                            self.pending_auth = None;
                            return self.handle_exit(session, channel);
                        }
                        0x7f | 0x08 => {
                            // Backspace/delete
                            if let Some(_ch) = auth.buffer.pop() {
                                if echo_flag {
                                    echo_out.extend_from_slice(b"\x08 \x08");
                                }
                            }
                        }
                        0x15 => {
                            // Ctrl+U: clear entire line
                            let count = auth.buffer.len();
                            auth.buffer.clear();
                            if echo_flag && count > 0 {
                                for _ in 0..count {
                                    echo_out.extend_from_slice(b"\x08");
                                }
                                for _ in 0..count {
                                    echo_out.extend_from_slice(b" ");
                                }
                                for _ in 0..count {
                                    echo_out.extend_from_slice(b"\x08");
                                }
                            }
                        }
                        0x17 => {
                            // Ctrl+W: delete word back to whitespace
                            let mut removed = 0usize;
                            while let Some(ch) = auth.buffer.pop() {
                                removed += 1;
                                if ch.is_ascii_whitespace() {
                                    break;
                                }
                            }
                            if echo_flag && removed > 0 {
                                for _ in 0..removed {
                                    echo_out.extend_from_slice(b"\x08 \x08");
                                }
                            }
                        }
                        b'\r' | b'\n' => {
                            response_to_send = Some(String::from_utf8_lossy(&auth.buffer).to_string());
                            done = true;
                            break;
                        }
                        byte => {
                            auth.buffer.push(byte);
                            if echo_flag {
                                echo_out.push(byte);
                            }
                        }
                    }
                }
                echo_flag
            }; // drop mutable borrow of pending_auth

            if !echo_out.is_empty() {
                let _ = self.send_bytes(session, channel, &echo_out);
            }

            if let Some(resp) = response_to_send {
                if let Some(tx) = self.auth_tx.as_ref() {
                    let _ = tx.send(resp);
                }
            }
            if done {
                // Add a single newline after submit so next prompt/output is on a new line
                let _ = self.send_bytes(session, channel, b"\r\n");
                // If auth failed elsewhere, force a flush by sending an empty data packet
                if self.pending_relay.is_none() && self.relay_handle.is_none() {
                    let _ = self.send_bytes(session, channel, b"");
                }
                self.pending_auth = None;
            }
            return Ok(());
        }

        if let Some(relay) = self.relay_handle.as_ref() {
            if !data.is_empty() {
                relay.send(data.to_vec());
            }
            return Ok(());
        }

        if let Some(app_session) = self.app_session.as_mut() {
            // Normalize incoming SSH bytes to canonical TUI sequences
            let canonical = tui_core::input::canonicalize(data);

            // Filter out DSR response if we requested it (cursor position report)
            // \x1b[<row>;<col>R
            if canonical.starts_with(b"\x1b[") && canonical.ends_with(b"R") {
                return Ok(());
            }

            let action = app_session
                .handle_input(&canonical)
                .map_err(|e| russh::Error::IO(std::io::Error::other(e)))?;
            self.process_action(action, session, channel).await?;
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

impl ServerHandler {
    async fn process_action(&mut self, action: AppAction, session: &mut Session, channel: ChannelId) -> Result<(), russh::Error> {
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
                // Kick off background connect; prompts/results handled in data()
                self.connect_to_relay(session, channel, &name).await?;
            }
            AppAction::FetchHostkey { id, name } => {
                let status = tui_core::app::StatusLine {
                    text: format!("Fetching host key for '{}'...", name),
                    kind: tui_core::app::StatusKind::Info,
                };
                self.show_status_line(status, session, channel)?;
                // Kick off the fetch in the background; results are pushed through action_tx.
                let tx = self.action_tx.clone();
                let name_clone = name.clone();
                let server_handle = session.handle();
                tokio::spawn(async move {
                    let action = AppAction::FetchHostkey {
                        id,
                        name: name_clone.clone(),
                    };
                    match crate::handle_management_action(action).await {
                        Ok(Some(res_action)) => {
                            let _ = tx.send(res_action);
                        }
                        Ok(None) => {
                            let _ = tx.send(AppAction::Error(format!("Host '{}' did not present a host key", name_clone)));
                        }
                        Err(e) => {
                            let _ = tx.send(AppAction::Error(format!("Hostkey fetch failed: {}", e)));
                        }
                    }
                    // Trigger a DSR to wake the data loop even if the client stays idle.
                    let _ = server_handle.data(channel, CryptoVec::from_slice(b"\x1b[6n")).await;
                });
            }
            AppAction::ReviewHostkey(review) => {
                // Reload management app with the review data
                self.reload_management_app(session, channel, 0, Some(review)).await?;
            }
            AppAction::AddRelay(_)
            | AppAction::UpdateRelay(_)
            | AppAction::DeleteRelay(_)
            | AppAction::AddCredential(_)
            | AppAction::DeleteCredential(_)
            | AppAction::UnassignCredential(_)
            | AppAction::AssignCredential { .. }
            | AppAction::StoreHostkey { .. }
            | AppAction::CancelHostkey { .. } => {
                let cloned = action.clone();
                let tab = match action {
                    AppAction::AddCredential(_) | AppAction::DeleteCredential(_) => 1,
                    _ => 0,
                };
                match crate::handle_management_action(cloned.clone()).await {
                    Ok(_) => {
                        // Reload Management app with fresh data and redraw.
                        self.reload_management_app(session, channel, tab, None).await?;
                        // Success-specific status for certain actions
                        if let AppAction::StoreHostkey { name, .. } = &action
                            && let Some(app_session) = self.app_session.as_mut()
                        {
                            let status = tui_core::app::StatusLine {
                                text: format!("Stored host key for '{}'", name),
                                kind: tui_core::app::StatusKind::Success,
                            };
                            app_session.set_status(Some(status));
                            self.render_terminal(session, channel)?;
                        }
                    }
                    Err(e) => {
                        warn!("failed to apply management action: {}", e);
                        // Reload Management app anyway so the status message surfaces on the new instance.
                        self.reload_management_app(session, channel, tab, None).await?;
                        if let Some(app_session) = self.app_session.as_mut() {
                            let msg = crate::format_action_error(&cloned, &e);
                            let status = tui_core::app::StatusLine {
                                text: msg,
                                kind: tui_core::app::StatusKind::Error,
                            };
                            app_session.set_status(Some(status));
                            self.render_terminal(session, channel)?;
                        }
                    }
                }
            }
            AppAction::Error(msg) => {
                if let Some(app_session) = self.app_session.as_mut() {
                    let status = tui_core::app::StatusLine {
                        text: msg,
                        kind: tui_core::app::StatusKind::Error,
                    };
                    app_session.set_status(Some(status));
                    self.render_terminal(session, channel)?;
                }
            }
            AppAction::AuthPrompt { prompt, echo } => {
                // Send prompt to the user's terminal and start capturing input
                if !self.prompt_sink_active {
                    let _ = self.send_bytes(session, channel, prompt.as_bytes());
                    if echo {
                        let _ = self.send_bytes(session, channel, b" ");
                    }
                }
                if let Some(app_session) = self.app_session.as_mut() {
                    app_session.set_status_message(Some(prompt.clone()));
                    self.render_terminal(session, channel)?;
                }
                self.pending_auth = Some(AuthPromptState { buffer: Vec::new(), echo });
            }
            AppAction::BackendEvent(_) => {
                // Backend events are internal signals, not handled in server mode
            }
            AppAction::Continue => {
                // no background reloads; status and fetches are session-scoped
            }
        }
        Ok(())
    }
}

/// Display helper used for tracing; keeps logging concise when the socket address is unavailable.
pub(super) fn display_addr(addr: Option<SocketAddr>) -> String {
    addr.map(|a| a.to_string()).unwrap_or_else(|| "<unknown>".into())
}
// (moved helper methods into impl ServerHandler)
