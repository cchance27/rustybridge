//! SSH handler implementation that drives per-connection state and the echo TUI.

use std::{
    net::SocketAddr, time::{Duration, Instant}
};

use russh::{
    Channel, ChannelId, CryptoVec, Pty, server::{self as ssh_server, Auth, Session}
};
use tokio::{sync::watch, task::JoinHandle, time};
use tracing::{info, warn};

use crate::server::{
    remote_backend::ServerTerminal, tui::{EchoTui, HELLO_BANNER, INSTRUCTIONS, desired_rect, status_tick_sequence}
};

/// Tracks the lifecycle of a single SSH session, including authentication, PTY events, and TUI I/O.
pub(super) struct ServerHandler {
    pub(super) peer_addr: Option<SocketAddr>,
    username: Option<String>,
    channel: Option<ChannelId>,
    closed: bool,
    connected_at: Instant,
    tui: Option<EchoTui>,
    terminal: Option<ServerTerminal>,
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
            channel: None,
            closed: false,
            connected_at: Instant::now(),
            tui: None,
            terminal: None,
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
        self.tui = Some(EchoTui::with_default_messages());
        self.last_was_cr = false;
        self.ensure_terminal()?;
        Ok(())
    }

    /// Lazily create the ratatui terminal when a session first needs it.
    fn ensure_terminal(&mut self) -> Result<(), russh::Error> {
        if self.terminal.is_none() {
            let rect = desired_rect(self.view_size());
            let terminal = ServerTerminal::new(rect).map_err(russh::Error::IO)?;
            self.terminal = Some(terminal);
        }
        Ok(())
    }

    /// Render the TUI and forward any emitted bytes to the SSH client.
    fn render_terminal(&mut self, session: &mut Session, channel: ChannelId) -> Result<(), russh::Error> {
        if self.tui.is_none() {
            return Ok(());
        }
        self.ensure_terminal()?;
        let rect = desired_rect(self.view_size());
        {
            let term = match self.terminal.as_mut() {
                Some(term) => term,
                None => return Ok(()),
            };
            term.ensure_size(rect).map_err(russh::Error::IO)?;
            if let Some(tui) = self.tui.as_ref() {
                let connected_for = self.connected_at.elapsed();
                term.draw(|frame| tui.render(frame, connected_for)).map_err(russh::Error::IO)?;
            }
        }
        self.flush_terminal(session, channel)
    }

    /// Push accumulated escape sequences toward the remote SSH channel.
    fn flush_terminal(&mut self, session: &mut Session, channel: ChannelId) -> Result<(), russh::Error> {
        if let Some(term) = self.terminal.as_ref() {
            let bytes = term.drain_bytes();
            if !bytes.is_empty() {
                self.send_bytes(session, channel, &bytes)?;
            }
        }
        Ok(())
    }

    fn drop_terminal(&mut self) {
        self.terminal = None;
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

    /// Remove the most recent character from the TUI input buffer and refresh the view.
    fn handle_backspace(&mut self, session: &mut Session, channel: ChannelId) -> Result<(), russh::Error> {
        if let Some(tui) = self.tui.as_mut()
            && tui.pop_char()
        {
            self.render_terminal(session, channel)?;
        }
        Ok(())
    }

    /// Append a printable character to the input buffer and trigger a redraw.
    fn handle_printable(&mut self, ch: char, session: &mut Session, channel: ChannelId) -> Result<(), russh::Error> {
        if let Some(tui) = self.tui.as_mut()
            && tui.push_char(ch)
        {
            self.render_terminal(session, channel)?;
        }
        Ok(())
    }

    /// Process a full line (exit, echo, etc.) once the user presses Enter.
    fn complete_line(&mut self, session: &mut Session, channel: ChannelId) -> Result<LineAction, russh::Error> {
        let Some(tui) = self.tui.as_mut() else {
            return Ok(LineAction::Continue);
        };
        let line = tui.take_input();
        let trimmed = line.trim().to_string();

        if trimmed.is_empty() {
            self.render_terminal(session, channel)?;
            return Ok(LineAction::Continue);
        }

        tui.push_line(format!("> {trimmed}"));

        if trimmed.eq_ignore_ascii_case("exit") || trimmed.eq_ignore_ascii_case("quit") {
            tui.push_line("Bye!");
            self.render_terminal(session, channel)?;
            self.handle_exit(session, channel)?;
            return Ok(LineAction::Closed);
        }

        let response = format!("echoed: {trimmed}");
        tui.push_line(response);
        self.render_terminal(session, channel)?;
        Ok(LineAction::Continue)
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
        if user == "admin" && password == "admin" {
            self.username = Some(user.to_string());
            info!(
                peer = %display_addr(self.peer_addr),
                user,
                "password authentication accepted"
            );
            Ok(Auth::Accept)
        } else {
            warn!(
                peer = %display_addr(self.peer_addr),
                user,
                "password authentication rejected"
            );
            Ok(Auth::reject())
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
        self.init_shell()?;
        self.enter_alt_screen(session, channel)?;
        self.start_tick_task(session, channel);
        self.render_terminal(session, channel)
    }

    async fn exec_request(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        self.channel = Some(channel);
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

        for &byte in data {
            match byte {
                b'\r' => {
                    if matches!(self.complete_line(session, channel)?, LineAction::Closed) {
                        break;
                    }
                    self.last_was_cr = true;
                }
                b'\n' => {
                    if self.last_was_cr {
                        self.last_was_cr = false;
                        continue;
                    }
                    if matches!(self.complete_line(session, channel)?, LineAction::Closed) {
                        break;
                    }
                }
                0x7f | 0x08 => {
                    self.last_was_cr = false;
                    self.handle_backspace(session, channel)?;
                }
                b'\t' => {
                    self.last_was_cr = false;
                    self.handle_printable(' ', session, channel)?;
                }
                byte if byte.is_ascii() => {
                    self.last_was_cr = false;
                    let ch = byte as char;
                    if !ch.is_control() {
                        self.handle_printable(ch, session, channel)?;
                    }
                }
                _ => {}
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
        self.render_terminal(session, channel)
    }

    async fn channel_close(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        if Some(channel) == self.channel {
            self.leave_alt_screen(session, channel)?;
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

/// Signal used inside `data` to determine whether the SSH channel should remain open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineAction {
    Continue,
    Closed,
}
