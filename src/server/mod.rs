use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use rand_core::OsRng;
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{self as ssh_server, Auth, Server, Session};
use russh::{Channel, ChannelId, CryptoVec, MethodKind, MethodSet};
use tracing::{info, warn};

use crate::cli::ServerConfig;
use crate::crypto::legacy_preferred;

const HELLO_BANNER: &str = "hello world!";
const INSTRUCTIONS: &str = "Type anything to have it echoed back, or 'exit' to disconnect.";
const PROMPT: &str = "echo> ";

pub async fn run_server(config: ServerConfig) -> Result<()> {
    let mut server_config = ssh_server::Config {
        preferred: legacy_preferred(),
        auth_rejection_time: Duration::from_millis(250),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        nodelay: true,
        ..Default::default()
    };

    server_config.methods = MethodSet::empty();
    server_config.methods.push(MethodKind::Password);
    server_config
        .keys
        .push(PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?);

    let mut server = HelloServer;
    info!(
        "starting embedded SSH server on {}:{} (credentials admin/admin)",
        config.bind, config.port
    );

    server
        .run_on_address(Arc::new(server_config), (config.bind.as_str(), config.port))
        .await?;
    Ok(())
}

#[derive(Default)]
struct HelloServer;

impl ssh_server::Server for HelloServer {
    type Handler = HelloHandler;

    fn new_client(&mut self, addr: Option<SocketAddr>) -> Self::Handler {
        info!(peer = %display_addr(addr), "client connected");
        HelloHandler::new(addr)
    }

    fn handle_session_error(&mut self, error: <Self::Handler as ssh_server::Handler>::Error) {
        warn!(?error, "server session ended with error");
    }
}

struct HelloHandler {
    peer_addr: Option<SocketAddr>,
    username: Option<String>,
    channel: Option<ChannelId>,
    closed: bool,
    connected_at: Instant,
    pending_input: String,
    last_was_cr: bool,
}

impl HelloHandler {
    fn new(peer_addr: Option<SocketAddr>) -> Self {
        Self {
            peer_addr,
            username: None,
            channel: None,
            closed: false,
            connected_at: Instant::now(),
            pending_input: String::new(),
            last_was_cr: false,
        }
    }

    fn send_bytes(
        &self,
        session: &mut Session,
        channel: ChannelId,
        bytes: &[u8],
    ) -> Result<(), russh::Error> {
        let mut payload = CryptoVec::new();
        payload.extend(bytes);
        session.data(channel, payload)
    }

    fn send_line(
        &self,
        session: &mut Session,
        channel: ChannelId,
        line: &str,
    ) -> Result<(), russh::Error> {
        let mut payload = CryptoVec::new();
        payload.extend(line.as_bytes());
        payload.extend(b"\r\n");
        session.data(channel, payload)
    }

    fn send_prompt(&self, session: &mut Session, channel: ChannelId) -> Result<(), russh::Error> {
        self.send_bytes(session, channel, PROMPT.as_bytes())
    }

    fn greet(&self, session: &mut Session, channel: ChannelId) -> Result<(), russh::Error> {
        self.send_line(session, channel, HELLO_BANNER)?;
        self.send_line(session, channel, INSTRUCTIONS)?;
        self.send_prompt(session, channel)
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

    fn handle_exit(
        &mut self,
        session: &mut Session,
        channel: ChannelId,
    ) -> Result<(), russh::Error> {
        self.send_line(session, channel, "Bye!")?;
        session.exit_status_request(channel, 0)?;
        session.close(channel)?;
        self.channel = None;
        self.log_disconnect("client requested exit");
        Ok(())
    }

    fn complete_line(
        &mut self,
        session: &mut Session,
        channel: ChannelId,
    ) -> Result<LineAction, russh::Error> {
        if self.pending_input.is_empty() {
            self.send_prompt(session, channel)?;
            return Ok(LineAction::Continue);
        }

        let line = std::mem::take(&mut self.pending_input);
        let trimmed = line.trim();

        if trimmed.eq_ignore_ascii_case("exit") || trimmed.eq_ignore_ascii_case("quit") {
            self.handle_exit(session, channel)?;
            return Ok(LineAction::Closed);
        }

        if trimmed.is_empty() {
            self.send_prompt(session, channel)?;
            return Ok(LineAction::Continue);
        }

        let response = format!("echoed: {trimmed}");
        self.send_line(session, channel, &response)?;
        self.send_prompt(session, channel)?;
        Ok(LineAction::Continue)
    }

    fn echo_byte(
        &self,
        session: &mut Session,
        channel: ChannelId,
        byte: u8,
    ) -> Result<(), russh::Error> {
        self.send_bytes(session, channel, &[byte])
    }

    fn echo_newline(&self, session: &mut Session, channel: ChannelId) -> Result<(), russh::Error> {
        self.send_bytes(session, channel, b"\r\n")
    }

    fn handle_backspace(
        &mut self,
        session: &mut Session,
        channel: ChannelId,
    ) -> Result<(), russh::Error> {
        if self.pending_input.pop().is_some() {
            self.send_bytes(session, channel, b"\x08 \x08")?;
        }
        Ok(())
    }
}

impl Drop for HelloHandler {
    fn drop(&mut self) {
        if !self.closed {
            self.log_disconnect("connection dropped");
        }
    }
}

impl ssh_server::Handler for HelloHandler {
    type Error = russh::Error;

    async fn channel_open_session(
        &mut self,
        channel: Channel<ssh_server::Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
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

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        self.channel = Some(channel);
        self.greet(session, channel)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        self.channel = Some(channel);
        self.greet(session, channel)?;
        if !data.is_empty() {
            let cmd = String::from_utf8_lossy(data).trim().to_string();
            if !cmd.is_empty() {
                let response = format!("exec received: {cmd}");
                self.send_line(session, channel, &response)?;
            }
        }
        self.handle_exit(session, channel)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if Some(channel) != self.channel {
            return Ok(());
        }

        for &byte in data {
            match byte {
                b'\r' => {
                    self.echo_newline(session, channel)?;
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
                    self.echo_newline(session, channel)?;
                    if matches!(self.complete_line(session, channel)?, LineAction::Closed) {
                        break;
                    }
                }
                0x7f | 0x08 => {
                    self.last_was_cr = false;
                    self.handle_backspace(session, channel)?;
                }
                byte => {
                    self.last_was_cr = false;
                    if let Some(ch) = char::from_u32(byte as u32) {
                        self.pending_input.push(ch);
                    }
                    self.echo_byte(session, channel, byte)?;
                }
            }
        }

        Ok(())
    }

    async fn channel_close(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channel = None;
        self.log_disconnect("channel closed");
        Ok(())
    }
}

fn display_addr(addr: Option<SocketAddr>) -> String {
    addr.map(|a| a.to_string())
        .unwrap_or_else(|| "<unknown>".into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineAction {
    Continue,
    Closed,
}
