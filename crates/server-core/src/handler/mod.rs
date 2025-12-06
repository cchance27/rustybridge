//! SSH handler implementation that drives per-connection state and the echo TUI.

use std::{net::SocketAddr, sync::Arc, time::Instant};

use russh::{ChannelId, CryptoVec, server::Session};
use tokio::sync::{
    mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel}, watch
};
use tracing::info;
use tui_core::{AppAction, AppSession, backend::RemoteBackend};

use crate::{relay::RelayHandle, sessions::SessionRegistry};

mod actions;
mod auth;
mod input;
mod relay;
mod session;

pub(crate) type PendingRelay = tokio::sync::oneshot::Receiver<Result<(u32, UnboundedSender<String>), russh::Error>>;

pub(crate) struct AuthPromptState {
    pub(crate) buffer: Vec<u8>,
    pub(crate) echo: bool,
}

/// Tracks the lifecycle of a single SSH session, including authentication, PTY events, and TUI I/O.
pub(super) struct ServerHandler {
    pub(super) registry: Arc<SessionRegistry>,
    pub(super) connection_session_id: Option<String>, // UUIDv7 for this SSH connection
    pub(super) session_number: Option<u32>,
    pub(super) tui_session_number: Option<u32>,
    pub(super) peer_addr: Option<SocketAddr>,
    pub(super) username: Option<String>,
    pub(super) user_id: Option<i64>,
    pub(super) relay_target: Option<String>,
    pub(super) relay_handle: Option<RelayHandle>,
    pub(super) pending_relay: Option<PendingRelay>,
    pub(super) active_relay_id: Option<i64>,
    pub(super) prompt_sink_active: bool,
    pub(super) channel: Option<ChannelId>,
    pub(super) closed: bool,
    pub(super) connected_at: Instant,
    pub(super) app_session: Option<AppSession<RemoteBackend>>,
    pub(super) last_was_cr: bool,
    pub(super) pty_size: Option<(u16, u16)>,
    pub(super) alt_screen: bool,
    pub(super) size_updates: watch::Sender<(u16, u16)>,
    // Channel for background tasks (e.g., hostkey fetch) to inject actions
    pub(super) action_tx: UnboundedSender<AppAction>,
    pub(super) action_rx: UnboundedReceiver<AppAction>,
    // Interactive auth plumbing
    pub(super) auth_tx: Option<UnboundedSender<String>>,
    pub(super) pending_auth: Option<AuthPromptState>,
    // SSH OIDC keyboard-interactive auth session code
    pub(super) pending_ssh_auth_code: Option<String>,
    // Last time we checked SSH auth status (for rate limiting)
    pub(super) last_ssh_auth_check: Option<Instant>,
    // Whether we've shown the initial SSH auth message
    pub(super) ssh_auth_message_shown: bool,
    // Once set, keyboard-interactive is hard-rejected (e.g., OIDC mismatch/expired)
    pub(super) deny_keyboard_interactive: bool,
    // Whether we've already sent a one-time failure banner for OIDC auth
    pub(super) ssh_auth_failure_banner_sent: bool,
}

impl ServerHandler {
    /// Create a handler bound to the connecting client's socket address.
    pub(super) fn new(peer_addr: Option<SocketAddr>, registry: Arc<SessionRegistry>) -> Self {
        let (size_updates, _) = watch::channel((80, 24));
        let (action_tx, action_rx) = unbounded_channel();
        Self {
            registry,
            connection_session_id: None, // Set on successful auth
            session_number: None,
            tui_session_number: None,
            peer_addr,
            username: None,
            user_id: None,
            relay_target: None,
            relay_handle: None,
            pending_relay: None,
            active_relay_id: None,
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
            pending_ssh_auth_code: None,
            last_ssh_auth_check: None,
            ssh_auth_message_shown: false,
            deny_keyboard_interactive: false,
            ssh_auth_failure_banner_sent: false,
        }
    }

    pub(super) fn send_bytes(&self, session: &mut Session, channel: ChannelId, bytes: &[u8]) -> Result<(), russh::Error> {
        if bytes.is_empty() {
            return Ok(());
        }
        let mut payload = CryptoVec::new();
        payload.extend(bytes);
        session.data(channel, payload)
    }

    pub(super) fn send_line(&self, session: &mut Session, channel: ChannelId, line: &str) -> Result<(), russh::Error> {
        let mut payload = CryptoVec::new();
        payload.extend(line.as_bytes());
        payload.extend(b"\r\n");
        session.data(channel, payload)
    }

    pub(super) fn log_disconnect(&mut self, reason: &str) {
        if self.closed {
            return;
        }

        // If an OIDC SSH auth session was in progress, mark it abandoned so it can't linger after the client drops.
        if let Some(code) = self.pending_ssh_auth_code.take() {
            let user = self.username.clone();
            tokio::spawn(async move {
                if let Err(e) = crate::auth::ssh_auth::abandon_ssh_auth_session(&code).await {
                    tracing::warn!(%code, ?user, error = %e, "failed to mark abandoned SSH OIDC session");
                } else {
                    tracing::info!(%code, ?user, "abandoned SSH OIDC session marked as abandoned on disconnect");
                }
            });
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
}

impl Drop for ServerHandler {
    fn drop(&mut self) {
        if !self.closed {
            // Handle abrupt SSH disconnects (no channel_close callback).
            self.log_disconnect("connection dropped");
        }
    }
}

impl russh::server::Handler for ServerHandler {
    type Error = russh::Error;

    async fn channel_open_session(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.channel = Some(channel.id());
        Ok(true)
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<russh::server::Auth, Self::Error> {
        self.handle_auth_password(user, password).await
    }

    async fn auth_publickey(&mut self, user: &str, public_key: &russh::keys::PublicKey) -> Result<russh::server::Auth, Self::Error> {
        self.handle_auth_publickey(user, public_key).await
    }

    async fn auth_keyboard_interactive(
        &mut self,
        user: &str,
        submethods: &str,
        response: Option<russh::server::Response<'_>>,
    ) -> Result<russh::server::Auth, Self::Error> {
        self.handle_auth_keyboard_interactive(user, submethods, response).await
    }

    async fn auth_succeeded(&mut self, _session: &mut Session) -> Result<(), Self::Error> {
        self.handle_auth_succeeded().await
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        self.handle_shell_request(channel, session).await
    }

    async fn exec_request(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        self.handle_exec_request(channel, data, session).await
    }

    async fn data(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        self.handle_data(channel, data, session).await
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.handle_pty_request(channel, term, col_width, row_height, pix_width, pix_height, modes, session)
            .await
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.handle_window_change_request(channel, col_width, row_height, pix_width, pix_height, session)
            .await
    }

    async fn channel_close(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        self.handle_channel_close(channel, session).await
    }
}

/// Display helper used for tracing; keeps logging concise when the socket address is unavailable.
pub(super) fn display_addr(addr: Option<SocketAddr>) -> String {
    addr.map(|a| a.to_string()).unwrap_or_else(|| "<unknown>".into())
}
