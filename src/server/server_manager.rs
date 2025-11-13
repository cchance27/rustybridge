//! Minimal russh `Server` that hands each TCP connection to our [`ServerHandler`].

use std::net::SocketAddr;

use tracing::{info, warn};

use super::handler::{ServerHandler, display_addr};

/// Factory invoked by russh whenever a client connects.
#[derive(Default)]
pub(super) struct ServerManager;

impl russh::server::Server for ServerManager {
    type Handler = ServerHandler;

    fn new_client(&mut self, addr: Option<SocketAddr>) -> Self::Handler {
        info!(peer = %display_addr(addr), "client connected");
        ServerHandler::new(addr)
    }

    fn handle_session_error(&mut self, error: <Self::Handler as russh::server::Handler>::Error) {
        warn!(?error, "server session ended with error");
    }
}
