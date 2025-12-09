//! Relay module containing submodules for handling remote SSH connections.
//!
//! This module has been refactored from a single large file into smaller,
//! more focused modules for better maintainability and separation of concerns.
//!
//! The main functionality includes:
//! - Credential resolution and management
//! - Authentication to remote relay hosts
//! - Connection handling and bridging
//! - Shared handler for relay sessions

pub mod auth;
pub mod connection;
pub mod credential;
pub mod handler;

// Re-export main types and functions for backwards compatibility
pub use auth::{authenticate_relay_session, prompt_for_input};
pub use connection::{RelayHandle, connect_to_relay_backend, connect_to_relay_channel, connect_to_relay_local, start_bridge_backend};
pub use credential::{ResolvedCredential, fetch_and_resolve_credential};
pub use handler::{SharedRelayHandler, WarningCallback};

// Re-export the main result type alias
pub type Result<T> = crate::error::ServerResult<T>;
