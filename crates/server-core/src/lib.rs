//! Embedded SSH server entry point and module wiring.
//!
//! This module intentionally keeps the public surface small: `run_server` wires up the russh
//! configuration, while the heavy lifting lives in the submodules.

pub mod auth;
pub mod error;
mod handler;
pub mod relay;
pub use relay::connect_to_relay_local;
pub mod secrets;
mod server_manager;

// Re-export functionality from new modules
pub mod credential;
pub mod group;
pub mod relay_host;
pub mod role;
pub mod sessions;
pub mod ssh_server;
pub mod tui;
pub mod user;

// Top level exports for backwards compatability we should likely update callsights in future.
pub use credential::*;
pub use group::*;
pub use relay_host::{access::*, management::*, options::*};
pub use role::*;
pub use ssh_server::*;
pub use tui::*;
pub use user::*;
