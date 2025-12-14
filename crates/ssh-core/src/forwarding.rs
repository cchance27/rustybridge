//! SSH port forwarding, SOCKS proxies, and environment propagation.
//!
//! This module provides functionality for:
//! - Local TCP and Unix socket forwarding
//! - Remote TCP and Unix socket forwarding
//! - Dynamic SOCKS5 proxies
//! - Environment variable propagation
//!
//! The main entry point is [`ForwardingManager`], which coordinates all
//! forwarding activities for an SSH session.

mod local;
mod manager;
mod parsing;
mod remote;
mod socks;
mod traits;

// Re-export public API
pub use manager::ForwardingManager;
pub use parsing::{
    parse_dynamic_socks,
    parse_env_entry,
    parse_local_tcp,
    parse_local_unix,
    parse_remote_tcp,
    parse_remote_unix,
    parse_subsystem,
};
pub use traits::{ForwardSession, ForwardStream, ForwardStreamIo, RemoteForwardChannel, RemoteRegistrar};
