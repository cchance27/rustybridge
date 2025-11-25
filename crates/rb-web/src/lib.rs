//! RustyBridge web entrypoint and common exports.
//!
//! This crate hosts the Dioxus-based web UI and HTTP/WebSocket server that
//! runs alongside the existing SSH/TUI runtime.

pub mod app;
pub mod app_root;

// Server module is only compiled for server builds
#[cfg(feature = "server")]
pub mod server;

pub use app::{components, pages};
pub use app_root::Routes;
#[cfg(feature = "server")]
pub use server::run_web_server;
