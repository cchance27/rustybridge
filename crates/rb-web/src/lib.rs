//! RustyBridge web entrypoint and common exports.
//!
//! This crate hosts the Dioxus-based web UI and HTTP/WebSocket server that
//! runs alongside the existing SSH/TUI runtime.

pub mod app;
pub mod app_root;

// Server module needs to be available for Dioxus RPC to generate client stubs
pub mod server;

pub use app::{components, pages, routes};
#[cfg(feature = "server")]
pub use server::config::{WebServerConfig, WebTlsConfig};
#[cfg(feature = "server")]
pub use server::run_web_server;
