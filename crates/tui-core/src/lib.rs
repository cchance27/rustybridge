//! TUI Core - Extensible terminal UI framework for rustybridge
//!
//! This crate provides a clean architecture for building interactive terminal
//! applications that can run both over SSH (remote) and in standalone mode (local).

mod app;
mod error;

pub mod apps;
pub mod backend;
pub mod registry;
pub mod session;
pub mod utils;
pub mod widgets;

// Re-export core types
pub use app::{AppAction, CONTINUE, RE_RENDER, TuiApp};
pub use error::{TuiError, TuiResult};
pub use registry::{AppFactory, AppRegistry};
pub use session::AppSession;
