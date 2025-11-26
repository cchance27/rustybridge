//! Management application module for TUI
//! Contains the admin management interface with tabs for relay hosts, credentials, etc.

mod app;
mod forms;
mod input_handler;
mod main_input;
mod navigation;
mod popup_input;
mod popup_manager;
mod popups;
mod render;
mod types;
mod utils;

pub use app::ManagementApp;
pub use types::{CredentialItem, CredentialSpec};
