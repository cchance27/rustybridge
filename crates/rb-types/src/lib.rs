//! Shared type definitions for RustyBridge
//!
//! This crate contains lightweight type definitions that are shared across
//! the entire RustyBridge application, including server-side and client-side (WASM) code.

pub mod access;
pub mod audit;
pub mod auth;
pub mod client;
pub mod config;
pub mod credentials;
pub mod net;
pub mod relay;
pub mod ssh;
pub mod state;
pub mod tasks;
pub mod users;
pub mod validation;
