//! Shared type definitions for RustyBridge
//!
//! This crate contains lightweight type definitions that are shared across
//! the entire RustyBridge application, including server-side and client-side (WASM) code.

use serde::{Deserialize, Serialize};
#[cfg(feature = "sqlx")]
use sqlx::FromRow;

pub mod auth;
pub mod validation;
pub mod web;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(FromRow))]
pub struct RelayInfo {
    pub id: i64,
    pub name: String,
    pub ip: String,
    pub port: i64,
}
