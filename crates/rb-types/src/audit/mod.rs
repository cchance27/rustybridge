//! Audit event types and structures for system-wide event logging.
//!
//! This module provides strongly-typed event definitions for tracking all
//! security-relevant and administrative actions across the RB platform.

mod category;
mod context;
mod event;
mod filter;
mod log_hint;
mod recorded;
mod retention;

pub use category::*;
pub use context::*;
pub use event::*;
pub use filter::*;
pub use log_hint::*;
pub use recorded::*;
pub use retention::*;
