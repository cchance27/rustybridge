//! Audit event types and structures for system-wide event logging.
//!
//! This module provides strongly-typed event definitions for tracking all
//! security-relevant and administrative actions across the RB platform.

mod category;
mod context;
mod event;
mod filter;
mod recorded;

pub use category::*;
pub use context::*;
pub use event::*;
pub use filter::*;
pub use recorded::*;
