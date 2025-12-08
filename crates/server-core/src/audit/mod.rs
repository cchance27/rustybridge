//! Audit event logging module for server-core.
//!
//! This module provides a clean API for logging audit events throughout
//! the server-core operations. It wraps the state-store persistence layer
//! and provides convenience functions for common patterns.

pub mod logger;
pub mod query;

pub use logger::{log_event_from_context_best_effort, log_event_with_context_best_effort};
pub use query::*;

/// Helper to log changes to relay options in a batch.
pub async fn log_relay_option_changes(
    ctx: &rb_types::audit::AuditContext,
    relay_name: String,
    relay_id: i64,
    cleared_keys: Vec<String>,
    set_keys: Vec<(String, bool)>,
) {
    for key in cleared_keys {
        log_event_from_context_best_effort(
            ctx,
            rb_types::audit::EventType::RelayOptionCleared {
                relay_name: relay_name.clone(),
                relay_id,
                key,
            },
        )
        .await;
    }

    for (key, is_secure) in set_keys {
        log_event_from_context_best_effort(
            ctx,
            rb_types::audit::EventType::RelayOptionSet {
                relay_name: relay_name.clone(),
                relay_id,
                key,
                is_secure,
            },
        )
        .await;
    }
}

/// Helper to log OIDC login failures consistently.
pub async fn log_oidc_failure(ip_address: Option<String>, session_id: String, username: Option<String>, reason: String) {
    log_event_with_context_best_effort(
        None,
        rb_types::audit::EventType::LoginFailure {
            method: rb_types::audit::AuthMethod::Oidc,
            username: username.or_else(|| Some("unknown".to_string())),
            reason,
        },
        ip_address,
        Some(session_id),
    )
    .await;
}
// Re-export types from rb-types for convenience
pub use rb_types::audit::{AuditEvent, AuthMethod, EventCategory, EventFilter, EventType};
