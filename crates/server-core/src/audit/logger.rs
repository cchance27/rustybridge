//! Core audit event logging functionality.

use rb_types::audit::{AuditContext, AuditEvent, EventType};
use tracing::warn;

use crate::error::{ServerError, ServerResult};

/// Log an audit event to the audit database.
///
/// This function is async and non-blocking. If logging fails, it will
/// log a warning but not fail the operation.
pub async fn log_event(event: AuditEvent) -> ServerResult<()> {
    let db = state_store::audit_db().await.map_err(ServerError::StateStore)?;

    state_store::events::insert_audit_event(&db, &event)
        .await
        .map_err(ServerError::StateStore)?;

    Ok(())
}

/// Log an audit event with automatic construction.
///
/// This is a convenience function that creates an AuditEvent with the
/// provided actor_id and event_type, then logs it.
pub async fn log_event_simple(actor_id: Option<i64>, event_type: EventType) -> ServerResult<()> {
    let event = AuditEvent::new(actor_id, event_type);
    log_event(event).await
}

/// Log an audit event with additional context.
///
/// This convenience function adds IP address and session ID to the event.
pub async fn log_event_with_context(
    actor_id: Option<i64>,
    event_type: EventType,
    ip_address: Option<String>,
    session_id: Option<String>,
) -> ServerResult<()> {
    let mut event = AuditEvent::new(actor_id, event_type);

    if let Some(ip) = ip_address {
        event = event.with_ip_address(ip);
    }

    if let Some(sid) = session_id {
        event = event.with_session_id(sid);
    }

    log_event(event).await
}

/// Log an audit event, but don't fail if logging fails.
///
/// This is useful for operations where audit logging should not prevent
/// the operation from succeeding. Failures are logged as warnings.
pub async fn log_event_best_effort(event: AuditEvent) {
    if let Err(e) = log_event(event).await {
        warn!(error = %e, "failed to log audit event");
    }
}

/// Log an audit event (simple version) without failing on error.
pub async fn log_event_simple_best_effort(actor_id: Option<i64>, event_type: EventType) {
    let event = AuditEvent::new(actor_id, event_type);
    log_event_best_effort(event).await;
}

/// Log an audit event with context, without failing on error.
pub async fn log_event_with_context_best_effort(
    actor_id: Option<i64>,
    event_type: EventType,
    ip_address: Option<String>,
    session_id: Option<String>,
) {
    let mut event = AuditEvent::new(actor_id, event_type);

    if let Some(ip) = ip_address {
        event = event.with_ip_address(ip);
    }

    if let Some(sid) = session_id {
        event = event.with_session_id(sid);
    }

    log_event_best_effort(event).await;
}

// ============================================================================
// CONTEXT-FIRST API (RECOMMENDED)
// ============================================================================

/// Log an audit event from a context (RECOMMENDED).
///
/// This is the preferred way to log events as it ensures all context
/// information is properly captured.
pub async fn log_event_from_context(ctx: &AuditContext, event_type: EventType) -> ServerResult<()> {
    let event = AuditEvent::from_context(ctx, event_type);
    log_event(event).await
}

/// Log an audit event from a context, without failing on error (RECOMMENDED).
pub async fn log_event_from_context_best_effort(ctx: &AuditContext, event_type: EventType) {
    let event = AuditEvent::from_context(ctx, event_type);
    log_event_best_effort(event).await;
}
