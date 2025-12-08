//! Query audit events from the database.

use rb_types::audit::{AuditEvent, EventFilter};

use crate::error::{ServerError, ServerResult};

/// Query audit events with filtering.
pub async fn query_events(filter: EventFilter) -> ServerResult<Vec<AuditEvent>> {
    let db = state_store::audit_db().await.map_err(ServerError::StateStore)?;

    state_store::events::query_audit_events(&db, filter)
        .await
        .map_err(ServerError::StateStore)
}

/// Query recent audit events (last 100).
pub async fn query_recent_events(limit: i64) -> ServerResult<Vec<AuditEvent>> {
    let filter = EventFilter::new().with_limit(limit);
    query_events(filter).await
}

/// Query events by actor ID.
pub async fn query_events_by_actor(actor_id: i64, limit: Option<i64>) -> ServerResult<Vec<AuditEvent>> {
    let mut filter = EventFilter::new().with_actor(actor_id);

    if let Some(lim) = limit {
        filter = filter.with_limit(lim);
    }

    query_events(filter).await
}

/// Query events by session ID.
pub async fn query_events_by_session(session_id: String, limit: Option<i64>) -> ServerResult<Vec<AuditEvent>> {
    let mut filter = EventFilter::new();
    filter.session_id = Some(session_id);

    if let Some(lim) = limit {
        filter = filter.with_limit(lim);
    }

    query_events(filter).await
}

/// Count total events matching a filter.
pub async fn count_events(filter: EventFilter) -> ServerResult<i64> {
    let db = state_store::audit_db().await.map_err(ServerError::StateStore)?;

    state_store::events::count_audit_events(&db, &filter)
        .await
        .map_err(ServerError::StateStore)
}
