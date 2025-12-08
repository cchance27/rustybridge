//! System events persistence layer.
//!
//! This module handles storing and querying audit events in the audit database.

use rb_types::{
    audit::{AuditEvent, EventFilter}, state::DbHandle
};
use sqlx::Row;

use crate::{DbError, DbResult};

/// Insert an audit event into the database.
pub async fn insert_audit_event(db: &DbHandle, event: &AuditEvent) -> DbResult<()> {
    let details = serde_json::to_string(&event.event_type).map_err(|e| DbError::JsonSerialization {
        context: "event_type serialization".to_string(),
        source: e,
    })?;

    let action_type = event.event_type.action_type();
    let category = event.category.as_str();

    sqlx::query(
        "INSERT INTO system_events 
         (id, timestamp, actor_id, action_type, resource_id, details, category, ip_address, session_id, parent_session_id) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&event.id)
    .bind(event.timestamp)
    .bind(event.actor_id)
    .bind(action_type)
    .bind(&event.resource_id)
    .bind(&details)
    .bind(category)
    .bind(&event.ip_address)
    .bind(&event.session_id)
    .bind(&event.parent_session_id)
    .execute(&db.pool)
    .await?;

    Ok(())
}

/// Query audit events with filtering.
pub async fn query_audit_events(db: &DbHandle, filter: EventFilter) -> DbResult<Vec<AuditEvent>> {
    // Execute query with filters
    let rows = execute_filtered_query(db, &filter).await?;

    let mut events = Vec::new();
    for row in rows {
        let id: String = row.get("id");
        let timestamp: i64 = row.get("timestamp");
        let actor_id: Option<i64> = row.get("actor_id");
        let resource_id: Option<String> = row.get("resource_id");
        let details: String = row.get("details");
        let category_str: Option<String> = row.get("category");
        let ip_address: Option<String> = row.get("ip_address");
        let session_id: Option<String> = row.get("session_id");
        let parent_session_id: Option<String> = row.try_get("parent_session_id").ok().flatten();

        // Deserialize event_type from details JSON
        let event_type: rb_types::audit::EventType = serde_json::from_str(&details).map_err(|e| DbError::JsonSerialization {
            context: "event_type deserialization".to_string(),
            source: e,
        })?;

        let category = if let Some(cat_str) = category_str {
            // Parse category from string (best effort)
            serde_json::from_value(serde_json::Value::String(cat_str)).unwrap_or_else(|_| event_type.category())
        } else {
            event_type.category()
        };

        events.push(AuditEvent {
            id,
            timestamp,
            actor_id,
            category,
            event_type,
            resource_id,
            ip_address,
            session_id,
            parent_session_id,
        });
    }

    Ok(events)
}

/// Execute filtered query with proper type handling.
async fn execute_filtered_query(db: &DbHandle, filter: &EventFilter) -> DbResult<Vec<sqlx::sqlite::SqliteRow>> {
    let mut builder = sqlx::QueryBuilder::new(
        "SELECT id, timestamp, actor_id, action_type, resource_id, details, category, ip_address, session_id, parent_session_id 
         FROM system_events WHERE 1=1",
    );

    if let Some(actor_id) = filter.actor_id {
        builder.push(" AND actor_id = ").push_bind(actor_id);
    }

    if let Some(ref category) = filter.category {
        builder.push(" AND category = ").push_bind(category.as_str());
    }

    if let Some(ref resource_id) = filter.resource_id {
        builder.push(" AND resource_id = ").push_bind(resource_id);
    }

    if let Some(start_time) = filter.start_time {
        builder.push(" AND timestamp >= ").push_bind(start_time);
    }

    if let Some(end_time) = filter.end_time {
        builder.push(" AND timestamp <= ").push_bind(end_time);
    }

    if let Some(ref session_id) = filter.session_id {
        builder.push(" AND session_id = ").push_bind(session_id);
    }

    builder.push(" ORDER BY timestamp DESC");

    if let Some(limit) = filter.limit {
        builder.push(" LIMIT ").push_bind(limit);
    }

    if let Some(offset) = filter.offset {
        builder.push(" OFFSET ").push_bind(offset);
    }

    let query = builder.build();
    query.fetch_all(&db.pool).await.map_err(Into::into)
}

/// Count total events matching a filter (for pagination).
pub async fn count_audit_events(db: &DbHandle, filter: &EventFilter) -> DbResult<i64> {
    let mut builder = sqlx::QueryBuilder::new("SELECT COUNT(*) as count FROM system_events WHERE 1=1");

    if let Some(actor_id) = filter.actor_id {
        builder.push(" AND actor_id = ").push_bind(actor_id);
    }
    if let Some(ref category) = filter.category {
        builder.push(" AND category = ").push_bind(category.as_str());
    }
    if let Some(ref resource_id) = filter.resource_id {
        builder.push(" AND resource_id = ").push_bind(resource_id);
    }
    if let Some(start_time) = filter.start_time {
        builder.push(" AND timestamp >= ").push_bind(start_time);
    }
    if let Some(end_time) = filter.end_time {
        builder.push(" AND timestamp <= ").push_bind(end_time);
    }
    if let Some(ref session_id) = filter.session_id {
        builder.push(" AND session_id = ").push_bind(session_id);
    }

    let query = builder.build();
    let row = query.fetch_one(&db.pool).await?;

    let count: i64 = row.get("count");
    Ok(count)
}
