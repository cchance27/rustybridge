//! Cascading retention cleanup for audit database.
//!
//! This module implements cascading cleanup where deleting relay_sessions
//! automatically cascades to related data (chunks, participants, client_sessions, events).

use crate::DbResult;
use chrono::Utc;
use rb_types::{
    audit::{DatabaseStats, OrphanEventsSizes, RetentionConfig, RetentionPolicy, RetentionResult, SessionDataSizes, TableRowCounts},
    state::DbHandle,
};

// --------------------------------
// Size Measurements
// --------------------------------

/// Get the size of a table in KB using SQLite's dbstat virtual table.
pub async fn get_table_size_kb(db: &DbHandle, table_name: &str) -> DbResult<u64> {
    let result: Option<(i64,)> = sqlx::query_as("SELECT COALESCE(SUM(pgsize), 0) FROM dbstat WHERE name = ?")
        .bind(table_name)
        .fetch_optional(&db.pool)
        .await?;

    Ok(result.map(|(size,)| (size / 1024) as u64).unwrap_or(0))
}

/// Get the total database size in KB.
pub async fn get_database_size_kb(db: &DbHandle) -> DbResult<u64> {
    let result: Option<(i64,)> = sqlx::query_as("SELECT COALESCE(SUM(pgsize), 0) FROM dbstat")
        .fetch_optional(&db.pool)
        .await?;

    Ok(result.map(|(size,)| (size / 1024) as u64).unwrap_or(0))
}

/// Get size breakdown for session-related data.
pub async fn get_session_data_sizes(db: &DbHandle) -> DbResult<SessionDataSizes> {
    let relay_sessions_kb = get_table_size_kb(db, "relay_sessions").await?;
    let session_chunks_kb = get_table_size_kb(db, "session_chunks").await?;
    let participants_kb = get_table_size_kb(db, "relay_session_participants").await?;
    let client_sessions_kb = get_table_size_kb(db, "client_sessions").await?;

    // DEBT: Size heuristic assumes even distribution of size per row.
    // Session events are often much larger (JSON blobs) than system events.
    // Risk: Inaccurate size estimation leading to premature/delayed cleanup.
    // Fix: Add a 'size_bytes' column to system_events or use more precise queries.
    // Session events size: events that have a session_id or parent_session_id
    let session_events_kb: (f64,) = sqlx::query_as(
        r#"
        SELECT COALESCE(
            (SELECT SUM(pgsize) FROM dbstat WHERE name = 'system_events') *
            (SELECT CAST(COUNT(*) AS REAL) FROM system_events WHERE session_id IS NOT NULL OR parent_session_id IS NOT NULL) /
            NULLIF((SELECT COUNT(*) FROM system_events), 0),
            0
        ) / 1024
        "#,
    )
    .fetch_one(&db.pool)
    .await?;

    let mut sizes = SessionDataSizes {
        relay_sessions_kb,
        session_chunks_kb,
        participants_kb,
        client_sessions_kb,
        session_events_kb: session_events_kb.0 as u64,
        total_kb: 0,
    };
    sizes.calculate_total();

    Ok(sizes)
}

/// Get size of orphan events (not tied to sessions).
pub async fn get_orphan_events_sizes(db: &DbHandle) -> DbResult<OrphanEventsSizes> {
    // Orphan events: events with no session_id AND no parent_session_id
    let events_kb: (f64,) = sqlx::query_as(
        r#"
        SELECT COALESCE(
            (SELECT SUM(pgsize) FROM dbstat WHERE name = 'system_events') *
            (SELECT CAST(COUNT(*) AS REAL) FROM system_events WHERE session_id IS NULL AND parent_session_id IS NULL) /
            NULLIF((SELECT COUNT(*) FROM system_events), 0),
            0
        ) / 1024
        "#,
    )
    .fetch_one(&db.pool)
    .await?;

    Ok(OrphanEventsSizes {
        events_kb: events_kb.0 as u64,
    })
}

/// Get row counts for each table.
pub async fn get_row_counts(db: &DbHandle) -> DbResult<TableRowCounts> {
    let relay_sessions: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM relay_sessions").fetch_one(&db.pool).await?;
    let session_chunks: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM session_chunks").fetch_one(&db.pool).await?;
    let participants: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM relay_session_participants")
        .fetch_one(&db.pool)
        .await?;
    let client_sessions: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM client_sessions").fetch_one(&db.pool).await?;
    let system_events: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM system_events").fetch_one(&db.pool).await?;
    let orphan_events: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM system_events WHERE session_id IS NULL AND parent_session_id IS NULL")
        .fetch_one(&db.pool)
        .await?;

    Ok(TableRowCounts {
        relay_sessions: relay_sessions.0 as u64,
        session_chunks: session_chunks.0 as u64,
        participants: participants.0 as u64,
        client_sessions: client_sessions.0 as u64,
        system_events: system_events.0 as u64,
        orphan_events: orphan_events.0 as u64,
    })
}

/// Get complete database statistics.
pub async fn get_database_stats(db: &DbHandle) -> DbResult<DatabaseStats> {
    let session_data = get_session_data_sizes(db).await?;
    let orphan_events = get_orphan_events_sizes(db).await?;
    let total_size_kb = get_database_size_kb(db).await?;
    let row_counts = get_row_counts(db).await?;

    // Get actual on-disk file size (includes WAL, unvacuumed space)
    let file_size_kb = get_file_size_kb(&crate::audit::audit_db_path());

    Ok(DatabaseStats {
        session_data,
        orphan_events,
        total_size_kb,
        file_size_kb,
        row_counts,
        last_cleanup_at: None,
        last_cleanup_sessions: None,
        last_cleanup_events: None,
    })
}

/// Get on-disk file size in KB (includes WAL and unvacuumed space).
pub fn get_file_size_kb(path: &std::path::Path) -> u64 {
    // Main database file
    let main_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);

    // WAL file
    let wal_path = path.with_extension("db-wal");
    let wal_size = std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);

    // SHM file (shared memory, usually small)
    let shm_path = path.with_extension("db-shm");
    let shm_size = std::fs::metadata(&shm_path).map(|m| m.len()).unwrap_or(0);

    (main_size + wal_size + shm_size) / 1024
}

// --------------------------------
// Cascading Session Cleanup
// --------------------------------

/// Get the oldest relay_session ID.
async fn get_oldest_relay_session_id(db: &DbHandle) -> DbResult<Option<String>> {
    let result: Option<(String,)> = sqlx::query_as("SELECT id FROM relay_sessions ORDER BY start_time ASC LIMIT 1")
        .fetch_optional(&db.pool)
        .await?;

    Ok(result.map(|(id,)| id))
}

/// Delete a relay_session and all cascaded data.
///
/// This deletes:
/// - The relay_session (session_chunks and participants cascade via FK)
/// - Related client_sessions (initiator + all participants)
/// - Related system_events (by session_id and parent_session_id)
async fn delete_relay_session_cascade(db: &DbHandle, relay_session_id: &str) -> DbResult<CascadeResult> {
    let mut result = CascadeResult::default();

    // 1. Find all client_session IDs related to this relay session
    let client_ids: Vec<(String,)> = sqlx::query_as(
        r#"
        SELECT DISTINCT id FROM (
            SELECT initiator_client_session_id AS id FROM relay_sessions WHERE id = ?
            UNION
            SELECT client_session_id AS id FROM relay_session_participants WHERE relay_session_id = ?
        ) WHERE id IS NOT NULL
        "#,
    )
    .bind(relay_session_id)
    .bind(relay_session_id)
    .fetch_all(&db.pool)
    .await?;

    let client_id_list: Vec<String> = client_ids.into_iter().map(|(id,)| id).collect();

    // 2. Delete system_events tied to these client sessions or this relay session
    if !client_id_list.is_empty() {
        let placeholders = client_id_list.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let query = format!(
            "DELETE FROM system_events WHERE session_id IN ({}) OR parent_session_id = ?",
            placeholders
        );
        let mut q = sqlx::query(&query);
        for id in &client_id_list {
            q = q.bind(id);
        }
        q = q.bind(relay_session_id);
        let del = q.execute(&db.pool).await?;
        result.events_deleted = del.rows_affected();
    } else {
        // Just delete by parent_session_id
        let del = sqlx::query("DELETE FROM system_events WHERE parent_session_id = ?")
            .bind(relay_session_id)
            .execute(&db.pool)
            .await?;
        result.events_deleted = del.rows_affected();
    }

    // 3. Delete the relay_session (chunks and participants cascade via FK)
    // DEBT: Relies on ON DELETE CASCADE in schema for chunks/participants.
    // If FKs are disabled or schema is missing CASCADE, this leaves orphaned data.
    // Risk: Data integrity/leaked rows. Fix: Verify migrations or explicit delete.
    let del = sqlx::query("DELETE FROM relay_sessions WHERE id = ?")
        .bind(relay_session_id)
        .execute(&db.pool)
        .await?;
    result.sessions_deleted = del.rows_affected();

    // 4. Delete related client_sessions that are NOT still referenced by other relay_sessions
    // This prevents FK constraint violations when a client_session initiated multiple relay_sessions
    if !client_id_list.is_empty() {
        let placeholders = client_id_list.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        // Only delete client_sessions that are truly orphaned (not referenced by any remaining relay_sessions)
        let query = format!(
            r#"DELETE FROM client_sessions 
               WHERE id IN ({}) 
               AND id NOT IN (SELECT DISTINCT initiator_client_session_id FROM relay_sessions WHERE initiator_client_session_id IS NOT NULL)
               AND id NOT IN (SELECT DISTINCT client_session_id FROM relay_session_participants WHERE client_session_id IS NOT NULL)"#,
            placeholders
        );
        let mut q = sqlx::query(&query);
        for id in &client_id_list {
            q = q.bind(id);
        }
        let del = q.execute(&db.pool).await?;
        result.client_sessions_deleted = del.rows_affected();
    }

    Ok(result)
}

#[derive(Default)]
struct CascadeResult {
    sessions_deleted: u64,
    client_sessions_deleted: u64,
    events_deleted: u64,
}

/// Cleanup sessions older than max_age_days.
pub async fn cleanup_old_sessions(db: &DbHandle, max_age_days: u32) -> DbResult<(u64, u64, u64)> {
    let cutoff_ms = Utc::now().timestamp_millis() - (max_age_days as i64 * 24 * 60 * 60 * 1000);

    // Get IDs of sessions to delete
    let session_ids: Vec<(String,)> = sqlx::query_as("SELECT id FROM relay_sessions WHERE start_time < ?")
        .bind(cutoff_ms)
        .fetch_all(&db.pool)
        .await?;

    let mut total_sessions = 0u64;
    let mut total_clients = 0u64;
    let mut total_events = 0u64;

    for (id,) in session_ids {
        let cascade = delete_relay_session_cascade(db, &id).await?;
        total_sessions += cascade.sessions_deleted;
        total_clients += cascade.client_sessions_deleted;
        total_events += cascade.events_deleted;
    }

    Ok((total_sessions, total_clients, total_events))
}

/// Cleanup sessions by size - delete oldest until under limit.
pub async fn cleanup_sessions_by_size(db: &DbHandle, max_size_kb: u64) -> DbResult<(u64, u64, u64)> {
    let mut total_sessions = 0u64;
    let mut total_clients = 0u64;
    let mut total_events = 0u64;

    // DEBT: This loop deletes sessions one at a time (N+1 deletes).
    // If a server has 50k+ tiny sessions to clean up, this will be extremely slow
    // and cause high disk I/O.
    // Risk: Performance degradation during cleanup. Fix: Use batch deletes (LIMIT N).
    loop {
        let sizes = get_session_data_sizes(db).await?;
        if sizes.total_kb <= max_size_kb {
            break;
        }

        // Get and delete oldest session
        let Some(oldest_id) = get_oldest_relay_session_id(db).await? else {
            break;
        };

        let cascade = delete_relay_session_cascade(db, &oldest_id).await?;
        total_sessions += cascade.sessions_deleted;
        total_clients += cascade.client_sessions_deleted;
        total_events += cascade.events_deleted;

        // Yield to prevent blocking
        tokio::task::yield_now().await;
    }

    Ok((total_sessions, total_clients, total_events))
}

// --------------------------------
// Orphan Events Cleanup
// --------------------------------

/// Cleanup orphan events older than max_age_days.
pub async fn cleanup_old_orphan_events(db: &DbHandle, max_age_days: u32) -> DbResult<u64> {
    let cutoff_ms = Utc::now().timestamp_millis() - (max_age_days as i64 * 24 * 60 * 60 * 1000);

    let result = sqlx::query("DELETE FROM system_events WHERE timestamp < ? AND session_id IS NULL AND parent_session_id IS NULL")
        .bind(cutoff_ms)
        .execute(&db.pool)
        .await?;

    Ok(result.rows_affected())
}

/// Cleanup orphan events by size - delete oldest until under limit.
pub async fn cleanup_orphan_events_by_size(db: &DbHandle, max_size_kb: u64) -> DbResult<u64> {
    let mut total_deleted = 0u64;
    let batch_size = 500i64;

    loop {
        let sizes = get_orphan_events_sizes(db).await?;
        if sizes.events_kb <= max_size_kb {
            break;
        }

        let result = sqlx::query(
            r#"
            DELETE FROM system_events WHERE rowid IN (
                SELECT rowid FROM system_events 
                WHERE session_id IS NULL AND parent_session_id IS NULL
                ORDER BY timestamp ASC LIMIT ?
            )
            "#,
        )
        .bind(batch_size)
        .execute(&db.pool)
        .await?;

        if result.rows_affected() == 0 {
            break;
        }
        total_deleted += result.rows_affected();

        tokio::task::yield_now().await;
    }

    Ok(total_deleted)
}

// --------------------------------
// Main Cleanup Entry Point
// --------------------------------

/// Apply session retention policy.
async fn apply_session_policy(db: &DbHandle, policy: &RetentionPolicy) -> DbResult<(u64, u64, u64)> {
    if !policy.enabled {
        return Ok((0, 0, 0));
    }

    let (mut total_sessions, mut total_clients, mut total_events) = (0u64, 0u64, 0u64);

    // Age-based cleanup first
    if let Some(max_age_days) = policy.max_age_days {
        let (s, c, e) = cleanup_old_sessions(db, max_age_days).await?;
        total_sessions += s;
        total_clients += c;
        total_events += e;
    }

    // Then size-based cleanup
    if let Some(max_size_kb) = policy.max_size_kb {
        let (s, c, e) = cleanup_sessions_by_size(db, max_size_kb).await?;
        total_sessions += s;
        total_clients += c;
        total_events += e;
    }

    Ok((total_sessions, total_clients, total_events))
}

/// Apply orphan events retention policy.
async fn apply_orphan_events_policy(db: &DbHandle, policy: &RetentionPolicy) -> DbResult<u64> {
    if !policy.enabled {
        return Ok(0);
    }

    let mut total_deleted = 0u64;

    // Age-based cleanup first
    if let Some(max_age_days) = policy.max_age_days {
        total_deleted += cleanup_old_orphan_events(db, max_age_days).await?;
    }

    // Then size-based cleanup
    if let Some(max_size_kb) = policy.max_size_kb {
        total_deleted += cleanup_orphan_events_by_size(db, max_size_kb).await?;
    }

    Ok(total_deleted)
}

/// Run complete retention cleanup with cascading logic.
pub async fn run_retention_cleanup(db: &DbHandle, config: &RetentionConfig) -> DbResult<RetentionResult> {
    let start = std::time::Instant::now();
    let mut result = RetentionResult::default();

    // Session cleanup (cascading)
    match apply_session_policy(db, &config.sessions).await {
        Ok((sessions, clients, events)) => {
            result.sessions_deleted = sessions;
            result.client_sessions_deleted = clients;
            result.session_events_deleted = events;
        }
        Err(e) => result.errors.push(("sessions".to_string(), e.to_string())),
    }

    // Orphan events cleanup
    match apply_orphan_events_policy(db, &config.orphan_events).await {
        Ok(deleted) => result.orphan_events_deleted = deleted,
        Err(e) => result.errors.push(("orphan_events".to_string(), e.to_string())),
    }

    result.duration_ms = start.elapsed().as_millis() as u64;

    Ok(result)
}
