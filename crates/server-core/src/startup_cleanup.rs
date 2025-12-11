//! Startup cleanup for stale sessions, connections, and retention policies.
//!
//! This module handles cleaning up any sessions or connections that were left
//! in an unclosed state due to server restart or crash, and applies retention
//! policies to the audit database.

use chrono::Utc;
use tracing::{info, warn};

use crate::error::ServerResult;

/// Run all startup cleanup tasks.
///
/// This should be called on server startup, after database migrations but before
/// accepting any client connections.
///
/// Tasks performed:
/// - Mark stale sessions as closed
/// - Log SessionForceClosed audit events for orphaned sessions
/// - Clean up stale participants and client sessions
/// - Apply retention policies to audit database
pub async fn run_startup_cleanup() -> ServerResult<()> {
    cleanup_stale_sessions_internal().await?;

    // Run retention cleanup on startup
    if let Err(e) = crate::retention::run_retention_cleanup().await {
        warn!(error = ?e, "startup retention cleanup failed (non-fatal)");
    }

    Ok(())
}

/// Clean up stale sessions from the audit database that were left unclosed.
async fn cleanup_stale_sessions_internal() -> ServerResult<()> {
    let audit_db = state_store::audit::audit_db()
        .await
        .map_err(crate::error::ServerError::StateStore)?;
    let pool = &audit_db.pool;

    // 1. Find all sessions without an end_time (unclosed)
    // We fetch session_number and username to log a proper SessionForceClosed event
    let stale_sessions: Vec<(String, i64, String, i64, u32)> = sqlx::query_as(
        "SELECT rs.id, rs.user_id, 
                COALESCE(json_extract(rs.metadata, '$.relay_name'), 'unknown') as relay_name,
                COALESCE(json_extract(rs.metadata, '$.relay_id'), 0) as relay_id,
                rs.session_number
         FROM relay_sessions rs
         WHERE rs.end_time IS NULL",
    )
    .fetch_all(pool)
    .await
    .map_err(crate::error::ServerError::Database)?;

    let now = Utc::now().timestamp_millis();
    let ctx = rb_types::audit::AuditContext::system("startup-cleanup");

    if !stale_sessions.is_empty() {
        info!(count = stale_sessions.len(), "cleaning up stale sessions from previous server run");

        for (session_id, user_id, relay_name, relay_id, session_number) in stale_sessions {
            // Update the session end_time
            if let Err(e) = sqlx::query("UPDATE relay_sessions SET end_time = ? WHERE id = ?")
                .bind(now)
                .bind(&session_id)
                .execute(pool)
                .await
            {
                warn!(session_id = %session_id, error = ?e, "failed to update stale session end_time");
                continue;
            }

            info!(
                session_id = %session_id,
                user_id = user_id,
                relay_name = %relay_name,
                "marked stale session as closed (server restart cleanup)"
            );

            // Fetch username for audit log if possible
            let target_username = if let Ok(Some(u)) = crate::api::fetch_user_auth_record_by_id(user_id).await {
                u.username
            } else {
                format!("user:{}", user_id)
            };

            // Log SessionForceClosed event
            crate::audit!(
                &ctx,
                SessionForceClosed {
                    session_id: session_id.clone(),
                    session_number,
                    relay_id,
                    relay_name: relay_name.clone(),
                    target_username,
                    reason: "Server Restart".to_string(),
                }
            );
        }
    }

    // 2. Clean up stale relay_session_participants
    let participants_result = sqlx::query("UPDATE relay_session_participants SET left_at = ? WHERE left_at IS NULL")
        .bind(now)
        .execute(pool)
        .await
        .map_err(crate::error::ServerError::Database)?;

    if participants_result.rows_affected() > 0 {
        info!(count = participants_result.rows_affected(), "cleaned up stale session participants");
    }

    // 3. Clean up stale client_sessions (SSH/Web client connections)
    let client_sessions_result = sqlx::query("UPDATE client_sessions SET disconnected_at = ? WHERE disconnected_at IS NULL")
        .bind(now)
        .execute(pool)
        .await
        .map_err(crate::error::ServerError::Database)?;

    if client_sessions_result.rows_affected() > 0 {
        info!(count = client_sessions_result.rows_affected(), "cleaned up stale client sessions");
    }

    // 4. Clean up stale session_connections (legacy table, keeping just in case)
    // Note: client_sessions is the new table, session_connections might be deprecated or used for something else
    let stale_connections: Vec<String> = sqlx::query_scalar("SELECT id FROM session_connections WHERE disconnected_at IS NULL")
        .fetch_all(pool)
        .await
        .unwrap_or_default();

    if !stale_connections.is_empty() {
        info!(count = stale_connections.len(), "cleaning up stale session_connections");
        for conn_id in stale_connections {
            let _ = sqlx::query("UPDATE session_connections SET disconnected_at = ? WHERE id = ?")
                .bind(now)
                .bind(&conn_id)
                .execute(pool)
                .await;
        }
    }

    Ok(())
}
