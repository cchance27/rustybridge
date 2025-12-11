//! Retention policy management and cleanup orchestration.
//!
//! This module provides the server-core layer for retention cleanup,
//! coordinating between state-store cleanup functions and the periodic
//! background task.

use rb_types::audit::{DatabaseStats, RetentionConfig, RetentionResult, VacuumResult};
use tracing::{info, warn};

use crate::error::{ServerError, ServerResult};

// --------------------------------
// Configuration Access
// --------------------------------

/// Get the current retention configuration.
pub async fn get_retention_config() -> ServerResult<RetentionConfig> {
    let db = state_store::server_db().await?;
    state_store::get_retention_config(&db.into_pool())
        .await
        .map_err(ServerError::StateStore)
}

/// Save retention configuration.
pub async fn set_retention_config(config: &RetentionConfig) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    state_store::set_retention_config(&db.into_pool(), config)
        .await
        .map_err(ServerError::StateStore)
}

// --------------------------------
// Database Statistics
// --------------------------------

/// Get statistics for all audit database tables.
pub async fn get_database_stats() -> ServerResult<DatabaseStats> {
    let db = state_store::audit::audit_db().await.map_err(ServerError::StateStore)?;
    state_store::audit::retention::get_database_stats(&db)
        .await
        .map_err(ServerError::StateStore)
}

// --------------------------------
// Cleanup Operations
// --------------------------------

/// Run retention cleanup according to the current configuration.
///
/// This is called:
/// - On server startup (via run_startup_cleanup)
/// - Periodically by the background task
pub async fn run_retention_cleanup() -> ServerResult<RetentionResult> {
    let config = get_retention_config().await?;

    let db = state_store::audit::audit_db().await.map_err(ServerError::StateStore)?;

    let result = state_store::audit::retention::run_retention_cleanup(&db, &config)
        .await
        .map_err(ServerError::StateStore)?;

    if result.total_deleted() > 0 {
        info!(
            sessions_deleted = result.sessions_deleted,
            client_sessions_deleted = result.client_sessions_deleted,
            session_events_deleted = result.session_events_deleted,
            orphan_events_deleted = result.orphan_events_deleted,
            duration_ms = result.duration_ms,
            "Retention cleanup completed"
        );
    }

    for (area, error) in &result.errors {
        warn!(area = %area, error = %error, "Retention cleanup error");
    }

    Ok(result)
}

/// Get on-disk file size in KB
fn get_file_size_kb(path: &std::path::Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len() / 1024).unwrap_or(0)
}

/// Vacuum a single database (checkpoint WAL + VACUUM).
async fn vacuum_single_db(db_name: &str, db: &rb_types::state::DbHandle, db_path: &std::path::Path) -> ServerResult<VacuumResult> {
    // Get sizes before
    let size_before_kb = state_store::audit::retention::get_database_size_kb(db)
        .await
        .map_err(ServerError::StateStore)?;
    let file_size_before_kb = get_file_size_kb(db_path);

    // Checkpoint WAL to merge it into main database
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&db.pool)
        .await
        .map_err(|e| ServerError::StateStore(e.into()))?;

    // Run VACUUM to reclaim unused pages
    sqlx::query("VACUUM")
        .execute(&db.pool)
        .await
        .map_err(|e| ServerError::StateStore(e.into()))?;

    // Get sizes after
    let size_after_kb = state_store::audit::retention::get_database_size_kb(db)
        .await
        .map_err(ServerError::StateStore)?;
    let file_size_after_kb = get_file_size_kb(db_path);

    let result = VacuumResult {
        database: db_name.to_string(),
        size_before_kb,
        size_after_kb,
        file_size_before_kb,
        file_size_after_kb,
    };

    info!(
        database = db_name,
        size_before_kb,
        size_after_kb,
        file_size_before_kb,
        file_size_after_kb,
        bytes_reclaimed = result.bytes_reclaimed(),
        "Database vacuum completed"
    );

    Ok(result)
}

/// Vacuum all enabled databases based on configuration.
/// Returns a list of results, one per database vacuumed.
pub async fn vacuum_all_databases() -> ServerResult<Vec<VacuumResult>> {
    let config = get_retention_config().await?;
    let mut results = Vec::new();

    if config.vacuum.enabled_audit_db {
        let db = state_store::audit::audit_db().await.map_err(ServerError::StateStore)?;
        let path = state_store::audit::audit_db_path();
        match vacuum_single_db("audit", &db, &path).await {
            Ok(r) => results.push(r),
            Err(e) => warn!(error = ?e, "Audit DB vacuum failed"),
        }
    }

    if config.vacuum.enabled_server_db {
        let db = state_store::server_db().await.map_err(ServerError::StateStore)?;
        let path = state_store::server_db_path();
        match vacuum_single_db("server", &db, &path).await {
            Ok(r) => results.push(r),
            Err(e) => warn!(error = ?e, "Server DB vacuum failed"),
        }
    }

    Ok(results)
}
