//! Server settings API endpoints for retention configuration and database management.

use dioxus::prelude::*;
use rb_types::audit::{DatabaseStats, RetentionConfig, RetentionResult, VacuumResult};
#[cfg(feature = "server")]
use rb_types::auth::ClaimLevel;

use crate::error::ApiError;
#[cfg(feature = "server")]
use crate::server::audit::WebAuditContext;
#[cfg(feature = "server")]
use crate::server::auth::guards::{WebAuthSession, ensure_claim};

#[cfg(feature = "server")]
fn ensure_server_claim(auth: &WebAuthSession, level: ClaimLevel) -> Result<(), ApiError> {
    ensure_claim(auth, &rb_types::auth::ClaimType::Server(level))
}

// --------------------------------
// Retention Configuration
// --------------------------------

/// Get the current retention configuration
#[get(
    "/api/admin/settings/retention",
    auth: WebAuthSession
)]
pub async fn get_retention_settings() -> Result<RetentionConfig, ApiError> {
    ensure_server_claim(&auth, ClaimLevel::View)?;
    server_core::retention::get_retention_config().await.map_err(ApiError::internal)
}

/// Update the retention configuration
#[post(
    "/api/admin/settings/retention",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
pub async fn update_retention_settings(config: RetentionConfig) -> Result<(), ApiError> {
    ensure_server_claim(&auth, ClaimLevel::Edit)?;

    // Log audit event for settings change
    server_core::audit::log_event_from_context_best_effort(
        &audit.0,
        rb_types::audit::EventType::ServerSettingsUpdated {
            setting_name: "retention_config".to_string(),
        },
    )
    .await;

    server_core::retention::set_retention_config(&config)
        .await
        .map_err(ApiError::internal)
}

// --------------------------------
// Database Statistics
// --------------------------------

/// Get database statistics for admin dashboard
#[get(
    "/api/admin/database/stats",
    auth: WebAuthSession
)]
pub async fn get_database_stats() -> Result<DatabaseStats, ApiError> {
    ensure_server_claim(&auth, ClaimLevel::View)?;
    server_core::retention::get_database_stats().await.map_err(ApiError::internal)
}

// --------------------------------
// Manual Cleanup Operations
// --------------------------------

/// Run full retention cleanup (admin-triggered cascading cleanup)
#[post(
    "/api/admin/database/cleanup",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
pub async fn run_cleanup() -> Result<RetentionResult, ApiError> {
    ensure_server_claim(&auth, ClaimLevel::Delete)?;

    let result = server_core::retention::run_retention_cleanup().await.map_err(ApiError::internal)?;

    // Log audit event for admin-triggered cleanup
    if result.total_deleted() > 0 {
        server_core::audit::log_event_from_context_best_effort(
            &audit.0,
            rb_types::audit::EventType::AuditRetentionRun {
                total_deleted: result.total_deleted(),
                sessions_deleted: result.sessions_deleted,
                client_sessions_deleted: result.client_sessions_deleted,
                session_events_deleted: result.session_events_deleted,
                orphan_events_deleted: result.orphan_events_deleted,
                is_automated: false, // Admin-triggered
            },
        )
        .await;
    }

    Ok(result)
}

/// Vacuum the database to reclaim disk space (checkpoints WAL and compacts)
#[post(
    "/api/admin/database/vacuum_all",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
// DEBT: This endpoint triggers a full database VACUUM which takes an exclusive lock.
// On large databases (>1GB), this will cause API timeouts and block all other writes.
// Risk: High Availability impact. Fix: Only allow running this via background task or
// return 202 Accepted immediately.
pub async fn vacuum_all_databases() -> Result<Vec<VacuumResult>, ApiError> {
    use rb_types::audit::EventType;
    use server_core::audit::log_event_from_context_best_effort;

    ensure_server_claim(&auth, ClaimLevel::Delete)?;

    let result = server_core::retention::vacuum_all_databases().await.map_err(ApiError::internal)?;

    // Log audit events
    for res in &result {
        log_event_from_context_best_effort(
            &audit.0,
            EventType::DatabaseVacuumed {
                database: res.database.clone(),
                size_before_kb: res.size_before_kb,
                size_after_kb: res.size_after_kb,
                file_size_before_kb: res.file_size_before_kb,
                file_size_after_kb: res.file_size_after_kb,
            },
        )
        .await;
    }
    Ok(result)
}

// --------------------------------
// Log Level Configuration
// --------------------------------

/// Server log level information returned to the admin UI.
#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
pub struct ServerLogLevelResponse {
    /// The persisted log level from the server database (e.g. "info", "debug").
    pub level: String,
    /// Whether the effective runtime log configuration is currently overridden
    /// by the `RUST_LOG` environment variable.
    pub overridden_by_env: bool,
}

/// Get current server log level
#[get(
    "/api/admin/settings/log_level",
    auth: WebAuthSession
)]
pub async fn get_server_log_level() -> Result<ServerLogLevelResponse, ApiError> {
    ensure_server_claim(&auth, ClaimLevel::View)?;

    let level = server_core::logging::get_server_log_level().await.map_err(ApiError::internal)?;

    let overridden_by_env = matches!(
        std::env::var("RUST_LOG"),
        Ok(s) if !s.trim().is_empty()
    );

    Ok(ServerLogLevelResponse { level, overridden_by_env })
}

/// Update server log level
#[post(
    "/api/admin/settings/log_level",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
pub async fn update_server_log_level(level: String) -> Result<(), ApiError> {
    ensure_server_claim(&auth, ClaimLevel::Edit)?;

    // Log audit event
    server_core::audit::log_event_from_context_best_effort(
        &audit.0,
        rb_types::audit::EventType::ServerSettingsUpdated {
            setting_name: "log_level".to_string(),
        },
    )
    .await;

    server_core::logging::set_server_log_level(&level).await.map_err(ApiError::internal)
}
