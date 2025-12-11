//! Retention policy configuration types.
//!
//! These types define configurable retention policies for audit database tables,
//! allowing administrators to set limits on data age and size.

use serde::{Deserialize, Serialize};

/// Retention policy with age-based and size-based limits.
///
/// Entry count limits are intentionally omitted as they don't make sense
/// for multi-table cascading cleanup (sessions span multiple tables).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RetentionPolicy {
    /// Maximum age in days (oldest entries exceeding this are deleted)
    pub max_age_days: Option<u32>,
    /// Maximum total size in KB (iterative cleanup until under limit)
    pub max_size_kb: Option<u64>,
    /// Whether retention cleanup is enabled
    #[serde(default)]
    pub enabled: bool,
}

/// Size breakdown for session-related data across all tables.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SessionDataSizes {
    /// Size of relay_sessions table in KB
    pub relay_sessions_kb: u64,
    /// Size of session_chunks table in KB
    pub session_chunks_kb: u64,
    /// Size of relay_session_participants table in KB
    pub participants_kb: u64,
    /// Size of client_sessions table in KB
    pub client_sessions_kb: u64,
    /// Size of system_events tied to sessions in KB
    pub session_events_kb: u64,
    /// Total size of all session data in KB
    pub total_kb: u64,
}

impl SessionDataSizes {
    /// Calculate total from individual sizes.
    pub fn calculate_total(&mut self) {
        self.total_kb =
            self.relay_sessions_kb + self.session_chunks_kb + self.participants_kb + self.client_sessions_kb + self.session_events_kb;
    }
}

/// Size breakdown for orphan events (not tied to sessions).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct OrphanEventsSizes {
    /// Size of system_events not tied to any session in KB
    pub events_kb: u64,
}

/// Complete database statistics for admin dashboard.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct DatabaseStats {
    /// Session data size breakdown
    pub session_data: SessionDataSizes,
    /// Orphan events size
    pub orphan_events: OrphanEventsSizes,
    /// Total database size in KB (from dbstat - internal pages)
    pub total_size_kb: u64,
    /// Actual on-disk file size in KB (includes WAL, unvacuumed space)
    #[serde(default)]
    pub file_size_kb: u64,
    /// Row counts per table
    pub row_counts: TableRowCounts,
    /// Last cleanup run timestamp (ms since epoch)
    pub last_cleanup_at: Option<i64>,
    /// Sessions deleted in last cleanup
    pub last_cleanup_sessions: Option<u64>,
    /// Events deleted in last cleanup
    pub last_cleanup_events: Option<u64>,
}

/// Row counts for each table.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct TableRowCounts {
    pub relay_sessions: u64,
    pub session_chunks: u64,
    pub participants: u64,
    pub client_sessions: u64,
    pub system_events: u64,
    pub orphan_events: u64,
}

/// Configuration for periodic database vacuum/checkpoint operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VacuumConfig {
    /// Enable vacuum for audit database (default: false)
    #[serde(default = "default_false")]
    pub enabled_audit_db: bool,
    /// Enable vacuum for server database (default: false)
    #[serde(default = "default_false")]
    pub enabled_server_db: bool,
    /// Vacuum interval in seconds (minimum 5 minutes)
    #[serde(default = "default_vacuum_interval")]
    pub interval_secs: u64,
}

fn default_false() -> bool {
    false
}

pub fn default_vacuum_interval() -> u64 {
    86400 * 7 // 7 days
}

impl Default for VacuumConfig {
    fn default() -> Self {
        Self {
            enabled_audit_db: false,
            enabled_server_db: false,
            interval_secs: default_vacuum_interval(),
        }
    }
}

/// Retention configuration with two policy groups.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RetentionConfig {
    /// Policy for all session data (relay_sessions + chunks + participants + client_sessions + session events)
    /// Cleanup cascades: deleting a relay_session deletes all related data
    #[serde(default)]
    pub sessions: RetentionPolicy,
    /// Policy for orphan system_events (not tied to any session)
    #[serde(default)]
    pub orphan_events: RetentionPolicy,
    /// Cleanup interval in seconds (how often the background task runs)
    #[serde(default = "default_cleanup_interval")]
    pub cleanup_interval_secs: u64,
    /// Vacuum/checkpoint configuration
    #[serde(default)]
    pub vacuum: VacuumConfig,
}

pub fn default_cleanup_interval() -> u64 {
    3600 // 1 hour
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            sessions: RetentionPolicy::default(),
            orphan_events: RetentionPolicy::default(),
            cleanup_interval_secs: default_cleanup_interval(),
            vacuum: VacuumConfig::default(),
        }
    }
}

/// Result of a retention cleanup run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RetentionResult {
    /// Number of relay_sessions deleted (chunks/participants cascade)
    pub sessions_deleted: u64,
    /// Number of client_sessions deleted
    pub client_sessions_deleted: u64,
    /// Number of session-related events deleted
    pub session_events_deleted: u64,
    /// Number of orphan events deleted
    pub orphan_events_deleted: u64,
    /// Duration of cleanup in milliseconds
    pub duration_ms: u64,
    /// Any errors encountered (description -> error message)
    pub errors: Vec<(String, String)>,
}

impl RetentionResult {
    /// Total rows deleted across all tables.
    pub fn total_deleted(&self) -> u64 {
        self.sessions_deleted + self.client_sessions_deleted + self.session_events_deleted + self.orphan_events_deleted
    }
}

/// Result of a single database vacuum operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VacuumResult {
    /// Which database was vacuumed: "audit" or "server"
    pub database: String,
    /// dbstat internal size before vacuum (KB)
    pub size_before_kb: u64,
    /// dbstat internal size after vacuum (KB)
    pub size_after_kb: u64,
    /// Actual on-disk file size before vacuum (KB)
    pub file_size_before_kb: u64,
    /// Actual on-disk file size after vacuum (KB)
    pub file_size_after_kb: u64,
}

impl VacuumResult {
    /// Bytes reclaimed from on-disk file size
    pub fn bytes_reclaimed(&self) -> u64 {
        if self.file_size_before_kb > self.file_size_after_kb {
            (self.file_size_before_kb - self.file_size_after_kb) * 1024
        } else {
            0
        }
    }
}
