//! Task scheduler types with newtype patterns.

use chrono::{DateTime, Utc};
use derive_more::{Deref, Display, From, Into};
use serde::{Deserialize, Serialize};

/// Strongly-typed task identifier (UUIDv7 string).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Display, From, Into, Deref)]
#[display("{_0}")]
pub struct TaskId(String);

impl TaskId {
    pub fn new() -> Self {
        Self(uuid::Uuid::now_v7().to_string())
    }
}

impl Default for TaskId {
    fn default() -> Self {
        Self::new()
    }
}

/// Validated cron expression.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Display, Deref)]
#[display("{_0}")]
pub struct CronSchedule(String);

impl CronSchedule {
    pub fn parse(expr: &str) -> Result<Self, TaskError> {
        // Validation happens via croner/tokio-cron-scheduler at runtime mostly,
        // but we assume it's valid if constructed here.
        // For stricter validation we could pull in croner but keeping it lightweight for types.
        if expr.is_empty() {
            return Err(TaskError::InvalidCron("Expression cannot be empty".to_string()));
        }
        Ok(Self(expr.to_string()))
    }

    /// Get the raw cron expression string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Task timeout in seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Display, From, Into, Deref)]
#[display("{_0}s")]
pub struct TimeoutSecs(pub u64);

/// Maximum retry attempts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Display, From, Into, Deref)]
#[display("{_0}")]
pub struct MaxRetries(pub u32);

/// Task state enum for monitoring.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, strum::Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum TaskState {
    #[default]
    Idle,
    Running,
    Paused,
    Failed,
}

/// Outcome of a single task execution.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TaskOutcome {
    Success { duration_ms: u64 },
    Failed { error: String, duration_ms: u64 },
    TimedOut { timeout_secs: u64 },
    Panicked { message: String },
    Skipped { reason: String },
}

/// Record of a single task execution.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TaskRunRecord {
    pub started_at: DateTime<Utc>,
    pub outcome: TaskOutcome,
}

/// Summary info for admin display.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TaskSummary {
    pub id: TaskId,
    pub name: String,
    pub description: String,
    /// Raw cron expression
    pub schedule_display: String,
    /// Human-readable schedule description
    pub schedule_human: String,
    pub state: TaskState,
    pub last_run: Option<TaskRunRecord>,
    pub next_run: Option<DateTime<Utc>>,
    pub run_count: u64,
    pub failure_count: u64,
    pub history: Vec<TaskRunRecord>, // Last N runs
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToggleTaskRequest {
    pub enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateTaskScheduleRequest {
    pub schedule: String,
}

#[derive(Debug, thiserror::Error)]
pub enum TaskError {
    #[error("invalid cron expression: {0}")]
    InvalidCron(String),
    #[error("task not found: {0}")]
    NotFound(TaskId),
    #[error("task execution failed: {0}")]
    ExecutionFailed(String),
    #[error("scheduler error: {0}")]
    Scheduler(String),
}
