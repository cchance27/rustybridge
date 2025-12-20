//! Centralized task scheduler with monitoring and control.
//!
//! Provides a type-safe wrapper around tokio-cron-scheduler with:
//! - Retry on failure (configurable per-task)
//! - Execution timeouts
//! - Panic catching with graceful recovery
//! - Admin visibility (stats, history, next run)
//! - Pause/resume/trigger controls

pub mod executor;
pub mod manager;
pub mod registry;
pub mod tasks;

pub use executor::TaskConfig;

#[cfg(test)]
mod tests;
pub use manager::TaskManager;
pub use registry::TaskRegistry;
use std::sync::OnceLock;

static GLOBAL_SCHEDULER: OnceLock<TaskManager> = OnceLock::new();

/// Get the global task manager instance if initialized.
pub fn get_manager() -> Option<&'static TaskManager> {
    GLOBAL_SCHEDULER.get()
}

/// Set the global task manager instance.
pub fn set_global_manager(manager: TaskManager) -> Result<(), TaskManager> {
    GLOBAL_SCHEDULER.set(manager)
}

use crate::error::{ServerError, ServerResult};
use std::sync::Arc;

/// Initialize the global task manager, register built-in tasks, and start the scheduler.
/// This is idempotent; if the scheduler is already initialized, it returns Ok.
pub async fn init(
    pool: sqlx::SqlitePool,
    registry: Arc<crate::sessions::SessionRegistry>,
) -> ServerResult<()> {
    if get_manager().is_some() {
        return Ok(());
    }

    let task_manager = TaskManager::new(pool.clone())
        .await
        .map_err(|e| ServerError::Internal(format!("Failed to init task manager: {}", e)))?;

    tasks::register_builtin_tasks(&task_manager, pool.clone(), registry.clone())
        .await
        .map_err(|e| ServerError::Internal(format!("Failed to register tasks: {}", e)))?;

    if let Err(_) = set_global_manager(task_manager.clone()) {
        // If setting fails, it means another thread raced us to init.
        // In that case, we can assume it's handled.
        return Ok(());
    }

    let manager_handle = task_manager.clone();
    tokio::spawn(async move {
        if let Err(e) = manager_handle.start().await {
            tracing::error!("task scheduler failed: {}", e);
        }
    });

    Ok(())
}
