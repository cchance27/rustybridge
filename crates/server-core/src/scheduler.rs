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
