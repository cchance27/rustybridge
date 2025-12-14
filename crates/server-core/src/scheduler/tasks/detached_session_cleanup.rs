use crate::scheduler::{TaskConfig, TaskManager};
use rb_types::tasks::*;
use std::sync::Arc;

/// Register the expired detached session cleanup task (runs every minute).
pub async fn register(manager: &TaskManager, registry: Arc<crate::sessions::SessionRegistry>) -> Result<(), TaskError> {
    manager
        .register(
            "detached_session_cleanup",
            "Clean up expired detached sessions",
            CronSchedule::parse("0 * * * * *")?,
            TaskConfig::default(),
            move || {
                let registry = registry.clone();
                async move {
                    registry.cleanup_expired_sessions().await;
                    Ok::<(), String>(())
                }
            },
        )
        .await?;
    Ok(())
}
