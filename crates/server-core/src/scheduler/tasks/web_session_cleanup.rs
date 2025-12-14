use crate::scheduler::{TaskConfig, TaskManager};
use rb_types::tasks::*;
use std::sync::Arc;

/// Register the stale web session cleanup task (runs every 2 minutes).
pub async fn register(manager: &TaskManager, registry: Arc<crate::sessions::SessionRegistry>) -> Result<(), TaskError> {
    manager
        .register(
            "web_session_cleanup",
            "Clean up stale web sessions",
            CronSchedule::parse("0 */2 * * * *")?,
            TaskConfig::default(),
            move || {
                let registry = registry.clone();
                async move {
                    // Clean up web sessions not seen in 5 minutes
                    registry.cleanup_stale_web_sessions(300).await;
                    Ok::<(), String>(())
                }
            },
        )
        .await?;
    Ok(())
}
