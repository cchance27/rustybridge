use crate::scheduler::{TaskConfig, TaskManager};
use rb_types::tasks::*;
use tracing::{info, warn};

/// Register the SSH auth session cleanup task (runs hourly).
pub async fn register(manager: &TaskManager, pool: sqlx::SqlitePool) -> Result<(), TaskError> {
    manager
        .register(
            "ssh_auth_cleanup",
            "Clean up expired SSH auth sessions",
            CronSchedule::parse("0 0 * * * *")?,
            TaskConfig::default(),
            move || {
                let pool = pool.clone();
                async move {
                    match state_store::cleanup_expired_ssh_auth_sessions(&pool).await {
                        Ok(count) if count > 0 => {
                            info!(count, "cleaned up expired/used ssh auth sessions");
                        }
                        Err(e) => {
                            warn!(error = %e, "failed to cleanup expired ssh auth sessions");
                            return Err(e.to_string());
                        }
                        _ => {}
                    }
                    Ok(())
                }
            },
        )
        .await?;
    Ok(())
}
