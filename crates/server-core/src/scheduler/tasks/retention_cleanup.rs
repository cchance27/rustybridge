use crate::scheduler::{TaskConfig, TaskManager};
use rb_types::{
    audit::{AuditContext, EventType},
    tasks::*,
};

/// Register the retention cleanup task (enforces audit log policies, runs every 15 minutes).
pub async fn register(manager: &TaskManager) -> Result<(), TaskError> {
    manager
        .register(
            "retention_cleanup",
            "Enforce audit log retention policies",
            CronSchedule::parse("0 */15 * * * *")?,
            TaskConfig {
                timeout: Some(TimeoutSecs(600)), // Allow 10 mins
                ..TaskConfig::default()
            },
            move || {
                async move {
                    // We just run it. If it ran recently, the DB query is cheap enough.
                    match crate::retention::run_retention_cleanup().await {
                        Ok(result) if result.total_deleted() > 0 => {
                            let ctx = AuditContext::system("retention-cleanup");
                            crate::audit::log_event_from_context_best_effort(
                                &ctx,
                                EventType::AuditRetentionRun {
                                    total_deleted: result.total_deleted(),
                                    sessions_deleted: result.sessions_deleted,
                                    client_sessions_deleted: result.client_sessions_deleted,
                                    session_events_deleted: result.session_events_deleted,
                                    orphan_events_deleted: result.orphan_events_deleted,
                                    is_automated: true,
                                },
                            )
                            .await;
                        }
                        Err(e) => {
                            return Err(format!("retention cleanup failed: {}", e));
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
