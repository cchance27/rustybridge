use crate::scheduler::{TaskConfig, TaskManager};
use rb_types::{
    audit::{AuditContext, EventType},
    tasks::*,
};

/// Register the database vacuum task (runs daily at 3 AM).
pub async fn register(manager: &TaskManager) -> Result<(), TaskError> {
    manager
        .register(
            "database_vacuum",
            "Vacuum databases to reclaim space",
            CronSchedule::parse("0 0 3 * * *")?,
            TaskConfig {
                timeout: Some(TimeoutSecs(3600)), // Allow 1 hour
                ..TaskConfig::default()
            },
            move || async move {
                match crate::retention::vacuum_all_databases().await {
                    Ok(results) => {
                        for result in results {
                            let ctx = AuditContext::system("vacuum-task");
                            crate::audit::log_event_from_context_best_effort(
                                &ctx,
                                EventType::DatabaseVacuumed {
                                    database: result.database.clone(),
                                    size_before_kb: result.size_before_kb,
                                    size_after_kb: result.size_after_kb,
                                    file_size_before_kb: result.file_size_before_kb,
                                    file_size_after_kb: result.file_size_after_kb,
                                },
                            )
                            .await;
                        }
                    }
                    Err(e) => {
                        return Err(format!("vacuum failed: {}", e));
                    }
                }
                Ok(())
            },
        )
        .await?;
    Ok(())
}
