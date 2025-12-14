//! Built-in server tasks.

use super::TaskManager;
use rb_types::tasks::TaskError;
use std::sync::Arc;

pub mod database_vacuum;
pub mod detached_session_cleanup;
pub mod retention_cleanup;
pub mod ssh_auth_cleanup;
pub mod web_session_cleanup;

/// Register all built-in server tasks.
pub async fn register_builtin_tasks(
    manager: &TaskManager,
    pool: sqlx::SqlitePool,
    registry: Arc<crate::sessions::SessionRegistry>,
) -> Result<(), TaskError> {
    ssh_auth_cleanup::register(manager, pool.clone()).await?;
    detached_session_cleanup::register(manager, registry.clone()).await?;
    web_session_cleanup::register(manager, registry.clone()).await?;
    retention_cleanup::register(manager).await?;
    database_vacuum::register(manager).await?;

    Ok(())
}
