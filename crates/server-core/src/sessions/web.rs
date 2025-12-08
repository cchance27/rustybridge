use axum_session_sqlx::SessionSqlitePool;
use rb_types::state::DbHandle;

pub type WebSessionManager = SessionSqlitePool;

pub fn create_web_session_manager(handle: &DbHandle) -> WebSessionManager {
    SessionSqlitePool::from(handle.pool.clone())
}
