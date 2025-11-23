use axum_session::Session;
use axum_session_sqlx::SessionSqlitePool;

use super::types::WebUser;

const SESSION_USER_KEY: &str = "user";

/// Get the currently authenticated user from the session
pub fn get_current_user(session: &Session<SessionSqlitePool>) -> Option<WebUser> {
    session.get::<WebUser>(SESSION_USER_KEY)
}

/// Set the current user in the session
pub fn set_current_user(session: &mut Session<SessionSqlitePool>, user: WebUser) {
    session.set(SESSION_USER_KEY, user);
}

/// Clear the session (logout)
pub fn clear_session(session: &mut Session<SessionSqlitePool>) {
    session.remove(SESSION_USER_KEY);
    session.destroy();
}
