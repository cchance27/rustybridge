use axum_session::Session;
use axum_session_sqlx::SessionSqlitePool;
use rb_types::auth::AuthUserInfo;

const SESSION_USER_KEY: &str = "user";

/// Get the currently authenticated user from the session
pub fn get_current_user(session: &Session<SessionSqlitePool>) -> Option<AuthUserInfo> {
    session.get::<AuthUserInfo>(SESSION_USER_KEY)
}

/// Set the current user in the session
pub fn set_current_user(session: &mut Session<SessionSqlitePool>, user: AuthUserInfo) {
    session.set(SESSION_USER_KEY, user);
}

/// Clear the session (logout)
pub fn clear_session(session: &mut Session<SessionSqlitePool>) {
    session.remove(SESSION_USER_KEY);
    session.destroy();
}
