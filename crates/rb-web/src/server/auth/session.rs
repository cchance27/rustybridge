use axum_session::Session;
use rb_types::auth::AuthUserInfo;
use server_core::sessions::web::WebSessionManager;

const SESSION_USER_KEY: &str = "user";

/// Get the currently authenticated user from the session
pub fn get_current_user(session: &Session<WebSessionManager>) -> Option<AuthUserInfo<'_>> {
    session.get::<AuthUserInfo>(SESSION_USER_KEY)
}

/// Set the current user in the session
pub fn set_current_user(session: &mut Session<WebSessionManager>, user: AuthUserInfo) {
    session.set(SESSION_USER_KEY, user);
}

/// Clear the session (logout)
pub fn clear_session(session: &mut Session<WebSessionManager>) {
    session.remove(SESSION_USER_KEY);
    session.destroy();
}
