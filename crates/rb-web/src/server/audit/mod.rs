//! Audit context extraction for web requests.
//!
//! This module provides an Axum extractor that automatically creates an AuditContext
//! from the authenticated session and request information.

use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, FromRequestParts}, http::request::Parts
};
use axum_session::Session;
use rb_types::audit::AuditContext;
use server_core::sessions::web::WebSessionManager;

use crate::server::auth::guards::WebAuthSession;

/// Extractor for audit context in web requests.
///
/// This automatically creates an AuditContext from the authenticated user
/// and request information (IP address).
///
/// # Usage
///
/// ```ignore
/// #[post("/api/users", auth: WebAuthSession, audit: WebAuditContext)]
/// pub async fn create_user(req: CreateUserRequest) -> Result<(), ServerFnError> {
///     server_core::add_user(&audit.0, &req.username, &req.password).await?;
///     Ok(())
/// }
/// ```
pub struct WebAuditContext(pub AuditContext);

impl<S> FromRequestParts<S> for WebAuditContext
where
    S: Send + Sync,
{
    type Rejection = (axum::http::StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Extract the authenticated session (which contains the user)
        let auth = WebAuthSession::from_request_parts(parts, state)
            .await
            .map_err(|_| (axum::http::StatusCode::UNAUTHORIZED, "Authentication required".to_string()))?;

        // Extract the backing session so we can use the real session identifier
        let session = Session::<WebSessionManager>::from_request_parts(parts, state)
            .await
            .map_err(|_| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Session unavailable".to_string()))?;

        // Extract IP address from ConnectInfo
        let connect_info = ConnectInfo::<SocketAddr>::from_request_parts(parts, state).await.ok();

        let ip_address = connect_info
            .map(|info| info.0.ip().to_string())
            .unwrap_or_else(|| "web".to_string());

        // Derive a stable session id from the session store
        let session_id = session.get_session_id();

        // Get user info from auth session
        let user = auth
            .current_user
            .ok_or_else(|| (axum::http::StatusCode::UNAUTHORIZED, "No authenticated user".to_string()))?;

        // Create audit context
        let ctx = AuditContext::web(user.id, &user.username, ip_address, session_id.clone(), Some(session_id));

        Ok(WebAuditContext(ctx))
    }
}
