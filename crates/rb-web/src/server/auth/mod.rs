// Authentication module - centralized auth code for maintainability

pub mod claims;
pub mod guards;
pub mod middleware;
pub mod session;
pub mod types;

use crate::error::ApiError;
pub use claims::*;
use dioxus::prelude::*;
pub use guards::*;
use rb_types::auth::{AuthDecision, AuthUserInfo, LoginRequest, LoginResponse};
pub use types::*;

pub mod oidc;
pub mod oidc_link;
pub mod oidc_unlink;

#[post("/api/auth/login",
    auth: WebAuthSession,
    session: axum_session::Session<server_core::sessions::web::WebSessionManager>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>
)]
pub async fn login(request: LoginRequest) -> Result<LoginResponse<'static>, ApiError> {
    // Touch the session to ensure it exists before we mutate auth state (avoids axum_session warnings)
    let session_id = session.get_session_id().to_string();
    let ip_address = connect_info.0.ip().to_string();

    // Authenticate user
    let login_target = server_core::auth::parse_login_target(&request.username);
    match server_core::auth::authenticate_password(&login_target, &request.password).await {
        Ok(AuthDecision::Accept) => {
            // Get user ID and claims

            let user_id = server_core::api::get_user_id_by_name(&request.username)
                .await?
                .ok_or(ApiError::Unauthorized)?;

            let claims = server_core::api::get_user_claims_by_id(user_id).await?;

            // Fetch latest OIDC profile info if available
            let oidc_profile = server_core::api::get_latest_oidc_profile(user_id).await?;

            let (name, picture) = oidc_profile.map(|p| (p.name, p.picture)).unwrap_or((None, None));

            // Clear auth cache for this user so refreshed profile info loads on next request
            auth.cache_clear_user(user_id);

            // Login user with AuthSession
            auth.login_user(user_id);

            // Audit: Login Success
            server_core::audit::log_event_with_context_best_effort(
                Some(user_id),
                rb_types::audit::EventType::LoginSuccess {
                    method: rb_types::audit::AuthMethod::Password,
                    connection_id: session_id.clone(),
                    username: request.username.clone(),
                    client_type: rb_types::audit::ClientType::Web,
                },
                Some(ip_address),
                Some(session_id),
            )
            .await;

            Ok(LoginResponse {
                success: true,
                message: "Login successful".to_string(),
                user: Some(AuthUserInfo {
                    id: user_id,
                    username: request.username,
                    claims,
                    password_hash: None,
                    name,
                    picture,
                }),
            })
        }
        Ok(AuthDecision::Reject) => {
            // Audit: Login Failure
            server_core::audit::log_event_with_context_best_effort(
                None,
                rb_types::audit::EventType::LoginFailure {
                    method: rb_types::audit::AuthMethod::Password,
                    reason: "Invalid username or password".to_string(),
                    username: Some(request.username.clone()),
                    client_type: rb_types::audit::ClientType::Web,
                },
                Some(ip_address),
                Some(session_id),
            )
            .await;

            Ok(LoginResponse {
                success: false,
                message: "Invalid username or password".to_string(),
                user: None,
            })
        }
        Err(e) => {
            // Audit: Login Error
            server_core::audit::log_event_with_context_best_effort(
                None,
                rb_types::audit::EventType::LoginFailure {
                    method: rb_types::audit::AuthMethod::Password,
                    reason: format!("Authentication error: {}", e),
                    username: Some(request.username.clone()),
                    client_type: rb_types::audit::ClientType::Web,
                },
                Some(ip_address),
                Some(session_id),
            )
            .await;
            Err(ApiError::internal(e))
        }
    }
}

#[post(
    "/api/auth/logout",
    auth: WebAuthSession,
    session: axum_session::Session<server_core::sessions::web::WebSessionManager>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>
)]
pub async fn logout() -> Result<(), ApiError> {
    // Touch session so backing store entry exists before logout_user mutates it.
    if auth.is_authenticated() {
        if let Some(user) = auth.current_user.clone() {
            let ip_address = connect_info.0.ip().to_string();
            let session_id = session.get_session_id().to_string();

            server_core::audit::log_event_with_context_best_effort(
                Some(user.id),
                rb_types::audit::EventType::Logout {
                    username: user.username.clone(),
                    reason: "User initiated".to_string(),
                    client_type: rb_types::audit::ClientType::Web,
                },
                Some(ip_address),
                Some(session_id),
            )
            .await;
        }
        auth.logout_user();
    }

    Ok(())
}

#[get("/api/auth/current-user", auth: WebAuthSession)]
pub async fn get_current_user() -> Result<Option<AuthUserInfo<'static>>, ApiError> {
    if auth.is_authenticated() {
        if let Some(user) = auth.current_user {
            Ok(Some(AuthUserInfo {
                id: user.id,
                username: user.0.username,
                claims: user.0.claims,
                password_hash: None,
                name: user.0.name,
                picture: user.0.picture,
            }))
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}
