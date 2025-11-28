// Authentication module - centralized auth code for maintainability

pub mod claims;
pub mod guards;
pub mod middleware;
pub mod session;
pub mod types;

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
    pool: axum::Extension<sqlx::SqlitePool>,
    session: axum_session::Session<axum_session_sqlx::SessionSqlitePool>)]
pub async fn login(request: LoginRequest) -> Result<LoginResponse> {
    use state_store::{get_latest_oidc_profile, get_user_claims_by_id};

    // Touch the session to ensure it exists before we mutate auth state (avoids axum_session warnings)
    let _ = session.get_session_id();

    // Authenticate user
    let login_target = server_core::auth::parse_login_target(&request.username);
    match server_core::auth::authenticate_password(&login_target, &request.password).await {
        Ok(AuthDecision::Accept) => {
            // Get user ID and claims

            use rb_types::auth::AuthUserInfo;
            let user_id = state_store::fetch_user_id_by_name(&*pool, &request.username)
                .await
                .map_err(|e| anyhow::anyhow!(e.to_string()))?
                .ok_or_else(|| anyhow::anyhow!("User not found"))?;

            let mut conn = pool.acquire().await.map_err(|e| anyhow::anyhow!(e.to_string()))?;
            let claims = get_user_claims_by_id(&mut conn, user_id)
                .await
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;

            // Fetch latest OIDC profile info if available
            let oidc_profile = get_latest_oidc_profile(&*pool, user_id)
                .await
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;

            let (name, picture) = oidc_profile.map(|p| (p.name, p.picture)).unwrap_or((None, None));

            // Clear auth cache for this user so refreshed profile info loads on next request
            auth.cache_clear_user(user_id);

            // Login user with AuthSession
            auth.login_user(user_id);

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
        Ok(AuthDecision::Reject) => Ok(LoginResponse {
            success: false,
            message: "Invalid username or password".to_string(),
            user: None,
        }),
        Err(e) => Err(anyhow::anyhow!("Authentication error: {}", e).into()),
    }
}

#[post(
    "/api/auth/logout",
    auth: WebAuthSession,
)]
pub async fn logout() -> Result<()> {
    // Touch session so backing store entry exists before logout_user mutates it.
    if auth.is_authenticated() {
        auth.logout_user();
    }

    Ok(())
}

#[get("/api/auth/current-user", auth: WebAuthSession)]
pub async fn get_current_user() -> Result<Option<AuthUserInfo>> {
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
