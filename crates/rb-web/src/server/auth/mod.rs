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

#[post("/api/auth/login", 
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>)]
pub async fn login(request: LoginRequest) -> Result<LoginResponse> {
    use state_store::get_user_claims;

    // Authenticate user
    let login_target = server_core::auth::parse_login_target(&request.username);
    match server_core::auth::authenticate_password(&login_target, &request.password).await {
        Ok(AuthDecision::Accept) => {
            // Get user ID and claims

            use rb_types::auth::AuthUserInfo;
            let user_id = state_store::fetch_user_id_by_name(&pool, &request.username)
                .await
                .map_err(|e| anyhow::anyhow!(e.to_string()))?
                .ok_or_else(|| anyhow::anyhow!("User not found"))?;

            let claims = get_user_claims(&pool, &request.username)
                .await
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;

            let has_management_access = claims.iter().any(|c| c == "*" || c.to_string().ends_with(":view"));

            // Login user with AuthSession
            auth.login_user(user_id);

            Ok(LoginResponse {
                success: true,
                message: "Login successful".to_string(),
                user: Some(AuthUserInfo {
                    id: user_id,
                    username: request.username,
                    claims,
                    has_management_access,
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

#[post("/api/auth/logout", auth: WebAuthSession)]
pub async fn logout() -> Result<()> {
    auth.logout_user();
    Ok(())
}

#[get("/api/auth/current-user", auth: WebAuthSession)]
pub async fn get_current_user() -> Result<Option<AuthUserInfo>> {
    if auth.is_authenticated() {
        if let Some(user) = auth.current_user {
            let has_management_access = user.has_management_access();

            Ok(Some(AuthUserInfo {
                id: user.id,
                username: user.username,
                claims: user.claims,
                has_management_access,
            }))
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}
