// Authentication server functions
// These are Dioxus server functions that can be called from client code via RPC

use dioxus::prelude::*;
use rb_types::auth::{AuthUserInfo, LoginRequest, LoginResponse};

#[cfg(feature = "server")]
use crate::server::auth::WebAuthSession;

#[post(
    "/api/auth/login",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>,
)]
pub async fn login(request: LoginRequest) -> Result<LoginResponse> {
    use rb_types::auth::AuthDecision;
    use server_core::auth::authenticate_password;
    use state_store::get_user_claims_by_id;

    // Authenticate user
    let login_target = server_core::auth::parse_login_target(&request.username);
    match authenticate_password(&login_target, &request.password).await {
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

            //let has_management_access = claims.iter().any(|c| c == "*" || c.to_string().ends_with(":view"));

            // Login user with AuthSession
            auth.login_user(user_id);

            Ok(LoginResponse {
                success: true,
                message: "Login successful".to_string(),
                user: Some(AuthUserInfo {
                    id: user_id,
                    username: request.username,
                    password_hash: None,
                    claims,
                    name: None,
                    picture: None,
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
                id: user.0.id,
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
