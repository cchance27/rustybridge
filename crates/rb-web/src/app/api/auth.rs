// Authentication server functions
// These are Dioxus server functions that can be called from client code via RPC

use dioxus::prelude::*;
use rb_types::auth::{AuthUserInfo, LoginRequest, LoginResponse};

#[cfg(feature = "server")]
use crate::server::auth::WebAuthSession;

#[post("/api/auth/login", auth: WebAuthSession)]
pub async fn login(request: LoginRequest) -> Result<LoginResponse> {
    use state_store::{get_user_claims, migrate_server, server_db};

    let db = server_db().await.map_err(|e| anyhow::anyhow!(e.to_string()))?;
    migrate_server(&db).await.map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let pool = db.into_pool();

    // Authenticate user
    let login_target = server_core::auth::parse_login_target(&request.username);
    match server_core::auth::authenticate_password(&login_target, &request.password).await {
        Ok(server_core::auth::AuthDecision::Accept) => {
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
        Ok(server_core::auth::AuthDecision::Reject) => Ok(LoginResponse {
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
