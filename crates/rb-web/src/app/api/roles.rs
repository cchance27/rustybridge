use dioxus::prelude::*;
#[cfg(feature = "server")]
use rb_types::auth::ClaimLevel;
use rb_types::{auth::ClaimType, users::RoleInfo};

#[cfg(feature = "server")]
use crate::server::auth::guards::{WebAuthSession, ensure_claim};

#[cfg(feature = "server")]
fn ensure_role_claim(auth: &WebAuthSession, level: ClaimLevel) -> Result<(), ServerFnError> {
    ensure_claim(auth, &ClaimType::Roles(level)).map_err(|e| ServerFnError::new(e.to_string()))
}

#[get(
    "/api/roles",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn list_roles() -> Result<Vec<RoleInfo>, ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::View)?;
    use server_core::{get_role_claims_server, list_role_groups_server, list_role_users_server};
    use state_store::list_roles;

    let roles = list_roles(&pool).await.map_err(|e| ServerFnError::new(e.to_string()))?;

    let mut result = Vec::new();
    for role in roles {
        // Get user count and names
        let users = list_role_users_server(&role.name)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        let user_count = users.len() as i64;

        // Get group count and names
        let groups = list_role_groups_server(&role.name)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        let group_count = groups.len() as i64;

        // Get claims
        let claims = get_role_claims_server(&role.name)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;

        result.push(RoleInfo {
            name: role.name,
            description: role.description,
            user_count,
            group_count,
            users,
            groups,
            claims,
        });
    }

    Ok(result)
}

#[post(
    "/api/roles",
    auth: WebAuthSession
)]
pub async fn create_role(name: String, description: Option<String>) -> Result<(), ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::Create)?;
    use server_core::create_role;
    create_role(&name, description.as_deref())
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[delete(
    "/api/roles/{name}",
    auth: WebAuthSession
)]
pub async fn delete_role(name: String) -> Result<(), ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::Delete)?;
    use server_core::delete_role_server;
    delete_role_server(&name).await.map_err(|e| ServerFnError::new(e.to_string()))
}

#[get(
    "/api/roles/{name}/users",
    auth: WebAuthSession
)]
pub async fn list_role_users(name: String) -> Result<Vec<String>, ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::View)?;
    use server_core::list_role_users_server;
    list_role_users_server(&name).await.map_err(|e| ServerFnError::new(e.to_string()))
}

#[post(
    "/api/roles/{name}/users",
    auth: WebAuthSession
)]
pub async fn assign_role_to_user(name: String, username: String) -> Result<(), ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::Edit)?;
    use server_core::assign_role;
    assign_role(&username, &name).await.map_err(|e| ServerFnError::new(e.to_string()))
}

#[delete(
    "/api/roles/{name}/users/{username}",
    auth: WebAuthSession
)]
pub async fn revoke_role_from_user(name: String, username: String) -> Result<(), ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::Delete)?;
    use server_core::revoke_role_from_user_server;
    revoke_role_from_user_server(&username, &name)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[get(
    "/api/roles/{name}/groups",
    auth: WebAuthSession
)]
pub async fn list_role_groups(name: String) -> Result<Vec<String>, ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::View)?;
    use server_core::list_role_groups_server;
    list_role_groups_server(&name).await.map_err(|e| ServerFnError::new(e.to_string()))
}

#[post(
    "/api/roles/{name}/groups",
    auth: WebAuthSession
)]
pub async fn assign_role_to_group(name: String, group_name: String) -> Result<(), ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::Edit)?;
    use server_core::assign_role_to_group_server;
    assign_role_to_group_server(&group_name, &name)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[delete(
    "/api/roles/{name}/groups/{group_name}",
    auth: WebAuthSession
)]
pub async fn revoke_role_from_group(name: String, group_name: String) -> Result<(), ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::Delete)?;
    use server_core::revoke_role_from_group_server;
    revoke_role_from_group_server(&group_name, &name)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[post(
    "/api/roles/{name}/claims",
    auth: WebAuthSession
)]
pub async fn add_role_claim(name: String, claim: ClaimType) -> Result<(), ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::Edit)?;
    use server_core::add_role_claim;
    add_role_claim(&name, &claim).await.map_err(|e| ServerFnError::new(e.to_string()))
}

/// NOTE: Uses POST instead of DELETE because ClaimType contains colons (e.g. "relays:view")
/// which cause routing issues when used as path parameters in DELETE requests
#[post(
    "/api/roles/{name}/claims/remove",
    auth: WebAuthSession
)]
pub async fn remove_role_claim(name: String, claim: ClaimType) -> Result<(), ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::Delete)?;
    use server_core::remove_role_claim_server;
    remove_role_claim_server(&name, &claim)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}
