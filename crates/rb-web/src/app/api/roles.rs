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
    use state_store::{get_role_claims_by_id, list_role_groups_by_id, list_role_users_by_id, list_roles};

    let roles = list_roles(&*pool).await.map_err(|e| ServerFnError::new(e.to_string()))?;

    let mut result = Vec::new();
    for role in roles {
        // Get user count and names
        let users = list_role_users_by_id(&*pool, role.id)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        let user_count = users.len() as i64;

        // Get group count and names
        let groups = list_role_groups_by_id(&*pool, role.id)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        let group_count = groups.len() as i64;

        // Get claims
        let claims = get_role_claims_by_id(&*pool, role.id)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;

        result.push(RoleInfo {
            id: role.id,
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
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn create_role(name: String, description: Option<String>) -> Result<(), ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::Create)?;
    state_store::create_role(&*pool, &name, description.as_deref())
        .await
        .map(|_| ())
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[delete(
    "/api/roles/{id}",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn delete_role(id: i64) -> Result<(), ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::Delete)?;
    state_store::delete_role_by_id(&*pool, id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[get(
    "/api/roles/{id}/users",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn list_role_users(id: i64) -> Result<Vec<String>, ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::View)?;
    state_store::list_role_users_by_id(&*pool, id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[post(
    "/api/roles/{id}/users",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn assign_role_to_user(id: i64, user_id: i64) -> Result<(), ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::Edit)?;
    state_store::assign_role_to_user_by_ids(&*pool, user_id, id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[delete(
    "/api/roles/{id}/users/{user_id}",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn revoke_role_from_user(id: i64, user_id: i64) -> Result<(), ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::Delete)?;
    let mut conn = pool.acquire().await.map_err(|e| ServerFnError::new(e.to_string()))?;
    state_store::revoke_role_from_user_by_ids(&mut conn, user_id, id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[get(
    "/api/roles/{id}/groups",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn list_role_groups(id: i64) -> Result<Vec<String>, ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::View)?;
    state_store::list_role_groups_by_id(&*pool, id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[post(
    "/api/roles/{id}/groups",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn assign_role_to_group(id: i64, group_id: i64) -> Result<(), ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::Edit)?;
    state_store::assign_role_to_group_by_ids(&*pool, group_id, id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[delete(
    "/api/roles/{id}/groups/{group_id}",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn revoke_role_from_group(id: i64, group_id: i64) -> Result<(), ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::Delete)?;
    state_store::revoke_role_from_group_by_ids(&*pool, group_id, id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[post(
    "/api/roles/{id}/claims",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn add_role_claim(id: i64, claim: ClaimType) -> Result<(), ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::Edit)?;
    use state_store::add_claim_to_role_by_id;
    add_claim_to_role_by_id(&*pool, id, &claim)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Now uses proper DELETE method with role ID (no colon encoding issues)
#[delete(
    "/api/roles/{id}/claims",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn remove_role_claim(id: i64, claim: ClaimType) -> Result<(), ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::Delete)?;
    use state_store::remove_claim_from_role_by_id;
    remove_claim_from_role_by_id(&*pool, id, &claim)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}
