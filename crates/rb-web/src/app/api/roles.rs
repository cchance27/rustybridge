use dioxus::prelude::*;
#[cfg(feature = "server")]
use rb_types::auth::ClaimLevel;
use rb_types::{auth::ClaimType, users::RoleInfo};

#[cfg(feature = "server")]
use crate::server::audit::WebAuditContext;
#[cfg(feature = "server")]
use crate::server::auth::guards::{WebAuthSession, ensure_claim};

#[cfg(feature = "server")]
fn ensure_role_claim(auth: &WebAuthSession, level: ClaimLevel) -> Result<(), ServerFnError> {
    ensure_claim(auth, &ClaimType::Roles(level)).map_err(|e| ServerFnError::new(e.to_string()))
}

#[get(
    "/api/roles",
    auth: WebAuthSession
)]
pub async fn list_roles() -> Result<Vec<RoleInfo<'static>>, ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::View)?;
    server_core::list_roles_with_details()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[post(
    "/api/roles",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
pub async fn create_role(name: String, description: Option<String>) -> Result<(), ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::Create)?;
    server_core::create_role(&audit.0, &name, description.as_deref())
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[delete(
    "/api/roles/{id}",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
pub async fn delete_role(id: i64) -> Result<(), ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::Delete)?;
    server_core::delete_role(&audit.0, id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[get(
    "/api/roles/{id}/users",
    auth: WebAuthSession
)]
pub async fn list_role_users(id: i64) -> Result<Vec<String>, ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::View)?;
    server_core::list_role_users_by_id(id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[post(
    "/api/roles/{id}/users",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
pub async fn assign_role_to_user(id: i64, user_id: i64) -> Result<(), ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::Edit)?;
    server_core::assign_role_to_user(&audit.0, user_id, id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[delete(
    "/api/roles/{id}/users/{user_id}",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
pub async fn revoke_role_from_user(id: i64, user_id: i64) -> Result<(), ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::Delete)?;
    server_core::revoke_role_from_user(&audit.0, user_id, id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[get(
    "/api/roles/{id}/groups",
    auth: WebAuthSession
)]
pub async fn list_role_groups(id: i64) -> Result<Vec<String>, ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::View)?;
    server_core::list_role_groups_by_id(id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[post(
    "/api/roles/{id}/groups",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
pub async fn assign_role_to_group(id: i64, group_id: i64) -> Result<(), ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::Edit)?;
    server_core::assign_role_to_group_by_ids(&audit.0, group_id, id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[delete(
    "/api/roles/{id}/groups/{group_id}",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
pub async fn revoke_role_from_group(id: i64, group_id: i64) -> Result<(), ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::Delete)?;
    server_core::revoke_role_from_group_by_ids(&audit.0, group_id, id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[post(
    "/api/roles/{id}/claims",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
pub async fn add_role_claim(id: i64, claim: ClaimType<'static>) -> Result<(), ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::Edit)?;
    server_core::add_claim_to_role(&audit.0, id, &claim)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Now uses proper DELETE method with role ID (no colon encoding issues)
#[delete(
    "/api/roles/{id}/claims",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
pub async fn remove_role_claim(id: i64, claim: ClaimType<'static>) -> Result<(), ServerFnError> {
    ensure_role_claim(&auth, ClaimLevel::Delete)?;
    server_core::remove_claim_from_role(&audit.0, id, &claim)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}
