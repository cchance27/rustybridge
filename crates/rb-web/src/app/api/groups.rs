use dioxus::prelude::*;
#[cfg(feature = "server")]
use rb_types::auth::ClaimLevel;
use rb_types::{auth::ClaimType, users::GroupInfo};

use crate::error::ApiError;
#[cfg(feature = "server")]
use crate::server::audit::WebAuditContext;
#[cfg(feature = "server")]
use crate::server::auth::guards::{WebAuthSession, ensure_claim};

#[cfg(feature = "server")]
fn ensure_group_claim(auth: &WebAuthSession, level: ClaimLevel) -> Result<(), ApiError> {
    ensure_claim(auth, &ClaimType::Groups(level))
}

#[get(
    "/api/groups",
    auth: WebAuthSession
)]
pub async fn list_groups() -> Result<Vec<GroupInfo<'static>>, ApiError> {
    ensure_group_claim(&auth, ClaimLevel::View)?;
    server_core::list_groups_overview().await.map_err(ApiError::internal)
}

#[post(
    "/api/groups",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
pub async fn create_group(name: String) -> Result<(), ApiError> {
    ensure_group_claim(&auth, ClaimLevel::Create)?;
    server_core::add_group(&audit.0, &name).await.map_err(ApiError::internal)
}

#[put(
    "/api/groups/{id}",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
pub async fn update_group(id: i64, name: String) -> Result<(), ApiError> {
    ensure_group_claim(&auth, ClaimLevel::Edit)?;

    server_core::update_group_name(&audit.0, id, &name)
        .await
        .map_err(ApiError::internal)
}

#[delete(
    "/api/groups/{id}",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
pub async fn delete_group(id: i64) -> Result<(), ApiError> {
    ensure_group_claim(&auth, ClaimLevel::Delete)?;
    server_core::remove_group_by_id(&audit.0, id).await.map_err(ApiError::internal)
}

#[get(
    "/api/groups/{id}/members",
    auth: WebAuthSession
)]
pub async fn list_group_members(id: i64) -> Result<Vec<String>, ApiError> {
    ensure_group_claim(&auth, ClaimLevel::View)?;
    server_core::list_group_members_by_id(id).await.map_err(ApiError::internal)
}

#[post(
    "/api/groups/{id}/members",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
pub async fn add_member_to_group(id: i64, user_id: i64) -> Result<(), ApiError> {
    ensure_group_claim(&auth, ClaimLevel::Edit)?;
    server_core::add_user_to_group_by_ids(&audit.0, user_id, id)
        .await
        .map_err(ApiError::internal)
}

#[delete(
    "/api/groups/{id}/members/{user_id}",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
pub async fn remove_member_from_group(id: i64, user_id: i64) -> Result<(), ApiError> {
    ensure_group_claim(&auth, ClaimLevel::Delete)?;
    server_core::remove_user_from_group_by_ids(&audit.0, user_id, id)
        .await
        .map_err(ApiError::internal)
}

#[get(
    "/api/groups/{id}/claims",
    auth: WebAuthSession
)]
pub async fn get_group_claims(id: i64) -> Result<Vec<ClaimType<'static>>, ApiError> {
    ensure_group_claim(&auth, ClaimLevel::View)?;
    server_core::get_group_claims_by_id(id).await.map_err(ApiError::internal)
}

#[post(
    "/api/groups/{id}/claims",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
pub async fn add_group_claim(id: i64, claim: ClaimType<'static>) -> Result<(), ApiError> {
    ensure_group_claim(&auth, ClaimLevel::Edit)?;
    server_core::add_claim_to_group_by_id(&audit.0, id, &claim)
        .await
        .map_err(ApiError::internal)
}

/// Remove a claim from a group
/// Now uses proper DELETE method with group ID (no colon encoding issues)
#[delete(
    "/api/groups/{id}/claims",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
pub async fn remove_group_claim(id: i64, claim: ClaimType<'static>) -> Result<(), ApiError> {
    ensure_group_claim(&auth, ClaimLevel::Delete)?;
    server_core::remove_claim_from_group_by_id(&audit.0, id, &claim)
        .await
        .map_err(ApiError::internal)
}
