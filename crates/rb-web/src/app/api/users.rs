use crate::error::ApiError;
use dioxus::prelude::*;
use rb_types::{
    auth::ClaimType,
    users::{CreateUserRequest, UpdateUserRequest, UserGroupInfo},
};
#[cfg(feature = "server")]
use {
    crate::server::audit::WebAuditContext,
    crate::server::auth::guards::{WebAuthSession, ensure_claim},
    rb_types::auth::ClaimLevel,
};

#[cfg(feature = "server")]
fn ensure_user_claim(auth: &WebAuthSession, level: ClaimLevel) -> Result<(), ApiError> {
    ensure_claim(auth, &ClaimType::Users(level))
}

#[get(
    "/api/users",
    auth: WebAuthSession
)]
pub async fn list_users() -> Result<Vec<UserGroupInfo<'static>>, ApiError> {
    ensure_user_claim(&auth, ClaimLevel::View)?;
    server_core::list_users_overview().await.map_err(ApiError::internal)
}

#[post(
    "/api/users",
    auth: WebAuthSession,
    audit: WebAuditContext,
    server: axum::Extension<server_core::ServerContext>
)]
pub async fn create_user(req: CreateUserRequest) -> Result<(), ApiError> {
    ensure_user_claim(&auth, ClaimLevel::Create)?;
    use server_core::add_user;

    add_user(&server.0, &audit.0, &req.username, &req.password)
        .await
        .map_err(ApiError::internal)
}

#[delete(
    "/api/users/{id}",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
pub async fn delete_user(id: i64) -> Result<(), ApiError> {
    ensure_user_claim(&auth, ClaimLevel::Delete)?;
    use server_core::remove_user_by_id;

    remove_user_by_id(&audit.0, id).await.map_err(ApiError::internal)
}

#[put(
    "/api/users/{id}",
    auth: WebAuthSession,
    audit: WebAuditContext,
    server: axum::Extension<server_core::ServerContext>
)]
pub async fn update_user(id: i64, req: UpdateUserRequest) -> Result<(), ApiError> {
    ensure_user_claim(&auth, ClaimLevel::Edit)?;

    if let Some(password) = req.password {
        server_core::update_user_password_by_id(&server.0, &audit.0, id, &password)
            .await
            .map_err(ApiError::internal)?;
    }

    Ok(())
}

#[get(
    "/api/users/{id}/claims",
    auth: WebAuthSession
)]
pub async fn get_user_claims(id: i64) -> Result<Vec<ClaimType<'static>>, ApiError> {
    ensure_user_claim(&auth, ClaimLevel::View)?;
    server_core::get_user_claims_by_id(id).await.map_err(ApiError::internal)
}

#[post(
    "/api/users/{id}/claims",
    auth: WebAuthSession,
    audit: WebAuditContext,
    server: axum::Extension<server_core::ServerContext>
)]
pub async fn add_user_claim(id: i64, claim: ClaimType<'static>) -> Result<(), ApiError> {
    ensure_user_claim(&auth, ClaimLevel::Edit)?;
    server_core::add_claim_to_user_by_id(&server.0, &audit.0, id, &claim)
        .await
        .map_err(ApiError::internal)
}

/// Remove a claim from a user
/// Now uses proper DELETE method with user ID (no colon encoding issues)
#[delete(
    "/api/users/{id}/claims",
    auth: WebAuthSession,
    audit: WebAuditContext,
    server: axum::Extension<server_core::ServerContext>
)]
pub async fn remove_user_claim(id: i64, claim: ClaimType<'static>) -> Result<(), ApiError> {
    ensure_user_claim(&auth, ClaimLevel::Edit)?;
    server_core::remove_claim_from_user_by_id(&server.0, &audit.0, id, &claim)
        .await
        .map_err(ApiError::internal)
}
