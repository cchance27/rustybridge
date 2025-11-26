//! Role management functionality
//!
//! This module handles creating, deleting, assigning roles and managing role claims.

use rb_types::{auth::ClaimType, state::Role};
use tracing::info;

use crate::error::{ServerError, ServerResult};

// Super Admin role protection constant
const SUPER_ADMIN_ROLE_ID: i64 = 1;

/// Create a new role
pub async fn create_role(name: &str, description: Option<&str>) -> ServerResult<()> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    state_store::create_role(&pool, name, description).await?;
    info!(role = name, "role created");
    Ok(())
}

/// Delete a role with Super Admin protection (cannot delete role id 1).
pub async fn delete_role_server(name: &str) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    // Check if this is the Super Admin role
    let role_id = state_store::fetch_role_id_by_name(&pool, name)
        .await?
        .ok_or_else(|| ServerError::not_found("role", name))?;

    if role_id == SUPER_ADMIN_ROLE_ID {
        return Err(ServerError::InvalidConfig(
            "Cannot delete Super Admin role (role id 1 is protected)".to_string(),
        ));
    }

    state_store::delete_role(&pool, name).await?;
    info!(role = name, "role deleted");
    Ok(())
}

/// List all roles
pub async fn list_roles() -> ServerResult<Vec<Role>> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    Ok(state_store::list_roles(&pool).await?)
}

/// Assign a role to a user
pub async fn assign_role(username: &str, role_name: &str) -> ServerResult<()> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    state_store::assign_role_to_user(&pool, username, role_name).await?;
    info!(user = username, role = role_name, "role assigned to user");
    Ok(())
}

/// Revoke a role from a user with Super Admin protection (ensure ≥1 user remains for role id 1).
pub async fn revoke_role_from_user_server(username: &str, role_name: &str) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    // Check if this is the Super Admin role
    let role_id = state_store::fetch_role_id_by_name(&pool, role_name)
        .await?
        .ok_or_else(|| ServerError::not_found("role", role_name))?;

    if role_id == SUPER_ADMIN_ROLE_ID {
        // Count how many users have this role
        let users = state_store::list_role_users(&pool, role_name).await?;
        if users.len() <= 1 {
            return Err(ServerError::InvalidConfig(
                "Cannot revoke Super Admin role from last user (role id 1 must have at least 1 user)".to_string(),
            ));
        }
    }

    state_store::revoke_role_from_user(&pool, username, role_name).await?;
    info!(user = username, role = role_name, "role revoked from user");
    Ok(())
}

/// Add a claim to a role
pub async fn add_role_claim(role_name: &str, claim: &ClaimType) -> ServerResult<()> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    state_store::add_claim_to_role(&pool, role_name, claim).await?;
    info!(role = role_name, claim = %claim, "claim added to role");
    Ok(())
}

/// Remove claim from role with Super Admin protection (cannot modify role id 1).
pub async fn remove_role_claim_server(role_name: &str, claim: &ClaimType) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    // Check if this is the Super Admin role
    let role_id = state_store::fetch_role_id_by_name(&pool, role_name)
        .await?
        .ok_or_else(|| ServerError::not_found("role", role_name))?;

    if role_id == SUPER_ADMIN_ROLE_ID {
        return Err(ServerError::InvalidConfig(
            "Cannot modify Super Admin role claims (role id 1 is protected)".to_string(),
        ));
    }

    state_store::remove_claim_from_role(&pool, role_name, claim).await?;
    info!(role = role_name, claim = %claim, "claim removed from role");
    Ok(())
}

/// Add a claim to a user
pub async fn add_user_claim(username: &str, claim: &ClaimType) -> ServerResult<()> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    state_store::add_claim_to_user(&pool, username, claim).await?;
    info!(user = username, claim = %claim, "claim added to user");
    Ok(())
}

/// Remove a claim from a user
pub async fn remove_user_claim(username: &str, claim: &ClaimType) -> ServerResult<()> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    state_store::remove_claim_from_user(&pool, username, claim).await?;
    info!(user = username, claim = %claim, "claim removed from user");
    Ok(())
}

/// Add a claim to a group
pub async fn add_group_claim(group_name: &str, claim: &ClaimType) -> ServerResult<()> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    state_store::add_claim_to_group(&pool, group_name, claim).await?;
    info!(group = group_name, claim = %claim, "claim added to group");
    Ok(())
}

/// Remove a claim from a group
pub async fn remove_group_claim(group_name: &str, claim: &ClaimType) -> ServerResult<()> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    state_store::remove_claim_from_group(&pool, group_name, claim).await?;
    info!(group = group_name, claim = %claim, "claim removed from group");
    Ok(())
}

/// Get claims for a group
pub async fn get_group_claims_server(group_name: &str) -> ServerResult<Vec<ClaimType>> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    Ok(state_store::get_group_claims(&pool, group_name).await?)
}

/// Get direct claims for a user (not inherited from roles/groups)
pub async fn get_user_direct_claims_server(username: &str) -> ServerResult<Vec<ClaimType>> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    Ok(state_store::get_user_direct_claims(&pool, username).await?)
}

/// Get claims for a role
pub async fn get_role_claims_server(role_name: &str) -> ServerResult<Vec<ClaimType>> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();
    Ok(state_store::get_role_claims(&pool, role_name).await?)
}

/// List roles for a user
pub async fn list_user_roles_server(username: &str) -> ServerResult<Vec<String>> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();
    Ok(state_store::list_user_roles(&pool, username).await?)
}

/// List users for a role
pub async fn list_role_users_server(role_name: &str) -> ServerResult<Vec<String>> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();
    Ok(state_store::list_role_users(&pool, role_name).await?)
}

/// List roles for a group
pub async fn list_group_roles_server(group_name: &str) -> ServerResult<Vec<String>> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();
    Ok(state_store::list_group_roles(&pool, group_name).await?)
}

/// List groups for a role
pub async fn list_role_groups_server(role_name: &str) -> ServerResult<Vec<String>> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();
    Ok(state_store::list_role_groups(&pool, role_name).await?)
}

/// Assign a role to a group
pub async fn assign_role_to_group_server(group_name: &str, role_name: &str) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();
    state_store::assign_role_to_group(&pool, group_name, role_name).await?;
    info!(group = group_name, role = role_name, "role assigned to group");
    Ok(())
}

/// Revoke a role from a group
pub async fn revoke_role_from_group_server(group_name: &str, role_name: &str) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();
    state_store::revoke_role_from_group(&pool, group_name, role_name).await?;
    info!(group = group_name, role = role_name, "role revoked from group");
    Ok(())
}

// Re-exports for backwards compatibility with existing CLI imports
pub use delete_role_server as delete_role;
pub use remove_role_claim_server as remove_role_claim;
pub use revoke_role_from_user_server as revoke_role;
