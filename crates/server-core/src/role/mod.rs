//! Role management functionality
//!
//! This module handles creating, deleting, assigning roles and managing role claims.

use rb_types::auth::ClaimType;

use crate::error::{ServerError, ServerResult};

/// Get claims for a group.
///
/// # Name-Based Function
/// This function accepts a group name instead of group_id because it's used by:
/// - CLI commands that work with group names
/// - TUI interfaces that display group names
/// - WebUI list operations that fetch by name
pub async fn get_group_claims_server(group_name: &str) -> ServerResult<Vec<ClaimType<'_>>> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    let group_id = state_store::fetch_group_id_by_name(&pool, group_name)
        .await?
        .ok_or_else(|| ServerError::not_found("group", group_name))?;

    Ok(state_store::get_group_claims_by_id(&pool, group_id).await?)
}

/// List roles for a user.
///
/// # Name-Based Function
/// This function accepts a username instead of user_id because it's used by:
/// - CLI commands that work with usernames
/// - TUI interfaces that display usernames
/// - WebUI list operations that fetch by name
pub async fn list_user_roles_server(username: &str) -> ServerResult<Vec<String>> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    let user_id = state_store::fetch_user_id_by_name(&pool, username)
        .await?
        .ok_or_else(|| ServerError::not_found("user", username))?;

    Ok(state_store::list_user_roles_by_id(&pool, user_id).await?)
}

/// List roles for a group.
///
/// # Name-Based Function
/// This function accepts a group name instead of group_id because it's used by:
/// - CLI commands that work with group names
/// - TUI interfaces that display group names
/// - WebUI list operations that fetch by name
pub async fn list_group_roles_server(group_name: &str) -> ServerResult<Vec<String>> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    let group_id = state_store::fetch_group_id_by_name(&pool, group_name)
        .await?
        .ok_or_else(|| ServerError::not_found("group", group_name))?;

    Ok(state_store::list_group_roles_by_id(&pool, group_id).await?)
}
