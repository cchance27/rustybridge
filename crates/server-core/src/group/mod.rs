//! Group management functionality
//!
//! This module handles adding, removing, listing, and configuring groups and group memberships.

use tracing::info;

use crate::error::{ServerError, ServerResult};

/// Add a new group
pub async fn add_group(name: &str) -> ServerResult<()> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();

    if state_store::fetch_group_id_by_name(&pool, name).await?.is_some() {
        return Err(ServerError::already_exists("group", name));
    }

    state_store::create_group(&pool, name).await?;
    info!(group = name, "group added");
    Ok(())
}

/// Remove a group by ID (preferred to avoid race conditions).
pub async fn remove_group_by_id(group_id: i64) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    let mut tx = pool.begin().await.map_err(ServerError::Database)?;

    // Remove ACLs that reference this group
    state_store::revoke_group_relay_accesses(&mut *tx, group_id).await?;

    state_store::delete_group_by_id(&mut *tx, group_id).await?;

    tx.commit().await.map_err(ServerError::Database)?;

    info!(group_id, "group removed and access revoked");
    Ok(())
}

/// List all groups
pub async fn list_groups() -> ServerResult<Vec<String>> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    Ok(state_store::list_groups(&pool).await?)
}

/// List all groups for a user.
///
/// # Name-Based Function
/// This function accepts a username instead of user_id because it's used by:
/// - CLI commands that work with usernames
/// - TUI interfaces that display usernames
pub async fn list_user_groups_server(username: &str) -> ServerResult<Vec<String>> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    let user_id = state_store::fetch_user_id_by_name(&pool, username)
        .await?
        .ok_or_else(|| ServerError::not_found("user", username))?;

    Ok(state_store::list_user_groups_by_id(&pool, user_id).await?)
}

/// List all members of a group.
///
/// # Name-Based Function
/// This function accepts a group name instead of group_id because it's used by:
/// - CLI commands that work with group names
/// - TUI interfaces that display group names
pub async fn list_group_members_server(group: &str) -> ServerResult<Vec<String>> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    let group_id = state_store::fetch_group_id_by_name(&pool, group)
        .await?
        .ok_or_else(|| ServerError::not_found("group", group))?;

    Ok(state_store::list_group_members_by_id(&pool, group_id).await?)
}
