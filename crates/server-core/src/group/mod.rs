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

/// Remove a group completely
pub async fn remove_group(name: &str) -> ServerResult<()> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();

    // Remove ACLs that reference this group
    sqlx::query("DELETE FROM relay_host_acl WHERE principal_kind = 'group' AND principal_name = ?")
        .bind(name)
        .execute(&pool)
        .await?;

    state_store::delete_group_by_name(&pool, name).await?;
    info!(group = name, "group removed and access revoked");
    Ok(())
}

/// List all groups
pub async fn list_groups() -> ServerResult<Vec<String>> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    Ok(state_store::list_groups(&pool).await?)
}

/// Add a user to a group
pub async fn add_user_to_group_server(username: &str, group: &str) -> ServerResult<()> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    state_store::add_user_to_group(&pool, username, group).await?;
    info!(user = username, group, "user added to group");
    Ok(())
}

/// Remove a user from a group
pub async fn remove_user_from_group_server(username: &str, group: &str) -> ServerResult<()> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    state_store::remove_user_from_group(&pool, username, group).await?;
    info!(user = username, group, "user removed from group");
    Ok(())
}

/// List all groups for a user
pub async fn list_user_groups_server(username: &str) -> ServerResult<Vec<String>> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    Ok(state_store::list_user_groups(&pool, username).await?)
}

/// List all members of a group
pub async fn list_group_members_server(group: &str) -> ServerResult<Vec<String>> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    Ok(state_store::list_group_members(&pool, group).await?)
}
