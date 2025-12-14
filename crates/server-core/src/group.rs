//! Group management functionality
//!
//! This module handles adding, removing, listing, and configuring groups and group memberships.

use crate::error::{ServerError, ServerResult};
use rb_types::auth::ClaimType;

/// Add a new group, tracking the full context of who performed the action.
///
/// # Examples
///
/// ```ignore
/// let ctx = AuditContext::web(user_id, username, ip_address, session_id);
/// add_group(&ctx, "admins").await?;
/// ```
pub async fn add_group(ctx: &rb_types::audit::AuditContext, name: &str) -> ServerResult<()> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();

    if state_store::fetch_group_id_by_name(&pool, name).await?.is_some() {
        return Err(ServerError::already_exists("group", name));
    }

    state_store::create_group(&pool, name).await?;
    // Log audit event with full context
    crate::audit!(ctx, GroupCreated { name: name.to_string() });

    Ok(())
}

/// Update a group's name, tracking the full context.
pub async fn update_group_name(ctx: &rb_types::audit::AuditContext, group_id: i64, new_name: &str) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    // Check if name already exists
    if state_store::fetch_group_id_by_name(&pool, new_name).await?.is_some() {
        return Err(ServerError::already_exists("group", new_name));
    }

    // Fetch old name for logging
    // We can't easily get the old name inside the same transaction if we just update it,
    // but fetching it first is fine.
    let old_name = state_store::fetch_group_name_by_id(&pool, group_id)
        .await?
        .ok_or_else(|| ServerError::not_found("group", group_id.to_string()))?;

    state_store::update_group_name(&pool, group_id, new_name).await?;

    // Log audit event
    crate::audit!(
        ctx,
        GroupUpdated {
            group_id,
            old_name,
            new_name: new_name.to_string(),
        }
    );

    Ok(())
}

/// Add a user to a group, tracking the full context.
pub async fn add_user_to_group_by_ids(ctx: &rb_types::audit::AuditContext, user_id: i64, group_id: i64) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    let username = state_store::fetch_username_by_id(&pool, user_id)
        .await?
        .ok_or_else(|| ServerError::not_found("user", user_id.to_string()))?;

    let group_name = state_store::fetch_group_name_by_id(&pool, group_id)
        .await?
        .ok_or_else(|| ServerError::not_found("group", group_id.to_string()))?;

    state_store::add_user_to_group_by_ids(&pool, user_id, group_id).await?;

    // Log audit event
    crate::audit!(
        ctx,
        UserAddedToGroup {
            username,
            user_id,
            group_name,
            group_id,
        }
    );

    Ok(())
}

/// Remove a user from a group, tracking the full context.
pub async fn remove_user_from_group_by_ids(ctx: &rb_types::audit::AuditContext, user_id: i64, group_id: i64) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    let username = state_store::fetch_username_by_id(&pool, user_id)
        .await?
        .ok_or_else(|| ServerError::not_found("user", user_id.to_string()))?;

    let group_name = state_store::fetch_group_name_by_id(&pool, group_id)
        .await?
        .ok_or_else(|| ServerError::not_found("group", group_id.to_string()))?;

    state_store::remove_user_from_group_by_ids(&pool, user_id, group_id).await?;

    // Log audit event
    crate::audit!(
        ctx,
        UserRemovedFromGroup {
            username,
            user_id,
            group_name,
            group_id,
        }
    );

    Ok(())
}

/// Add a claim to a group, tracking the full context.
pub async fn add_claim_to_group_by_id(ctx: &rb_types::audit::AuditContext, group_id: i64, claim: &ClaimType<'static>) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    let group_name = state_store::fetch_group_name_by_id(&pool, group_id)
        .await?
        .ok_or_else(|| ServerError::not_found("group", group_id.to_string()))?;

    state_store::add_claim_to_group_by_id(&pool, group_id, claim).await?;

    // Log audit event
    crate::audit!(
        ctx,
        GroupClaimAdded {
            group_name,
            group_id,
            claim: claim.clone(),
        }
    );

    Ok(())
}

/// Remove a claim from a group, tracking the full context.
pub async fn remove_claim_from_group_by_id(
    ctx: &rb_types::audit::AuditContext,
    group_id: i64,
    claim: &ClaimType<'static>,
) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    let group_name = state_store::fetch_group_name_by_id(&pool, group_id)
        .await?
        .ok_or_else(|| ServerError::not_found("group", group_id.to_string()))?;

    state_store::remove_claim_from_group_by_id(&pool, group_id, claim).await?;

    // Log audit event
    crate::audit!(
        ctx,
        GroupClaimRemoved {
            group_name,
            group_id,
            claim: claim.clone(),
        }
    );

    Ok(())
}

/// Remove a group by ID, tracking the full context of who performed the action.
///
/// # Examples
///
/// ```ignore
/// let ctx = AuditContext::web(user_id, username, ip_address, session_id);
/// remove_group_by_id(&ctx, group_id).await?;
/// ```
pub async fn remove_group_by_id(ctx: &rb_types::audit::AuditContext, group_id: i64) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    let mut tx = pool.begin().await.map_err(ServerError::Database)?;

    // Fetch group name before deletion for audit log
    let name = state_store::fetch_group_name_by_id(&mut *tx, group_id)
        .await?
        .unwrap_or_else(|| format!("group_{}", group_id));

    // Remove ACLs that reference this group
    state_store::revoke_group_relay_accesses(&mut *tx, group_id).await?;

    state_store::delete_group_by_id(&mut *tx, group_id).await?;

    tx.commit().await.map_err(ServerError::Database)?;

    // Log audit event with full context
    crate::audit!(ctx, GroupDeleted { name, group_id });

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
