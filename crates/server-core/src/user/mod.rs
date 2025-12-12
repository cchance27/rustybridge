//! User management functionality
//!
//! This module handles adding, removing, listing, and configuring users and their public keys.

use std::borrow::Cow;

use rb_types::auth::ClaimType;
use russh::keys::ssh_key;
use tracing::{info, warn};

use crate::{
    ServerContext, error::{ServerError, ServerResult}
};

/// Add a user with a password, tracking the full context of who performed the action.
///
/// This is the recommended function to use. It requires an `AuditContext` which ensures
/// proper attribution of the operation to a user, session, or system component.
///
/// # Examples
///
/// # Examples
///
/// ```ignore
/// // Web context
/// let ctx = AuditContext::web(user_id, username, ip_address, session_id);
/// add_user(&ctx, "alice", "password").await?;
///
/// // SSH context
/// let ctx = AuditContext::ssh(user_id, username, ip_address, connection_id);
/// add_user(&ctx, "bob", "password").await?;
///
/// // CLI context
/// let ctx = AuditContext::server_cli(None, hostname);
/// add_user(&ctx, "charlie", "password").await?;
/// ```
pub async fn add_user(server: &ServerContext, ctx: &rb_types::audit::AuditContext, user: &str, password: &str) -> ServerResult<()> {
    let pool = server.server_pool();

    // Check if user already exists (read-only check before transaction is fine,
    // but better inside transaction for strict correctness, though SQLite only allows one writer anyway)
    // We'll do it inside transaction to be safe.

    let mut tx = pool.begin().await.map_err(ServerError::Database)?;

    if state_store::fetch_user_id_by_name(&mut *tx, user).await?.is_some() {
        return Err(ServerError::already_exists("user", user));
    }

    let hash = crate::auth::hash_password(password)?;
    let user_id = state_store::create_user(&mut *tx, user, &hash).await?;

    let _promoted = maybe_promote_first_user(&mut tx, user, user_id).await?;

    tx.commit().await.map_err(ServerError::Database)?;

    // Log audit event with full context
    crate::audit!(
        ctx,
        UserCreated {
            username: user.to_string(),
        }
    );

    Ok(())
}

/// Update a user's password, tracking the full context.
pub async fn update_user_password_by_id(
    server: &ServerContext,
    ctx: &rb_types::audit::AuditContext,
    user_id: i64,
    password: &str,
) -> ServerResult<()> {
    let pool = server.server_pool();

    // Fetch username for audit log
    let username = state_store::fetch_username_by_id(pool, user_id)
        .await?
        .ok_or_else(|| ServerError::not_found("user", user_id.to_string()))?;

    let hash = crate::auth::hash_password(password)?;
    state_store::update_user_password_by_id(pool, user_id, &hash).await?;

    // Log audit event
    crate::audit!(ctx, UserPasswordChanged { username, user_id });

    Ok(())
}

/// Add a claim to a user, tracking the full context.
pub async fn add_claim_to_user_by_id(
    server: &ServerContext,
    ctx: &rb_types::audit::AuditContext,
    user_id: i64,
    claim: &ClaimType<'static>,
) -> ServerResult<()> {
    let pool = server.server_pool();

    // Fetch username for audit log
    let username = state_store::fetch_username_by_id(pool, user_id)
        .await?
        .ok_or_else(|| ServerError::not_found("user", user_id.to_string()))?;

    state_store::add_claim_to_user_by_id(pool, user_id, claim).await?;

    // Log audit event
    crate::audit!(
        ctx,
        UserClaimAdded {
            username,
            user_id,
            claim: claim.clone(),
        }
    );

    Ok(())
}

/// Remove a claim from a user, tracking the full context.
pub async fn remove_claim_from_user_by_id(
    server: &ServerContext,
    ctx: &rb_types::audit::AuditContext,
    user_id: i64,
    claim: &ClaimType<'static>,
) -> ServerResult<()> {
    let pool = server.server_pool();

    // Fetch username for audit log
    let username = state_store::fetch_username_by_id(pool, user_id)
        .await?
        .ok_or_else(|| ServerError::not_found("user", user_id.to_string()))?;

    state_store::remove_claim_from_user_by_id(pool, user_id, claim).await?;

    // Log audit event
    crate::audit!(
        ctx,
        UserClaimRemoved {
            username,
            user_id,
            claim: claim.clone(),
        }
    );

    Ok(())
}

/// Add an SSH public key for a user (validated before storing), tracking the full context.
///
/// # Name-Based Function
/// This function accepts a username instead of user_id because it's used by:
/// - SSH authentication flow (user connects with username)
/// - CLI commands that work with usernames
/// - TUI interfaces that display usernames
pub async fn add_user_public_key(
    server: &ServerContext,
    ctx: &rb_types::audit::AuditContext,
    username: &str,
    public_key: &str,
    comment: Option<&str>,
) -> ServerResult<i64> {
    let pool = server.server_pool();

    // Basic validation to prevent storing malformed keys.
    let parsed_key =
        ssh_key::PublicKey::from_openssh(public_key).map_err(|e| ServerError::InvalidConfig(format!("invalid public key: {}", e)))?;
    let fingerprint = parsed_key.fingerprint(Default::default()).to_string();

    let user_id = state_store::fetch_user_id_by_name(pool, username)
        .await?
        .ok_or_else(|| ServerError::not_found("user", username))?;

    let id = state_store::add_user_public_key_by_id(pool, user_id, public_key, comment).await?;
    // Log audit event
    crate::audit!(
        ctx,
        UserSshKeyAdded {
            username: username.to_string(),
            user_id,
            key_id: id,
            fingerprint: Some(fingerprint),
        }
    );

    Ok(id)
}

/// List a user's public keys (id, key, comment, created_at epoch seconds).
///
/// # Name-Based Function
/// This function accepts a username instead of user_id because it's used by:
/// - CLI commands that work with usernames
/// - TUI interfaces that display usernames
pub async fn list_user_public_keys(server: &ServerContext, username: &str) -> ServerResult<Vec<(i64, String, Option<String>, i64)>> {
    let pool = server.server_pool();

    let user_id = state_store::fetch_user_id_by_name(pool, username)
        .await?
        .ok_or_else(|| ServerError::not_found("user", username))?;

    let keys = state_store::list_user_public_keys_by_id(pool, user_id).await?;
    Ok(keys)
}

/// Remove a specific public key by id for a user, tracking the full context.
///
/// # Name-Based Function
/// This function accepts a username instead of user_id because it's used by:
/// - CLI commands that work with usernames
/// - TUI interfaces that display usernames
///
/// # Security
/// Validates that the key belongs to the specified user to prevent cross-user deletion.
pub async fn delete_user_public_key(
    server: &ServerContext,
    ctx: &rb_types::audit::AuditContext,
    username: &str,
    key_id: i64,
) -> ServerResult<()> {
    let pool = server.server_pool();

    let mut tx = pool.begin().await.map_err(ServerError::Database)?;

    let user_id = state_store::fetch_user_id_by_name(&mut *tx, username)
        .await?
        .ok_or_else(|| ServerError::not_found("user", username))?;

    // Ensure the key belongs to the user to avoid deleting cross-user IDs
    let keys = state_store::list_user_public_keys_by_id(&mut *tx, user_id).await?;
    if keys.iter().all(|(id, _, _, _)| *id != key_id) {
        return Err(ServerError::NotFound("public key".into(), key_id.to_string()));
    }

    state_store::delete_user_public_key(&mut *tx, key_id).await?;

    tx.commit().await.map_err(ServerError::Database)?;

    // Log audit event
    crate::audit!(
        ctx,
        UserSshKeyRemoved {
            username: username.to_string(),
            user_id,
            key_id,
        }
    );

    Ok(())
}

/// Grant elevated access if this is the first persisted user record.
async fn maybe_promote_first_user(conn: &mut sqlx::SqliteConnection, username: &str, user_id: i64) -> ServerResult<bool> {
    let earliest_id = state_store::get_earliest_user_id(&mut *conn).await?;

    match earliest_id {
        Some(id) if id == user_id => {
            ensure_super_admin_privileges(conn, username).await?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// Best-effort helper that attaches the Super Admin role (or wildcard claim if the role hasn't been seeded yet).
async fn ensure_super_admin_privileges(conn: &mut sqlx::SqliteConnection, username: &str) -> ServerResult<()> {
    const SUPER_ADMIN_ROLE: &str = "Super Admin";

    // Get user_id first
    let user_id = state_store::fetch_user_id_by_name(&mut *conn, username)
        .await?
        .ok_or_else(|| ServerError::not_found("user", username))?;

    // Get role_id
    match state_store::fetch_role_id_by_name(&mut *conn, SUPER_ADMIN_ROLE).await? {
        Some(role_id) => {
            state_store::assign_role_to_user_by_ids(&mut *conn, user_id, role_id).await?;
            info!(user = username, role = SUPER_ADMIN_ROLE, "granted Super Admin role to first user");
            Ok(())
        }
        None => {
            warn!(
                user = username,
                role = SUPER_ADMIN_ROLE,
                "Super Admin role missing; granting wildcard claim directly"
            );
            let wildcard = rb_types::auth::ClaimType::Custom(Cow::Borrowed("*"));
            state_store::add_claim_to_user_by_id(&mut *conn, user_id, &wildcard).await?;
            Ok(())
        }
    }
}

/// Remove a user by ID, tracking the full context of who performed the action.
///
/// This is the preferred way to remove users as it ensures proper audit attribution.
///
/// # Examples
///
/// ```ignore
/// let ctx = AuditContext::web(user_id, username, ip_address, session_id);
/// remove_user_by_id(&ctx, target_user_id).await?;
/// ```
pub async fn remove_user_by_id(ctx: &rb_types::audit::AuditContext, user_id: i64) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    let mut tx = pool.begin().await.map_err(ServerError::Database)?;

    // Fetch username before deletion for audit log
    let username = state_store::fetch_username_by_id(&mut *tx, user_id)
        .await?
        .unwrap_or_else(|| format!("user_{}", user_id));

    // Revoke all ACLs for this user (ID-based)
    state_store::revoke_user_relay_accesses(&mut *tx, user_id).await?;

    // Remove user record (cascades user_groups, user_roles, user_claims, ssh_keys, oidc_links)
    state_store::delete_user_by_id(&mut *tx, user_id).await?;

    tx.commit().await.map_err(ServerError::Database)?;

    // Log audit event with full context
    crate::audit!(ctx, UserDeleted { username, user_id });

    Ok(())
}
