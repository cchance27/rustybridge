//! User management functionality
//!
//! This module handles adding, removing, listing, and configuring users and their public keys.

use russh::keys::ssh_key;
use tracing::{info, warn};

use crate::error::{ServerError, ServerResult};

/// Add a user with a password
pub async fn add_user(user: &str, password: &str) -> ServerResult<()> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();

    // Check if user already exists
    if state_store::fetch_user_id_by_name(&pool, user).await?.is_some() {
        return Err(ServerError::already_exists("user", user));
    }

    let hash = crate::auth::hash_password(password)?;
    let result = sqlx::query("INSERT INTO users (username, password_hash) VALUES (?, ?)")
        .bind(user)
        .bind(hash)
        .execute(&pool)
        .await?;
    let user_id = result.last_insert_rowid();
    let promoted = maybe_promote_first_user(&pool, user, user_id).await?;
    info!(user, first_user = promoted, "user added");
    Ok(())
}

/// Add an SSH public key for a user (validated before storing).
pub async fn add_user_public_key(username: &str, public_key: &str, comment: Option<&str>) -> ServerResult<i64> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();

    // Basic validation to prevent storing malformed keys.
    ssh_key::PublicKey::from_openssh(public_key).map_err(|e| ServerError::InvalidConfig(format!("invalid public key: {}", e)))?;

    let id = state_store::add_user_public_key(&pool, username, public_key, comment).await?;
    info!(user = username, key_id = id, "user public key added");
    Ok(id)
}

/// List a user's public keys (id, key, comment, created_at epoch seconds).
pub async fn list_user_public_keys(username: &str) -> ServerResult<Vec<(i64, String, Option<String>, i64)>> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();
    let keys = state_store::list_user_public_keys(&pool, username).await?;
    Ok(keys)
}

/// Remove a specific public key by id for a user.
pub async fn delete_user_public_key(username: &str, key_id: i64) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    // Ensure the key belongs to the user to avoid deleting cross-user IDs
    let keys = state_store::list_user_public_keys(&pool, username).await?;
    if keys.iter().all(|(id, _, _, _)| *id != key_id) {
        return Err(ServerError::NotFound("public key".into(), key_id.to_string()));
    }

    state_store::delete_user_public_key(&pool, key_id).await?;
    info!(user = username, key_id, "user public key deleted");
    Ok(())
}

/// Grant elevated access if this is the first persisted user record.
async fn maybe_promote_first_user(pool: &sqlx::SqlitePool, username: &str, user_id: i64) -> ServerResult<bool> {
    let earliest_id: i64 = sqlx::query_scalar("SELECT id FROM users ORDER BY id ASC LIMIT 1")
        .fetch_one(pool)
        .await?;
    if earliest_id != user_id {
        return Ok(false);
    }

    ensure_super_admin_privileges(pool, username).await?;
    Ok(true)
}

/// Best-effort helper that attaches the Super Admin role (or wildcard claim if the role hasn't been seeded yet).
async fn ensure_super_admin_privileges(pool: &sqlx::SqlitePool, username: &str) -> ServerResult<()> {
    const SUPER_ADMIN_ROLE: &str = "Super Admin";
    match state_store::assign_role_to_user(pool, username, SUPER_ADMIN_ROLE).await {
        Ok(_) => {
            info!(user = username, role = SUPER_ADMIN_ROLE, "granted Super Admin role to first user");
            Ok(())
        }
        Err(state_store::DbError::GroupNotFound { .. }) => {
            warn!(
                user = username,
                role = SUPER_ADMIN_ROLE,
                "Super Admin role missing; granting wildcard claim directly"
            );
            let wildcard = rb_types::auth::ClaimType::Custom("*".to_string());
            state_store::add_claim_to_user(pool, username, &wildcard).await?;
            Ok(())
        }
        Err(err) => Err(err.into()),
    }
}

/// Remove a user completely
pub async fn remove_user(user: &str) -> ServerResult<()> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    // Revoke all ACLs for this user
    sqlx::query("DELETE FROM relay_host_acl WHERE principal_kind = 'user' AND principal_name = ?")
        .bind(user)
        .execute(&pool)
        .await?;
    // Remove user record (cascades user_groups)
    sqlx::query("DELETE FROM users WHERE username = ?")
        .bind(user)
        .execute(&pool)
        .await?;
    info!(user, "user removed and access revoked");
    Ok(())
}

/// Update user information (like password)
pub async fn update_user(username: &str, new_password: Option<&str>) -> ServerResult<()> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();

    // Verify user exists
    let user_id = state_store::fetch_user_id_by_name(&pool, username)
        .await?
        .ok_or_else(|| ServerError::not_found("user", username))?;

    if let Some(npw) = new_password {
        let hash = crate::auth::hash_password(npw)?;
        sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
            .bind(&hash)
            .bind(user_id)
            .execute(&pool)
            .await?;
    }

    info!(user = username, "user updated");
    Ok(())
}

/// List all users
pub async fn list_users() -> ServerResult<Vec<String>> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    let users = state_store::list_usernames(&pool).await?;
    Ok(users)
}
