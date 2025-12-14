//! Role-based access control (RBAC) operations.

use crate::{ClaimType, DbResult};
use rb_types::state::Role;
use sqlx::{Row, SqliteExecutor};
use std::str::FromStr;

fn current_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub async fn create_role(executor: impl SqliteExecutor<'_>, name: &str, description: Option<&str>) -> DbResult<i64> {
    let now = current_ts();
    let result = sqlx::query("INSERT INTO roles (name, description, created_at) VALUES (?, ?, ?)")
        .bind(name)
        .bind(description)
        .bind(now)
        .execute(executor)
        .await?;
    Ok(result.last_insert_rowid())
}

/// Delete a role by ID (preferred over name-based deletion).
///
/// # Super Admin Protection
/// Cannot delete role ID 1 (Super Admin role).
/// Returns the number of rows affected (0 or 1).
pub async fn delete_role_by_id(executor: impl SqliteExecutor<'_>, id: i64) -> DbResult<u64> {
    if id == crate::SUPER_ADMIN_ROLE_ID {
        return Err(crate::DbError::InvalidOperation {
            operation: "delete_role".to_string(),
            reason: "Cannot delete Super Admin role (role ID 1 is protected)".to_string(),
        });
    }

    let result = sqlx::query("DELETE FROM roles WHERE id = ?").bind(id).execute(executor).await?;
    Ok(result.rows_affected())
}

pub async fn list_roles(executor: impl SqliteExecutor<'_>) -> DbResult<Vec<Role>> {
    let rows = sqlx::query_as::<_, Role>("SELECT id, name, description, created_at FROM roles ORDER BY name")
        .fetch_all(executor)
        .await?;
    Ok(rows)
}

/// Assign a role to a user using IDs (preferred over name-based operation).
pub async fn assign_role_to_user_by_ids(executor: impl SqliteExecutor<'_>, user_id: i64, role_id: i64) -> DbResult<()> {
    sqlx::query("INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)")
        .bind(user_id)
        .bind(role_id)
        .execute(executor)
        .await?;
    Ok(())
}

/// Revoke a role from a user using IDs (preferred over name-based operation).
///
/// # Super Admin Protection
/// Ensures at least 1 user has the Super Admin role (role ID 1).
pub async fn revoke_role_from_user_by_ids(conn: &mut sqlx::SqliteConnection, user_id: i64, role_id: i64) -> DbResult<()> {
    // Super Admin protection: ensure at least 1 user has the Super Admin role
    if role_id == crate::SUPER_ADMIN_ROLE_ID {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_roles WHERE role_id = ?")
            .bind(crate::SUPER_ADMIN_ROLE_ID)
            .fetch_one(&mut *conn)
            .await?;

        if count <= 1 {
            return Err(crate::DbError::InvalidOperation {
                operation: "revoke_role".to_string(),
                reason: "Cannot revoke Super Admin role from last user (role ID 1 must have at least 1 user)".to_string(),
            });
        }
    }

    sqlx::query("DELETE FROM user_roles WHERE user_id = ? AND role_id = ?")
        .bind(user_id)
        .bind(role_id)
        .execute(conn)
        .await?;
    Ok(())
}

/// Add a claim to a role using role ID (preferred over name-based operation).
pub async fn add_claim_to_role_by_id(executor: impl SqliteExecutor<'_>, role_id: i64, claim: &ClaimType<'_>) -> DbResult<()> {
    sqlx::query("INSERT OR IGNORE INTO role_claims (role_id, claim_key) VALUES (?, ?)")
        .bind(role_id)
        .bind(claim.to_string())
        .execute(executor)
        .await?;
    Ok(())
}

/// Remove a claim from a role using role ID (preferred over name-based operation).
///
/// # Super Admin Protection
/// Cannot modify claims for role ID 1 (Super Admin role).
pub async fn remove_claim_from_role_by_id(executor: impl SqliteExecutor<'_>, role_id: i64, claim: &ClaimType<'_>) -> DbResult<()> {
    if role_id == crate::SUPER_ADMIN_ROLE_ID {
        return Err(crate::DbError::InvalidOperation {
            operation: "remove_role_claim".to_string(),
            reason: "Cannot modify Super Admin role claims (role ID 1 is protected)".to_string(),
        });
    }

    sqlx::query("DELETE FROM role_claims WHERE role_id = ? AND claim_key = ?")
        .bind(role_id)
        .bind(claim.to_string())
        .execute(executor)
        .await?;
    Ok(())
}

/// Get all user claims (direct + via roles + via groups + via group roles) by user ID.
/// This is the preferred method to avoid race conditions.
pub async fn get_user_claims_by_id(conn: &mut sqlx::SqliteConnection, user_id: i64) -> DbResult<Vec<ClaimType<'static>>> {
    // Fetch direct user claims
    let user_claims = sqlx::query_scalar::<_, String>("SELECT claim_key FROM user_claims WHERE user_id = ?")
        .bind(user_id)
        .fetch_all(&mut *conn)
        .await?;

    // Fetch claims via roles
    let role_claims = sqlx::query_scalar::<_, String>(
        r#"
        SELECT rc.claim_key 
        FROM role_claims rc
        JOIN user_roles ur ON rc.role_id = ur.role_id
        WHERE ur.user_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_all(&mut *conn)
    .await?;

    // Fetch claims via groups
    let group_claims = sqlx::query_scalar::<_, String>(
        r#"
        SELECT gc.claim_key 
        FROM group_claims gc
        JOIN user_groups ug ON gc.group_id = ug.group_id
        WHERE ug.user_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_all(&mut *conn)
    .await?;

    // Fetch claims via group roles (NEW: groups → roles → claims)
    let group_role_claims = sqlx::query_scalar::<_, String>(
        r#"
        SELECT rc.claim_key 
        FROM role_claims rc
        JOIN group_roles gr ON rc.role_id = gr.role_id
        JOIN user_groups ug ON gr.group_id = ug.group_id
        WHERE ug.user_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_all(&mut *conn)
    .await?;

    let mut all_claims = Vec::new();
    all_claims.extend(user_claims);
    all_claims.extend(role_claims);
    all_claims.extend(group_claims);
    all_claims.extend(group_role_claims); // NEW: Add group role claims

    // Dedup strings first
    all_claims.sort();
    all_claims.dedup();

    // Convert to ClaimType
    Ok(all_claims.into_iter().filter_map(|s| ClaimType::from_str(&s).ok()).collect())
}

/// Get direct user claims by user ID (preferred over username-based lookup).
pub async fn get_user_direct_claims_by_id(executor: impl SqliteExecutor<'_>, user_id: i64) -> DbResult<Vec<ClaimType<'static>>> {
    let user_claims = sqlx::query_scalar::<_, String>("SELECT claim_key FROM user_claims WHERE user_id = ?")
        .bind(user_id)
        .fetch_all(executor)
        .await?;

    Ok(user_claims.into_iter().filter_map(|s| ClaimType::from_str(&s).ok()).collect())
}

/// Add a claim to a user using user ID (preferred over username-based operation).
pub async fn add_claim_to_user_by_id(executor: impl SqliteExecutor<'_>, user_id: i64, claim: &ClaimType<'_>) -> DbResult<()> {
    sqlx::query("INSERT OR IGNORE INTO user_claims (user_id, claim_key) VALUES (?, ?)")
        .bind(user_id)
        .bind(claim.to_string())
        .execute(executor)
        .await?;
    Ok(())
}

/// Remove a claim from a user using user ID (preferred over username-based operation).
pub async fn remove_claim_from_user_by_id(executor: impl SqliteExecutor<'_>, user_id: i64, claim: &ClaimType<'_>) -> DbResult<()> {
    sqlx::query("DELETE FROM user_claims WHERE user_id = ? AND claim_key = ?")
        .bind(user_id)
        .bind(claim.to_string())
        .execute(executor)
        .await?;
    Ok(())
}

/// Add a claim to a group using group ID (preferred over name-based operation).
pub async fn add_claim_to_group_by_id(executor: impl SqliteExecutor<'_>, group_id: i64, claim: &ClaimType<'_>) -> DbResult<()> {
    sqlx::query("INSERT OR IGNORE INTO group_claims (group_id, claim_key) VALUES (?, ?)")
        .bind(group_id)
        .bind(claim.to_string())
        .execute(executor)
        .await?;
    Ok(())
}

/// Remove a claim from a group using group ID (preferred over name-based operation).
pub async fn remove_claim_from_group_by_id(executor: impl SqliteExecutor<'_>, group_id: i64, claim: &ClaimType<'_>) -> DbResult<()> {
    sqlx::query("DELETE FROM group_claims WHERE group_id = ? AND claim_key = ?")
        .bind(group_id)
        .bind(claim.to_string())
        .execute(executor)
        .await?;
    Ok(())
}

/// Get group claims by group ID (preferred over name-based lookup).
pub async fn get_group_claims_by_id(executor: impl SqliteExecutor<'_>, group_id: i64) -> DbResult<Vec<ClaimType<'static>>> {
    let claims = sqlx::query_scalar::<_, String>("SELECT claim_key FROM group_claims WHERE group_id = ?")
        .bind(group_id)
        .fetch_all(executor)
        .await?;

    Ok(claims.into_iter().filter_map(|s| ClaimType::from_str(&s).ok()).collect())
}

/// Get role claims by role ID (preferred over name-based lookup).
pub async fn get_role_claims_by_id(executor: impl SqliteExecutor<'_>, role_id: i64) -> DbResult<Vec<ClaimType<'static>>> {
    let claims = sqlx::query_scalar::<_, String>("SELECT claim_key FROM role_claims WHERE role_id = ?")
        .bind(role_id)
        .fetch_all(executor)
        .await?;

    Ok(claims.into_iter().filter_map(|s| ClaimType::from_str(&s).ok()).collect())
}

pub async fn list_user_roles_by_id(executor: impl SqliteExecutor<'_>, user_id: i64) -> DbResult<Vec<String>> {
    let rows = sqlx::query("SELECT r.name FROM roles r JOIN user_roles ur ON r.id = ur.role_id WHERE ur.user_id = ? ORDER BY r.name")
        .bind(user_id)
        .fetch_all(executor)
        .await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("name")).collect())
}

pub async fn list_role_users_by_id(executor: impl SqliteExecutor<'_>, role_id: i64) -> DbResult<Vec<String>> {
    let rows =
        sqlx::query("SELECT u.username FROM users u JOIN user_roles ur ON u.id = ur.user_id WHERE ur.role_id = ? ORDER BY u.username")
            .bind(role_id)
            .fetch_all(executor)
            .await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("username")).collect())
}

pub async fn list_group_roles_by_id(executor: impl SqliteExecutor<'_>, group_id: i64) -> DbResult<Vec<String>> {
    let rows = sqlx::query("SELECT r.name FROM roles r JOIN group_roles gr ON r.id = gr.role_id WHERE gr.group_id = ? ORDER BY r.name")
        .bind(group_id)
        .fetch_all(executor)
        .await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("name")).collect())
}

pub async fn list_role_groups_by_id(executor: impl SqliteExecutor<'_>, role_id: i64) -> DbResult<Vec<String>> {
    let rows = sqlx::query("SELECT g.name FROM groups g JOIN group_roles gr ON g.id = gr.group_id WHERE gr.role_id = ? ORDER BY g.name")
        .bind(role_id)
        .fetch_all(executor)
        .await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("name")).collect())
}

/// Assign a role to a group using IDs (preferred over name-based operation).
pub async fn assign_role_to_group_by_ids(executor: impl SqliteExecutor<'_>, group_id: i64, role_id: i64) -> DbResult<()> {
    sqlx::query("INSERT OR IGNORE INTO group_roles (group_id, role_id) VALUES (?, ?)")
        .bind(group_id)
        .bind(role_id)
        .execute(executor)
        .await?;
    Ok(())
}

/// Revoke a role from a group using IDs (preferred over name-based operation).
pub async fn revoke_role_from_group_by_ids(executor: impl SqliteExecutor<'_>, group_id: i64, role_id: i64) -> DbResult<()> {
    sqlx::query("DELETE FROM group_roles WHERE group_id = ? AND role_id = ?")
        .bind(group_id)
        .bind(role_id)
        .execute(executor)
        .await?;
    Ok(())
}

pub async fn fetch_role_id_by_name(executor: impl SqliteExecutor<'_>, name: &str) -> DbResult<Option<i64>> {
    let row = sqlx::query("SELECT id FROM roles WHERE name = ?")
        .bind(name)
        .fetch_optional(executor)
        .await?;
    Ok(row.map(|r| r.get::<i64, _>("id")))
}

/// Fetch role name by ID for audit logging.
pub async fn fetch_role_name_by_id(executor: impl SqliteExecutor<'_>, id: i64) -> DbResult<Option<String>> {
    sqlx::query_scalar("SELECT name FROM roles WHERE id = ?")
        .bind(id)
        .fetch_optional(executor)
        .await
        .map_err(crate::DbError::from)
}
