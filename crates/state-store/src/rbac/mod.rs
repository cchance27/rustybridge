//! Role-based access control (RBAC) operations.

use std::str::FromStr;

use rb_types::state::Role;
use sqlx::{Row, SqlitePool};

use crate::{ClaimType, DbResult};

fn current_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub async fn create_role(pool: &SqlitePool, name: &str, description: Option<&str>) -> DbResult<i64> {
    let now = current_ts();
    sqlx::query("INSERT INTO roles (name, description, created_at) VALUES (?, ?, ?)")
        .bind(name)
        .bind(description)
        .bind(now)
        .execute(pool)
        .await?;
    let row = sqlx::query("SELECT id FROM roles WHERE name = ?")
        .bind(name)
        .fetch_one(pool)
        .await?;
    Ok(row.get::<i64, _>("id"))
}

pub async fn delete_role(pool: &SqlitePool, name: &str) -> DbResult<()> {
    sqlx::query("DELETE FROM roles WHERE name = ?").bind(name).execute(pool).await?;
    Ok(())
}

pub async fn list_roles(pool: &SqlitePool) -> DbResult<Vec<Role>> {
    let rows = sqlx::query_as::<_, Role>("SELECT id, name, description, created_at FROM roles ORDER BY name")
        .fetch_all(pool)
        .await?;
    Ok(rows)
}

pub async fn assign_role_to_user(pool: &SqlitePool, username: &str, role_name: &str) -> DbResult<()> {
    let user_id = crate::fetch_user_id_by_name(pool, username)
        .await?
        .ok_or(crate::DbError::UserNotFound {
            username: username.to_string(),
        })?;
    let role_id = fetch_role_id_by_name(pool, role_name).await?.ok_or(crate::DbError::GroupNotFound {
        group: role_name.to_string(), // Reusing GroupNotFound for generic "not found" or add RoleNotFound
    })?;
    sqlx::query("INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)")
        .bind(user_id)
        .bind(role_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn revoke_role_from_user(pool: &SqlitePool, username: &str, role_name: &str) -> DbResult<()> {
    let user_id = crate::fetch_user_id_by_name(pool, username)
        .await?
        .ok_or(crate::DbError::UserNotFound {
            username: username.to_string(),
        })?;
    let role_id = fetch_role_id_by_name(pool, role_name).await?.ok_or(crate::DbError::GroupNotFound {
        group: role_name.to_string(),
    })?;
    sqlx::query("DELETE FROM user_roles WHERE user_id = ? AND role_id = ?")
        .bind(user_id)
        .bind(role_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn add_claim_to_role(pool: &SqlitePool, role_name: &str, claim: &ClaimType) -> DbResult<()> {
    let role_id = fetch_role_id_by_name(pool, role_name).await?.ok_or(crate::DbError::GroupNotFound {
        group: role_name.to_string(),
    })?;
    sqlx::query("INSERT OR IGNORE INTO role_claims (role_id, claim_key) VALUES (?, ?)")
        .bind(role_id)
        .bind(claim.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn remove_claim_from_role(pool: &SqlitePool, role_name: &str, claim: &ClaimType) -> DbResult<()> {
    let role_id = fetch_role_id_by_name(pool, role_name).await?.ok_or(crate::DbError::GroupNotFound {
        group: role_name.to_string(),
    })?;
    sqlx::query("DELETE FROM role_claims WHERE role_id = ? AND claim_key = ?")
        .bind(role_id)
        .bind(claim.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn get_user_claims(pool: &SqlitePool, username: &str) -> DbResult<Vec<ClaimType>> {
    let user_id = crate::fetch_user_id_by_name(pool, username)
        .await?
        .ok_or(crate::DbError::UserNotFound {
            username: username.to_string(),
        })?;

    // Fetch direct user claims
    let user_claims = sqlx::query_scalar::<_, String>("SELECT claim_key FROM user_claims WHERE user_id = ?")
        .bind(user_id)
        .fetch_all(pool)
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
    .fetch_all(pool)
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
    .fetch_all(pool)
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
    .fetch_all(pool)
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

pub async fn get_user_direct_claims(pool: &SqlitePool, username: &str) -> DbResult<Vec<ClaimType>> {
    let user_id = crate::fetch_user_id_by_name(pool, username)
        .await?
        .ok_or(crate::DbError::UserNotFound {
            username: username.to_string(),
        })?;

    // Fetch direct user claims only
    let user_claims = sqlx::query_scalar::<_, String>("SELECT claim_key FROM user_claims WHERE user_id = ?")
        .bind(user_id)
        .fetch_all(pool)
        .await?;

    Ok(user_claims.into_iter().filter_map(|s| ClaimType::from_str(&s).ok()).collect())
}

pub async fn add_claim_to_user(pool: &SqlitePool, username: &str, claim: &ClaimType) -> DbResult<()> {
    let user_id = crate::fetch_user_id_by_name(pool, username)
        .await?
        .ok_or(crate::DbError::UserNotFound {
            username: username.to_string(),
        })?;
    sqlx::query("INSERT OR IGNORE INTO user_claims (user_id, claim_key) VALUES (?, ?)")
        .bind(user_id)
        .bind(claim.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn remove_claim_from_user(pool: &SqlitePool, username: &str, claim: &ClaimType) -> DbResult<()> {
    let user_id = crate::fetch_user_id_by_name(pool, username)
        .await?
        .ok_or(crate::DbError::UserNotFound {
            username: username.to_string(),
        })?;
    sqlx::query("DELETE FROM user_claims WHERE user_id = ? AND claim_key = ?")
        .bind(user_id)
        .bind(claim.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn add_claim_to_group(pool: &SqlitePool, group_name: &str, claim: &ClaimType) -> DbResult<()> {
    let group_id = crate::fetch_group_id_by_name(pool, group_name)
        .await?
        .ok_or(crate::DbError::GroupNotFound {
            group: group_name.to_string(),
        })?;
    sqlx::query("INSERT OR IGNORE INTO group_claims (group_id, claim_key) VALUES (?, ?)")
        .bind(group_id)
        .bind(claim.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn remove_claim_from_group(pool: &SqlitePool, group_name: &str, claim: &ClaimType) -> DbResult<()> {
    let group_id = crate::fetch_group_id_by_name(pool, group_name)
        .await?
        .ok_or(crate::DbError::GroupNotFound {
            group: group_name.to_string(),
        })?;
    sqlx::query("DELETE FROM group_claims WHERE group_id = ? AND claim_key = ?")
        .bind(group_id)
        .bind(claim.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn get_group_claims(pool: &SqlitePool, group_name: &str) -> DbResult<Vec<ClaimType>> {
    let group_id = crate::fetch_group_id_by_name(pool, group_name)
        .await?
        .ok_or(crate::DbError::GroupNotFound {
            group: group_name.to_string(),
        })?;
    let claims = sqlx::query_scalar::<_, String>("SELECT claim_key FROM group_claims WHERE group_id = ?")
        .bind(group_id)
        .fetch_all(pool)
        .await?;

    Ok(claims.into_iter().filter_map(|s| ClaimType::from_str(&s).ok()).collect())
}

pub async fn get_role_claims(pool: &SqlitePool, role_name: &str) -> DbResult<Vec<ClaimType>> {
    let role_id = fetch_role_id_by_name(pool, role_name).await?.ok_or(crate::DbError::GroupNotFound {
        group: role_name.to_string(), // TODO: Add RoleNotFound error
    })?;
    let claims = sqlx::query_scalar::<_, String>("SELECT claim_key FROM role_claims WHERE role_id = ?")
        .bind(role_id)
        .fetch_all(pool)
        .await?;

    Ok(claims.into_iter().filter_map(|s| ClaimType::from_str(&s).ok()).collect())
}

pub async fn list_user_roles(pool: &SqlitePool, username: &str) -> DbResult<Vec<String>> {
    let rows = sqlx::query(
        "SELECT r.name FROM roles r JOIN user_roles ur ON r.id = ur.role_id JOIN users u ON u.id = ur.user_id WHERE u.username = ? ORDER BY r.name",
    )
    .bind(username)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("name")).collect())
}

pub async fn list_role_users(pool: &SqlitePool, role_name: &str) -> DbResult<Vec<String>> {
    let rows = sqlx::query(
        "SELECT u.username FROM users u JOIN user_roles ur ON u.id = ur.user_id JOIN roles r ON r.id = ur.role_id WHERE r.name = ? ORDER BY u.username",
    )
    .bind(role_name)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("username")).collect())
}

pub async fn list_group_roles(pool: &SqlitePool, group_name: &str) -> DbResult<Vec<String>> {
    let rows = sqlx::query(
        "SELECT r.name FROM roles r JOIN group_roles gr ON r.id = gr.role_id JOIN groups g ON g.id = gr.group_id WHERE g.name = ? ORDER BY r.name",
    )
    .bind(group_name)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("name")).collect())
}

pub async fn list_role_groups(pool: &SqlitePool, role_name: &str) -> DbResult<Vec<String>> {
    let rows = sqlx::query(
        "SELECT g.name FROM groups g JOIN group_roles gr ON g.id = gr.group_id JOIN roles r ON r.id = gr.role_id WHERE r.name = ? ORDER BY g.name",
    )
    .bind(role_name)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("name")).collect())
}

pub async fn assign_role_to_group(pool: &SqlitePool, group_name: &str, role_name: &str) -> DbResult<()> {
    let group_id = crate::fetch_group_id_by_name(pool, group_name)
        .await?
        .ok_or(crate::DbError::GroupNotFound {
            group: group_name.to_string(),
        })?;
    let role_id = fetch_role_id_by_name(pool, role_name).await?.ok_or(crate::DbError::GroupNotFound {
        group: role_name.to_string(), // TODO: Add RoleNotFound error
    })?;
    sqlx::query("INSERT OR IGNORE INTO group_roles (group_id, role_id) VALUES (?, ?)")
        .bind(group_id)
        .bind(role_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn revoke_role_from_group(pool: &SqlitePool, group_name: &str, role_name: &str) -> DbResult<()> {
    let group_id = crate::fetch_group_id_by_name(pool, group_name)
        .await?
        .ok_or(crate::DbError::GroupNotFound {
            group: group_name.to_string(),
        })?;
    let role_id = fetch_role_id_by_name(pool, role_name).await?.ok_or(crate::DbError::GroupNotFound {
        group: role_name.to_string(),
    })?;
    sqlx::query("DELETE FROM group_roles WHERE group_id = ? AND role_id = ?")
        .bind(group_id)
        .bind(role_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn fetch_role_id_by_name(pool: &SqlitePool, name: &str) -> DbResult<Option<i64>> {
    let row = sqlx::query("SELECT id FROM roles WHERE name = ?")
        .bind(name)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.get::<i64, _>("id")))
}
