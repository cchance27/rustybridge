//! User and group management operations.

use rb_types::auth::UserAuthRecord;
use sqlx::{Row, SqlitePool};

use crate::DbResult;

fn current_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub async fn fetch_user_id_by_name(pool: &SqlitePool, username: &str) -> DbResult<Option<i64>> {
    let row = sqlx::query("SELECT id FROM users WHERE username = ?")
        .bind(username)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.get::<i64, _>("id")))
}

/// Fetch a user's auth record by ID (id, username, password hash).
pub async fn fetch_user_auth_record(pool: &SqlitePool, user_id: i64) -> DbResult<Option<UserAuthRecord>> {
    let row = sqlx::query("SELECT id, username, password_hash FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(pool)
        .await?;

    Ok(row.map(|r| UserAuthRecord {
        id: r.get("id"),
        username: r.get("username"),
        password_hash: r.get("password_hash"),
    }))
}

pub async fn fetch_group_id_by_name(pool: &SqlitePool, name: &str) -> DbResult<Option<i64>> {
    let row = sqlx::query("SELECT id FROM groups WHERE name = ?")
        .bind(name)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.get::<i64, _>("id")))
}

pub async fn create_group(pool: &SqlitePool, name: &str) -> DbResult<i64> {
    sqlx::query("INSERT INTO groups (name, created_at) VALUES (?, ?)")
        .bind(name)
        .bind(current_ts())
        .execute(pool)
        .await?;
    let row = sqlx::query("SELECT id FROM groups WHERE name = ?")
        .bind(name)
        .fetch_one(pool)
        .await?;
    Ok(row.get::<i64, _>("id"))
}

pub async fn delete_group_by_name(pool: &SqlitePool, name: &str) -> DbResult<()> {
    sqlx::query("DELETE FROM groups WHERE name = ?").bind(name).execute(pool).await?;
    Ok(())
}

pub async fn list_groups(pool: &SqlitePool) -> DbResult<Vec<String>> {
    let rows = sqlx::query("SELECT name FROM groups ORDER BY name").fetch_all(pool).await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("name")).collect())
}

pub async fn add_user_to_group(pool: &SqlitePool, username: &str, group_name: &str) -> DbResult<()> {
    let user_id = fetch_user_id_by_name(pool, username).await?.ok_or(crate::DbError::UserNotFound {
        username: username.to_string(),
    })?;
    let group_id = fetch_group_id_by_name(pool, group_name)
        .await?
        .ok_or(crate::DbError::GroupNotFound {
            group: group_name.to_string(),
        })?;
    sqlx::query("INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES (?, ?)")
        .bind(user_id)
        .bind(group_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn remove_user_from_group(pool: &SqlitePool, username: &str, group_name: &str) -> DbResult<()> {
    let user_id = fetch_user_id_by_name(pool, username).await?.ok_or(crate::DbError::UserNotFound {
        username: username.to_string(),
    })?;
    let group_id = fetch_group_id_by_name(pool, group_name)
        .await?
        .ok_or(crate::DbError::GroupNotFound {
            group: group_name.to_string(),
        })?;
    sqlx::query("DELETE FROM user_groups WHERE user_id = ? AND group_id = ?")
        .bind(user_id)
        .bind(group_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_user_groups(pool: &SqlitePool, username: &str) -> DbResult<Vec<String>> {
    let rows = sqlx::query(
        "SELECT g.name FROM groups g JOIN user_groups ug ON g.id = ug.group_id JOIN users u ON u.id = ug.user_id WHERE u.username = ? ORDER BY g.name",
    )
    .bind(username)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("name")).collect())
}

pub async fn list_group_members(pool: &SqlitePool, group_name: &str) -> DbResult<Vec<String>> {
    let rows = sqlx::query(
        "SELECT u.username FROM users u JOIN user_groups ug ON u.id = ug.user_id JOIN groups g ON g.id = ug.group_id WHERE g.name = ? ORDER BY u.username",
    )
    .bind(group_name)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("username")).collect())
}

pub async fn fetch_user_password_hash(pool: &SqlitePool, username: &str) -> DbResult<Option<String>> {
    let row = sqlx::query("SELECT password_hash FROM users WHERE username = ?")
        .bind(username)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.get::<String, _>("password_hash")))
}

pub async fn count_users(pool: &SqlitePool) -> DbResult<i64> {
    let row = sqlx::query("SELECT COUNT(*) as cnt FROM users").fetch_one(pool).await?;
    Ok(row.get::<i64, _>("cnt"))
}

pub async fn list_usernames(pool: &SqlitePool) -> DbResult<Vec<String>> {
    let rows = sqlx::query("SELECT username FROM users ORDER BY username").fetch_all(pool).await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("username")).collect())
}

/// Get user ID by username
pub async fn get_user_id(pool: &SqlitePool, username: &str) -> DbResult<Option<i64>> {
    let result = sqlx::query_scalar::<_, i64>("SELECT id FROM users WHERE username = ?")
        .bind(username)
        .fetch_optional(pool)
        .await?;
    Ok(result)
}
