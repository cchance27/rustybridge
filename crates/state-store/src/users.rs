//! User and group management operations.

use crate::DbResult;
use rb_types::auth::UserAuthRecord;
use sqlx::{Row, SqliteExecutor};

fn current_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub async fn fetch_user_id_by_name(executor: impl SqliteExecutor<'_>, username: &str) -> DbResult<Option<i64>> {
    let result = sqlx::query_scalar::<_, i64>("SELECT id FROM users WHERE username = ?")
        .bind(username)
        .fetch_optional(executor)
        .await?;
    Ok(result)
}

pub async fn fetch_username_by_id(executor: impl SqliteExecutor<'_>, user_id: i64) -> DbResult<Option<String>> {
    let result = sqlx::query_scalar::<_, String>("SELECT username FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(executor)
        .await?;
    Ok(result)
}

/// Fetch a user's auth record by ID (id, username, password hash).
pub async fn fetch_user_auth_record(executor: impl SqliteExecutor<'_>, user_id: i64) -> DbResult<Option<UserAuthRecord>> {
    let row = sqlx::query("SELECT id, username, password_hash FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(executor)
        .await?;

    Ok(row.map(|r| UserAuthRecord {
        id: r.get("id"),
        username: r.get("username"),
        password_hash: r.get("password_hash"),
    }))
}

pub async fn fetch_group_id_by_name(executor: impl SqliteExecutor<'_>, name: &str) -> DbResult<Option<i64>> {
    let row = sqlx::query("SELECT id FROM groups WHERE name = ?")
        .bind(name)
        .fetch_optional(executor)
        .await?;
    Ok(row.map(|r| r.get::<i64, _>("id")))
}

pub async fn fetch_group_name_by_id(executor: impl SqliteExecutor<'_>, group_id: i64) -> DbResult<Option<String>> {
    let result = sqlx::query_scalar::<_, String>("SELECT name FROM groups WHERE id = ?")
        .bind(group_id)
        .fetch_optional(executor)
        .await?;
    Ok(result)
}

pub async fn create_group(executor: impl SqliteExecutor<'_>, name: &str) -> DbResult<i64> {
    let result = sqlx::query("INSERT INTO groups (name, created_at) VALUES (?, ?)")
        .bind(name)
        .bind(current_ts())
        .execute(executor)
        .await?;
    Ok(result.last_insert_rowid())
}

/// Delete a group by ID (preferred over name-based deletion).
pub async fn delete_group_by_id(executor: impl SqliteExecutor<'_>, id: i64) -> DbResult<()> {
    sqlx::query("DELETE FROM groups WHERE id = ?").bind(id).execute(executor).await?;
    Ok(())
}

/// Delete a user by ID (avoids race conditions).
pub async fn delete_user_by_id(executor: impl SqliteExecutor<'_>, id: i64) -> DbResult<()> {
    sqlx::query("DELETE FROM users WHERE id = ?").bind(id).execute(executor).await?;
    Ok(())
}

pub async fn create_user(executor: impl SqliteExecutor<'_>, username: &str, password_hash: &str) -> DbResult<i64> {
    let result = sqlx::query("INSERT INTO users (username, password_hash) VALUES (?, ?)")
        .bind(username)
        .bind(password_hash)
        .execute(executor)
        .await?;
    Ok(result.last_insert_rowid())
}

pub async fn get_earliest_user_id(executor: impl SqliteExecutor<'_>) -> DbResult<Option<i64>> {
    let row = sqlx::query_scalar("SELECT id FROM users ORDER BY id ASC LIMIT 1")
        .fetch_optional(executor)
        .await?;
    Ok(row)
}

/// Update a user's password by ID (preferred over username-based update).
pub async fn update_user_password_by_id(executor: impl SqliteExecutor<'_>, user_id: i64, password_hash: &str) -> DbResult<()> {
    sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
        .bind(password_hash)
        .bind(user_id)
        .execute(executor)
        .await?;
    Ok(())
}

pub async fn list_groups(executor: impl SqliteExecutor<'_>) -> DbResult<Vec<String>> {
    let rows = sqlx::query("SELECT name FROM groups ORDER BY name").fetch_all(executor).await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("name")).collect())
}

/// Update group name by ID
pub async fn update_group_name(executor: impl SqliteExecutor<'_>, group_id: i64, new_name: &str) -> DbResult<()> {
    sqlx::query("UPDATE groups SET name = ? WHERE id = ?")
        .bind(new_name)
        .bind(group_id)
        .execute(executor)
        .await?;
    Ok(())
}

/// Add a user to a group using IDs (preferred over name-based operation).
pub async fn add_user_to_group_by_ids(executor: impl SqliteExecutor<'_>, user_id: i64, group_id: i64) -> DbResult<()> {
    sqlx::query("INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES (?, ?)")
        .bind(user_id)
        .bind(group_id)
        .execute(executor)
        .await?;
    Ok(())
}

/// Remove a user from a group using IDs (preferred over name-based operation).
pub async fn remove_user_from_group_by_ids(executor: impl SqliteExecutor<'_>, user_id: i64, group_id: i64) -> DbResult<()> {
    sqlx::query("DELETE FROM user_groups WHERE user_id = ? AND group_id = ?")
        .bind(user_id)
        .bind(group_id)
        .execute(executor)
        .await?;
    Ok(())
}

/// List groups for a user by user ID (preferred over username-based lookup).
pub async fn list_user_groups_by_id(executor: impl SqliteExecutor<'_>, user_id: i64) -> DbResult<Vec<String>> {
    let rows = sqlx::query("SELECT g.name FROM groups g JOIN user_groups ug ON g.id = ug.group_id WHERE ug.user_id = ? ORDER BY g.name")
        .bind(user_id)
        .fetch_all(executor)
        .await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("name")).collect())
}

/// List members of a group by group ID (preferred over name-based lookup).
pub async fn list_group_members_by_id(executor: impl SqliteExecutor<'_>, group_id: i64) -> DbResult<Vec<String>> {
    let rows =
        sqlx::query("SELECT u.username FROM users u JOIN user_groups ug ON u.id = ug.user_id WHERE ug.group_id = ? ORDER BY u.username")
            .bind(group_id)
            .fetch_all(executor)
            .await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("username")).collect())
}

pub async fn fetch_user_password_hash(executor: impl SqliteExecutor<'_>, username: &str) -> DbResult<Option<String>> {
    let row = sqlx::query("SELECT password_hash FROM users WHERE username = ?")
        .bind(username)
        .fetch_optional(executor)
        .await?;
    Ok(row.map(|r| r.get::<String, _>("password_hash")))
}

pub async fn count_users(executor: impl SqliteExecutor<'_>) -> DbResult<i64> {
    let row = sqlx::query("SELECT COUNT(*) as cnt FROM users").fetch_one(executor).await?;
    Ok(row.get::<i64, _>("cnt"))
}

pub async fn list_usernames(executor: impl SqliteExecutor<'_>) -> DbResult<Vec<String>> {
    let rows = sqlx::query("SELECT username FROM users ORDER BY username")
        .fetch_all(executor)
        .await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("username")).collect())
}
