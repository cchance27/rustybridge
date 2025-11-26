//! SSH public key management operations.

use sqlx::SqlitePool;

use crate::DbResult;

/// Get all public keys for a user by username
pub async fn get_user_public_keys(pool: &SqlitePool, username: &str) -> DbResult<Vec<String>> {
    let rows = sqlx::query_scalar::<_, String>(
        "SELECT public_key FROM user_public_keys 
         WHERE user_id = (SELECT id FROM users WHERE username = ?)",
    )
    .bind(username)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Add a public key for a user
pub async fn add_user_public_key(pool: &SqlitePool, username: &str, public_key: &str, comment: Option<&str>) -> DbResult<i64> {
    let user_id = crate::users::fetch_user_id_by_name(pool, username)
        .await?
        .ok_or(crate::DbError::UserNotFound {
            username: username.to_string(),
        })?;

    let result = sqlx::query("INSERT INTO user_public_keys (user_id, public_key, comment) VALUES (?, ?, ?)")
        .bind(user_id)
        .bind(public_key)
        .bind(comment)
        .execute(pool)
        .await?;

    Ok(result.last_insert_rowid())
}

/// Delete a user's public key by ID
pub async fn delete_user_public_key(pool: &SqlitePool, key_id: i64) -> DbResult<()> {
    sqlx::query("DELETE FROM user_public_keys WHERE id = ?")
        .bind(key_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// List all public keys for a user (with full details)
pub async fn list_user_public_keys(pool: &SqlitePool, username: &str) -> DbResult<Vec<(i64, String, Option<String>, i64)>> {
    let user_id = crate::users::fetch_user_id_by_name(pool, username)
        .await?
        .ok_or(crate::DbError::UserNotFound {
            username: username.to_string(),
        })?;

    // Cast created_at to Unix epoch seconds so callers receive a numeric value (integer).
    let rows = sqlx::query_as::<_, (i64, String, Option<String>, i64)>(
        "SELECT id, public_key, comment, CAST(strftime('%s', created_at) AS INTEGER) as created_at
         FROM user_public_keys WHERE user_id = ? ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}
