//! SSH public key management operations.
use sqlx::SqliteExecutor;

use crate::DbResult;

/// Get all public keys for a user by username
pub async fn get_user_public_keys(executor: impl SqliteExecutor<'_>, username: &str) -> DbResult<Vec<String>> {
    let rows = sqlx::query_scalar::<_, String>(
        "SELECT public_key FROM user_public_keys 
         WHERE user_id = (SELECT id FROM users WHERE username = ?)",
    )
    .bind(username)
    .fetch_all(executor)
    .await?;
    Ok(rows)
}

/// Add a public key for a user by user ID (preferred over username-based operation).
pub async fn add_user_public_key_by_id(
    executor: impl SqliteExecutor<'_>,
    user_id: i64,
    public_key: &str,
    comment: Option<&str>,
) -> DbResult<i64> {
    let result = sqlx::query("INSERT INTO user_public_keys (user_id, public_key, comment) VALUES (?, ?, ?)")
        .bind(user_id)
        .bind(public_key)
        .bind(comment)
        .execute(executor)
        .await?;

    Ok(result.last_insert_rowid())
}

/// Fetch public key owner info by key ID for audit logging.
/// Returns (user_id, username) if found.
pub async fn fetch_public_key_by_id(executor: impl SqliteExecutor<'_>, key_id: i64) -> DbResult<Option<(i64, String)>> {
    let row = sqlx::query_as::<_, (i64, String)>(
        "SELECT upk.user_id, u.username 
         FROM user_public_keys upk
         JOIN users u ON u.id = upk.user_id
         WHERE upk.id = ?",
    )
    .bind(key_id)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

/// Delete a user's public key by ID
pub async fn delete_user_public_key(executor: impl SqliteExecutor<'_>, key_id: i64) -> DbResult<()> {
    sqlx::query("DELETE FROM user_public_keys WHERE id = ?")
        .bind(key_id)
        .execute(executor)
        .await?;
    Ok(())
}

/// List all public keys for a user by user ID (preferred over username-based lookup).
pub async fn list_user_public_keys_by_id(
    executor: impl SqliteExecutor<'_>,
    user_id: i64,
) -> DbResult<Vec<(i64, String, Option<String>, i64)>> {
    // Cast created_at to Unix epoch seconds so callers receive a numeric value (integer).
    let rows = sqlx::query_as::<_, (i64, String, Option<String>, i64)>(
        "SELECT id, public_key, comment, CAST(strftime('%s', created_at) AS INTEGER) as created_at
         FROM user_public_keys WHERE user_id = ? ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(executor)
    .await?;

    Ok(rows)
}
