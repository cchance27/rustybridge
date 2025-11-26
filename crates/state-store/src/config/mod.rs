//! Server configuration and options management.

use sqlx::{Row, SqlitePool};

use crate::DbResult;

pub async fn get_server_option(pool: &SqlitePool, key: &str) -> DbResult<Option<String>> {
    let row = sqlx::query("SELECT value FROM server_options WHERE key = ?")
        .bind(key)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.get("value")))
}

pub async fn set_server_option(pool: &SqlitePool, key: &str, value: &str) -> DbResult<()> {
    sqlx::query("INSERT OR REPLACE INTO server_options (key, value) VALUES (?, ?)")
        .bind(key)
        .bind(value)
        .execute(pool)
        .await?;
    Ok(())
}
