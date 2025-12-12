//! Server configuration and options management.

use rb_types::audit::RetentionConfig;
use sqlx::{Row, SqliteExecutor};

use crate::{DbError, DbResult};

// --------------------------------
// Generic Server Options
// --------------------------------

pub async fn get_server_option(executor: impl SqliteExecutor<'_>, key: &str) -> DbResult<Option<String>> {
    let row = sqlx::query("SELECT value FROM server_options WHERE key = ?")
        .bind(key)
        .fetch_optional(executor)
        .await?;
    Ok(row.map(|r| r.get("value")))
}

pub async fn set_server_option(executor: impl SqliteExecutor<'_>, key: &str, value: &str) -> DbResult<()> {
    sqlx::query("INSERT OR REPLACE INTO server_options (key, value) VALUES (?, ?)")
        .bind(key)
        .bind(value)
        .execute(executor)
        .await?;
    Ok(())
}

// --------------------------------
// Retention Config
// --------------------------------

const RETENTION_CONFIG_KEY: &str = "retention_config";

/// Get the retention configuration from the database.
/// Returns default config if not set.
pub async fn get_retention_config(executor: impl SqliteExecutor<'_>) -> DbResult<RetentionConfig> {
    match get_server_option(executor, RETENTION_CONFIG_KEY).await? {
        Some(json) => serde_json::from_str(&json).map_err(|e| DbError::JsonSerialization {
            context: "retention_config deserialization".to_string(),
            source: e,
        }),
        None => Ok(RetentionConfig::default()),
    }
}

/// Save the retention configuration to the database.
pub async fn set_retention_config(executor: impl SqliteExecutor<'_>, config: &RetentionConfig) -> DbResult<()> {
    let json = serde_json::to_string(config).map_err(|e| DbError::JsonSerialization {
        context: "retention_config serialization".to_string(),
        source: e,
    })?;
    set_server_option(executor, RETENTION_CONFIG_KEY, &json).await
}
