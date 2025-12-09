use sqlx::SqliteExecutor;
use tracing::info;

use crate::{
    error::{ServerError, ServerResult}, secrets::{SecretBoxedString, encrypt_string}
};

/// Set a relay option and record an audit event.
pub async fn set_relay_option_by_id(
    ctx: &rb_types::audit::AuditContext,
    host_id: i64,
    key: &str,
    value: &str,
    is_secure: bool,
) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    let should_encrypt = set_relay_option_internal(&pool, host_id, key, value, is_secure).await?;

    if let Some(relay) = state_store::fetch_relay_host_by_id(&pool, host_id).await? {
        crate::audit!(
            ctx,
            RelayOptionSet {
                relay_name: relay.name,
                relay_id: host_id,
                key: key.to_string(),
                is_secure: should_encrypt,
            }
        );
    }

    Ok(())
}

pub(crate) async fn set_relay_option_internal(
    executor: impl SqliteExecutor<'_>,
    host_id: i64,
    key: &str,
    value: &str,
    is_secure: bool,
) -> ServerResult<bool> {
    // Auto-determine if the option should be encrypted based on the key name
    // Only truly sensitive values should be encrypted
    let should_encrypt = match key {
        // These should always be encrypted
        "auth.password" | "auth.identity" | "auth.passphrase" | "hostkey.openssh" => true,
        // These can be plain text
        "auth.source"
        | "auth.id"
        | "auth.method"
        | "auth.username"
        | "auth.agent_socket"
        | "auth.agent_pubkey"
        | "auth.username_mode"
        | "auth.password_required" => false,
        // For any other keys, respect the caller's preference (default to secure)
        _ => is_secure,
    };

    let stored_value = if should_encrypt {
        encrypt_string(SecretBoxedString::new(Box::new(value.to_string())))?
    } else {
        value.to_string()
    };

    sqlx::query(
        "INSERT INTO relay_host_options (relay_host_id, key, value, is_secure) VALUES (?, ?, ?, ?) \
         ON CONFLICT(relay_host_id, key) DO UPDATE SET value = excluded.value, is_secure = excluded.is_secure",
    )
    .bind(host_id)
    .bind(key)
    .bind(stored_value)
    .bind(should_encrypt)
    .execute(executor)
    .await?;
    info!(relay_host_id = host_id, key, is_secure = should_encrypt, "relay option set");
    Ok(should_encrypt)
}

/// Unset a relay option and record an audit event.
pub async fn unset_relay_option_by_id(ctx: &rb_types::audit::AuditContext, host_id: i64, key: &str) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();
    unset_relay_option_internal(&pool, host_id, key).await?;

    if let Some(relay) = state_store::fetch_relay_host_by_id(&pool, host_id).await? {
        crate::audit!(
            ctx,
            RelayOptionCleared {
                relay_name: relay.name,
                relay_id: host_id,
                key: key.to_string(),
            }
        );
    }

    Ok(())
}

pub(crate) async fn unset_relay_option_internal(executor: impl SqliteExecutor<'_>, host_id: i64, key: &str) -> ServerResult<()> {
    sqlx::query("DELETE FROM relay_host_options WHERE relay_host_id = ? AND key = ?")
        .bind(host_id)
        .bind(key)
        .execute(executor)
        .await?;
    info!(relay_host_id = host_id, key, "relay option unset");
    Ok(())
}

pub async fn list_options_by_id(host_id: i64) -> ServerResult<Vec<(String, String)>> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();
    let map = state_store::fetch_relay_host_options(&pool, host_id).await?;
    // For CLI display, mask encrypted values to avoid leaking secrets.
    let mut items: Vec<(String, String)> = map
        .into_iter()
        .map(
            |(k, (v, is_secure))| {
                if is_secure { (k, "<encrypted>".to_string()) } else { (k, v) }
            },
        )
        .collect();
    items.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(items)
}

/// Set custom password authentication for a relay by ID
pub async fn set_custom_password_auth_by_id(
    ctx: &rb_types::audit::AuditContext,
    host_id: i64,
    username: Option<&str>,
    password: &str,
    username_mode: &str,
    password_required: bool,
) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();
    let mut tx = pool.begin().await.map_err(ServerError::Database)?;

    // Capture existing auth keys for audit clearing
    let existing_keys: Vec<String> = sqlx::query_scalar("SELECT key FROM relay_host_options WHERE relay_host_id = ? AND key LIKE 'auth.%'")
        .bind(host_id)
        .fetch_all(&mut *tx)
        .await?;

    // Clear any existing auth first
    sqlx::query("DELETE FROM relay_host_options WHERE relay_host_id = ? AND key LIKE 'auth.%'")
        .bind(host_id)
        .execute(&mut *tx)
        .await?;

    let mut set_keys = Vec::new();

    let enc = set_relay_option_internal(&mut *tx, host_id, "auth.source", "inline", true).await?;
    set_keys.push(("auth.source".to_string(), enc));
    if let Some(user) = username {
        let enc = set_relay_option_internal(&mut *tx, host_id, "auth.username", user, true).await?;
        set_keys.push(("auth.username".to_string(), enc));
    }
    let enc = set_relay_option_internal(&mut *tx, host_id, "auth.password", password, true).await?;
    set_keys.push(("auth.password".to_string(), enc));
    let enc = set_relay_option_internal(&mut *tx, host_id, "auth.username_mode", username_mode, true).await?;
    set_keys.push(("auth.username_mode".to_string(), enc));
    let enc = set_relay_option_internal(
        &mut *tx,
        host_id,
        "auth.password_required",
        if password_required { "true" } else { "false" },
        true,
    )
    .await?;
    set_keys.push(("auth.password_required".to_string(), enc));

    tx.commit().await.map_err(ServerError::Database)?;
    info!(relay_host_id = host_id, "custom password auth configured");

    if let Some(relay) = state_store::fetch_relay_host_by_id(&pool, host_id).await? {
        crate::audit::log_relay_option_changes(ctx, relay.name.clone(), host_id, existing_keys, set_keys).await;
    }
    Ok(())
}

/// Set custom SSH key authentication for a relay by ID
pub async fn set_custom_ssh_key_auth_by_id(
    ctx: &rb_types::audit::AuditContext,
    host_id: i64,
    username: Option<&str>,
    private_key: &str,
    passphrase: Option<&str>,
    username_mode: &str,
) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();
    let mut tx = pool.begin().await.map_err(ServerError::Database)?;

    let existing_keys: Vec<String> = sqlx::query_scalar("SELECT key FROM relay_host_options WHERE relay_host_id = ? AND key LIKE 'auth.%'")
        .bind(host_id)
        .fetch_all(&mut *tx)
        .await?;

    // Clear any existing auth first
    sqlx::query("DELETE FROM relay_host_options WHERE relay_host_id = ? AND key LIKE 'auth.%'")
        .bind(host_id)
        .execute(&mut *tx)
        .await?;

    let mut set_keys = Vec::new();

    let enc = set_relay_option_internal(&mut *tx, host_id, "auth.source", "inline", true).await?;
    set_keys.push(("auth.source".to_string(), enc));
    let enc = set_relay_option_internal(&mut *tx, host_id, "auth.method", "publickey", true).await?;
    set_keys.push(("auth.method".to_string(), enc));
    if let Some(user) = username {
        let enc = set_relay_option_internal(&mut *tx, host_id, "auth.username", user, true).await?;
        set_keys.push(("auth.username".to_string(), enc));
    }
    let enc = set_relay_option_internal(&mut *tx, host_id, "auth.identity", private_key, true).await?;
    set_keys.push(("auth.identity".to_string(), enc));
    if let Some(pass) = passphrase {
        let enc = set_relay_option_internal(&mut *tx, host_id, "auth.passphrase", pass, true).await?;
        set_keys.push(("auth.passphrase".to_string(), enc));
    }
    let enc = set_relay_option_internal(&mut *tx, host_id, "auth.username_mode", username_mode, true).await?;
    set_keys.push(("auth.username_mode".to_string(), enc));

    tx.commit().await.map_err(ServerError::Database)?;
    info!(relay_host_id = host_id, "custom SSH key auth configured");

    if let Some(relay) = state_store::fetch_relay_host_by_id(&pool, host_id).await? {
        crate::audit::log_relay_option_changes(ctx, relay.name.clone(), host_id, existing_keys, set_keys).await;
    }
    Ok(())
}

/// Set custom SSH agent authentication for a relay by ID
pub async fn set_custom_agent_auth_by_id(
    ctx: &rb_types::audit::AuditContext,
    host_id: i64,
    username: Option<&str>,
    public_key: &str,
    username_mode: &str,
) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();
    let mut tx = pool.begin().await.map_err(ServerError::Database)?;

    let existing_keys: Vec<String> = sqlx::query_scalar("SELECT key FROM relay_host_options WHERE relay_host_id = ? AND key LIKE 'auth.%'")
        .bind(host_id)
        .fetch_all(&mut *tx)
        .await?;

    // Clear any existing auth first
    sqlx::query("DELETE FROM relay_host_options WHERE relay_host_id = ? AND key LIKE 'auth.%'")
        .bind(host_id)
        .execute(&mut *tx)
        .await?;

    let mut set_keys = Vec::new();

    let enc = set_relay_option_internal(&mut *tx, host_id, "auth.source", "inline", true).await?;
    set_keys.push(("auth.source".to_string(), enc));
    let enc = set_relay_option_internal(&mut *tx, host_id, "auth.method", "agent", true).await?;
    set_keys.push(("auth.method".to_string(), enc));
    if let Some(user) = username {
        let enc = set_relay_option_internal(&mut *tx, host_id, "auth.username", user, true).await?;
        set_keys.push(("auth.username".to_string(), enc));
    }
    let enc = set_relay_option_internal(&mut *tx, host_id, "auth.agent_pubkey", public_key, true).await?;
    set_keys.push(("auth.agent_pubkey".to_string(), enc));
    let enc = set_relay_option_internal(&mut *tx, host_id, "auth.username_mode", username_mode, true).await?;
    set_keys.push(("auth.username_mode".to_string(), enc));

    tx.commit().await.map_err(ServerError::Database)?;
    info!(relay_host_id = host_id, "custom agent auth configured");

    if let Some(relay) = state_store::fetch_relay_host_by_id(&pool, host_id).await? {
        crate::audit::log_relay_option_changes(ctx, relay.name.clone(), host_id, existing_keys, set_keys).await;
    }
    Ok(())
}

/// Clear all authentication settings from a relay by ID
pub async fn clear_all_auth_by_id(ctx: &rb_types::audit::AuditContext, host_id: i64) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    // Capture keys before deletion for audit logging
    let keys: Vec<String> = sqlx::query_scalar("SELECT key FROM relay_host_options WHERE relay_host_id = ? AND key LIKE 'auth.%'")
        .bind(host_id)
        .fetch_all(&pool)
        .await
        .unwrap_or_default();

    sqlx::query("DELETE FROM relay_host_options WHERE relay_host_id = ? AND key LIKE 'auth.%'")
        .bind(host_id)
        .execute(&pool)
        .await?;
    info!(relay_host_id = host_id, "all auth settings cleared");

    if let Some(relay) = state_store::fetch_relay_host_by_id(&pool, host_id).await? {
        crate::audit::log_relay_option_changes(ctx, relay.name.clone(), host_id, keys, vec![]).await;
    }
    Ok(())
}
