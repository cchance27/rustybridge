use tracing::info;

use crate::{
    error::{ServerError, ServerResult}, secrets::{SecretBoxedString, encrypt_string}
};

pub async fn set_relay_option(name: &str, key: &str, value: &str, is_secure: bool) -> ServerResult<()> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_name(&pool, name)
        .await?
        .ok_or_else(|| ServerError::not_found("relay host", name))?;

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
    .bind(host.id)
    .bind(key)
    .bind(stored_value)
    .bind(should_encrypt)
    .execute(&pool)
    .await?;
    info!(relay_host = name, key, is_secure = should_encrypt, "relay option set");
    Ok(())
}

pub async fn unset_relay_option(name: &str, key: &str) -> ServerResult<()> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_name(&pool, name)
        .await?
        .ok_or_else(|| ServerError::not_found("relay host", name))?;
    sqlx::query("DELETE FROM relay_host_options WHERE relay_host_id = ? AND key = ?")
        .bind(host.id)
        .bind(key)
        .execute(&pool)
        .await?;
    info!(relay_host = name, key, "relay option unset");
    Ok(())
}

pub async fn list_options(name: &str) -> ServerResult<Vec<(String, String)>> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_name(&pool, name)
        .await?
        .ok_or_else(|| ServerError::not_found("relay host", name))?;
    let map = state_store::fetch_relay_host_options(&pool, host.id).await?;
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
