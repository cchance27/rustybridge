//! SSH server configuration and startup functionality
//!
//! This module handles starting the SSH server and loading/creating host keys.

use std::{sync::Arc, time::Duration};

use base64::Engine;
use rb_types::config::ServerConfig;
use russh::{
    MethodKind, MethodSet, keys::{
        Algorithm, PrivateKey, ssh_key::{LineEnding, rand_core::OsRng}
    }, server::{self as ssh_server, Server}
};
use secrecy::ExposeSecret;
use sqlx::Row;
use tracing::{info, warn};

use crate::{
    error::{ServerError, ServerResult}, secrets::{self, SecretBoxedString}
};

/// Launch the embedded SSH server using the parsed CLI configuration.
///
/// This configures russh with our crypto preferences, enables only password auth,
/// and defers to `ServerManager` (and ultimately `handler::ServerHandler`) for per-connection
/// state machines.
pub async fn run_ssh_server(config: ServerConfig) -> ServerResult<()> {
    // Refuse to start without a non-empty master secret configured
    secrets::require_master_secret()?;

    let db = state_store::server_db().await?;

    let pool = db.into_pool();

    // Require at least one user to be present; avoid starting an unauthenticated server.
    let user_count = state_store::count_users(&pool).await?;
    if user_count == 0 {
        return Err(ServerError::InvalidConfig(
            "no users configured; add one with: rb-server users add <name> --password <pass>".to_string(),
        ));
    }

    if config.roll_hostkey {
        sqlx::query("DELETE FROM server_options WHERE key = 'server_hostkey'")
            .execute(&pool)
            .await?;
        info!("rolled server host key per rb-server secrets rotate-key request");
    }

    let host_key = load_or_create_host_key(&pool).await?;

    let mut server_config = ssh_server::Config {
        // Inbound server connections must always run with secure defaults
        preferred: ssh_core::crypto::default_preferred(),
        auth_rejection_time: Duration::from_millis(250),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        nodelay: true,
        ..Default::default()
    };

    server_config.methods = MethodSet::empty();
    server_config.methods.push(MethodKind::Password);
    server_config.methods.push(MethodKind::KeyboardInteractive);
    server_config.methods.push(MethodKind::PublicKey);
    server_config.keys.push(host_key);

    // Spawn background task for SSH auth session cleanup
    let cleanup_pool = pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Every hour
        loop {
            interval.tick().await;
            match state_store::cleanup_expired_ssh_auth_sessions(&cleanup_pool).await {
                Ok(count) if count > 0 => {
                    info!("Cleaned up {} expired/used SSH auth sessions", count);
                }
                Err(e) => {
                    warn!("Failed to cleanup expired SSH auth sessions: {}", e);
                }
                _ => {}
            }
        }
    });

    let mut server = super::server_manager::ServerManager;
    info!(bind = %config.bind, port = config.port, "starting embedded SSH server");

    server
        .run_on_address(Arc::new(server_config), (config.bind.as_str(), config.port))
        .await?;
    Ok(())
}

async fn load_or_create_host_key(pool: &sqlx::SqlitePool) -> ServerResult<PrivateKey> {
    const KEY_NAME: &str = "server_hostkey";
    if let Some(row) = sqlx::query("SELECT value FROM server_options WHERE key = ?")
        .bind(KEY_NAME)
        .fetch_optional(pool)
        .await?
    {
        let raw: String = row.get("value");
        // Host key may be stored encrypted; decrypt if needed
        let (pem, is_legacy) = secrets::decrypt_string_if_encrypted(&raw)?;
        if is_legacy {
            warn!("Upgrading legacy v1 server host key");
            let s: String = pem.expose_secret().to_string();
            let b: Box<String> = Box::new(s);
            let ss: secrecy::SecretBox<String> = secrecy::SecretBox::new(b);
            if let Ok(new_enc) = secrets::encrypt_string(ss) {
                let _ = sqlx::query("INSERT OR REPLACE INTO server_options (key, value) VALUES (?, ?)")
                    .bind(KEY_NAME)
                    .bind(new_enc)
                    .execute(pool)
                    .await;
            }
        }
        // If it wasn't encrypted before and a master secret is configured, upgrade to encrypted at rest
        if !secrets::is_encrypted_marker(&raw) {
            if let Ok(()) = secrets::require_master_secret() {
                if let Ok(enc) = secrets::encrypt_string(SecretBoxedString::new(Box::new(pem.expose_secret().clone()))) {
                    let _ = sqlx::query("INSERT OR REPLACE INTO server_options (key, value) VALUES (?, ?)")
                        .bind(KEY_NAME)
                        .bind(enc)
                        .execute(pool)
                        .await;
                    tracing::info!("secured server host key with encryption");
                }
            } else {
                tracing::warn!(
                    "server host key is stored unencrypted; set RB_SERVER_SECRETS_KEY or RB_SERVER_SECRETS_PASSPHRASE to enable encryption"
                );
            }
        }
        let key = PrivateKey::from_openssh(pem.expose_secret()).map_err(|e| ServerError::Crypto(e.to_string()))?;
        info!("loaded persisted server host key");
        Ok(key)
    } else {
        // Ensure we have a usable master secret before generating so we don't persist unencrypted keys
        secrets::require_master_secret()?;
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).map_err(|e| ServerError::Crypto(e.to_string()))?;
        let pem = key
            .to_openssh(LineEnding::LF)
            .map_err(|e| ServerError::Crypto(e.to_string()))?
            .to_string();

        // Encrypt before storing at rest
        let enc = secrets::encrypt_string(SecretBoxedString::new(Box::new(pem)))?;
        sqlx::query("INSERT OR REPLACE INTO server_options (key, value) VALUES (?, ?)")
            .bind(KEY_NAME)
            .bind(enc)
            .execute(pool)
            .await?;

        info!("generated new server host key and cached it in the state database");
        Ok(key)
    }
}

/// Set a server option key/value in the shared state database.
/// Avoid logging values here to prevent leaking secrets (OIDC client secrets, etc.).
pub async fn set_server_option(key: &str, value: &str) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    state_store::set_server_option(&pool, key, value).await?;
    info!(key, "server option updated");
    Ok(())
}

/// Rotate secrets key - changes the master key and re-encrypts all encrypted data
pub async fn rotate_secrets_key(old_input: &str, new_input: &str) -> ServerResult<()> {
    // Trim inputs to match load_master_key behavior (prevents rotation failures with whitespace)
    let old_input = old_input.trim();
    let new_input = new_input.trim();

    // Derive master keys properly - if input looks like a passphrase, use Argon2id KDF
    let old_master = if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(old_input)
        && decoded.len() == 32
    {
        decoded
    } else {
        // It's a passphrase, derive using Argon2id (matches load_master_key)
        secrets::derive_master_key_from_passphrase(old_input)?
    };

    let new_master = if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(new_input)
        && decoded.len() == 32
    {
        decoded
    } else {
        // It's a passphrase, derive using Argon2id (matches load_master_key)
        secrets::derive_master_key_from_passphrase(new_input)?
    };

    let db = state_store::server_db().await?;

    let pool = db.into_pool();

    // Rotate credentials
    {
        let rows = sqlx::query("SELECT id, salt, nonce, secret FROM relay_credentials")
            .fetch_all(&pool)
            .await?;
        for row in rows {
            let id: i64 = row.get("id");
            let salt: Vec<u8> = row.get("salt");
            let nonce: Vec<u8> = row.get("nonce");
            let secret: Vec<u8> = row.get("secret");
            let pt = secrets::decrypt_secret_with(&salt, &nonce, &secret, &old_master)?;
            let blob = secrets::encrypt_secret_with(pt.expose_secret(), &new_master)?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            sqlx::query("UPDATE relay_credentials SET salt = ?, nonce = ?, secret = ?, updated_at = ? WHERE id = ?")
                .bind(&blob.salt)
                .bind(&blob.nonce)
                .bind(&blob.ciphertext)
                .bind(now)
                .bind(id)
                .execute(&pool)
                .await?;
        }
    }

    // Rotate relay_host_options values. Respect the is_secure flag so plaintext
    // options remain plaintext and only sensitive rows are re-encrypted.
    {
        let rows = sqlx::query("SELECT relay_host_id, key, value, is_secure FROM relay_host_options")
            .fetch_all(&pool)
            .await?;
        for row in rows {
            let host_id: i64 = row.get("relay_host_id");
            let key: String = row.get("key");
            let value: String = row.get("value");
            let is_secure: bool = row.get("is_secure");

            // Only rotate entries explicitly marked secure; keep plaintext values untouched.
            if is_secure {
                // If a secure row somehow contains plaintext, treat it as such to avoid corrupting data.
                let plaintext = if secrets::is_encrypted_marker(&value) {
                    secrets::decrypt_string_with(&value, &old_master)?
                } else {
                    SecretBoxedString::new(Box::new(value))
                };
                let reenc = secrets::encrypt_string_with(plaintext, &new_master)?;
                sqlx::query("UPDATE relay_host_options SET value = ?, is_secure = 1 WHERE relay_host_id = ? AND key = ?")
                    .bind(reenc)
                    .bind(host_id)
                    .bind(key)
                    .execute(&pool)
                    .await?;
            } else if secrets::is_encrypted_marker(&value) {
                // Data hygiene: if a non-secure row was encrypted previously, restore plaintext so consumers do not misinterpret it.
                let plaintext = secrets::decrypt_string_with(&value, &old_master)?;
                sqlx::query("UPDATE relay_host_options SET value = ?, is_secure = 0 WHERE relay_host_id = ? AND key = ?")
                    .bind(plaintext.expose_secret().to_string())
                    .bind(host_id)
                    .bind(key)
                    .execute(&pool)
                    .await?;
            }
        }
    }

    info!("secrets rotated for credentials and options");
    Ok(())
}
