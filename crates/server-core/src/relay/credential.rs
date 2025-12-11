//! Credential handling for relay connections.
//!
//! This module handles fetching, resolving, and managing credentials for relay connections.

use std::collections::HashMap;

use secrecy::ExposeSecret;
use serde_json::Value as JsonValue;
use tracing::{error, warn};

use crate::{
    error::{ServerError, ServerResult}, secrets::{SecretBoxedString, SecretVec, decrypt_secret, encrypt_secret}
};

// Internal Result type alias
type Result<T> = ServerResult<T>;

/// Resolved credential data fetched from the database and decrypted.
/// This struct eliminates TOCTOU issues by fetching credential data once.
#[derive(Debug)]
pub struct ResolvedCredential {
    pub id: i64,
    pub kind: String,
    pub username: Option<String>, // Resolved username (None if interactive/blank mode)
    pub username_mode: String,
    pub password_required: bool,
    pub secret: SecretVec<u8>, // Decrypted secret (password, SSH key JSON, or agent JSON)
}

const ERR_CREDENTIAL_NOT_CONFIGURED: &str = "credential type for this host aren't configured";

/// Fetch and resolve a credential from the database in one atomic operation.
/// This eliminates TOCTOU issues by fetching, decrypting, and resolving username in a single step.
/// Returns None if no credential ID is specified (inline auth).
pub async fn fetch_and_resolve_credential(
    options: &HashMap<String, SecretBoxedString>,
    base_username: &str,
) -> Result<Option<ResolvedCredential>> {
    let auth_source = options.get("auth.source").map(|s| s.expose_secret().as_str());

    match auth_source {
        Some("inline") => {
            // Inline authentication is handled later; nothing to resolve here.
            return Ok(None);
        }
        Some("credential") => {}
        _ => {
            // No declared auth source; treat as misconfigured instead of falling back.
            return Err(ServerError::Other(ERR_CREDENTIAL_NOT_CONFIGURED.to_string()));
        }
    }

    // Check if we have a credential ID
    let cred_id = match options.get("auth.id").and_then(|s| s.expose_secret().parse::<i64>().ok()) {
        Some(id) => id,
        None => {
            return Err(ServerError::Other(ERR_CREDENTIAL_NOT_CONFIGURED.to_string()));
        }
    };

    // Fetch credential from database
    let db = state_store::server_db().await?;
    let pool = db.into_pool();
    let cred = state_store::get_relay_credential_by_id(&pool, cred_id)
        .await?
        .ok_or_else(|| ServerError::not_found("credential", cred_id.to_string()))?;

    // Decrypt secret and handle legacy upgrade
    let secret = if !cred.secret.is_empty() {
        match decrypt_secret(&cred.salt, &cred.nonce, &cred.secret) {
            Ok((pt, is_legacy)) => {
                if is_legacy {
                    warn!(cred_id, kind = %cred.kind, "upgrading legacy v1 credential");
                    if let Ok(blob) = encrypt_secret(pt.expose_secret()) {
                        let _ = sqlx::query("UPDATE relay_credentials SET salt = ?, nonce = ?, secret = ? WHERE id = ?")
                            .bind(blob.salt)
                            .bind(blob.nonce)
                            .bind(blob.ciphertext)
                            .bind(cred_id)
                            .execute(&pool)
                            .await;
                    }
                }
                pt
            }
            Err(e) => {
                error!(cred_id, error = %e, "failed to decrypt credential");
                return Err(e);
            }
        }
    } else {
        SecretVec::new(Box::new(Vec::new()))
    };

    // Resolve username based on username_mode
    let username = match cred.username_mode.as_str() {
        "passthrough" => Some(base_username.to_string()),
        "blank" => None, // Interactive username prompt
        _ => {
            // fixed and others
            // Try to get username from meta JSON, fallback to base_username
            if let Some(ref meta) = cred.meta
                && let Ok(json) = serde_json::from_str::<JsonValue>(meta)
                && let Some(u) = json.get("username").and_then(|v| v.as_str())
            {
                Some(u.to_string())
            } else {
                Some(base_username.to_string())
            }
        }
    };

    Ok(Some(ResolvedCredential {
        id: cred.id,
        kind: cred.kind,
        username,
        username_mode: cred.username_mode,
        password_required: cred.password_required,
        secret,
    }))
}
