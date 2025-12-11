//! Credential management functionality
//!
//! This module handles creating, updating, deleting, and assigning credentials.

use secrecy::ExposeSecret;
use serde_json::Value as JsonValue;
use sqlx::Row;
use tracing::{info, warn};

use crate::{
    error::{ServerError, ServerResult}, secrets::SecretBoxedString
};

/// Create a password credential, tracking the full context.
pub async fn create_password_credential(
    ctx: &rb_types::audit::AuditContext,
    name: &str,
    username: Option<&str>,
    password: &str,
    username_mode: &str,
    password_required: bool,
) -> ServerResult<i64> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    let blob = crate::secrets::encrypt_secret(password.as_bytes())?;
    let meta = username.map(|u| serde_json::json!({"username": u}).to_string());
    let id = state_store::insert_relay_credential(
        &pool,
        name,
        "password",
        &blob.salt,
        &blob.nonce,
        &blob.ciphertext,
        meta.as_deref(),
        username_mode,
        password_required,
    )
    .await?;
    // Log audit event
    crate::audit!(
        ctx,
        CredentialCreated {
            name: name.to_string(),
            kind: "password".to_string(),
        }
    );

    Ok(id)
}

/// Create an SSH key credential, tracking the full context.
pub async fn create_ssh_key_credential(
    ctx: &rb_types::audit::AuditContext,
    name: &str,
    username: Option<&str>,
    key: &str,
    certificate: Option<&str>,
    passphrase: Option<&str>,
    username_mode: &str,
) -> ServerResult<i64> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    let mut secret_obj = serde_json::Map::new();
    secret_obj.insert("private_key".to_string(), serde_json::Value::String(key.to_string()));
    if let Some(c) = certificate {
        secret_obj.insert("certificate".to_string(), serde_json::Value::String(c.to_string()));
    }
    if let Some(p) = passphrase {
        secret_obj.insert("passphrase".to_string(), serde_json::Value::String(p.to_string()));
    }
    let secret_json = serde_json::Value::Object(secret_obj).to_string();
    let blob = crate::secrets::encrypt_secret(secret_json.as_bytes())?;
    let meta = username.map(|u| serde_json::json!({"username": u}).to_string());
    let id = state_store::insert_relay_credential(
        &pool,
        name,
        "ssh_key",
        &blob.salt,
        &blob.nonce,
        &blob.ciphertext,
        meta.as_deref(),
        username_mode,
        true, // password_required not applicable for ssh_key
    )
    .await?;
    // Log audit event
    crate::audit!(
        ctx,
        CredentialCreated {
            name: name.to_string(),
            kind: "ssh_key".to_string(),
        }
    );

    Ok(id)
}

/// Create an SSH agent credential, tracking the full context.
pub async fn create_agent_credential(
    ctx: &rb_types::audit::AuditContext,
    name: &str,
    username: Option<&str>,
    public_key: &str,
    username_mode: &str,
) -> ServerResult<i64> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    // For agent, we store the public key fingerprint/content to match against agent keys
    // We'll store it as a JSON object in the secret
    let secret = serde_json::json!({
        "public_key": public_key,
        // We could also store fingerprint if we wanted to pre-calculate it
    })
    .to_string();
    let blob = crate::secrets::encrypt_secret(secret.as_bytes())?;
    let meta = username.map(|u| serde_json::json!({"username": u}).to_string());
    let id = state_store::insert_relay_credential(
        &pool,
        name,
        "agent",
        &blob.salt,
        &blob.nonce,
        &blob.ciphertext,
        meta.as_deref(),
        username_mode,
        true, // password_required not applicable for agent
    )
    .await?;
    // Log audit event
    crate::audit!(
        ctx,
        CredentialCreated {
            name: name.to_string(),
            kind: "agent".to_string(),
        }
    );

    Ok(id)
}

/// Update a password credential, tracking the full context.
pub async fn update_password_credential(
    ctx: &rb_types::audit::AuditContext,
    id: i64,
    name: &str,
    username: Option<&str>,
    password: Option<&str>,
    username_mode: &str,
    password_required: bool,
) -> ServerResult<()> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    let (salt, nonce, secret) = if let Some(p) = password {
        let blob = crate::secrets::encrypt_secret(p.as_bytes())?;
        (blob.salt, blob.nonce, blob.ciphertext)
    } else {
        // Keep existing secret
        let current = state_store::get_relay_credential_by_id(&pool, id)
            .await?
            .ok_or_else(|| ServerError::not_found("credential", id.to_string()))?;
        (current.salt, current.nonce, current.secret)
    };
    let meta = username.map(|u| serde_json::json!({"username": u}).to_string());
    state_store::update_relay_credential(
        &pool,
        id,
        "password",
        &salt,
        &nonce,
        &secret,
        meta.as_deref(),
        username_mode,
        password_required,
    )
    .await?;
    // Log audit event
    crate::audit!(
        ctx,
        CredentialUpdated {
            name: name.to_string(),
            cred_id: id,
            kind: "password".to_string(),
        }
    );

    Ok(())
}

/// Update an SSH key credential, tracking the full context.
#[allow(clippy::too_many_arguments)]
pub async fn update_ssh_key_credential(
    ctx: &rb_types::audit::AuditContext,
    id: i64,
    name: &str,
    username: Option<&str>,
    key: Option<&str>,
    certificate: Option<&str>,
    passphrase: Option<&str>,
    username_mode: &str,
) -> ServerResult<()> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    let (salt, nonce, secret) = if let Some(k) = key {
        let mut secret_obj = serde_json::Map::new();
        secret_obj.insert("private_key".to_string(), serde_json::Value::String(k.to_string()));
        if let Some(c) = certificate {
            secret_obj.insert("certificate".to_string(), serde_json::Value::String(c.to_string()));
        }
        if let Some(p) = passphrase {
            secret_obj.insert("passphrase".to_string(), serde_json::Value::String(p.to_string()));
        }
        let secret_json = serde_json::Value::Object(secret_obj).to_string();
        let blob = crate::secrets::encrypt_secret(secret_json.as_bytes())?;
        (blob.salt, blob.nonce, blob.ciphertext)
    } else {
        // Keep existing secret
        let current = state_store::get_relay_credential_by_id(&pool, id)
            .await?
            .ok_or_else(|| ServerError::not_found("credential", id.to_string()))?;
        (current.salt, current.nonce, current.secret)
    };
    let meta = username.map(|u| serde_json::json!({"username": u}).to_string());
    state_store::update_relay_credential(
        &pool,
        id,
        "ssh_key",
        &salt,
        &nonce,
        &secret,
        meta.as_deref(),
        username_mode,
        true, // password_required not applicable for ssh_key
    )
    .await?;
    // Log audit event
    crate::audit!(
        ctx,
        CredentialUpdated {
            name: name.to_string(),
            cred_id: id,
            kind: "ssh_key".to_string(),
        }
    );

    Ok(())
}

/// Update an SSH agent credential, tracking the full context.
pub async fn update_agent_credential(
    ctx: &rb_types::audit::AuditContext,
    id: i64,
    name: &str,
    username: Option<&str>,
    public_key: Option<&str>,
    username_mode: &str,
) -> ServerResult<()> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    let (salt, nonce, secret) = if let Some(pk) = public_key {
        let secret = serde_json::json!({
            "public_key": pk,
        })
        .to_string();
        let blob = crate::secrets::encrypt_secret(secret.as_bytes())?;
        (blob.salt, blob.nonce, blob.ciphertext)
    } else {
        // Keep existing secret
        let current = state_store::get_relay_credential_by_id(&pool, id)
            .await?
            .ok_or_else(|| ServerError::not_found("credential", id.to_string()))?;
        (current.salt, current.nonce, current.secret)
    };
    let meta = username.map(|u| serde_json::json!({"username": u}).to_string());
    state_store::update_relay_credential(
        &pool,
        id,
        "agent",
        &salt,
        &nonce,
        &secret,
        meta.as_deref(),
        username_mode,
        true, // password_required not applicable for agent
    )
    .await?;
    // Log audit event
    crate::audit!(
        ctx,
        CredentialUpdated {
            name: name.to_string(),
            cred_id: id,
            kind: "agent".to_string(),
        }
    );

    Ok(())
}

/// Delete a credential by ID, tracking the full context.
///
/// # Examples
///
/// ```ignore
/// let ctx = AuditContext::web(user_id, username, ip_address, session_id);
/// delete_credential_by_id(&ctx, credential_id).await?;
/// ```
pub async fn delete_credential_by_id(ctx: &rb_types::audit::AuditContext, id: i64) -> ServerResult<()> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();

    let mut tx = pool.begin().await.map_err(ServerError::Database)?;

    // Guard: prevent deletion if in use by any relay host
    let rows = sqlx::query("SELECT relay_host_id, value FROM relay_host_options WHERE key = 'auth.id'")
        .fetch_all(&mut *tx)
        .await?;
    let target_id_str = id.to_string();
    for row in rows {
        let value: String = row.get("value");
        let (resolved, is_legacy) = if crate::secrets::is_encrypted_marker(&value) {
            match crate::secrets::decrypt_string_if_encrypted(&value) {
                Ok((s, legacy)) => (s, legacy),
                Err(_) => continue,
            }
        } else {
            (SecretBoxedString::new(Box::new(value)), false)
        };

        if is_legacy {
            warn!("upgrading legacy v1 secret for relay option 'auth.id' (credential check)");
            let s: String = resolved.expose_secret().to_string();
            let b: Box<String> = Box::new(s);
            let ss: SecretBoxedString = SecretBoxedString::new(b);
            if let Ok(new_enc) = crate::secrets::encrypt_string(ss) {
                let _ = sqlx::query("UPDATE relay_host_options SET value = ? WHERE relay_host_id = ? AND key = 'auth.id'")
                    .bind(new_enc)
                    .bind(row.get::<i64, _>("relay_host_id"))
                    .execute(&mut *tx)
                    .await;
            }
        }
        if resolved.expose_secret() == &target_id_str {
            let host_id: i64 = row.get("relay_host_id");
            let host = state_store::fetch_relay_host_by_id(&mut *tx, host_id).await?;
            let host_name = host.map(|h| h.name).unwrap_or_else(|| "unknown".to_string());
            return Err(ServerError::Internal(format!(
                "Cannot delete credential: credential is in use by relay host '{}'",
                host_name
            )));
        }
    }

    // Fetch credential info before deletion for audit log
    let cred_info = state_store::get_relay_credential_by_id(&mut *tx, id).await?;

    state_store::delete_relay_credential_by_id(&mut *tx, id).await?;

    tx.commit().await.map_err(ServerError::Database)?;

    // Log audit event with full context
    if let Some(cred) = cred_info {
        crate::audit!(
            ctx,
            CredentialDeleted {
                name: cred.name,
                cred_id: id,
                kind: cred.kind,
            }
        );
    }

    Ok(())
}

/// List all credentials
pub async fn list_credentials() -> ServerResult<Vec<(i64, String, String, Option<String>, String, bool)>> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    let rows = state_store::list_relay_credentials(&pool).await?;
    Ok(rows)
}

/// List credentials with assigned relay hosts
/// Returns (id, name, kind, username, username_mode, password_required, assigned_relays)
pub async fn list_credentials_with_assignments() -> ServerResult<Vec<(i64, String, String, Option<String>, String, bool, Vec<String>)>> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();

    let creds = state_store::list_relay_credentials(&pool).await?;
    let hosts = state_store::list_relay_hosts(&pool, None).await?;
    let host_map: std::collections::HashMap<i64, String> = hosts.into_iter().map(|h| (h.id, h.name)).collect();

    let opts_rows: Vec<(i64, String)> = sqlx::query_as("SELECT relay_host_id, value FROM relay_host_options WHERE key = 'auth.id'")
        .fetch_all(&pool)
        .await?;

    let mut assignments: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();

    for (host_id, value) in opts_rows {
        let (resolved, is_legacy) = if crate::secrets::is_encrypted_marker(&value) {
            match crate::secrets::decrypt_string_if_encrypted(&value) {
                Ok((s, legacy)) => (s, legacy),
                Err(_) => continue,
            }
        } else {
            (SecretBoxedString::new(Box::new(value)), false)
        };

        if is_legacy {
            warn!("upgrading legacy v1 secret for relay option 'auth.id' (list assignments)");
            if let Ok(new_enc) =
                crate::secrets::encrypt_string(secrecy::SecretBox::<String>::new(Box::new(resolved.expose_secret().to_string())))
            {
                let _ = sqlx::query("UPDATE relay_host_options SET value = ? WHERE relay_host_id = ? AND key = 'auth.id'")
                    .bind(new_enc)
                    .bind(host_id)
                    .execute(&pool)
                    .await;
            }
        }

        let cred_id_str = resolved.expose_secret().clone();
        if let Some(host_name) = host_map.get(&host_id) {
            assignments.entry(cred_id_str).or_default().push(host_name.clone());
        }
    }

    let mut result = Vec::new();
    for (id, name, kind, meta, username_mode, password_required) in creds {
        let username = meta
            .as_deref()
            .and_then(|m| serde_json::from_str::<JsonValue>(m).ok())
            .and_then(|v| v.get("username").and_then(|u| u.as_str().map(|s| s.to_string())));

        let mut assigned_relays = assignments.remove(&id.to_string()).unwrap_or_default();
        assigned_relays.sort();

        result.push((id, name, kind, username, username_mode, password_required, assigned_relays));
    }

    Ok(result)
}

/// Assign a credential to a host by IDs, tracking the full context.
pub async fn assign_credential_by_ids(ctx: &rb_types::audit::AuditContext, host_id: i64, cred_id: i64) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    let cred = state_store::get_relay_credential_by_id(&pool, cred_id)
        .await?
        .ok_or_else(|| ServerError::not_found("credential", cred_id.to_string()))?;
    let credential_name = cred.name.clone(); // Capture for audit log

    let host = state_store::fetch_relay_host_by_id(&pool, host_id)
        .await?
        .ok_or_else(|| ServerError::not_found("relay_host", host_id.to_string()))?;
    let relay_name = host.name.clone(); // Capture for audit log

    // Normalize: map ssh_key-like kinds to publickey for relay auth.method
    let method_plain: &str = match cred.kind.as_str() {
        "ssh_key" | "ssh_cert_key" => "publickey",
        other => other,
    };

    let mut tx = pool.begin().await.map_err(ServerError::Database)?;

    // Capture and clear any existing auth first to ensure clean state
    let existing_keys: Vec<String> = sqlx::query_scalar("SELECT key FROM relay_host_options WHERE relay_host_id = ? AND key LIKE 'auth.%'")
        .bind(host_id)
        .fetch_all(&mut *tx)
        .await?;

    sqlx::query("DELETE FROM relay_host_options WHERE relay_host_id = ? AND key LIKE 'auth.%'")
        .bind(host_id)
        .execute(&mut *tx)
        .await?;

    // Use set_relay_option_internal inside the transaction; log after commit
    let mut set_keys = Vec::new();
    let enc = crate::relay_host::options::set_relay_option_internal(&mut *tx, host_id, "auth.source", "credential", true).await?;
    set_keys.push(("auth.source".to_string(), enc));
    let enc = crate::relay_host::options::set_relay_option_internal(&mut *tx, host_id, "auth.id", &cred.id.to_string(), true).await?;
    set_keys.push(("auth.id".to_string(), enc));
    let enc = crate::relay_host::options::set_relay_option_internal(&mut *tx, host_id, "auth.method", method_plain, true).await?;
    set_keys.push(("auth.method".to_string(), enc));

    tx.commit().await.map_err(ServerError::Database)?;

    info!(relay_host_id = host_id, credential_id = cred_id, context = %ctx, "credential assigned to host");

    // Log audit event
    crate::audit!(
        ctx,
        CredentialAssigned {
            cred_id: cred_id,
            cred_name: credential_name.clone(),
            relay_id: host_id,
            relay_name: relay_name.clone(),
        }
    );

    if let Some(relay) = state_store::fetch_relay_host_by_id(&pool, host_id).await? {
        for key in existing_keys {
            crate::audit!(
                ctx,
                RelayOptionCleared {
                    relay_name: relay.name.clone(),
                    relay_id: host_id,
                    key,
                }
            );
        }

        for (key, is_secure) in set_keys {
            crate::audit!(
                ctx,
                RelayOptionSet {
                    relay_name: relay.name.clone(),
                    relay_id: host_id,
                    key,
                    is_secure,
                }
            );
        }
    }

    Ok(())
}

/// Unassign a credential from a host by ID, tracking the full context.
pub async fn unassign_credential_by_id(ctx: &rb_types::audit::AuditContext, host_id: i64) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    // Fetch relay info before modification for audit log
    let relay_info = state_store::fetch_relay_host_by_id(&pool, host_id).await?;

    // Capture current auth keys for logging
    let existing_keys: Vec<String> = sqlx::query_scalar("SELECT key FROM relay_host_options WHERE relay_host_id = ? AND key LIKE 'auth.%'")
        .bind(host_id)
        .fetch_all(&pool)
        .await?;

    sqlx::query("DELETE FROM relay_host_options WHERE relay_host_id = ? AND key LIKE 'auth.%'")
        .bind(host_id)
        .execute(&pool)
        .await?;
    info!(relay_host_id = host_id, context = %ctx, "credential unassigned from host");

    // Log audit event
    if let Some(relay) = relay_info {
        for key in existing_keys {
            crate::audit!(
                ctx,
                RelayOptionCleared {
                    relay_name: relay.name.clone(),
                    relay_id: host_id,
                    key,
                }
            );
        }

        crate::audit!(
            ctx,
            CredentialUnassigned {
                relay_name: relay.name,
                relay_id: host_id,
            }
        );
    }

    Ok(())
}
