#[cfg(feature = "server")]
use anyhow::anyhow;
use dioxus::prelude::*;
#[cfg(feature = "server")]
use rb_types::auth::{ClaimLevel, ClaimType};
use rb_types::web::{CreateRelayRequest, CustomAuthRequest, RelayHostInfo, UpdateRelayRequest};
#[cfg(feature = "server")]
use secrecy::ExposeSecret;

#[cfg(feature = "server")]
use crate::server::auth::guards::{WebAuthSession, ensure_claim};

#[cfg(feature = "server")]
fn ensure_relay_claim(auth: &WebAuthSession, level: ClaimLevel) -> Result<()> {
    ensure_claim(auth, &ClaimType::Relays(level))
}

/// List all relay hosts with credential and hostkey status
#[get(
    "/api/relays",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn list_relay_hosts() -> Result<Vec<RelayHostInfo>> {
    ensure_relay_claim(&auth, ClaimLevel::View)?;
    let hosts = server_core::list_hosts().await.map_err(|e| anyhow!("{}", e))?;

    let mut result = Vec::new();

    for host in hosts {
        use rb_types::web::{AuthWebConfig, RelayAccessPrincipal};

        let opts = state_store::fetch_relay_host_options(&pool, host.id)
            .await
            .map_err(|e| anyhow!("{}", e))?;

        let decode_value = |raw: &str, is_secure: bool| {
            if is_secure {
                server_core::secrets::decrypt_string_if_encrypted(raw)
                    .map(|s| s.0.expose_secret().to_string())
                    .unwrap_or_else(|_| raw.to_string())
            } else {
                raw.to_string()
            }
        };

        let auth_source = opts.get("auth.source").map(|(v, s)| decode_value(v, *s));

        let credential_id = if let Some((auth_id, is_secure)) = opts.get("auth.id") {
            if *is_secure {
                server_core::secrets::decrypt_string_if_encrypted(auth_id)
                    .ok()
                    .and_then(|s| s.0.expose_secret().parse::<i64>().ok())
            } else {
                auth_id.parse::<i64>().ok()
            }
        } else {
            None
        };

        let (credential, credential_kind, credential_username_mode, credential_password_required) = match auth_source.as_deref() {
            Some("credential") => {
                if let Some(cred_id) = credential_id {
                    match state_store::get_relay_credential_by_id(&pool, cred_id).await {
                        Ok(Some(cred)) => (
                            Some(cred.name),
                            Some(cred.kind),
                            Some(cred.username_mode),
                            Some(cred.password_required),
                        ),
                        Ok(None) => (Some("<unknown>".to_string()), None, None, None),
                        Err(_) => (None, None, None, None),
                    }
                } else {
                    (None, None, None, None)
                }
            }
            Some("inline") => (None, None, None, None),
            _ => (None, None, None, None),
        };

        // Check for hostkey
        let has_hostkey = opts.contains_key("hostkey.openssh");

        let auth_config = match auth_source.as_deref() {
            Some("credential") => Some(AuthWebConfig {
                mode: "saved".to_string(),
                saved_credential_id: credential_id,
                custom_type: None,
                username: None,
                username_mode: None,
                has_password: false,
                has_private_key: false,
                has_passphrase: false,
                has_public_key: false,
                password_required: None,
            }),
            Some("inline") => Some(AuthWebConfig {
                mode: "custom".to_string(),
                saved_credential_id: None,
                custom_type: opts.get("auth.method").map(|(v, s)| decode_value(v, *s)),
                username: opts.get("auth.username").map(|(v, s)| decode_value(v, *s)),
                username_mode: opts.get("auth.username_mode").map(|(v, s)| decode_value(v, *s)),
                has_password: opts.contains_key("auth.password"),
                has_private_key: opts.contains_key("auth.identity"),
                has_passphrase: opts.contains_key("auth.passphrase"),
                has_public_key: opts.contains_key("auth.agent_pubkey"),
                password_required: opts
                    .get("auth.password_required")
                    .map(|(v, s)| decode_value(v, *s))
                    .and_then(|v| v.parse::<bool>().ok()),
            }),
            _ => Some(AuthWebConfig {
                mode: "none".to_string(),
                saved_credential_id: None,
                custom_type: None,
                username: None,
                username_mode: None,
                has_password: false,
                has_private_key: false,
                has_passphrase: false,
                has_public_key: false,
                password_required: None,
            }),
        };

        // Fetch access principals for this relay
        let access_principals = state_store::fetch_relay_access_principals(&pool, host.id)
            .await
            .map_err(|e| anyhow!("{}", e))?
            .into_iter()
            .map(|p| RelayAccessPrincipal {
                kind: p.kind,
                name: p.name,
            })
            .collect();

        result.push(RelayHostInfo {
            id: host.id,
            name: host.name,
            ip: host.ip,
            port: host.port,
            credential,
            credential_kind,
            credential_username_mode,
            credential_password_required,
            has_hostkey,
            auth_config,
            access_principals,
        });
    }

    Ok(result)
}

/// Create a new relay host
#[post(
    "/api/relays",
    auth: WebAuthSession
)]
pub async fn create_relay_host(req: CreateRelayRequest) -> Result<()> {
    ensure_relay_claim(&auth, ClaimLevel::Create)?;
    server_core::add_relay_host_without_hostkey(&req.endpoint, &req.name)
        .await
        .map_err(|e| anyhow!("{}", e))?;
    Ok(())
}

/// Update an existing relay host
#[put(
    "/api/relays/{id}",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn update_relay_host(id: i64, req: UpdateRelayRequest) -> Result<()> {
    ensure_relay_claim(&auth, ClaimLevel::Edit)?;
    // Parse endpoint
    let (ip, port_str) = req.endpoint.rsplit_once(':').ok_or_else(|| anyhow!("Invalid endpoint format"))?;
    let port = port_str.parse::<i64>().map_err(|_| anyhow!("Invalid port"))?;

    state_store::update_relay_host(&pool, id, &req.name, ip, port)
        .await
        .map_err(|e| anyhow!("{}", e))?;

    Ok(())
}

/// Delete a relay host
#[delete(
    "/api/relays/{id}",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn delete_relay_host(id: i64) -> Result<()> {
    ensure_relay_claim(&auth, ClaimLevel::Delete)?;

    // Delete by ID, not name
    state_store::delete_relay_host_by_id(&pool, id)
        .await
        .map_err(|e| anyhow!("{}", e))?;
    Ok(())
}

/// Assign a credential to a relay host
#[post(
    "/api/relays/{id}/credential/{credential_id}",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn assign_relay_credential(id: i64, credential_id: i64) -> Result<()> {
    ensure_relay_claim(&auth, ClaimLevel::Edit)?;

    let host = state_store::fetch_relay_host_by_id(&pool, id)
        .await
        .map_err(|e| anyhow!("{}", e))?
        .ok_or_else(|| anyhow!("Relay host not found"))?;

    // Get credential name from ID
    let cred = state_store::get_relay_credential_by_id(&pool, credential_id)
        .await
        .map_err(|e| anyhow!("{}", e))?
        .ok_or_else(|| anyhow!("Credential not found"))?;

    server_core::assign_credential(&host.name, &cred.name)
        .await
        .map_err(|e| anyhow!("{}", e))?;
    Ok(())
}

/// Clear credential assignment from a relay host
#[delete(
    "/api/relays/{id}/credential",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn clear_relay_credential(id: i64) -> Result<()> {
    ensure_relay_claim(&auth, ClaimLevel::Edit)?;

    let host = state_store::fetch_relay_host_by_id(&pool, id)
        .await
        .map_err(|e| anyhow!("{}", e))?
        .ok_or_else(|| anyhow!("Relay host not found"))?;

    server_core::unassign_credential(&host.name).await.map_err(|e| anyhow!("{}", e))?;
    Ok(())
}

/// Fetch hostkey for review (step 1 of 2-step process)
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
pub struct HostkeyReview {
    pub host_id: i64,
    pub host: String,
    pub old_fingerprint: Option<String>,
    pub old_key_type: Option<String>,
    pub new_fingerprint: String,
    pub new_key_type: String,
    pub new_key_pem: String,
}

#[get(
    "/api/relays/{id}/fetch-hostkey",
    auth: WebAuthSession
)]
pub async fn fetch_relay_hostkey_for_review(id: i64) -> Result<HostkeyReview> {
    ensure_relay_claim(&auth, ClaimLevel::Edit)?;
    // Use server_core helper that returns a tuple
    server_core::fetch_relay_hostkey_for_web(id)
        .await
        .map(|review| HostkeyReview {
            host_id: review.0,
            host: review.1,
            old_fingerprint: review.2,
            old_key_type: review.3,
            new_fingerprint: review.4,
            new_key_type: review.5,
            new_key_pem: review.6,
        })
        .map_err(|e| anyhow!("{}", e).into())
}

/// Store hostkey after user approval (step 2 of 2-step process)
#[post(
    "/api/relays/{id}/store-hostkey",
    auth: WebAuthSession
)]
pub async fn store_relay_hostkey(id: i64, key_pem: String) -> Result<()> {
    ensure_relay_claim(&auth, ClaimLevel::Edit)?;
    server_core::store_relay_hostkey_from_web(id, key_pem)
        .await
        .map_err(|e| anyhow!("{}", e).into())
}

/// Set custom authentication for a relay (inline, not using a saved credential)
#[post(
    "/api/relays/{id}/auth/custom",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn set_custom_auth(id: i64, req: CustomAuthRequest) -> Result<()> {
    use rb_types::validation::CredentialValidationInput;

    ensure_relay_claim(&auth, ClaimLevel::Edit)?;
    let relay = state_store::fetch_relay_host_by_id(&pool, id)
        .await
        .map_err(|e| anyhow!("{}", e))?
        .ok_or_else(|| anyhow!("Relay not found"))?;

    let errors = CredentialValidationInput {
        kind: &req.auth_type,
        username_mode: &req.username_mode,
        username: req.username.as_deref().unwrap_or(""),
        password_required: req.password_required,
        password: req.password.as_deref().unwrap_or(""),
        private_key: req.private_key.as_deref().unwrap_or(""),
        public_key: req.public_key.as_deref().unwrap_or(""),
        // Treat custom auth set as new/overwrite (no "keep existing" logic yet)
        ..Default::default()
    }
    .validate();

    if !errors.is_empty() {
        return Err(anyhow!("Validation failed: {}", rb_types::validation::format_errors(&errors)).into());
    }

    match req.auth_type.as_str() {
        "password" => {
            // Only require password if username_mode is "fixed" AND password_required is true
            let password = if req.username_mode == "fixed" && req.password_required {
                req.password.as_deref().ok_or_else(|| anyhow!("Password required"))?
            } else {
                // For interactive/passthrough modes, password is optional
                req.password.as_deref().unwrap_or("")
            };
            server_core::set_custom_password_auth(
                &relay.name,
                req.username.as_deref(),
                password,
                &req.username_mode,
                req.password_required,
            )
            .await
            .map_err(|e| anyhow!("{}", e))?;
        }
        "ssh_key" => {
            let private_key = req.private_key.as_deref().ok_or_else(|| anyhow!("Private key required"))?;
            server_core::set_custom_ssh_key_auth(
                &relay.name,
                req.username.as_deref(),
                private_key,
                req.passphrase.as_deref(),
                &req.username_mode,
            )
            .await
            .map_err(|e| anyhow!("{}", e))?;
        }
        "agent" => {
            let public_key = req.public_key.as_deref().ok_or_else(|| anyhow!("Public key required"))?;
            server_core::set_custom_agent_auth(&relay.name, req.username.as_deref(), public_key, &req.username_mode)
                .await
                .map_err(|e| anyhow!("{}", e))?;
        }
        _ => return Err(anyhow!("Invalid auth type: {}", req.auth_type).into()),
    }
    Ok(())
}

/// Clear all authentication settings from a relay
#[delete(
    "/api/relays/{id}/auth",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn clear_relay_auth(id: i64) -> Result<()> {
    ensure_relay_claim(&auth, ClaimLevel::Edit)?;

    let relay = state_store::fetch_relay_host_by_id(&pool, id)
        .await
        .map_err(|e| anyhow!("{}", e))?
        .ok_or_else(|| anyhow!("Relay not found"))?;

    server_core::clear_all_auth(&relay.name).await.map_err(|e| anyhow!("{}", e))?;
    Ok(())
}
