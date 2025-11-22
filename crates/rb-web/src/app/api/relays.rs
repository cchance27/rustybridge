#[cfg(feature = "server")]
use anyhow::anyhow;
use dioxus::prelude::*;
#[cfg(feature = "server")]
use secrecy::ExposeSecret;

use crate::app::models::*;

/// List all relay hosts with credential and hostkey status
#[get("/api/relays")]
pub async fn list_relay_hosts() -> Result<Vec<RelayHostInfo>> {
    #[cfg(feature = "server")]
    {
        let hosts = server_core::list_hosts().await.map_err(|e| anyhow!("{}", e))?;

        // Get database connection for querying options
        let db = state_store::server_db().await.map_err(|e| anyhow!("{}", e))?;
        state_store::migrate_server(&db).await.map_err(|e| anyhow!("{}", e))?;
        let pool = db.into_pool();

        let mut result = Vec::new();

        for host in hosts {
            let opts = state_store::fetch_relay_host_options(&pool, host.id)
                .await
                .map_err(|e| anyhow!("{}", e))?;

            let decode_non_secret = |raw: &str| {
                server_core::secrets::decrypt_string_if_encrypted(raw)
                    .map(|s| s.expose_secret().to_string())
                    .unwrap_or_else(|_| raw.to_string())
            };

            let auth_source = opts.get("auth.source").map(|(v, _)| decode_non_secret(v));

            let credential_id = if let Some((auth_id, is_secure)) = opts.get("auth.id") {
                if *is_secure {
                    server_core::secrets::decrypt_string_if_encrypted(auth_id)
                        .ok()
                        .and_then(|s| s.expose_secret().parse::<i64>().ok())
                } else {
                    auth_id.parse::<i64>().ok()
                }
            } else {
                None
            };

            let credential = match auth_source.as_deref() {
                Some("credential") => {
                    if let Some(cred_id) = credential_id {
                        match state_store::get_relay_credential_by_id(&pool, cred_id).await {
                            Ok(Some(cred)) => Some(cred.name),
                            Ok(None) => Some("<unknown>".to_string()),
                            Err(_) => None,
                        }
                    } else {
                        None
                    }
                }
                Some("inline") => {
                    let method = opts
                        .get("auth.method")
                        .map(|(v, _)| decode_non_secret(v))
                        .unwrap_or_else(|| "unknown".to_string());

                    match method.as_str() {
                        "password" => Some("Custom (Password)".to_string()),
                        "publickey" => Some("Custom (SSH Key)".to_string()),
                        "agent" => Some("Custom (Agent)".to_string()),
                        other => Some(format!("Custom ({})", other)),
                    }
                }
                _ => None,
            };

            // Check for hostkey
            let has_hostkey = opts.contains_key("hostkey.openssh");

            let auth_config = match auth_source.as_deref() {
                Some("credential") => Some(AuthConfig {
                    mode: "saved".to_string(),
                    saved_credential_id: credential_id,
                    custom_type: None,
                    username: None,
                    has_password: false,
                    has_private_key: false,
                    has_passphrase: false,
                    has_public_key: false,
                }),
                Some("inline") => Some(AuthConfig {
                    mode: "custom".to_string(),
                    saved_credential_id: None,
                    custom_type: opts.get("auth.method").map(|(v, _)| decode_non_secret(v)),
                    username: opts.get("auth.username").map(|(v, _)| decode_non_secret(v)),
                    has_password: opts.contains_key("auth.password"),
                    has_private_key: opts.contains_key("auth.identity"),
                    has_passphrase: opts.contains_key("auth.passphrase"),
                    has_public_key: opts.contains_key("auth.agent_pubkey"),
                }),
                _ => Some(AuthConfig {
                    mode: "none".to_string(),
                    saved_credential_id: None,
                    custom_type: None,
                    username: None,
                    has_password: false,
                    has_private_key: false,
                    has_passphrase: false,
                    has_public_key: false,
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
                has_hostkey,
                auth_config,
                access_principals,
            });
        }

        Ok(result)
    }
    #[cfg(not(feature = "server"))]
    {
        // This will never be called on the client - Dioxus handles the RPC
        unreachable!("Server function called on client")
    }
}

/// Create a new relay host
#[post("/api/relays")]
pub async fn create_relay_host(req: CreateRelayRequest) -> Result<()> {
    #[cfg(feature = "server")]
    {
        server_core::add_relay_host(&req.endpoint, &req.name)
            .await
            .map_err(|e| anyhow!("{}", e))?;
        Ok(())
    }
    #[cfg(not(feature = "server"))]
    {
        unreachable!("Server function called on client")
    }
}

/// Update an existing relay host
#[put("/api/relays/{id}")]
pub async fn update_relay_host(id: i64, req: UpdateRelayRequest) -> Result<()> {
    #[cfg(feature = "server")]
    {
        // Parse endpoint
        let (ip, port_str) = req.endpoint.rsplit_once(':').ok_or_else(|| anyhow!("Invalid endpoint format"))?;
        let port = port_str.parse::<i64>().map_err(|_| anyhow!("Invalid port"))?;

        let db = state_store::server_db().await.map_err(|e| anyhow!("{}", e))?;
        state_store::migrate_server(&db).await.map_err(|e| anyhow!("{}", e))?;
        let pool = db.into_pool();

        state_store::update_relay_host(&pool, id, &req.name, ip, port)
            .await
            .map_err(|e| anyhow!("{}", e))?;

        Ok(())
    }
    #[cfg(not(feature = "server"))]
    {
        unreachable!("Server function called on client")
    }
}

/// Delete a relay host
#[delete("/api/relays/{id}")]
pub async fn delete_relay_host(id: i64) -> Result<()> {
    #[cfg(feature = "server")]
    {
        let db = state_store::server_db().await.map_err(|e| anyhow!("{}", e))?;
        state_store::migrate_server(&db).await.map_err(|e| anyhow!("{}", e))?;
        let pool = db.into_pool();

        // Delete by ID, not name
        state_store::delete_relay_host_by_id(&pool, id)
            .await
            .map_err(|e| anyhow!("{}", e))?;
        Ok(())
    }
    #[cfg(not(feature = "server"))]
    {
        unreachable!("Server function called on client")
    }
}

/// Assign a credential to a relay host
#[post("/api/relays/{id}/credential/{credential_id}")]
pub async fn assign_relay_credential(id: i64, credential_id: i64) -> Result<()> {
    #[cfg(feature = "server")]
    {
        // Get relay host name from ID
        let db = state_store::server_db().await.map_err(|e| anyhow!("{}", e))?;
        state_store::migrate_server(&db).await.map_err(|e| anyhow!("{}", e))?;
        let pool = db.into_pool();

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
    #[cfg(not(feature = "server"))]
    {
        unreachable!("Server function called on client")
    }
}

/// Clear credential assignment from a relay host
#[delete("/api/relays/{id}/credential")]
pub async fn clear_relay_credential(id: i64) -> Result<()> {
    #[cfg(feature = "server")]
    {
        // Get relay host name from ID
        let db = state_store::server_db().await.map_err(|e| anyhow!("{}", e))?;
        state_store::migrate_server(&db).await.map_err(|e| anyhow!("{}", e))?;
        let pool = db.into_pool();

        let host = state_store::fetch_relay_host_by_id(&pool, id)
            .await
            .map_err(|e| anyhow!("{}", e))?
            .ok_or_else(|| anyhow!("Relay host not found"))?;

        server_core::unassign_credential(&host.name).await.map_err(|e| anyhow!("{}", e))?;
        Ok(())
    }
    #[cfg(not(feature = "server"))]
    {
        unreachable!("Server function called on client")
    }
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

#[get("/api/relays/{id}/fetch-hostkey")]
pub async fn fetch_relay_hostkey_for_review(id: i64) -> Result<HostkeyReview> {
    #[cfg(feature = "server")]
    {
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
    #[cfg(not(feature = "server"))]
    {
        unreachable!("Server function called on client")
    }
}

/// Store hostkey after user approval (step 2 of 2-step process)
#[post("/api/relays/{id}/store-hostkey")]
pub async fn store_relay_hostkey(id: i64, key_pem: String) -> Result<()> {
    #[cfg(feature = "server")]
    {
        server_core::store_relay_hostkey_from_web(id, key_pem)
            .await
            .map_err(|e| anyhow!("{}", e).into())
    }
    #[cfg(not(feature = "server"))]
    {
        unreachable!("Server function called on client")
    }
}

/// Set custom authentication for a relay (inline, not using a saved credential)
#[post("/api/relays/{id}/auth/custom")]
pub async fn set_custom_auth(id: i64, req: CustomAuthRequest) -> Result<()> {
    #[cfg(feature = "server")]
    {
        // Get relay name from ID
        let db = state_store::server_db().await.map_err(|e| anyhow!("{}", e))?;
        state_store::migrate_server(&db).await.map_err(|e| anyhow!("{}", e))?;
        let pool = db.into_pool();
        let relay = state_store::fetch_relay_host_by_id(&pool, id)
            .await
            .map_err(|e| anyhow!("{}", e))?
            .ok_or_else(|| anyhow!("Relay not found"))?;

        match req.auth_type.as_str() {
            "password" => {
                let password = req.password.as_deref().ok_or_else(|| anyhow!("Password required"))?;
                server_core::set_custom_password_auth(&relay.name, req.username.as_deref(), password)
                    .await
                    .map_err(|e| anyhow!("{}", e))?;
            }
            "ssh_key" => {
                let private_key = req.private_key.as_deref().ok_or_else(|| anyhow!("Private key required"))?;
                server_core::set_custom_ssh_key_auth(&relay.name, req.username.as_deref(), private_key, req.passphrase.as_deref())
                    .await
                    .map_err(|e| anyhow!("{}", e))?;
            }
            "agent" => {
                let public_key = req.public_key.as_deref().ok_or_else(|| anyhow!("Public key required"))?;
                server_core::set_custom_agent_auth(&relay.name, req.username.as_deref(), public_key)
                    .await
                    .map_err(|e| anyhow!("{}", e))?;
            }
            _ => return Err(anyhow!("Invalid auth type: {}", req.auth_type).into()),
        }
        Ok(())
    }
    #[cfg(not(feature = "server"))]
    {
        unreachable!("Server function called on client")
    }
}

/// Clear all authentication settings from a relay
#[delete("/api/relays/{id}/auth")]
pub async fn clear_relay_auth(id: i64) -> Result<()> {
    #[cfg(feature = "server")]
    {
        // Get relay name from ID
        let db = state_store::server_db().await.map_err(|e| anyhow!("{}", e))?;
        state_store::migrate_server(&db).await.map_err(|e| anyhow!("{}", e))?;
        let pool = db.into_pool();
        let relay = state_store::fetch_relay_host_by_id(&pool, id)
            .await
            .map_err(|e| anyhow!("{}", e))?
            .ok_or_else(|| anyhow!("Relay not found"))?;

        server_core::clear_all_auth(&relay.name).await.map_err(|e| anyhow!("{}", e))?;
        Ok(())
    }
    #[cfg(not(feature = "server"))]
    {
        unreachable!("Server function called on client")
    }
}
