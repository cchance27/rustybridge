use dioxus::prelude::*;
#[cfg(feature = "server")]
use rb_types::auth::{ClaimLevel, ClaimType};
use rb_types::{
    credentials::CustomAuthRequest, relay::{CreateRelayRequest, HostkeyReview, RelayHostInfo, UpdateRelayRequest}
};

use crate::error::ApiError;
#[cfg(feature = "server")]
use crate::server::audit::WebAuditContext;
#[cfg(feature = "server")]
use crate::server::auth::guards::{WebAuthSession, ensure_claim};

#[cfg(feature = "server")]
fn ensure_relay_claim(auth: &WebAuthSession, level: ClaimLevel) -> Result<(), ApiError> {
    ensure_claim(auth, &ClaimType::Relays(level))
}

/// List all relay hosts with credential and hostkey status
#[get(
    "/api/relays",
    auth: WebAuthSession
)]
pub async fn list_relay_hosts() -> Result<Vec<RelayHostInfo>, ApiError> {
    ensure_relay_claim(&auth, ClaimLevel::View)?;
    server_core::list_relay_hosts_with_details().await.map_err(ApiError::internal)
}

/// Create a new relay host
#[post(
    "/api/relays",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
pub async fn create_relay_host(req: CreateRelayRequest) -> Result<(), ApiError> {
    ensure_relay_claim(&auth, ClaimLevel::Create)?;
    server_core::add_relay_host_without_hostkey(&audit.0, &req.endpoint, &req.name)
        .await
        .map_err(ApiError::internal)?;
    Ok(())
}

/// Update an existing relay host
#[put(
    "/api/relays/{id}",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
pub async fn update_relay_host(id: i64, req: UpdateRelayRequest) -> Result<(), ApiError> {
    ensure_relay_claim(&auth, ClaimLevel::Edit)?;
    // Parse endpoint
    let (ip, port_str) = req
        .endpoint
        .rsplit_once(':')
        .ok_or_else(|| ApiError::validation("Invalid endpoint format"))?;
    let port = port_str.parse::<i64>().map_err(|_| ApiError::validation("Invalid port"))?;

    server_core::update_relay_host_by_id(&audit.0, id, &req.name, ip, port)
        .await
        .map_err(ApiError::internal)?;

    Ok(())
}

/// Delete a relay host
#[delete(
    "/api/relays/{id}",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
pub async fn delete_relay_host(id: i64) -> Result<(), ApiError> {
    ensure_relay_claim(&auth, ClaimLevel::Delete)?;

    // Delete by ID, not name
    server_core::delete_relay_host_by_id(&audit.0, id)
        .await
        .map_err(ApiError::internal)?;
    Ok(())
}

/// Assign a credential to a relay host
#[post(
    "/api/relays/{id}/credential/{credential_id}",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
pub async fn assign_relay_credential(id: i64, credential_id: i64) -> Result<(), ApiError> {
    ensure_relay_claim(&auth, ClaimLevel::Edit)?;

    let host = server_core::fetch_relay_by_id(id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("relay host", id.to_string()))?;

    let cred = server_core::get_relay_credential_by_id(credential_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("credential", credential_id.to_string()))?;

    server_core::assign_credential_by_ids(&audit.0, host.id, cred.id)
        .await
        .map_err(ApiError::internal)?;
    Ok(())
}

/// Clear credential assignment from a relay host
#[delete(
    "/api/relays/{id}/credential",
    auth: WebAuthSession,
    audit: WebAuditContext,
)]
pub async fn clear_relay_credential(id: i64) -> Result<(), ApiError> {
    ensure_relay_claim(&auth, ClaimLevel::Edit)?;

    let host = server_core::fetch_relay_by_id(id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("relay host", id.to_string()))?;

    server_core::unassign_credential_by_id(&audit.0, host.id)
        .await
        .map_err(ApiError::internal)?;
    Ok(())
}

#[get(
    "/api/relays/{id}/fetch-hostkey",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
pub async fn fetch_relay_hostkey_for_review(id: i64) -> Result<HostkeyReview, ApiError> {
    ensure_relay_claim(&auth, ClaimLevel::Edit)?;
    // Use server_core helper that returns a tuple
    server_core::fetch_relay_hostkey_for_web(&audit.0, id)
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
        .map_err(ApiError::internal)
}

/// Store hostkey after user approval (step 2 of 2-step process)
#[post(
    "/api/relays/{id}/store-hostkey",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
pub async fn store_relay_hostkey(id: i64, key_pem: String) -> Result<(), ApiError> {
    ensure_relay_claim(&auth, ClaimLevel::Edit)?;
    server_core::store_relay_hostkey_from_web(&audit.0, id, key_pem)
        .await
        .map_err(ApiError::internal)
}

/// Set custom authentication for a relay (inline, not using a saved credential)
#[post(
    "/api/relays/{id}/auth/custom",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
pub async fn set_custom_auth(id: i64, req: CustomAuthRequest) -> Result<(), ApiError> {
    use rb_types::validation::CredentialValidationInput;

    ensure_relay_claim(&auth, ClaimLevel::Edit)?;
    let relay = server_core::fetch_relay_by_id(id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("relay host", id.to_string()))?;

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
        return Err(ApiError::validation(rb_types::validation::format_errors(&errors)));
    }

    match req.auth_type.as_str() {
        "password" => {
            // Only require password if username_mode is "fixed" AND password_required is true
            let password = if req.username_mode == "fixed" && req.password_required {
                req.password.as_deref().ok_or_else(|| ApiError::validation("Password required"))?
            } else {
                // For interactive/passthrough modes, password is optional
                req.password.as_deref().unwrap_or("")
            };
            server_core::set_custom_password_auth_by_id(
                &audit.0,
                relay.id,
                req.username.as_deref(),
                password,
                &req.username_mode,
                req.password_required,
            )
            .await
            .map_err(ApiError::internal)?;
        }
        "ssh_key" => {
            let private_key = req
                .private_key
                .as_deref()
                .ok_or_else(|| ApiError::validation("Private key required"))?;
            server_core::set_custom_ssh_key_auth_by_id(
                &audit.0,
                relay.id,
                req.username.as_deref(),
                private_key,
                req.passphrase.as_deref(),
                &req.username_mode,
            )
            .await
            .map_err(ApiError::internal)?;
        }
        "agent" => {
            let public_key = req
                .public_key
                .as_deref()
                .ok_or_else(|| ApiError::validation("Public key required"))?;
            server_core::set_custom_agent_auth_by_id(&audit.0, relay.id, req.username.as_deref(), public_key, &req.username_mode)
                .await
                .map_err(ApiError::internal)?;
        }
        _ => return Err(ApiError::bad_request(format!("Invalid auth type: {}", req.auth_type))),
    }
    Ok(())
}

/// Clear all authentication settings from a relay
#[delete(
    "/api/relays/{id}/auth",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
pub async fn clear_relay_auth(id: i64) -> Result<(), ApiError> {
    ensure_relay_claim(&auth, ClaimLevel::Edit)?;

    let relay = server_core::fetch_relay_by_id(id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("relay host", id.to_string()))?;

    server_core::clear_all_auth_by_id(&audit.0, relay.id)
        .await
        .map_err(ApiError::internal)?;
    Ok(())
}
