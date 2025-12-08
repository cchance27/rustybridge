use dioxus::prelude::*;
use rb_types::access::{GrantAccessRequest, PrincipalKind, RelayAccessPrincipal};
#[cfg(feature = "server")]
use rb_types::auth::{ClaimLevel, ClaimType};

#[cfg(feature = "server")]
use crate::server::audit::WebAuditContext;
#[cfg(feature = "server")]
use crate::server::auth::guards::{WebAuthSession, ensure_claim};

#[get(
    "/api/relays/{relay_id}/access",
    auth: WebAuthSession
)]
pub async fn list_relay_access(relay_id: i64) -> Result<Vec<RelayAccessPrincipal>, ServerFnError> {
    ensure_claim(&auth, &ClaimType::Relays(ClaimLevel::View)).map_err(|e| ServerFnError::new(e.to_string()))?;
    server_core::list_access_by_id(relay_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[post(
    "/api/relays/{relay_id}/access",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
pub async fn grant_relay_access(relay_id: i64, req: GrantAccessRequest) -> Result<(), ServerFnError> {
    ensure_claim(&auth, &ClaimType::Relays(ClaimLevel::Edit)).map_err(|e| ServerFnError::new(e.to_string()))?;
    // Parse kind
    let kind = req
        .principal_kind
        .parse::<PrincipalKind>()
        .map_err(|_| ServerFnError::new("Invalid principal kind"))?;
    let principal_id = req.principal_id;

    server_core::grant_relay_access_by_id(&audit.0, relay_id, kind, principal_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(())
}

#[delete(
    "/api/relays/{relay_id}/access/{kind}/{principal_id}",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
pub async fn revoke_relay_access(relay_id: i64, kind: PrincipalKind, principal_id: i64) -> Result<(), ServerFnError> {
    ensure_claim(&auth, &ClaimType::Relays(ClaimLevel::Edit)).map_err(|e| ServerFnError::new(e.to_string()))?;
    server_core::revoke_relay_access_by_id(&audit.0, relay_id, kind, principal_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(())
}
