#[cfg(feature = "server")]
use axum::Extension;
use dioxus::prelude::*;
use rb_types::access::{GrantAccessRequest, PrincipalKind, RelayAccessPrincipal};
#[cfg(feature = "server")]
use rb_types::auth::{ClaimLevel, ClaimType};

#[cfg(feature = "server")]
use crate::server::auth::guards::{WebAuthSession, ensure_claim};

#[get(
    "/api/relays/{relay_id}/access",
    auth: WebAuthSession,
    pool: Extension<sqlx::SqlitePool>
)]
pub async fn list_relay_access(relay_id: i64) -> Result<Vec<RelayAccessPrincipal>, ServerFnError> {
    ensure_claim(&auth, &ClaimType::Relays(ClaimLevel::View)).map_err(|e| ServerFnError::new(e.to_string()))?;
    use state_store::fetch_relay_access_principals;

    let principals = fetch_relay_access_principals(&*pool, relay_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(principals
        .into_iter()
        .map(|p| RelayAccessPrincipal {
            kind: p.kind,
            id: p.id,
            name: p.name,
        })
        .collect())
}

#[post(
    "/api/relays/{relay_id}/access",
    auth: WebAuthSession
)]
pub async fn grant_relay_access(relay_id: i64, req: GrantAccessRequest) -> Result<(), ServerFnError> {
    ensure_claim(&auth, &ClaimType::Relays(ClaimLevel::Edit)).map_err(|e| ServerFnError::new(e.to_string()))?;
    use state_store::grant_relay_access_principal;

    let Extension(pool): axum::Extension<sqlx::SqlitePool> =
        FullstackContext::extract().await.map_err(|e| ServerFnError::new(e.to_string()))?;

    // Parse kind
    let kind = req
        .principal_kind
        .parse::<PrincipalKind>()
        .map_err(|_| ServerFnError::new("Invalid principal kind"))?;
    let principal_id = req.principal_id;

    grant_relay_access_principal(&pool, relay_id, kind.as_str(), principal_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(())
}

#[delete(
    "/api/relays/{relay_id}/access/{kind}/{principal_id}",
    auth: WebAuthSession
)]
pub async fn revoke_relay_access(relay_id: i64, kind: PrincipalKind, principal_id: i64) -> Result<(), ServerFnError> {
    ensure_claim(&auth, &ClaimType::Relays(ClaimLevel::Edit)).map_err(|e| ServerFnError::new(e.to_string()))?;
    use state_store::revoke_relay_access_principal;

    let Extension(pool): axum::Extension<sqlx::SqlitePool> =
        FullstackContext::extract().await.map_err(|e| ServerFnError::new(e.to_string()))?;

    revoke_relay_access_principal(&pool, relay_id, &kind, principal_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(())
}
