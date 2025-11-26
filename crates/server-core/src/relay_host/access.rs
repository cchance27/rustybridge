use rb_types::access::{PrincipalKind, RelayAccessPrincipal};
use tracing::info;

use crate::error::{ServerError, ServerResult};

pub async fn grant_relay_access(name: &str, principal_kind: PrincipalKind, principal_name: &str) -> ServerResult<()> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_name(&pool, name)
        .await?
        .ok_or_else(|| ServerError::not_found("relay host", name))?;
    state_store::grant_relay_access_principal(&pool, host.id, principal_kind.as_str(), principal_name).await?;
    info!(
        relay_host = name,
        principal_kind = principal_kind.as_str(),
        principal = principal_name,
        "granted access to relay host"
    );
    Ok(())
}

pub async fn revoke_relay_access(name: &str, principal_kind: PrincipalKind, principal_name: &str) -> ServerResult<()> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_name(&pool, name)
        .await?
        .ok_or_else(|| ServerError::not_found("relay host", name))?;
    state_store::revoke_relay_access_principal(&pool, host.id, &principal_kind, principal_name).await?;

    info!(
        relay_host = name,
        principal_kind = principal_kind.as_str(),
        principal = principal_name,
        "revoked access to relay host"
    );
    Ok(())
}

pub async fn list_access(name: &str) -> ServerResult<Vec<RelayAccessPrincipal>> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_name(&pool, name)
        .await?
        .ok_or_else(|| ServerError::not_found("relay host", name))?;
    let principals = state_store::fetch_relay_access_principals(&pool, host.id).await?;
    Ok(principals
        .into_iter()
        .map(|p| RelayAccessPrincipal {
            kind: p.kind,
            name: p.name,
        })
        .collect())
}
