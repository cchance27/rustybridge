use rb_types::access::{PrincipalKind, RelayAccessPrincipal};
use tracing::info;

use crate::error::ServerResult;

pub async fn grant_relay_access_by_id(host_id: i64, principal_kind: PrincipalKind, principal_id: i64) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    state_store::grant_relay_access_principal(&pool, host_id, principal_kind.as_str(), principal_id).await?;
    info!(
        relay_host_id = host_id,
        principal_kind = principal_kind.as_str(),
        principal_id,
        "granted access to relay host"
    );
    Ok(())
}

pub async fn revoke_relay_access_by_id(host_id: i64, principal_kind: PrincipalKind, principal_id: i64) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    state_store::revoke_relay_access_principal(&pool, host_id, &principal_kind, principal_id).await?;
    info!(
        relay_host_id = host_id,
        principal_kind = principal_kind.as_str(),
        principal_id,
        "revoked access to relay host"
    );
    Ok(())
}

pub async fn list_access_by_id(host_id: i64) -> ServerResult<Vec<RelayAccessPrincipal>> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();
    let principals = state_store::fetch_relay_access_principals(&pool, host_id).await?;
    Ok(principals
        .into_iter()
        .map(|p| RelayAccessPrincipal {
            kind: p.kind,
            id: p.id,
            name: p.name,
        })
        .collect())
}
