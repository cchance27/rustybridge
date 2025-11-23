use dioxus::prelude::*;
#[cfg(feature = "server")]
use rb_types::auth::{ClaimLevel, ClaimType};
use rb_types::web::{GrantAccessRequest, PrincipalKind, RelayAccessPrincipal};

#[cfg(feature = "server")]
use crate::server::auth::guards::{WebAuthSession, ensure_claim};

#[get(
    "/api/relays/{relay_id}/access",
    auth: WebAuthSession
)]
pub async fn list_relay_access(relay_id: i64) -> Result<Vec<RelayAccessPrincipal>, ServerFnError> {
    #[cfg(feature = "server")]
    {
        ensure_claim(&auth, &ClaimType::Relays(ClaimLevel::View)).map_err(|e| ServerFnError::new(e.to_string()))?;
        use rb_types::web::RelayAccessPrincipal;
        use state_store::fetch_relay_access_principals;

        let db = state_store::server_db().await.map_err(|e| ServerFnError::new(e.to_string()))?;
        state_store::migrate_server(&db)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        let pool = db.into_pool();

        let principals = fetch_relay_access_principals(&pool, relay_id)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;

        Ok(principals
            .into_iter()
            .map(|p| RelayAccessPrincipal {
                kind: p.kind,
                name: p.name,
            })
            .collect())
    }
    #[cfg(not(feature = "server"))]
    Err(ServerFnError::new("Not implemented"))
}

#[post(
    "/api/relays/{relay_id}/access",
    auth: WebAuthSession
)]
pub async fn grant_relay_access(relay_id: i64, req: GrantAccessRequest) -> Result<(), ServerFnError> {
    ensure_claim(&auth, &ClaimType::Relays(ClaimLevel::Edit)).map_err(|e| ServerFnError::new(e.to_string()))?;
    use state_store::grant_relay_access_principal;

    let db = state_store::server_db().await.map_err(|e| ServerFnError::new(e.to_string()))?;
    state_store::migrate_server(&db)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = db.into_pool();

    grant_relay_access_principal(&pool, relay_id, &req.principal_kind, &req.principal_name)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(())
}

#[delete(
    "/api/relays/{relay_id}/access/{kind}/{name}",
    auth: WebAuthSession
)]
pub async fn revoke_relay_access(relay_id: i64, kind: PrincipalKind, name: String) -> Result<(), ServerFnError> {
    ensure_claim(&auth, &ClaimType::Relays(ClaimLevel::Edit)).map_err(|e| ServerFnError::new(e.to_string()))?;
    use state_store::revoke_relay_access_principal;

    let db = state_store::server_db().await.map_err(|e| ServerFnError::new(e.to_string()))?;
    state_store::migrate_server(&db)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = db.into_pool();

    revoke_relay_access_principal(&pool, relay_id, &kind, &name)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(())
}
