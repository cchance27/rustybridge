#[cfg(feature = "server")]
use anyhow::Context;
use dioxus::prelude::*;
use rb_types::RelayInfo;
#[cfg(feature = "server")]
use rb_types::auth::{ClaimLevel, ClaimType};

#[cfg(feature = "server")]
use crate::server::auth::guards::{WebAuthSession, ensure_authenticated, ensure_claim};

#[get(
    "/api/relays/list",
    auth: WebAuthSession
)]
pub async fn list_user_relays() -> Result<Vec<RelayInfo>> {
    ensure_claim(&auth, &ClaimType::Relays(ClaimLevel::View))?;
    let user = ensure_authenticated(&auth)?;
    let username = user.username;

    use state_store::{list_relay_hosts, server_db};

    let db = server_db().await.context("Failed to connect to database")?;
    let pool = db.into_pool();

    let relays = list_relay_hosts(&pool, Some(&username)).await.context("Failed to list relays")?;

    Ok(relays
        .into_iter()
        .map(|r| RelayInfo {
            id: r.id,
            name: r.name,
            ip: r.ip,
            port: r.port,
        })
        .collect())
}
