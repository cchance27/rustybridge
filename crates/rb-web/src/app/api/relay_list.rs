#[cfg(feature = "server")]
use anyhow::Context;
use dioxus::prelude::*;
use rb_types::relay::RelayInfo;

#[cfg(feature = "server")]
use crate::server::auth::guards::{WebAuthSession, ensure_authenticated};

#[get(
    "/api/relays/list",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn list_user_relays() -> Result<Vec<RelayInfo>> {
    // NOTE: We don't restrict this to relays:view claim because that claim
    // is to view ALL Relays for management not for connections.
    let user = ensure_authenticated(&auth)?;

    use state_store::list_relay_hosts;
    let relays = list_relay_hosts(&*pool, Some(user.id)).await.context("Failed to list relays")?;

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
