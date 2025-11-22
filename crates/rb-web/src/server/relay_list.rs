use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RelayInfo {
    pub id: i64,
    pub name: String,
    pub ip: String,
    pub port: i64,
}

#[cfg(feature = "server")]
#[get("/api/relays/list")]
pub async fn list_user_relays() -> Result<Vec<RelayInfo>> {
    use anyhow::Context;
    use state_store::{list_relay_hosts, migrate_server, server_db};

    // TODO: Get actual username from session
    let username = "admin";

    let db = server_db().await.context("Failed to connect to database")?;
    migrate_server(&db).await.context("Failed to run migrations")?;
    let pool = db.into_pool();

    let relays = list_relay_hosts(&pool, Some(username)).await.context("Failed to list relays")?;

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

#[cfg(not(feature = "server"))]
#[get("/api/relays/list")]
pub async fn list_user_relays() -> Result<Vec<RelayInfo>> {
    unreachable!("Server function called on client")
}
