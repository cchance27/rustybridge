use dioxus::prelude::*;
use rb_types::relay::RelayInfo;

use crate::error::ApiError;
#[cfg(feature = "server")]
use crate::server::auth::guards::{WebAuthSession, ensure_authenticated};

#[get(
    "/api/relays/list",
    auth: WebAuthSession,
)]
pub async fn list_user_relays() -> Result<Vec<RelayInfo>, ApiError> {
    // NOTE: We don't restrict this to relays:view claim because that claim
    // is to view ALL Relays for management not for connections.
    let user = ensure_authenticated(&auth)?;

    let mut relays = Vec::new();
    for r in server_core::api::list_relay_hosts_with_details().await? {
        if server_core::api::user_has_relay_access(user.id, r.id).await.unwrap_or(false) {
            relays.push(RelayInfo {
                id: r.id,
                name: r.name,
                ip: r.ip,
                port: r.port,
            });
        }
    }

    Ok(relays)
}
