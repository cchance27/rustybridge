use dioxus::prelude::*;
#[cfg(feature = "server")]
use rb_types::auth::ClaimLevel;
use rb_types::{auth::ClaimType, web::GroupInfo};

#[cfg(feature = "server")]
use crate::server::auth::guards::{WebAuthSession, ensure_claim};

#[cfg(feature = "server")]
fn ensure_group_claim(auth: &WebAuthSession, level: ClaimLevel) -> Result<(), ServerFnError> {
    ensure_claim(auth, &ClaimType::Groups(level)).map_err(|e| ServerFnError::new(e.to_string()))
}

#[get(
    "/api/groups",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn list_groups() -> Result<Vec<GroupInfo>, ServerFnError> {
    ensure_group_claim(&auth, ClaimLevel::View)?;
    use server_core::{get_group_claims_server, list_group_members_server, list_groups};
    use state_store::{fetch_relay_access_principals, list_relay_hosts};

    let group_names = list_groups().await.map_err(|e| ServerFnError::new(e.to_string()))?;

    let mut result = Vec::new();
    for name in group_names {
        // Get member count and names
        let members = list_group_members_server(&name)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        let member_count = members.len() as i64;

        // Get relay count and names - count how many relays this group has access to
        let all_relays = list_relay_hosts(&pool, None).await.map_err(|e| ServerFnError::new(e.to_string()))?;

        let mut relay_count = 0i64;
        let mut relay_names = Vec::new();
        for relay in all_relays {
            use rb_types::web::PrincipalKind;

            let principals = fetch_relay_access_principals(&pool, relay.id)
                .await
                .map_err(|e| ServerFnError::new(e.to_string()))?;

            if principals.iter().any(|p| p.kind == PrincipalKind::Group && p.name == name) {
                relay_count += 1;
                relay_names.push(format!("{} ({}:{})", relay.name, relay.ip, relay.port));
            }
        }

        let claims_core = get_group_claims_server(&name)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;

        let claims = claims_core
            .into_iter()
            .map(|c| c.to_string().parse().unwrap_or(ClaimType::Custom(c.to_string())))
            .collect();

        result.push(GroupInfo {
            name,
            member_count,
            relay_count,
            members,
            relays: relay_names,
            claims,
        });
    }

    Ok(result)
}

#[post(
    "/api/groups",
    auth: WebAuthSession
)]
pub async fn create_group(name: String) -> Result<(), ServerFnError> {
    ensure_group_claim(&auth, ClaimLevel::Create)?;
    use server_core::add_group;
    add_group(&name).await.map_err(|e| ServerFnError::new(e.to_string()))
}

#[delete(
    "/api/groups/{name}",
    auth: WebAuthSession
)]
pub async fn delete_group(name: String) -> Result<(), ServerFnError> {
    ensure_group_claim(&auth, ClaimLevel::Delete)?;
    use server_core::remove_group;
    remove_group(&name).await.map_err(|e| ServerFnError::new(e.to_string()))
}

#[get(
    "/api/groups/{name}/members",
    auth: WebAuthSession
)]
pub async fn list_group_members(name: String) -> Result<Vec<String>, ServerFnError> {
    ensure_group_claim(&auth, ClaimLevel::View)?;
    use server_core::list_group_members_server;
    list_group_members_server(&name)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[post(
    "/api/groups/{name}/members",
    auth: WebAuthSession
)]
pub async fn add_member_to_group(name: String, username: String) -> Result<(), ServerFnError> {
    ensure_group_claim(&auth, ClaimLevel::Edit)?;
    use server_core::add_user_to_group_server;
    add_user_to_group_server(&username, &name)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[delete(
    "/api/groups/{name}/members/{username}",
    auth: WebAuthSession
)]
pub async fn remove_member_from_group(name: String, username: String) -> Result<(), ServerFnError> {
    ensure_group_claim(&auth, ClaimLevel::Delete)?;
    use server_core::remove_user_from_group_server;
    remove_user_from_group_server(&username, &name)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[post(
    "/api/groups/{name}/claims",
    auth: WebAuthSession
)]
pub async fn add_group_claim(name: String, claim: ClaimType) -> Result<(), ServerFnError> {
    ensure_group_claim(&auth, ClaimLevel::Edit)?;
    use server_core::add_group_claim;
    add_group_claim(&name, &claim).await.map_err(|e| ServerFnError::new(e.to_string()))
}

#[delete(
    "/api/groups/{name}/claims/{claim}",
    auth: WebAuthSession
)]
pub async fn remove_group_claim(name: String, claim: ClaimType) -> Result<(), ServerFnError> {
    ensure_group_claim(&auth, ClaimLevel::Delete)?;
    use server_core::remove_group_claim;
    remove_group_claim(&name, &claim)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}
