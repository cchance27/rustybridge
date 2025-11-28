use dioxus::prelude::*;
#[cfg(feature = "server")]
use rb_types::auth::ClaimLevel;
use rb_types::{auth::ClaimType, users::GroupInfo};

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
        let all_relays = list_relay_hosts(&*pool, None)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;

        let mut relay_count = 0i64;
        let mut relay_names = Vec::new();
        for relay in all_relays {
            use rb_types::access::PrincipalKind;

            let principals = fetch_relay_access_principals(&*pool, relay.id)
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

        // Get group roles
        let roles = server_core::list_group_roles_server(&name)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;

        // Get group ID
        let group_id = state_store::fetch_group_id_by_name(&*pool, &name)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?
            .ok_or_else(|| ServerFnError::new(format!("Group {} not found", name)))?;

        result.push(GroupInfo {
            id: group_id,
            name,
            member_count,
            relay_count,
            members,
            relays: relay_names,
            claims,
            roles,
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

#[put(
    "/api/groups/{id}",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn update_group(id: i64, name: String) -> Result<(), ServerFnError> {
    ensure_group_claim(&auth, ClaimLevel::Edit)?;

    // Check if name already taken
    if state_store::fetch_group_id_by_name(&*pool, &name)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .is_some()
    {
        return Err(ServerFnError::new(format!("Group '{}' already exists", name)));
    }

    state_store::update_group_name(&*pool, id, &name)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[delete(
    "/api/groups/{id}",
    auth: WebAuthSession
)]
pub async fn delete_group(id: i64) -> Result<(), ServerFnError> {
    ensure_group_claim(&auth, ClaimLevel::Delete)?;
    use server_core::remove_group_by_id;
    remove_group_by_id(id).await.map_err(|e| ServerFnError::new(e.to_string()))
}

#[get(
    "/api/groups/{id}/members",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn list_group_members(id: i64) -> Result<Vec<String>, ServerFnError> {
    ensure_group_claim(&auth, ClaimLevel::View)?;
    use state_store::list_group_members_by_id;
    list_group_members_by_id(&*pool, id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[post(
    "/api/groups/{id}/members",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn add_member_to_group(id: i64, user_id: i64) -> Result<(), ServerFnError> {
    ensure_group_claim(&auth, ClaimLevel::Edit)?;
    state_store::add_user_to_group_by_ids(&*pool, user_id, id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[delete(
    "/api/groups/{id}/members/{user_id}",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn remove_member_from_group(id: i64, user_id: i64) -> Result<(), ServerFnError> {
    ensure_group_claim(&auth, ClaimLevel::Delete)?;
    state_store::remove_user_from_group_by_ids(&*pool, user_id, id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[get(
    "/api/groups/{id}/claims",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn get_group_claims(id: i64) -> Result<Vec<ClaimType>, ServerFnError> {
    ensure_group_claim(&auth, ClaimLevel::View)?;
    use state_store::get_group_claims_by_id;
    get_group_claims_by_id(&*pool, id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[post(
    "/api/groups/{id}/claims",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn add_group_claim(id: i64, claim: ClaimType) -> Result<(), ServerFnError> {
    ensure_group_claim(&auth, ClaimLevel::Edit)?;
    use state_store::add_claim_to_group_by_id;
    add_claim_to_group_by_id(&*pool, id, &claim)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Remove a claim from a group
/// Now uses proper DELETE method with group ID (no colon encoding issues)
#[delete(
    "/api/groups/{id}/claims",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn remove_group_claim(id: i64, claim: ClaimType) -> Result<(), ServerFnError> {
    ensure_group_claim(&auth, ClaimLevel::Delete)?;
    use state_store::remove_claim_from_group_by_id;
    remove_claim_from_group_by_id(&*pool, id, &claim)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}
