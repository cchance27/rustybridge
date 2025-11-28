use dioxus::prelude::*;
#[cfg(feature = "server")]
use rb_types::auth::ClaimLevel;
use rb_types::{
    auth::ClaimType, users::{CreateUserRequest, UpdateUserRequest, UserGroupInfo}
};

#[cfg(feature = "server")]
use crate::server::auth::guards::{WebAuthSession, ensure_claim};

#[cfg(feature = "server")]
fn ensure_user_claim(auth: &WebAuthSession, level: ClaimLevel) -> Result<(), ServerFnError> {
    ensure_claim(auth, &ClaimType::Users(level)).map_err(|e| ServerFnError::new(e.to_string()))
}

#[get(
    "/api/users",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn list_users() -> Result<Vec<UserGroupInfo>, ServerFnError> {
    ensure_user_claim(&auth, ClaimLevel::View)?;
    use std::collections::HashMap;

    use rb_types::access::RelayAccessSource;
    use server_core::list_user_groups_server;
    use state_store::{fetch_relay_access_principals, get_user_direct_claims_by_id, list_relay_hosts, list_usernames};

    let usernames = list_usernames(&*pool).await.map_err(|e| ServerFnError::new(e.to_string()))?;

    // Get all relays
    let all_relays = list_relay_hosts(&*pool, None)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let mut result = Vec::new();
    for username in &usernames {
        use rb_types::{access::UserRelayAccess, users::UserGroupInfo};

        let groups = list_user_groups_server(username)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;

        // Build relay access list for this user
        let mut relay_access_map: HashMap<i64, UserRelayAccess> = HashMap::new();

        for relay in &all_relays {
            use rb_types::access::PrincipalKind;

            let principals = fetch_relay_access_principals(&*pool, relay.id)
                .await
                .map_err(|e| ServerFnError::new(e.to_string()))?;

            let has_direct = principals.iter().any(|p| p.kind == PrincipalKind::User && &p.name == username);
            let group_access: Vec<String> = principals
                .iter()
                .filter(|p| p.kind == PrincipalKind::Group && groups.contains(&p.name))
                .map(|p| p.name.clone())
                .collect();

            let access_source = if has_direct && !group_access.is_empty() {
                Some(RelayAccessSource::Both(group_access.join(", ")))
            } else if has_direct {
                Some(RelayAccessSource::Direct)
            } else if !group_access.is_empty() {
                Some(RelayAccessSource::ViaGroup(group_access.join(", ")))
            } else {
                None
            };

            if let Some(source) = access_source {
                relay_access_map.insert(
                    relay.id,
                    UserRelayAccess {
                        relay_name: relay.name.clone(),
                        relay_endpoint: format!("{}:{}", relay.ip, relay.port),
                        access_source: source,
                    },
                );
            }
        }

        let relays: Vec<UserRelayAccess> = relay_access_map.into_values().collect();

        // Get user ID first (will be used for both claims and ssh keys)
        let user_id = state_store::fetch_user_id_by_name(&*pool, username)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?
            .ok_or_else(|| ServerFnError::new(format!("User {} not found", username)))?;

        let claims_core = get_user_direct_claims_by_id(&*pool, user_id)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;

        let claims = claims_core
            .into_iter()
            .map(|c| c.to_string().parse().unwrap_or(ClaimType::Custom(c.to_string())))
            .collect();

        // Get SSH key count
        let ssh_keys = state_store::list_user_public_keys_by_id(&*pool, user_id)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        let ssh_key_count = ssh_keys.len() as i64;

        // Get user roles
        let roles = server_core::list_user_roles_server(username)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;

        result.push(UserGroupInfo {
            id: user_id,
            username: username.clone(),
            groups,
            relays,
            claims,
            ssh_key_count,
            roles,
        });
    }

    Ok(result)
}

#[post(
    "/api/users",
    auth: WebAuthSession
)]
pub async fn create_user(req: CreateUserRequest) -> Result<(), ServerFnError> {
    ensure_user_claim(&auth, ClaimLevel::Create)?;
    use server_core::add_user;
    add_user(&req.username, &req.password)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[delete(
    "/api/users/{id}",
    auth: WebAuthSession
)]
pub async fn delete_user(id: i64) -> Result<(), ServerFnError> {
    ensure_user_claim(&auth, ClaimLevel::Delete)?;
    use server_core::remove_user_by_id;
    remove_user_by_id(id).await.map_err(|e| ServerFnError::new(e.to_string()))
}

#[put(
    "/api/users/{id}",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn update_user(id: i64, req: UpdateUserRequest) -> Result<(), ServerFnError> {
    ensure_user_claim(&auth, ClaimLevel::Edit)?;

    if let Some(password) = req.password {
        let hash = server_core::auth::hash_password(&password).map_err(|e| ServerFnError::new(e.to_string()))?;
        state_store::update_user_password_by_id(&*pool, id, &hash)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
    }

    Ok(())
}

#[get(
    "/api/users/{id}/claims",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn get_user_claims(id: i64) -> Result<Vec<ClaimType>, ServerFnError> {
    ensure_user_claim(&auth, ClaimLevel::View)?;
    use state_store::get_user_direct_claims_by_id;
    get_user_direct_claims_by_id(&*pool, id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[post(
    "/api/users/{id}/claims",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn add_user_claim(id: i64, claim: ClaimType) -> Result<(), ServerFnError> {
    ensure_user_claim(&auth, ClaimLevel::Edit)?;
    use state_store::add_claim_to_user_by_id;
    add_claim_to_user_by_id(&*pool, id, &claim)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Remove a claim from a user
/// Now uses proper DELETE method with user ID (no colon encoding issues)
#[delete(
    "/api/users/{id}/claims",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn remove_user_claim(id: i64, claim: ClaimType) -> Result<(), ServerFnError> {
    ensure_user_claim(&auth, ClaimLevel::Edit)?;
    use state_store::remove_claim_from_user_by_id;
    remove_claim_from_user_by_id(&*pool, id, &claim)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}
