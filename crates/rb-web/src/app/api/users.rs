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
    use server_core::{list_user_groups_server, list_users as list_users_core};
    use state_store::{fetch_relay_access_principals, get_user_direct_claims, list_relay_hosts};

    let usernames = list_users_core().await.map_err(|e| ServerFnError::new(e.to_string()))?;

    // Get all relays
    let all_relays = list_relay_hosts(&pool, None).await.map_err(|e| ServerFnError::new(e.to_string()))?;

    let mut result = Vec::new();
    for username in usernames {
        use rb_types::{access::UserRelayAccess, users::UserGroupInfo};

        let groups = list_user_groups_server(&username)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;

        // Build relay access list for this user
        let mut relay_access_map: HashMap<i64, UserRelayAccess> = HashMap::new();

        for relay in &all_relays {
            use rb_types::access::PrincipalKind;

            let principals = fetch_relay_access_principals(&pool, relay.id)
                .await
                .map_err(|e| ServerFnError::new(e.to_string()))?;

            let has_direct = principals.iter().any(|p| p.kind == PrincipalKind::User && p.name == username);
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
        let claims_core = get_user_direct_claims(&pool, &username)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;

        let claims = claims_core
            .into_iter()
            .map(|c| c.to_string().parse().unwrap_or(ClaimType::Custom(c.to_string())))
            .collect();

        // Get user ID
        let user_id = state_store::get_user_id(&pool, &username)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?
            .ok_or_else(|| ServerFnError::new(format!("User {} not found", username)))?;

        // Get SSH key count
        let ssh_keys = state_store::list_user_public_keys(&pool, &username)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        let ssh_key_count = ssh_keys.len() as i64;

        // Get user roles
        let roles = server_core::list_user_roles_server(&username)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;

        result.push(UserGroupInfo {
            id: user_id,
            username,
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
    "/api/users/{username}",
    auth: WebAuthSession
)]
pub async fn delete_user(username: String) -> Result<(), ServerFnError> {
    ensure_user_claim(&auth, ClaimLevel::Delete)?;
    use server_core::remove_user;
    remove_user(&username).await.map_err(|e| ServerFnError::new(e.to_string()))
}

#[put(
    "/api/users/{username}",
    auth: WebAuthSession
)]
pub async fn update_user(username: String, req: UpdateUserRequest) -> Result<(), ServerFnError> {
    ensure_user_claim(&auth, ClaimLevel::Edit)?;
    use server_core::update_user;
    update_user(&username, req.password.as_deref())
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[get(
    "/api/users/{username}/claims",
    auth: WebAuthSession
)]
pub async fn get_user_claims(username: String) -> Result<Vec<ClaimType>, ServerFnError> {
    ensure_user_claim(&auth, ClaimLevel::View)?;
    use server_core::get_user_direct_claims_server;
    get_user_direct_claims_server(&username)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[post(
    "/api/users/{username}/claims",
    auth: WebAuthSession
)]
pub async fn add_user_claim(username: String, claim: ClaimType) -> Result<(), ServerFnError> {
    ensure_user_claim(&auth, ClaimLevel::Edit)?;
    use server_core::add_user_claim;
    add_user_claim(&username, &claim)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Remove a claim from a user
/// NOTE: Uses POST instead of DELETE because ClaimType contains colons (e.g. "relays:view")
/// which cause routing issues when used as path parameters in DELETE requests
#[post(
    "/api/users/{username}/claims/remove",
    auth: WebAuthSession
)]
pub async fn remove_user_claim(username: String, claim: ClaimType) -> Result<(), ServerFnError> {
    ensure_user_claim(&auth, ClaimLevel::Edit)?;
    use server_core::remove_user_claim;
    remove_user_claim(&username, &claim)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}
