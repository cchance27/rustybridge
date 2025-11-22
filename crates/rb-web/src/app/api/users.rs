use dioxus::prelude::*;

use crate::app::models::{CreateUserRequest, UserGroupInfo};

#[get("/api/users")]
pub async fn list_users() -> Result<Vec<UserGroupInfo>, ServerFnError> {
    #[cfg(feature = "server")]
    {
        use std::collections::HashMap;

        use server_core::{list_user_groups_server, list_users as list_users_core};
        use state_store::{fetch_relay_access_principals, list_relay_hosts};

        use crate::app::models::{RelayAccessSource, UserRelayAccess};

        let db = state_store::server_db().await.map_err(|e| ServerFnError::new(e.to_string()))?;
        state_store::migrate_server(&db)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        let pool = db.into_pool();

        let usernames = list_users_core().await.map_err(|e| ServerFnError::new(e.to_string()))?;

        // Get all relays
        let all_relays = list_relay_hosts(&pool, None).await.map_err(|e| ServerFnError::new(e.to_string()))?;

        let mut result = Vec::new();
        for username in usernames {
            let groups = list_user_groups_server(&username)
                .await
                .map_err(|e| ServerFnError::new(e.to_string()))?;

            // Build relay access list for this user
            let mut relay_access_map: HashMap<i64, UserRelayAccess> = HashMap::new();

            for relay in &all_relays {
                let principals = fetch_relay_access_principals(&pool, relay.id)
                    .await
                    .map_err(|e| ServerFnError::new(e.to_string()))?;

                let has_direct = principals.iter().any(|p| p.kind == "user" && p.name == username);
                let group_access: Vec<String> = principals
                    .iter()
                    .filter(|p| p.kind == "group" && groups.contains(&p.name))
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

            result.push(UserGroupInfo { username, groups, relays });
        }

        Ok(result)
    }
    #[cfg(not(feature = "server"))]
    Err(ServerFnError::new("Not implemented"))
}

#[post("/api/users")]
pub async fn create_user(req: CreateUserRequest) -> Result<(), ServerFnError> {
    #[cfg(feature = "server")]
    {
        use server_core::add_user;
        add_user(&req.username, &req.password)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))
    }
    #[cfg(not(feature = "server"))]
    Err(ServerFnError::new("Not implemented"))
}

#[delete("/api/users/{username}")]
pub async fn delete_user(username: String) -> Result<(), ServerFnError> {
    #[cfg(feature = "server")]
    {
        use server_core::remove_user;
        remove_user(&username).await.map_err(|e| ServerFnError::new(e.to_string()))
    }
    #[cfg(not(feature = "server"))]
    Err(ServerFnError::new("Not implemented"))
}

#[put("/api/users/{username}")]
pub async fn update_user(username: String, req: crate::app::models::UpdateUserRequest) -> Result<(), ServerFnError> {
    #[cfg(feature = "server")]
    {
        use server_core::update_user;
        update_user(&username, req.password.as_deref())
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))
    }
    #[cfg(not(feature = "server"))]
    Err(ServerFnError::new("Not implemented"))
}
