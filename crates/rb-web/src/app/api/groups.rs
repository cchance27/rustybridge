use dioxus::prelude::*;

use crate::app::models::GroupInfo;

#[get("/api/groups")]
pub async fn list_groups() -> Result<Vec<GroupInfo>, ServerFnError> {
    #[cfg(feature = "server")]
    {
        use server_core::{list_group_members_server, list_groups};
        use state_store::{fetch_relay_access_principals, list_relay_hosts};

        let db = state_store::server_db().await.map_err(|e| ServerFnError::new(e.to_string()))?;
        state_store::migrate_server(&db)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        let pool = db.into_pool();

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
                let principals = fetch_relay_access_principals(&pool, relay.id)
                    .await
                    .map_err(|e| ServerFnError::new(e.to_string()))?;

                if principals.iter().any(|p| p.kind == "group" && p.name == name) {
                    relay_count += 1;
                    relay_names.push(format!("{} ({}:{})", relay.name, relay.ip, relay.port));
                }
            }

            result.push(GroupInfo {
                name,
                member_count,
                relay_count,
                members,
                relays: relay_names,
            });
        }

        Ok(result)
    }
    #[cfg(not(feature = "server"))]
    Err(ServerFnError::new("Not implemented"))
}

#[post("/api/groups")]
pub async fn create_group(name: String) -> Result<(), ServerFnError> {
    #[cfg(feature = "server")]
    {
        use server_core::add_group;
        add_group(&name).await.map_err(|e| ServerFnError::new(e.to_string()))
    }
    #[cfg(not(feature = "server"))]
    Err(ServerFnError::new("Not implemented"))
}

#[delete("/api/groups/{name}")]
pub async fn delete_group(name: String) -> Result<(), ServerFnError> {
    #[cfg(feature = "server")]
    {
        use server_core::remove_group;
        remove_group(&name).await.map_err(|e| ServerFnError::new(e.to_string()))
    }
    #[cfg(not(feature = "server"))]
    Err(ServerFnError::new("Not implemented"))
}

#[get("/api/groups/{name}/members")]
pub async fn list_group_members(name: String) -> Result<Vec<String>, ServerFnError> {
    #[cfg(feature = "server")]
    {
        use server_core::list_group_members_server;
        list_group_members_server(&name)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))
    }
    #[cfg(not(feature = "server"))]
    Err(ServerFnError::new("Not implemented"))
}

#[post("/api/groups/{name}/members")]
pub async fn add_member_to_group(name: String, username: String) -> Result<(), ServerFnError> {
    #[cfg(feature = "server")]
    {
        use server_core::add_user_to_group_server;
        add_user_to_group_server(&username, &name)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))
    }
    #[cfg(not(feature = "server"))]
    Err(ServerFnError::new("Not implemented"))
}

#[delete("/api/groups/{name}/members/{username}")]
pub async fn remove_member_from_group(name: String, username: String) -> Result<(), ServerFnError> {
    #[cfg(feature = "server")]
    {
        use server_core::remove_user_from_group_server;
        remove_user_from_group_server(&username, &name)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))
    }
    #[cfg(not(feature = "server"))]
    Err(ServerFnError::new("Not implemented"))
}
