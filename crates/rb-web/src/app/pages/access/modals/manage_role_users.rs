use dioxus::prelude::*;

use crate::{
    app::api::{roles::*, users::list_users}, components::{Modal, use_toast}
};

/// Role Users Management Modal
#[component]
pub fn ManageRoleUsersModal(
    users_modal_open: Signal<bool>,
    role_id: Signal<i64>,
    users_role_name: Signal<String>,
    role_users: Signal<Vec<String>>,
    available_users: Signal<Vec<String>>,
    selected_user_to_add: Signal<String>,
    roles: Resource<Result<Vec<rb_types::users::RoleInfo>, ServerFnError>>,
    users: Resource<Result<Vec<rb_types::users::UserGroupInfo>, ServerFnError>>,
) -> Element {
    let toast = use_toast();
    let add_user_handler = move |_| {
        let role_name = users_role_name();
        let username = selected_user_to_add();
        let role_id_val = role_id();

        if username.is_empty() {
            return;
        }

        spawn(async move {
            // Find user ID from username
            if let Some(Ok(all_users)) = users.value()().as_ref()
                && let Some(user) = all_users.iter().find(|u| u.username == username)
            {
                match assign_role_to_user(role_id_val, user.id).await {
                    Ok(_) => {
                        // Reload role users
                        if let Ok(role_user_list) = list_role_users(role_id_val).await {
                            role_users.set(role_user_list.clone());

                            // Update available users
                            if let Ok(all_users_data) = list_users().await {
                                let available: Vec<String> = all_users_data
                                    .into_iter()
                                    .map(|u| u.username)
                                    .filter(|u| !role_user_list.contains(u))
                                    .collect();
                                available_users.set(available);
                            }
                        }
                        selected_user_to_add.set(String::new());
                        toast.success(&format!("Added user '{}' to role '{}'", username, role_name));
                        roles.restart();
                        users.restart();
                    }
                    Err(e) => {
                        toast.error(&format!("Failed to add user to role: {}", e));
                    }
                }
            }
        });
    };

    let remove_user_handler = move |username: String| {
        let role_name = users_role_name();
        let role_id_val = role_id();

        spawn(async move {
            // Find user ID from username
            if let Some(Ok(all_users)) = users.value()().as_ref()
                && let Some(user) = all_users.iter().find(|u| u.username == username)
            {
                match revoke_role_from_user(role_id_val, user.id).await {
                    Ok(_) => {
                        // Reload role users
                        if let Ok(role_user_list) = list_role_users(role_id_val).await {
                            role_users.set(role_user_list.clone());

                            // Update available users
                            if let Ok(all_users_data) = list_users().await {
                                let available: Vec<String> = all_users_data
                                    .into_iter()
                                    .map(|u| u.username)
                                    .filter(|u| !role_user_list.contains(u))
                                    .collect();
                                available_users.set(available);
                            }
                        }
                        toast.success(&format!("Removed user '{}' from role '{}'", username, role_name));
                        roles.restart();
                        users.restart();
                    }
                    Err(e) => {
                        toast.error(&format!("Failed to remove user from role: {}", e));
                    }
                }
            }
        });
    };

    rsx! {
        Modal {
            open: users_modal_open(),
            on_close: move |_| {
                users_modal_open.set(false);
                role_users.set(Vec::new());
                available_users.set(Vec::new());
                selected_user_to_add.set(String::new());
            },
            title: "Manage Role Users: {users_role_name}",
            div { class: "flex flex-col gap-4",
                // Current users
                div {
                    h4 { class: "font-semibold mb-2", "Current Users" }
                    if role_users().is_empty() {
                        p { class: "text-gray-500 italic", "No users assigned" }
                    } else {
                        div { class: "flex flex-wrap gap-2",
                            for user in role_users() {
                                div { class: "badge badge-lg badge-primary gap-2",
                                    span { "{user}" }
                                    button {
                                        class: "btn btn-xs btn-circle btn-ghost",
                                        onclick: {
                                            let u = user.clone();
                                            move |_| remove_user_handler(u.clone())
                                        },
                                        "×"
                                    }
                                }
                            }
                        }
                    }
                }

                div { class: "divider" }

                // Add user
                div {
                    h4 { class: "font-semibold mb-2", "Add User" }
                    if available_users().is_empty() {
                        p { class: "text-gray-500 italic", "All users are already assigned" }
                    } else {
                        div { class: "flex gap-2",
                            select {
                                class: "select select-bordered flex-1",
                                value: "{selected_user_to_add}",
                                onchange: move |e| selected_user_to_add.set(e.value()),
                                option { value: "", "Select a user..." }
                                for user in available_users() {
                                    option { value: "{user}", "{user}" }
                                }
                            }
                            button {
                                class: "btn btn-primary",
                                disabled: selected_user_to_add().is_empty(),
                                onclick: add_user_handler,
                                "Add"
                            }
                        }
                    }
                }
            }
        }
    }
}
