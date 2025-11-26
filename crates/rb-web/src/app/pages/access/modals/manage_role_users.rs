use dioxus::prelude::*;

use crate::{
    app::api::{roles::*, users::list_users}, components::{Modal, ToastMessage, ToastType}
};

/// Role Users Management Modal
#[component]
pub fn ManageRoleUsersModal(
    users_modal_open: Signal<bool>,
    users_role_name: Signal<String>,
    role_users: Signal<Vec<String>>,
    available_users: Signal<Vec<String>>,
    selected_user_to_add: Signal<String>,
    roles: Resource<Result<Vec<rb_types::users::RoleInfo>, ServerFnError>>,
    users: Resource<Result<Vec<rb_types::users::UserGroupInfo>, ServerFnError>>,
    toast: Signal<Option<ToastMessage>>,
) -> Element {
    let add_user_handler = move |_| {
        let role = users_role_name();
        let user = selected_user_to_add();

        if user.is_empty() {
            return;
        }

        spawn(async move {
            match assign_role_to_user(role.clone(), user.clone()).await {
                Ok(_) => {
                    // Reload role users
                    if let Ok(role_user_list) = list_role_users(role.clone()).await {
                        role_users.set(role_user_list.clone());

                        // Update available users
                        if let Ok(all_users) = list_users().await {
                            let available: Vec<String> = all_users
                                .into_iter()
                                .map(|u| u.username)
                                .filter(|u| !role_user_list.contains(u))
                                .collect();
                            available_users.set(available);
                        }
                    }
                    selected_user_to_add.set(String::new());
                    toast.set(Some(ToastMessage {
                        message: format!("Added user '{}' to role '{}'", user, role),
                        toast_type: ToastType::Success,
                    }));
                    roles.restart();
                    users.restart();
                }
                Err(e) => {
                    toast.set(Some(ToastMessage {
                        message: format!("Failed to add user to role: {}", e),
                        toast_type: ToastType::Error,
                    }));
                }
            }
        });
    };

    let remove_user_handler = move |user: String| {
        let role = users_role_name();

        spawn(async move {
            match revoke_role_from_user(role.clone(), user.clone()).await {
                Ok(_) => {
                    // Reload role users
                    if let Ok(role_user_list) = list_role_users(role.clone()).await {
                        role_users.set(role_user_list.clone());

                        // Update available users
                        if let Ok(all_users) = list_users().await {
                            let available: Vec<String> = all_users
                                .into_iter()
                                .map(|u| u.username)
                                .filter(|u| !role_user_list.contains(u))
                                .collect();
                            available_users.set(available);
                        }
                    }
                    toast.set(Some(ToastMessage {
                        message: format!("Removed user '{}' from role '{}'", user, role),
                        toast_type: ToastType::Success,
                    }));
                    roles.restart();
                    users.restart();
                }
                Err(e) => {
                    toast.set(Some(ToastMessage {
                        message: format!("Failed to remove user from role: {}", e),
                        toast_type: ToastType::Error,
                    }));
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
