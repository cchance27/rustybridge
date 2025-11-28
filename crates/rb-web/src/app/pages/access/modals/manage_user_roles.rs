use dioxus::prelude::*;

use crate::{
    app::api::roles::*, components::{Modal, ToastMessage, ToastType}
};

/// User Roles Management Modal
#[component]
pub fn ManageUserRolesModal(
    roles_modal_open: Signal<bool>,
    user_id: Signal<i64>,
    username: Signal<String>,
    user_roles: Signal<Vec<String>>,
    available_roles: Signal<Vec<String>>,
    selected_role_to_add: Signal<String>,
    roles: Resource<Result<Vec<rb_types::users::RoleInfo>, ServerFnError>>,
    users: Resource<Result<Vec<rb_types::users::UserGroupInfo>, ServerFnError>>,
    toast: Signal<Option<ToastMessage>>,
) -> Element {
    let add_role_handler = move |_| {
        let user_name = username();
        let role_name = selected_role_to_add();
        let user_id_val = user_id();

        if role_name.is_empty() {
            return;
        }

        spawn(async move {
            // Find role ID from role name
            if let Some(Ok(all_roles)) = roles.value()().as_ref()
                && let Some(role) = all_roles.iter().find(|r| r.name == role_name)
            {
                match assign_role_to_user(role.id, user_id_val).await {
                    Ok(_) => {
                        // Update local state
                        let mut current_roles = user_roles();
                        current_roles.push(role_name.clone());
                        user_roles.set(current_roles.clone());

                        // Update available roles
                        let mut available = available_roles();
                        available.retain(|r| r != &role_name);
                        available_roles.set(available);

                        selected_role_to_add.set(String::new());

                        toast.set(Some(ToastMessage {
                            message: format!("Assigned role '{}' to user '{}'", role_name, user_name),
                            toast_type: ToastType::Success,
                        }));

                        // Refresh resources
                        roles.restart();
                        users.restart();
                    }
                    Err(e) => {
                        toast.set(Some(ToastMessage {
                            message: format!("Failed to assign role: {}", e),
                            toast_type: ToastType::Error,
                        }));
                    }
                }
            }
        });
    };

    let remove_role_handler = move |role_name: String| {
        let user_name = username();
        let user_id_val = user_id();

        spawn(async move {
            // Find role ID from role name
            if let Some(Ok(all_roles)) = roles.value()().as_ref()
                && let Some(role) = all_roles.iter().find(|r| r.name == role_name)
            {
                match revoke_role_from_user(role.id, user_id_val).await {
                    Ok(_) => {
                        // Update local state
                        let mut current_roles = user_roles();
                        current_roles.retain(|r| r != &role_name);
                        user_roles.set(current_roles.clone());

                        // Update available roles
                        if let Some(Ok(all_roles)) = roles.value()().as_ref() {
                            let available: Vec<String> = all_roles
                                .iter()
                                .map(|r| r.name.clone())
                                .filter(|r| !current_roles.contains(r))
                                .collect();
                            available_roles.set(available);
                        }

                        toast.set(Some(ToastMessage {
                            message: format!("Removed role '{}' from user '{}'", role_name, user_name),
                            toast_type: ToastType::Success,
                        }));

                        roles.restart();
                        users.restart();
                    }
                    Err(e) => {
                        toast.set(Some(ToastMessage {
                            message: format!("Failed to remove role: {}", e),
                            toast_type: ToastType::Error,
                        }));
                    }
                }
            }
        });
    };

    rsx! {
        Modal {
            open: roles_modal_open(),
            on_close: move |_| {
                roles_modal_open.set(false);
                user_roles.set(Vec::new());
                available_roles.set(Vec::new());
                selected_role_to_add.set(String::new());
            },
            title: "Manage User Roles: {username}",
            div { class: "flex flex-col gap-4",
                // Current roles
                div {
                    h4 { class: "font-semibold mb-2", "Assigned Roles" }
                    if user_roles().is_empty() {
                        p { class: "text-gray-500 italic", "No roles assigned" }
                    } else {
                        div { class: "flex flex-wrap gap-2",
                            for role in user_roles() {
                                div { class: "badge badge-lg badge-secondary gap-2",
                                    span { "{role}" }
                                    button {
                                        class: "btn btn-xs btn-circle btn-ghost",
                                        onclick: {
                                            let r = role.clone();
                                            move |_| remove_role_handler(r.clone())
                                        },
                                        "×"
                                    }
                                }
                            }
                        }
                    }
                }

                div { class: "divider" }

                // Add role
                div {
                    h4 { class: "font-semibold mb-2", "Assign Role" }
                    if available_roles().is_empty() {
                        p { class: "text-gray-500 italic", "All available roles are already assigned" }
                    } else {
                        div { class: "flex gap-2",
                            select {
                                class: "select select-bordered flex-1",
                                value: "{selected_role_to_add}",
                                onchange: move |e| selected_role_to_add.set(e.value()),
                                option { value: "", "Select a role..." }
                                for role in available_roles() {
                                    option { value: "{role}", "{role}" }
                                }
                            }
                            button {
                                class: "btn btn-secondary",
                                disabled: selected_role_to_add().is_empty(),
                                onclick: add_role_handler,
                                "Assign"
                            }
                        }
                    }
                }
            }
        }
    }
}
