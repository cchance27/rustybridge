use dioxus::prelude::*;

use crate::{
    app::api::{groups::list_groups, roles::*}, components::{Modal, ToastMessage, ToastType}
};

/// Role Groups Management Modal
#[component]
pub fn ManageRoleGroupsModal(
    groups_modal_open: Signal<bool>,
    groups_role_name: Signal<String>,
    role_groups: Signal<Vec<String>>,
    available_groups: Signal<Vec<String>>,
    selected_group_to_add: Signal<String>,
    roles: Resource<Result<Vec<rb_types::users::RoleInfo>, ServerFnError>>,
    groups: Resource<Result<Vec<rb_types::users::GroupInfo>, ServerFnError>>,
    toast: Signal<Option<ToastMessage>>,
) -> Element {
    let add_group_handler = move |_| {
        let role = groups_role_name();
        let group = selected_group_to_add();

        if group.is_empty() {
            return;
        }

        spawn(async move {
            match assign_role_to_group(role.clone(), group.clone()).await {
                Ok(_) => {
                    // Reload role groups
                    if let Ok(role_group_list) = list_role_groups(role.clone()).await {
                        role_groups.set(role_group_list.clone());

                        // Update available groups
                        if let Ok(all_groups) = list_groups().await {
                            let available: Vec<String> = all_groups
                                .into_iter()
                                .map(|g| g.name)
                                .filter(|g| !role_group_list.contains(g))
                                .collect();
                            available_groups.set(available);
                        }
                    }
                    selected_group_to_add.set(String::new());
                    toast.set(Some(ToastMessage {
                        message: format!("Added group '{}' to role '{}'", group, role),
                        toast_type: ToastType::Success,
                    }));
                    roles.restart();
                    groups.restart();
                }
                Err(e) => {
                    toast.set(Some(ToastMessage {
                        message: format!("Failed to add group to role: {}", e),
                        toast_type: ToastType::Error,
                    }));
                }
            }
        });
    };

    let remove_group_handler = move |group: String| {
        let role = groups_role_name();

        spawn(async move {
            match revoke_role_from_group(role.clone(), group.clone()).await {
                Ok(_) => {
                    // Reload role groups
                    if let Ok(role_group_list) = list_role_groups(role.clone()).await {
                        role_groups.set(role_group_list.clone());

                        // Update available groups
                        if let Ok(all_groups) = list_groups().await {
                            let available: Vec<String> = all_groups
                                .into_iter()
                                .map(|g| g.name)
                                .filter(|g| !role_group_list.contains(g))
                                .collect();
                            available_groups.set(available);
                        }
                    }
                    toast.set(Some(ToastMessage {
                        message: format!("Removed group '{}' from role '{}'", group, role),
                        toast_type: ToastType::Success,
                    }));
                    roles.restart();
                    groups.restart();
                }
                Err(e) => {
                    toast.set(Some(ToastMessage {
                        message: format!("Failed to remove group from role: {}", e),
                        toast_type: ToastType::Error,
                    }));
                }
            }
        });
    };

    rsx! {
        Modal {
            open: groups_modal_open(),
            on_close: move |_| {
                groups_modal_open.set(false);
                role_groups.set(Vec::new());
                available_groups.set(Vec::new());
                selected_group_to_add.set(String::new());
            },
            title: "Manage Role Groups: {groups_role_name}",
            div { class: "flex flex-col gap-4",
                // Current groups
                div {
                    h4 { class: "font-semibold mb-2", "Current Groups" }
                    if role_groups().is_empty() {
                        p { class: "text-gray-500 italic", "No groups assigned" }
                    } else {
                        div { class: "flex flex-wrap gap-2",
                            for group in role_groups() {
                                div { class: "badge badge-lg badge-secondary gap-2",
                                    span { "{group}" }
                                    button {
                                        class: "btn btn-xs btn-circle btn-ghost",
                                        onclick: {
                                            let g = group.clone();
                                            move |_| remove_group_handler(g.clone())
                                        },
                                        "×"
                                    }
                                }
                            }
                        }
                    }
                }

                div { class: "divider" }

                // Add group
                div {
                    h4 { class: "font-semibold mb-2", "Add Group" }
                    if available_groups().is_empty() {
                        p { class: "text-gray-500 italic", "All groups are already assigned" }
                    } else {
                        div { class: "flex gap-2",
                            select {
                                class: "select select-bordered flex-1",
                                value: "{selected_group_to_add}",
                                onchange: move |e| selected_group_to_add.set(e.value()),
                                option { value: "", "Select a group..." }
                                for group in available_groups() {
                                    option { value: "{group}", "{group}" }
                                }
                            }
                            button {
                                class: "btn btn-primary",
                                disabled: selected_group_to_add().is_empty(),
                                onclick: add_group_handler,
                                "Add"
                            }
                        }
                    }
                }
            }
        }
    }
}
