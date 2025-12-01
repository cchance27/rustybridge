use dioxus::prelude::*;

use crate::{
    app::api::{groups::list_groups, roles::*}, components::{Modal, use_toast}
};

/// Role Groups Management Modal
#[component]
pub fn ManageRoleGroupsModal(
    groups_modal_open: Signal<bool>,
    role_id: Signal<i64>,
    groups_role_name: Signal<String>,
    role_groups: Signal<Vec<String>>,
    available_groups: Signal<Vec<String>>,
    selected_group_to_add: Signal<String>,
    roles: Resource<Result<Vec<rb_types::users::RoleInfo>, ServerFnError>>,
    groups: Resource<Result<Vec<rb_types::users::GroupInfo>, ServerFnError>>,
) -> Element {
    let toast = use_toast();
    let add_group_handler = move |_| {
        let role_name = groups_role_name();
        let group_name = selected_group_to_add();
        let role_id_val = role_id();

        if group_name.is_empty() {
            return;
        }

        spawn(async move {
            // Find group ID from group name
            if let Some(Ok(all_groups)) = groups.value()().as_ref()
                && let Some(group) = all_groups.iter().find(|g| g.name == group_name)
            {
                match assign_role_to_group(role_id_val, group.id).await {
                    Ok(_) => {
                        // Reload role groups
                        if let Ok(role_group_list) = list_role_groups(role_id_val).await {
                            role_groups.set(role_group_list.clone());

                            // Update available groups
                            if let Ok(all_groups_data) = list_groups().await {
                                let available: Vec<String> = all_groups_data
                                    .into_iter()
                                    .map(|g| g.name)
                                    .filter(|g| !role_group_list.contains(g))
                                    .collect();
                                available_groups.set(available);
                            }
                        }
                        selected_group_to_add.set(String::new());
                        toast.success(&format!("Added group '{}' to role '{}'", group_name, role_name));
                        roles.restart();
                        groups.restart();
                    }
                    Err(e) => {
                        toast.error(&format!("Failed to add group to role: {}", e));
                    }
                }
            }
        });
    };

    let remove_group_handler = move |group_name: String| {
        let role_name = groups_role_name();
        let role_id_val = role_id();

        spawn(async move {
            // Find group ID from group name
            if let Some(Ok(all_groups)) = groups.value()().as_ref()
                && let Some(group) = all_groups.iter().find(|g| g.name == group_name)
            {
                match revoke_role_from_group(role_id_val, group.id).await {
                    Ok(_) => {
                        // Reload role groups
                        if let Ok(role_group_list) = list_role_groups(role_id_val).await {
                            role_groups.set(role_group_list.clone());

                            // Update available groups
                            if let Ok(all_groups_data) = list_groups().await {
                                let available: Vec<String> = all_groups_data
                                    .into_iter()
                                    .map(|g| g.name)
                                    .filter(|g| !role_group_list.contains(g))
                                    .collect();
                                available_groups.set(available);
                            }
                        }
                        toast.success(&format!("Removed group '{}' from role '{}'", group_name, role_name));
                        roles.restart();
                        groups.restart();
                    }
                    Err(e) => {
                        toast.error(&format!("Failed to remove group from role: {}", e));
                    }
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
