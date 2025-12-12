use dioxus::prelude::*;
use rb_types::users::{GroupInfo, UserGroupInfo};

use crate::{
    app::api::groups::{add_member_to_group, remove_member_from_group}, components::{Modal, use_toast}, error::ApiError
};

/// User Groups Management Modal
#[component]
pub fn ManageUserGroupsModal(
    groups_modal_open: Signal<bool>,
    user_id: Signal<i64>,
    username: Signal<String>,
    user_groups: Signal<Vec<String>>,
    available_groups: Signal<Vec<String>>,
    selected_group_to_add: Signal<String>,
    users: Resource<Result<Vec<UserGroupInfo<'static>>, ApiError>>,
    groups: Resource<Result<Vec<GroupInfo<'static>>, ApiError>>,
) -> Element {
    let toast = use_toast();
    let add_group_handler = move |_| {
        let user_name = username();
        let group_name = selected_group_to_add();
        let user_id_val = user_id();

        if group_name.is_empty() {
            return;
        }

        spawn(async move {
            // Find group ID from group name
            if let Some(Ok(all_groups)) = groups.value()().as_ref()
                && let Some(group) = all_groups.iter().find(|g| g.name == group_name)
            {
                match add_member_to_group(group.id, user_id_val).await {
                    Ok(_) => {
                        // Update local state
                        let mut current_groups = user_groups();
                        current_groups.push(group_name.clone());
                        user_groups.set(current_groups.clone());

                        // Update available groups
                        let mut available = available_groups();
                        available.retain(|g| g != &group_name);
                        available_groups.set(available);

                        selected_group_to_add.set(String::new());

                        toast.success(&format!("Added user '{}' to group '{}'", user_name, group_name));

                        // Refresh resources
                        users.restart();
                        groups.restart();
                    }
                    Err(e) => {
                        toast.error(&format!("Failed to add user to group: {}", e));
                    }
                }
            }
        });
    };

    let remove_group_handler = move |group_name: String| {
        let user_name = username();
        let user_id_val = user_id();

        spawn(async move {
            // Find group ID from group name
            if let Some(Ok(all_groups)) = groups.value()().as_ref()
                && let Some(group) = all_groups.iter().find(|g| g.name == group_name)
            {
                match remove_member_from_group(group.id, user_id_val).await {
                    Ok(_) => {
                        // Update local state
                        let mut current_groups = user_groups();
                        current_groups.retain(|g| g != &group_name);
                        user_groups.set(current_groups.clone());

                        // Update available groups
                        if let Some(Ok(all_groups)) = groups.value()().as_ref() {
                            let available: Vec<String> = all_groups
                                .iter()
                                .map(|g| g.name.clone())
                                .filter(|g| !current_groups.contains(g))
                                .collect();
                            available_groups.set(available);
                        }

                        toast.success(&format!("Removed user '{}' from group '{}'", user_name, group_name));

                        users.restart();
                        groups.restart();
                    }
                    Err(e) => {
                        toast.error(&format!("Failed to remove user from group: {}", e));
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
                user_groups.set(Vec::new());
                available_groups.set(Vec::new());
                selected_group_to_add.set(String::new());
            },
            title: "Manage User Groups: {username}",
            div { class: "flex flex-col gap-4",
                // Current groups
                div {
                    h4 { class: "font-semibold mb-2", "Assigned Groups" }
                    if user_groups().is_empty() {
                        p { class: "text-gray-500 italic", "No groups assigned" }
                    } else {
                        div { class: "flex flex-wrap gap-2",
                            for group in user_groups() {
                                div { class: "badge badge-lg badge-primary gap-2",
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
                    h4 { class: "font-semibold mb-2", "Assign Group" }
                    if available_groups().is_empty() {
                        p { class: "text-gray-500 italic", "All available groups are already assigned" }
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
                                "Assign"
                            }
                        }
                    }
                }
            }
        }
    }
}
