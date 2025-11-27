use dioxus::prelude::*;

use crate::{
    app::api::groups::{add_member_to_group, remove_member_from_group}, components::{Modal, ToastMessage, ToastType}
};

/// User Groups Management Modal
#[component]
pub fn ManageUserGroupsModal(
    groups_modal_open: Signal<bool>,
    username: Signal<String>,
    user_groups: Signal<Vec<String>>,
    available_groups: Signal<Vec<String>>,
    selected_group_to_add: Signal<String>,
    users: Resource<Result<Vec<rb_types::users::UserGroupInfo>, ServerFnError>>,
    groups: Resource<Result<Vec<rb_types::users::GroupInfo>, ServerFnError>>,
    toast: Signal<Option<ToastMessage>>,
) -> Element {
    let add_group_handler = move |_| {
        let user = username();
        let group = selected_group_to_add();

        if group.is_empty() {
            return;
        }

        spawn(async move {
            match add_member_to_group(group.clone(), user.clone()).await {
                Ok(_) => {
                    // Update local state
                    let mut current_groups = user_groups();
                    current_groups.push(group.clone());
                    user_groups.set(current_groups.clone());

                    // Update available groups
                    let mut available = available_groups();
                    available.retain(|g| g != &group);
                    available_groups.set(available);

                    selected_group_to_add.set(String::new());

                    toast.set(Some(ToastMessage {
                        message: format!("Added user '{}' to group '{}'", user, group),
                        toast_type: ToastType::Success,
                    }));

                    // Refresh resources
                    users.restart();
                    groups.restart();
                }
                Err(e) => {
                    toast.set(Some(ToastMessage {
                        message: format!("Failed to add user to group: {}", e),
                        toast_type: ToastType::Error,
                    }));
                }
            }
        });
    };

    let remove_group_handler = move |group: String| {
        let user = username();

        spawn(async move {
            match remove_member_from_group(group.clone(), user.clone()).await {
                Ok(_) => {
                    // Update local state
                    let mut current_groups = user_groups();
                    current_groups.retain(|g| g != &group);
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

                    toast.set(Some(ToastMessage {
                        message: format!("Removed user '{}' from group '{}'", user, group),
                        toast_type: ToastType::Success,
                    }));

                    users.restart();
                    groups.restart();
                }
                Err(e) => {
                    toast.set(Some(ToastMessage {
                        message: format!("Failed to remove user from group: {}", e),
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
