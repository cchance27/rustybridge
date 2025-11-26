//! Groups section with table and modals
//! Self-contained components for managing groups

use std::collections::HashMap;

use dioxus::prelude::*;
use rb_types::auth::{ClaimLevel, ClaimType};

use crate::{
    app::api::{groups::*, users::*}, components::{Modal, Protected, StructuredTooltip, Table, ToastMessage, ToastType, TooltipSection}, pages::access::modals::{ConfirmDeleteGroupModal, EditGroupClaimsModal}
};

/// Main Groups Section component
#[component]
pub fn GroupsSection(
    groups: Resource<Result<Vec<rb_types::users::GroupInfo>, ServerFnError>>,
    users: Resource<Result<Vec<rb_types::users::UserGroupInfo>, ServerFnError>>,
    toast: Signal<Option<ToastMessage>>,
) -> Element {
    // Delete confirmation state
    let mut delete_confirm_open = use_signal(|| false);
    let mut delete_target_name = use_signal(String::new);

    let mut open_delete_confirm = move |target_name: String| {
        delete_target_name.set(target_name);
        delete_confirm_open.set(true);
    };

    let handle_delete = move |_| {
        let target_name = delete_target_name();

        spawn(async move {
            match delete_group(target_name.clone()).await {
                Ok(_) => {
                    delete_confirm_open.set(false);
                    toast.set(Some(ToastMessage {
                        message: format!("Group '{}' deleted successfully", target_name),
                        toast_type: ToastType::Success,
                    }));
                    groups.restart();
                    users.restart();
                }
                Err(e) => {
                    delete_confirm_open.set(false);
                    toast.set(Some(ToastMessage {
                        message: format!("Failed to delete group: {}", e),
                        toast_type: ToastType::Error,
                    }));
                }
            }
        });
    };
    // Group edit name modal state
    let mut edit_group_name_modal_open = use_signal(|| false);
    let mut edit_group_old_name = use_signal(String::new);
    let mut edit_group_new_name = use_signal(String::new);
    let mut edit_group_validation_errors = use_signal(HashMap::<String, String>::new);

    // Group members modal state
    let mut members_modal_open = use_signal(|| false);
    let mut members_group_name = use_signal(String::new);
    let mut group_members = use_signal(Vec::<String>::new);
    let mut available_users_for_group = use_signal(Vec::<String>::new);
    let mut selected_user_to_add = use_signal(String::new);

    // Group claims modal state
    let mut group_claims_modal_open = use_signal(|| false);
    let mut claims_group_name = use_signal(String::new);
    let group_claims = use_signal(Vec::<ClaimType>::new);
    let mut group_selected_claim_to_add = use_signal(String::new);

    let mut open_edit_group = move |group: String| {
        edit_group_old_name.set(group.clone());
        edit_group_new_name.set(group);
        edit_group_validation_errors.set(HashMap::new());
        edit_group_name_modal_open.set(true);
    };

    let mut open_manage_group_claims = move |group: String| {
        claims_group_name.set(group.clone());
        group_selected_claim_to_add.set(String::new());
        // Claims are now fetched by the modal itself
        group_claims_modal_open.set(true);
    };

    let mut open_manage_members = move |group: String| {
        members_group_name.set(group.clone());
        selected_user_to_add.set(String::new());

        // Load members and available users
        spawn(async move {
            if let Ok(members) = list_group_members(group.clone()).await {
                group_members.set(members.clone());

                // Get all users and filter out those already in the group
                if let Ok(all_users) = list_users().await {
                    let available: Vec<String> = all_users.into_iter().map(|u| u.username).filter(|u| !members.contains(u)).collect();
                    available_users_for_group.set(available);
                }
            }
            members_modal_open.set(true);
        });
    };

    // Group handlers
    let on_save_edit_group = move |_| {
        edit_group_validation_errors.set(HashMap::new());

        let _old_name = edit_group_old_name();
        let new_name = edit_group_new_name();

        let mut errors = HashMap::new();

        if new_name.trim().is_empty() {
            errors.insert("name".to_string(), "Group name is required".to_string());
        }

        if !errors.is_empty() {
            edit_group_validation_errors.set(errors);
            return;
        }

        // For now, we'll need to implement a rename function in the backend
        // As a workaround, we'll just show a message that renaming isn't supported yet
        spawn(async move {
            edit_group_name_modal_open.set(false);
            toast.set(Some(ToastMessage {
                message: "Group renaming not yet implemented. Please delete and recreate the group.".to_string(),
                toast_type: ToastType::Warning,
            }));
        });
    };

    let add_user_to_group = move |_| {
        let group = members_group_name();
        let user = selected_user_to_add();

        if user.is_empty() {
            return;
        }

        spawn(async move {
            match add_member_to_group(group.clone(), user.clone()).await {
                Ok(_) => {
                    // Reload members
                    if let Ok(members) = list_group_members(group.clone()).await {
                        group_members.set(members.clone());

                        // Update available users
                        if let Ok(all_users) = list_users().await {
                            let available: Vec<String> =
                                all_users.into_iter().map(|u| u.username).filter(|u| !members.contains(u)).collect();
                            available_users_for_group.set(available);
                        }
                    }
                    selected_user_to_add.set(String::new());
                    toast.set(Some(ToastMessage {
                        message: format!("Added '{}' to group '{}'", user, group),
                        toast_type: ToastType::Success,
                    }));
                    groups.restart();
                    users.restart(); // Refresh users list to show updated group memberships
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

    let remove_user_from_group_handler = move |user: String| {
        let group = members_group_name();

        spawn(async move {
            match remove_member_from_group(group.clone(), user.clone()).await {
                Ok(_) => {
                    // Reload members
                    if let Ok(members) = list_group_members(group.clone()).await {
                        group_members.set(members.clone());

                        // Update available users
                        if let Ok(all_users) = list_users().await {
                            let available: Vec<String> =
                                all_users.into_iter().map(|u| u.username).filter(|u| !members.contains(u)).collect();
                            available_users_for_group.set(available);
                        }
                    }
                    toast.set(Some(ToastMessage {
                        message: format!("Removed '{}' from group '{}'", user, group),
                        toast_type: ToastType::Success,
                    }));
                    groups.restart();
                    users.restart(); // Refresh users list to show updated group memberships
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
        Protected {
            claim: Some(ClaimType::Groups(ClaimLevel::View)),
            div { class: "card bg-base-200 shadow-xl self-start w-full",
                div { class: "card-body",
                    h2 { class: "card-title", "Groups" }
                    p { "Manage groups and assign users for relay access control." }

                    match groups() {
                        Some(Ok(group_list)) => rsx! {
                            Table {
                                headers: vec!["Group Name", "Members", "Relays", "Actions"],
                                for group in group_list {
                                    tr {
                                        td { "{group.name}" }
                                        td {
                                            // Member Count and Editable Badge with Tooltip
                                            StructuredTooltip {
                                                sections: {
                                                    let mut sections = Vec::new();
                                                    if !group.members.is_empty() {
                                                        sections.push(TooltipSection::new("Members").with_items(group.members.clone()));
                                                    } else {
                                                        sections.push(TooltipSection::without_header().with_empty_message("No members"));
                                                    }
                                                    sections
                                                },
                                                Protected {
                                                    claim: Some(ClaimType::Groups(ClaimLevel::Edit)),
                                                    fallback: rsx! {
                                                        span {
                                                            class: if group.member_count > 0 {
                                                                "badge badge-primary whitespace-nowrap"
                                                            } else {
                                                                "badge badge-error whitespace-nowrap"
                                                            },
                                                            "{group.member_count} "
                                                            {if group.member_count == 1 { "member" } else { "members" }}
                                                        }
                                                    },
                                                    button {
                                                        class: if group.member_count > 0 {
                                                            "badge badge-primary whitespace-nowrap cursor-pointer hover:badge-accent"
                                                        } else {
                                                            "badge badge-error whitespace-nowrap cursor-pointer hover:badge-accent"
                                                        },
                                                        onclick: {
                                                            let g = group.name.clone();
                                                            move |_| open_manage_members(g.clone())
                                                        },
                                                        "{group.member_count} "
                                                        {if group.member_count == 1 { "member" } else { "members" }}
                                                        // Edit icon
                                                        svg {
                                                            xmlns: "http://www.w3.org/2000/svg",
                                                            class: "h-3 w-3",
                                                            fill: "none",
                                                            view_box: "0 0 24 24",
                                                            stroke: "currentColor",
                                                            path {
                                                                stroke_linecap: "round",
                                                                stroke_linejoin: "round",
                                                                stroke_width: "2",
                                                                d: "M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z"
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        td {
                                            // Relay Count with Tooltip
                                            StructuredTooltip {
                                                sections: {
                                                    let mut sections = Vec::new();
                                                    if !group.relays.is_empty() {
                                                        sections.push(TooltipSection::new("Relays").with_items(group.relays.clone()));
                                                    } else {
                                                        sections.push(TooltipSection::without_header().with_empty_message("No relay access"));
                                                    }
                                                    sections
                                                },
                                                span { class: "badge badge-info whitespace-nowrap",
                                                    "{group.relay_count} "
                                                    {if group.relay_count == 1 { "relay" } else { "relays" }}
                                                }
                                            }
                                        }
                                        td { class: "text-right",
                                            div { class: "join",
                                                // Buttons for editing a group
                                                Protected {
                                                    any_claims: vec![ClaimType::Groups(ClaimLevel::Edit)],
                                                    button {
                                                        class: "btn btn-xs btn-secondary join-item",
                                                        onclick: {
                                                            let g = group.name.clone();
                                                            move |_| open_manage_group_claims(g.clone())
                                                        },
                                                        "Claims"
                                                    }
                                                    button {
                                                        class: "btn btn-xs btn-info join-item",
                                                        onclick: {
                                                            let g = group.name.clone();
                                                            move |_| open_edit_group(g.clone())
                                                        },
                                                        "Edit"
                                                    }
                                                }
                                                // Ability to delete groups
                                                Protected {
                                                    any_claims: vec![ClaimType::Groups(ClaimLevel::Delete)],
                                                    button {
                                                        class: "btn btn-xs btn-error join-item",
                                                        onclick: {
                                                            let g = group.name.clone();
                                                            move |_| open_delete_confirm(g.clone())
                                                        },
                                                        "Delete"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        Some(Err(e)) => rsx! {
                            div { class: "alert alert-error",
                                span { "Error loading groups: {e}" }
                            }
                        },
                        None => rsx! {
                            div { class: "flex justify-center p-8",
                                span { class: "loading loading-spinner loading-lg" }
                            }
                        }
                    }
                }
            }
        }

        // Edit Group Name Modal
        Modal {
            open: edit_group_name_modal_open(),
            on_close: move |_| {
                edit_group_name_modal_open.set(false);
                edit_group_validation_errors.set(HashMap::new());
            },
            title: "Edit Group Name",
            actions: rsx! {
                button { class: "btn btn-primary", onclick: on_save_edit_group, "Save" }
            },
            div { class: "flex flex-col gap-4",
                label { class: "form-control w-full",
                    div { class: "label", span { class: "label-text", "Group Name" } }
                    input {
                        r#type: "text",
                        class: if edit_group_validation_errors().contains_key("name") { "input input-bordered w-full input-error" } else { "input input-bordered w-full" },
                        placeholder: "developers",
                        value: "{edit_group_new_name}",
                        oninput: move |e| {
                            edit_group_new_name.set(e.value());
                            if edit_group_validation_errors().contains_key("name") {
                                let mut errs = edit_group_validation_errors();
                                errs.remove("name");
                                edit_group_validation_errors.set(errs);
                            }
                        }
                    }
                    if let Some(err) = edit_group_validation_errors().get("name") {
                        div { class: "text-error text-sm mt-1", "{err}" }
                    }
                }
            }
        }

        // Group Members Modal
        Modal {
            open: members_modal_open(),
            on_close: move |_| {
                members_modal_open.set(false);
                group_members.set(Vec::new());
                available_users_for_group.set(Vec::new());
                selected_user_to_add.set(String::new());
            },
            title: "Manage Group Members: {members_group_name}",
            div { class: "flex flex-col gap-4",
                // Current members
                div {
                    h4 { class: "font-semibold mb-2", "Current Members" }
                    if group_members().is_empty() {
                        p { class: "text-gray-500 italic", "No members yet" }
                    } else {
                        div { class: "flex flex-wrap gap-2",
                            for member in group_members() {
                                div { class: "badge badge-lg badge-primary whitespace-nowrap",
                                    span { "{member}" }
                                    button {
                                        class: "btn btn-xs btn-circle btn-ghost",
                                        onclick: {
                                            let m = member.clone();
                                            move |_| remove_user_from_group_handler(m.clone())
                                        },
                                        "×"
                                    }
                                }
                            }
                        }
                    }
                }

                div { class: "divider" }

                // Add member
                div {
                    h4 { class: "font-semibold mb-2", "Add Member" }
                    if available_users_for_group().is_empty() {
                        p { class: "text-gray-500 italic", "All users are already members" }
                    } else {
                        div { class: "flex gap-2",
                            select {
                                class: "select select-bordered flex-1",
                                value: "{selected_user_to_add}",
                                onchange: move |e| selected_user_to_add.set(e.value()),
                                option { value: "", "Select a user..." }
                                for user in available_users_for_group() {
                                    option { value: "{user}", "{user}" }
                                }
                            }
                            button {
                                class: "btn btn-primary",
                                disabled: selected_user_to_add().is_empty(),
                                onclick: add_user_to_group,
                                "Add"
                            }
                        }
                    }
                }
            }
        }

        EditGroupClaimsModal {
            group_claims_modal_open,
            claims_group_name,
            group_claims,
            group_selected_claim_to_add,
            groups,
            toast,
        }

        ConfirmDeleteGroupModal {
            group_name: delete_target_name,
            delete_confirm_open,
            handle_delete,
        }
    }
}
