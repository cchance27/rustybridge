//! Groups section with table and modals
//! Self-contained components for managing groups

use dioxus::prelude::*;
use rb_types::auth::{ClaimLevel, ClaimType};

use crate::{
    app::api::{groups::*, users::*}, components::{Modal, Protected, StructuredTooltip, Table, ToastMessage, ToastType, TooltipSection}, pages::access::modals::{ConfirmDeleteGroupModal, EditGroupModal, ManageGroupRolesModal}
};

/// Main Groups Section component
#[component]
pub fn GroupsSection(
    groups: Resource<Result<Vec<rb_types::users::GroupInfo>, ServerFnError>>,
    users: Resource<Result<Vec<rb_types::users::UserGroupInfo>, ServerFnError>>,
    roles: Resource<Result<Vec<rb_types::users::RoleInfo>, ServerFnError>>,
    toast: Signal<Option<ToastMessage>>,
) -> Element {
    // Delete confirmation state
    let mut delete_confirm_open = use_signal(|| false);
    let mut delete_target_id = use_signal(|| 0i64);
    let mut delete_target_name = use_signal(String::new);

    let mut open_delete_confirm = move |target_id: i64, target_name: String| {
        delete_target_id.set(target_id);
        delete_target_name.set(target_name);
        delete_confirm_open.set(true);
    };

    let handle_delete = move |_| {
        let target_id = delete_target_id();
        let target_name = delete_target_name();

        spawn(async move {
            match delete_group(target_id).await {
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

    // Edit Group Modal State
    let mut edit_group_modal_open = use_signal(|| false);
    let mut edit_group_id = use_signal(|| 0i64);
    let mut edit_group_name = use_signal(String::new);

    // Manage roles modal state
    let mut manage_roles_modal_open = use_signal(|| false);
    let mut manage_roles_group_id = use_signal(|| 0i64);
    let mut manage_roles_group = use_signal(String::new);
    let mut manage_roles_current = use_signal(Vec::<String>::new);
    let mut manage_roles_available = use_signal(Vec::<String>::new);
    let manage_roles_selected = use_signal(String::new);

    // Group members modal state
    let mut members_modal_open = use_signal(|| false);
    let mut members_group_id = use_signal(|| 0i64);
    let mut members_group_name = use_signal(String::new);
    let mut group_members = use_signal(Vec::<String>::new);
    let mut available_users_for_group = use_signal(Vec::<String>::new);
    let mut selected_user_to_add = use_signal(String::new);

    let mut open_edit_group = move |group_id: i64, group_name: String| {
        edit_group_id.set(group_id);
        edit_group_name.set(group_name);
        edit_group_modal_open.set(true);
    };

    let mut open_manage_roles = move |group: &rb_types::users::GroupInfo| {
        manage_roles_group_id.set(group.id);
        manage_roles_group.set(group.name.clone());
        manage_roles_current.set(group.roles.clone());
        if let Some(Ok(all_roles)) = roles.value()().as_ref() {
            let available: Vec<String> = all_roles
                .iter()
                .map(|r| r.name.clone())
                .filter(|r| !group.roles.contains(r))
                .collect();
            manage_roles_available.set(available);
        }
        manage_roles_modal_open.set(true);
    };

    let mut open_manage_members = move |group_id: i64, group_name: String| {
        members_group_id.set(group_id);
        members_group_name.set(group_name.clone());
        selected_user_to_add.set(String::new());

        // Load members and available users
        spawn(async move {
            if let Ok(members) = list_group_members(group_id).await {
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

    let add_user_to_group = move |_| {
        let group_id = members_group_id();
        let group_name = members_group_name();
        let username = selected_user_to_add();

        if username.is_empty() {
            return;
        }

        spawn(async move {
            // Find user ID from username
            if let Ok(all_users) = list_users().await
                && let Some(user) = all_users.iter().find(|u| u.username == username)
            {
                match add_member_to_group(group_id, user.id).await {
                    Ok(_) => {
                        // Reload members
                        if let Ok(members) = list_group_members(group_id).await {
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
                            message: format!("Added '{}' to group '{}'", username, group_name),
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
            }
        });
    };

    let remove_user_from_group_handler = move |username: String| {
        let group_id = members_group_id();
        let group_name = members_group_name();

        spawn(async move {
            // Find user ID from username
            if let Ok(all_users) = list_users().await
                && let Some(user) = all_users.iter().find(|u| u.username == username)
            {
                match remove_member_from_group(group_id, user.id).await {
                    Ok(_) => {
                        // Reload members
                        if let Ok(members) = list_group_members(group_id).await {
                            group_members.set(members.clone());

                            // Update available users
                            if let Ok(all_users) = list_users().await {
                                let available: Vec<String> =
                                    all_users.into_iter().map(|u| u.username).filter(|u| !members.contains(u)).collect();
                                available_users_for_group.set(available);
                            }
                        }
                        toast.set(Some(ToastMessage {
                            message: format!("Removed '{}' from group '{}'", username, group_name),
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
                                headers: vec!["Group Name", "Members", "Roles", "Claims", "Relays", "Actions"],
                                for group in group_list {
                                    tr {
                                        td { class: "text-left", "{group.name}" }
                                        td { class: "text-center",
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
                                                                "badge badge-accent whitespace-nowrap"
                                                            } else {
                                                                "badge badge-ghost whitespace-nowrap"
                                                            },
                                                            "{group.member_count} "
                                                            {if group.member_count == 1 { "member" } else { "members" }}
                                                        }
                                                    },
                                                    button {
                                                        class: if group.member_count > 0 {
                                                            "badge badge-accent whitespace-nowrap cursor-pointer hover:brightness-90"
                                                        } else {
                                                            "badge badge-ghost whitespace-nowrap cursor-pointer hover:brightness-90"
                                                        },
                                                        onclick: {
                                                            let group_id = group.id;
                                                            let group_name = group.name.clone();
                                                            move |_| open_manage_members(group_id, group_name.clone())
                                                        },
                                                        "{group.member_count} "
                                                        {if group.member_count == 1 { "member" } else { "members" }}
                                                        // Edit icon
                                                        svg {
                                                            xmlns: "http://www.w3.org/2000/svg",
                                                            class: "h-3 w-3 ml-1",
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
                                        td { class: "text-center",
                                            // Roles Column
                                            StructuredTooltip {
                                                sections: vec![TooltipSection::new("Roles").with_items(group.roles.clone())],
                                                button {
                                                    class: if group.roles.is_empty() {
                                                        "badge badge-ghost whitespace-nowrap cursor-pointer hover:brightness-90"
                                                    } else {
                                                        "badge badge-info whitespace-nowrap cursor-pointer hover:brightness-90"
                                                    },
                                                    onclick: {
                                                        let g = group.clone();
                                                        move |_| open_manage_roles(&g)
                                                    },
                                                    if group.roles.is_empty() {
                                                        "No roles"
                                                    } else if group.roles.len() == 1 {
                                                        "{group.roles[0]}"
                                                    } else {
                                                        "{group.roles.len()} roles"
                                                    }
                                                    // Edit icon
                                                    svg {
                                                        xmlns: "http://www.w3.org/2000/svg",
                                                        class: "h-3 w-3 ml-1",
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
                                        td { class: "text-center",
                                            // Claims Column (Effective Claims: Direct + Role)
                                            {
                                                let direct_claims = group.claims.clone();

                                                // Collect Role Claims
                                                let mut role_claims = Vec::new();
                                                if let Some(Ok(role_list)) = roles.value()().as_ref() {
                                                    for role_name in &group.roles {
                                                        if let Some(r) = role_list.iter().find(|r| &r.name == role_name) {
                                                            role_claims.extend(r.claims.clone());
                                                        }
                                                    }
                                                }

                                                let total_count = direct_claims.len() + role_claims.len();

                                                rsx! {
                                                    if total_count == 0 {
                                                        span { class: "badge badge-ghost whitespace-nowrap", "None" }
                                                    } else {
                                                        StructuredTooltip {
                                                            sections: vec![
                                                                TooltipSection::new("Direct Claims").with_items(direct_claims.iter().map(|c| c.to_string()).collect()),
                                                                TooltipSection::new("Role Claims").with_items(role_claims.iter().map(|c| c.to_string()).collect()),
                                                            ],
                                                            span { class: "badge badge-success whitespace-nowrap",
                                                                "{total_count} "
                                                                {if total_count == 1 { "claim" } else { "claims" }}
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        td { class: "text-center",
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
                                                span { class: "badge badge-warning whitespace-nowrap",
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
                                                        class: "btn btn-xs btn-primary join-item",
                                                        onclick: {
                                                            let group_id = group.id;
                                                            let group_name = group.name.clone();
                                                            move |_| open_edit_group(group_id, group_name.clone())
                                                        },
                                                        "Edit"
                                                    }
                                                }
                                                // Ability to delete groups
                                                Protected {
                                                    any_claims: vec![ClaimType::Groups(ClaimLevel::Delete)],
                                                    button {
                                                        class: "btn btn-xs btn-secondary join-item",
                                                        onclick: {
                                                            let group_id = group.id;
                                                            let group_name = group.name.clone();
                                                            move |_| open_delete_confirm(group_id, group_name.clone())
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

        // Edit Group Modal
        EditGroupModal {
            open: edit_group_modal_open,
            group_id: edit_group_id,
            group_name: edit_group_name,
            roles,
            groups,
            toast,
        }

        // Manage Group Roles Modal
        ManageGroupRolesModal {
             roles_modal_open: manage_roles_modal_open,
             group_id: manage_roles_group_id,
             group_name: manage_roles_group,
             group_roles: manage_roles_current,
             available_roles: manage_roles_available,
             selected_role_to_add: manage_roles_selected,
             roles,
             groups,
             toast,
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

        ConfirmDeleteGroupModal {
            group_name: delete_target_name,
            delete_confirm_open,
            handle_delete,
        }
    }
}
