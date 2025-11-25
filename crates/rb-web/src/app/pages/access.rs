use std::{collections::HashMap, str::FromStr as _};

use dioxus::prelude::*;
use rb_types::{
    access::RelayAccessSource, auth::{ClaimLevel, ClaimType}, users::{CreateUserRequest, UpdateUserRequest}
};

use crate::{
    app::api::{groups::*, users::*}, components::{
        Layout, Modal, MultiFab, Protected, RequireAuth, StructuredTooltip, Table, TableActions, Toast, ToastMessage, ToastType, TooltipSection
    }
};

#[component]
pub fn AccessPage() -> Element {
    // Load users and groups from server
    let mut users = use_resource(|| async move { list_users().await });
    let mut groups = use_resource(|| async move { list_groups().await });

    // Toast notification state
    let mut toast = use_signal(|| None::<ToastMessage>);

    // User modal state
    let mut user_modal_open = use_signal(|| false);
    let mut editing_username = use_signal(|| None::<String>);
    let mut username = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut has_existing_password = use_signal(|| false);
    let mut user_validation_errors = use_signal(HashMap::<String, String>::new);
    let mut user_claims = use_signal(Vec::<ClaimType>::new);
    let mut selected_claim_to_add = use_signal(String::new);

    // Group add/edit modal state
    let mut group_modal_open = use_signal(|| false);
    let mut editing_group_name = use_signal(|| None::<String>);
    let mut group_name = use_signal(String::new);
    let mut group_validation_errors = use_signal(HashMap::<String, String>::new);
    let mut group_claims = use_signal(Vec::<ClaimType>::new);
    let mut group_selected_claim_to_add = use_signal(String::new);
    let mut group_claims_modal_open = use_signal(|| false);
    let mut claims_group_name = use_signal(String::new);

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

    // Delete confirmation state
    let mut delete_confirm_open = use_signal(|| false);
    let mut delete_target_type = use_signal(String::new); // "user" or "group"
    let mut delete_target_name = use_signal(String::new);

    // FAB handlers
    let open_add_user = move |_| {
        editing_username.set(None);
        username.set(String::new());
        password.set(String::new());
        has_existing_password.set(false);
        user_validation_errors.set(HashMap::new());
        user_claims.set(Vec::new());
        selected_claim_to_add.set(String::new());
        user_modal_open.set(true);
    };

    let open_add_group = move |_| {
        editing_group_name.set(None);
        group_name.set(String::new());
        group_validation_errors.set(HashMap::new());
        group_modal_open.set(true);
    };

    let mut open_edit_group = move |group: String| {
        edit_group_old_name.set(group.clone());
        edit_group_new_name.set(group);
        edit_group_validation_errors.set(HashMap::new());
        edit_group_name_modal_open.set(true);
    };

    // User handlers
    let mut open_edit_user = move |user: String| {
        editing_username.set(Some(user.clone()));
        username.set(user.clone());
        password.set(String::new());
        has_existing_password.set(true);
        user_validation_errors.set(HashMap::new());

        // Find user to get claims
        if let Some(Ok(list)) = users.value()().as_ref()
            && let Some(u) = list.iter().find(|u| u.username == user)
        {
            user_claims.set(u.claims.clone());
        }

        selected_claim_to_add.set(String::new());
        user_modal_open.set(true);
    };

    let on_save_user = move |_| {
        user_validation_errors.set(HashMap::new());

        let username_val = username();
        let password_val = password();
        let is_editing = editing_username().is_some();

        let mut errors = HashMap::new();

        if !is_editing && username_val.trim().is_empty() {
            errors.insert("username".to_string(), "Username is required".to_string());
        }

        if password_val.trim().is_empty() {
            if !is_editing {
                errors.insert("password".to_string(), "Password is required".to_string());
            }
        } else if password_val.len() < 8 {
            errors.insert("password".to_string(), "Password must be at least 8 characters".to_string());
        }

        if !errors.is_empty() {
            user_validation_errors.set(errors);
            return;
        }

        spawn(async move {
            let result = if is_editing {
                update_user(
                    username_val.clone(),
                    UpdateUserRequest {
                        password: if password_val.is_empty() {
                            None
                        } else {
                            Some(password_val.clone())
                        },
                    },
                )
                .await
            } else {
                create_user(CreateUserRequest {
                    username: username_val.clone(),
                    password: password_val.clone(),
                })
                .await
            };

            match result {
                Ok(_) => {
                    user_modal_open.set(false);
                    toast.set(Some(ToastMessage {
                        message: format!(
                            "User '{}' {} successfully",
                            username_val,
                            if is_editing { "updated" } else { "created" }
                        ),
                        toast_type: ToastType::Success,
                    }));
                    users.restart();
                }
                Err(e) => {
                    user_modal_open.set(false);
                    toast.set(Some(ToastMessage {
                        message: format!("Failed to {} user: {}", if is_editing { "update" } else { "create" }, e),
                        toast_type: ToastType::Error,
                    }));
                }
            }
        });
    };

    let add_user_claim_handler = move |_| {
        let username = username();
        let claim = selected_claim_to_add();
        if claim.is_empty() {
            return;
        }
        let claim_str = selected_claim_to_add();
        if claim_str.is_empty() {
            return;
        }

        spawn(async move {
            // Parse the string into ClaimType
            let claim_type = match ClaimType::from_str(&claim_str) {
                Ok(ct) => ct,
                Err(e) => {
                    toast.set(Some(ToastMessage {
                        message: format!("Invalid claim format: {}", e),
                        toast_type: ToastType::Error,
                    }));
                    return;
                }
            };

            match add_user_claim(username.clone(), claim_type.clone()).await {
                Ok(_) => {
                    users.restart();
                    let mut current = user_claims();
                    if !current.contains(&claim_type) {
                        current.push(claim_type);
                        user_claims.set(current);
                    }
                    selected_claim_to_add.set(String::new());
                    toast.set(Some(ToastMessage {
                        message: format!("Added claim '{}' to user '{}'", claim_str, username),
                        toast_type: ToastType::Success,
                    }));
                }
                Err(e) => {
                    toast.set(Some(ToastMessage {
                        message: format!("Failed to add claim: {}", e),
                        toast_type: ToastType::Error,
                    }));
                }
            }
        });
    };

    let remove_user_claim_handler = move |claim: ClaimType| {
        let username = username();
        spawn(async move {
            match remove_user_claim(username.clone(), claim.clone()).await {
                Ok(_) => {
                    users.restart();
                    let mut current = user_claims();
                    current.retain(|c| c != &claim);
                    user_claims.set(current);
                    toast.set(Some(ToastMessage {
                        message: format!("Removed claim '{}' from user '{}'", claim, username),
                        toast_type: ToastType::Success,
                    }));
                }
                Err(e) => {
                    toast.set(Some(ToastMessage {
                        message: format!("Failed to remove claim: {}", e),
                        toast_type: ToastType::Error,
                    }));
                }
            }
        });
    };

    // Group handlers
    let on_save_group = move |_| {
        group_validation_errors.set(HashMap::new());

        let name_val = group_name();

        let mut errors = HashMap::new();

        if name_val.trim().is_empty() {
            errors.insert("name".to_string(), "Group name is required".to_string());
        }

        if !errors.is_empty() {
            group_validation_errors.set(errors);
            return;
        }

        spawn(async move {
            let result = create_group(name_val.clone()).await;

            match result {
                Ok(_) => {
                    group_modal_open.set(false);
                    toast.set(Some(ToastMessage {
                        message: format!("Group '{}' created successfully", name_val),
                        toast_type: ToastType::Success,
                    }));
                    groups.restart();
                }
                Err(e) => {
                    group_modal_open.set(false);
                    toast.set(Some(ToastMessage {
                        message: format!("Failed to create group: {}", e),
                        toast_type: ToastType::Error,
                    }));
                }
            }
        });
    };

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

    let mut open_manage_group_claims = move |group: String| {
        claims_group_name.set(group.clone());
        group_selected_claim_to_add.set(String::new());

        // Find group to get claims
        if let Some(Ok(list)) = groups.value()().as_ref()
            && let Some(g) = list.iter().find(|g| g.name == group)
        {
            group_claims.set(g.claims.clone());
        }

        group_claims_modal_open.set(true);
    };

    let add_group_claim_handler = move |claim: String| {
        let group = claims_group_name();
        spawn(async move {
            // Parse the string into ClaimType
            let claim_type = match ClaimType::from_str(&claim) {
                Ok(ct) => ct,
                Err(e) => {
                    toast.set(Some(ToastMessage {
                        message: format!("Invalid claim format: {}", e),
                        toast_type: ToastType::Error,
                    }));
                    return;
                }
            };

            match add_group_claim(group.clone(), claim_type.clone()).await {
                Ok(_) => {
                    groups.restart();
                    let mut current = group_claims();
                    current.push(claim_type);
                    group_claims.set(current);
                    toast.set(Some(ToastMessage {
                        message: format!("Added claim '{}' to group '{}'", claim, group),
                        toast_type: ToastType::Success,
                    }));
                }
                Err(e) => {
                    toast.set(Some(ToastMessage {
                        message: format!("Failed to add claim: {}", e),
                        toast_type: ToastType::Error,
                    }));
                }
            }
        });
    };

    let remove_group_claim_handler = move |claim: ClaimType| {
        let group = claims_group_name();
        spawn(async move {
            match remove_group_claim(group.clone(), claim.clone()).await {
                Ok(_) => {
                    groups.restart();
                    let mut current = group_claims();
                    current.retain(|c| c != &claim);
                    group_claims.set(current);
                    toast.set(Some(ToastMessage {
                        message: format!("Removed claim '{}' from group '{}'", claim, group),
                        toast_type: ToastType::Success,
                    }));
                }
                Err(e) => {
                    toast.set(Some(ToastMessage {
                        message: format!("Failed to remove claim: {}", e),
                        toast_type: ToastType::Error,
                    }));
                }
            }
        });
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

    // Delete handlers
    let mut open_delete_confirm = move |target_type: String, target_name: String| {
        delete_target_type.set(target_type);
        delete_target_name.set(target_name);
        delete_confirm_open.set(true);
    };

    let handle_delete = move |_| {
        let target_type = delete_target_type();
        let target_name = delete_target_name();

        spawn(async move {
            let result = if target_type == "user" {
                delete_user(target_name.clone()).await
            } else {
                delete_group(target_name.clone()).await
            };

            match result {
                Ok(_) => {
                    delete_confirm_open.set(false);
                    toast.set(Some(ToastMessage {
                        message: format!(
                            "{} '{}' deleted successfully",
                            if target_type == "user" { "User" } else { "Group" },
                            target_name
                        ),
                        toast_type: ToastType::Success,
                    }));
                    users.restart();
                    groups.restart();
                }
                Err(e) => {
                    delete_confirm_open.set(false);
                    toast.set(Some(ToastMessage {
                        message: format!("Failed to delete {}: {}", target_type, e),
                        toast_type: ToastType::Error,
                    }));
                }
            }
        });
    };

    rsx! {
        RequireAuth {
            any_claims: vec![ClaimType::Users(ClaimLevel::View), ClaimType::Groups(ClaimLevel::View)],
            Toast { message: toast }
            Layout {
                div { class: "flex flex-row gap-6",
                    // Users Section
                    Protected {
                        claim: Some(ClaimType::Users(ClaimLevel::View)),
                        div { class: "card bg-base-200 shadow-xl flex-1 self-start",
                            div { class: "card-body",
                                h2 { class: "card-title", "Users" }
                                p { "Manage system users and their group memberships." }
                                match users() {
                                    Some(Ok(user_list)) => rsx! {
                                        Table {
                                            headers: vec!["Username", "Groups", "Relays", "Actions"],
                                            for user in user_list {
                                                tr {
                                                    td { "{user.username}" }
                                                    td {
                                                        if user.groups.is_empty() {
                                                            span { class: "text-gray-500 italic", "No groups" }
                                                        } else {
                                                            StructuredTooltip {
                                                                sections: {
                                                                    vec![TooltipSection::new("Groups").with_items(user.groups.clone())]
                                                                },
                                                                span { class: "badge badge-primary",
                                                                    "{user.groups.len()} "
                                                                    {if user.groups.len() == 1 { "group" } else { "groups" }}
                                                                }
                                                            }
                                                        }
                                                    }
                                                    td {
                                                        if user.relays.is_empty() {
                                                            span { class: "badge badge-ghost", "No access" }
                                                        } else {
                                                            StructuredTooltip {
                                                                sections: {
                                                                    let items = user.relays.iter().map(|r| {
                                                                        let source_str = match &r.access_source {
                                                                            RelayAccessSource::Direct => "",
                                                                            RelayAccessSource::ViaGroup(g) => &format!(" (via {})", g),
                                                                            RelayAccessSource::Both(g) => &format!(" (direct + {})", g),
                                                                        };
                                                                        format!("{} ({}){}", r.relay_name, r.relay_endpoint, source_str)
                                                                    }).collect();
                                                                    vec![TooltipSection::new("Relays").with_items(items)]
                                                                },
                                                                span { class: "badge badge-success",
                                                                    "{user.relays.len()} "
                                                                    {if user.relays.len() == 1 { "relay" } else { "relays" }}
                                                                }
                                                            }
                                                        }
                                                    }
                                                    td { class: "text-right",
                                                        Protected {
                                                            any_claims: vec![ClaimType::Users(ClaimLevel::Edit), ClaimType::Users(ClaimLevel::Delete)],
                                                            TableActions {
                                                                on_edit: {
                                                                    let u = user.username.clone();
                                                                    move |_| open_edit_user(u.clone())
                                                                },
                                                                on_delete: {
                                                                    let u = user.username.clone();
                                                                    move |_| open_delete_confirm("user".to_string(), u.clone())
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
                                            span { "Error loading users: {e}" }
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

                    // Groups Section
                    Protected {
                        claim: Some(ClaimType::Groups(ClaimLevel::View)),
                        div { class: "card bg-base-200 shadow-xl flex-1 self-start",
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
                                                        // Make member badge clickable with icon to indicate it's editable
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
                                                                            "badge badge-primary gap-2"
                                                                        } else {
                                                                            "badge badge-error gap-2"
                                                                        },
                                                                        "{group.member_count} "
                                                                        {if group.member_count == 1 { "member" } else { "members" }}
                                                                    }
                                                                },
                                                                button {
                                                                    class: if group.member_count > 0 {
                                                                        "badge badge-primary gap-2 cursor-pointer hover:badge-accent"
                                                                    } else {
                                                                        "badge badge-error gap-2 cursor-pointer hover:badge-accent"
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
                                                            span { class: "badge badge-info",
                                                                "{group.relay_count} "
                                                                {if group.relay_count == 1 { "relay" } else { "relays" }}
                                                            }
                                                        }
                                                    }
                                                    td { class: "text-right",
                                                        div { class: "join",
                                                            Protected {
                                                                any_claims: vec![ClaimType::Groups(ClaimLevel::Edit), ClaimType::Groups(ClaimLevel::Delete)],
                                                                button {
                                                                    class: "btn btn-xs btn-primary join-item",
                                                                    onclick: {
                                                                        let g = group.name.clone();
                                                                        move |_| open_manage_members(g.clone())
                                                                    },
                                                                    "Members"
                                                                }
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
                                                                button {
                                                                    class: "btn btn-xs btn-error join-item",
                                                                    onclick: {
                                                                        let g = group.name.clone();
                                                                        move |_| open_delete_confirm("group".to_string(), g.clone())
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
                }

                // Multi-action FAB
                Protected {
                    any_claims: vec![ClaimType::Users(ClaimLevel::Create), ClaimType::Groups(ClaimLevel::Create)],
                    MultiFab {
                        on_add_user: open_add_user,
                        on_add_group: open_add_group
                    }
                }

                // User Modal
                Modal {
                    open: user_modal_open(),
                    on_close: move |_| user_modal_open.set(false),
                    title: if editing_username().is_some() { "Edit User" } else { "Add User" },
                    actions: rsx! {
                        button { class: "btn btn-primary", onclick: on_save_user, "Save" }
                    },
                    div { class: "flex flex-col gap-4",
                        label { class: "form-control w-full",
                            div { class: "label", span { class: "label-text", "Username" } }
                            if editing_username().is_some() {
                                div { class: "text-lg font-semibold py-2", "{username}" }
                            } else {
                                input {
                                    r#type: "text",
                                    class: if user_validation_errors().contains_key("username") { "input input-bordered w-full input-error" } else { "input input-bordered w-full" },
                                    placeholder: "jdoe",
                                    value: "{username}",
                                    oninput: move |e| {
                                        username.set(e.value());
                                        if user_validation_errors().contains_key("username") {
                                            let mut errs = user_validation_errors();
                                            errs.remove("username");
                                            user_validation_errors.set(errs);
                                        }
                                    }
                                }
                                if let Some(err) = user_validation_errors().get("username") {
                                    div { class: "text-error text-sm mt-1", "{err}" }
                                }
                            }
                        }
                        label { class: "form-control w-full",
                            div { class: "label items-center justify-between",
                                span { class: "label-text", "Password" }
                                if has_existing_password() && editing_username().is_some() {
                                    span { class: "badge badge-warning badge-xs", "Stored • not shown" }
                                }
                            }
                            input {
                                r#type: "password",
                                class: if user_validation_errors().contains_key("password") { "input input-bordered w-full input-error" } else { "input input-bordered w-full" },
                                placeholder: "••••••••",
                                value: "{password}",
                                oninput: move |e| {
                                    password.set(e.value());
                                    if user_validation_errors().contains_key("password") {
                                        let mut errs = user_validation_errors();
                                        errs.remove("password");
                                        user_validation_errors.set(errs);
                                    }
                                }
                            }
                            if let Some(err) = user_validation_errors().get("password") {
                                div { class: "text-error text-sm mt-1", "{err}" }
                            }
                        }
                        p { class: "text-xs text-gray-500",
                            "Secrets are encrypted and not displayed. Leave blank to keep the existing password."
                        }

                        if editing_username().is_some() {
                            div { class: "divider" }
                            div {
                                h4 { class: "font-semibold mb-2", "Claims" }
                                if user_claims().is_empty() {
                                    p { class: "text-gray-500 italic", "No claims assigned" }
                                } else {
                                    div { class: "flex flex-wrap gap-2",
                                        for claim in user_claims() {
                                            div { class: "badge badge-lg badge-secondary gap-2",
                                                span { "{claim}" }
                                                button {
                                                    class: "btn btn-xs btn-circle btn-ghost",
                                                    onclick: {
                                                        let c = claim.clone();
                                                        move |_| remove_user_claim_handler(c.clone())
                                                    },
                                                    "×"
                                                }
                                            }
                                        }
                                    }
                                }

                                div { class: "flex gap-2 mt-4",
                                    select {
                                        class: "select select-bordered flex-1",
                                        value: "{selected_claim_to_add}",
                                        onchange: move |e| selected_claim_to_add.set(e.value()),
                                        option { value: "", "Select a claim..." }
                                        for claim in ClaimType::all_variants() {
                                            option { value: "{claim}", "{claim}" }
                                        }
                                    }
                                    button {
                                        class: "btn btn-secondary",
                                        disabled: selected_claim_to_add().is_empty(),
                                        onclick: add_user_claim_handler,
                                        "Add Claim"
                                    }
                                }
                            }
                        }
                    }
                }

                // Add Group Modal
                Modal {
                    open: group_modal_open(),
                    on_close: move |_| group_modal_open.set(false),
                    title: "Add Group",
                    actions: rsx! {
                        button { class: "btn btn-primary", onclick: on_save_group, "Create" }
                    },
                    div { class: "flex flex-col gap-4",
                        label { class: "form-control w-full",
                            div { class: "label", span { class: "label-text", "Group Name" } }
                            input {
                                r#type: "text",
                                class: if group_validation_errors().contains_key("name") { "input input-bordered w-full input-error" } else { "input input-bordered w-full" },
                                placeholder: "developers",
                                value: "{group_name}",
                                oninput: move |e| {
                                    group_name.set(e.value());
                                    if group_validation_errors().contains_key("name") {
                                        let mut errs = group_validation_errors();
                                        errs.remove("name");
                                        group_validation_errors.set(errs);
                                    }
                                }
                            }
                            if let Some(err) = group_validation_errors().get("name") {
                                div { class: "text-error text-sm mt-1", "{err}" }
                            }
                        }
                    }
                }

                // Edit Group Name Modal
                Modal {
                    open: edit_group_name_modal_open(),
                    on_close: move |_| edit_group_name_modal_open.set(false),
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
                    on_close: move |_| members_modal_open.set(false),
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
                                        div { class: "badge badge-lg badge-primary gap-2",
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

                // Delete Confirmation Modal
                Modal {
                    open: delete_confirm_open(),
                    on_close: move |_| delete_confirm_open.set(false),
                    title: if delete_target_type() == "user" { "Delete User" } else { "Delete Group" },
                    actions: rsx! {
                        button { class: "btn btn-error", onclick: handle_delete, "Delete" }
                    },
                    div { class: "flex flex-col gap-4",
                        p { "Are you sure you want to delete {delete_target_type()} \"{delete_target_name()}\"?" }
                        p { class: "text-sm text-gray-500",
                            if delete_target_type() == "user" {
                                "This action cannot be undone. This will also revoke all relay access for this user."
                            } else {
                                "This action cannot be undone. This will also revoke relay access for all members of this group."
                            }
                        }
                    }
                }

                // Group Claims Modal
                Modal {
                    open: group_claims_modal_open(),
                    on_close: move |_| group_claims_modal_open.set(false),
                    title: "Manage Group Claims: {claims_group_name}",
                    div { class: "flex flex-col gap-4",
                        // Current claims
                        div {
                            h4 { class: "font-semibold mb-2", "Current Claims" }
                            if group_claims().is_empty() {
                                p { class: "text-gray-500 italic", "No claims assigned" }
                            } else {
                                div { class: "flex flex-wrap gap-2",
                                    for claim in group_claims() {
                                        div { class: "badge badge-lg badge-secondary gap-2",
                                            span { "{claim}" }
                                            button {
                                                class: "btn btn-xs btn-circle btn-ghost",
                                                onclick: {
                                                    let c = claim.clone();
                                                    move |_| remove_group_claim_handler(c.clone())
                                                },
                                                "×"
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        div { class: "divider" }

                        // Add claim
                        div {
                            h4 { class: "font-semibold mb-2", "Add Claim" }
                            div { class: "flex gap-2",
                                select {
                                    class: "select select-bordered flex-1",
                                    value: "{group_selected_claim_to_add}",
                                    onchange: move |e| group_selected_claim_to_add.set(e.value()),
                                    option { value: "", "Select a claim..." }
                                    for claim in ClaimType::all_variants() {
                                        option { value: "{claim}", "{claim}" }
                                    }
                                }
                                button {
                                    class: "btn btn-sm btn-primary",
                                    disabled: group_selected_claim_to_add().is_empty(),
                                    onclick: move |_| {
                                        let claim = group_selected_claim_to_add();
                                        add_group_claim_handler(claim)
                                    },
                                    "Add Claim"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
