//! Users section with table and modals
//! Self-contained components for managing users

use dioxus::prelude::*;
use rb_types::{
    access::RelayAccessSource, auth::{ClaimLevel, ClaimType}
};

use crate::{
    app::{
        api::users::*, auth::oidc::{OidcLinkStatus, get_user_oidc_status, unlink_user_oidc}
    }, components::{
        Protected, StructuredTooltip, Table, TableActions, ToastMessage, ToastType, TooltipSection, buttons::HoverSwapButton, icons
    }, pages::access::modals::{ConfirmDeleteUserModal, EditUserModal, ManageUserGroupsModal, ManageUserRolesModal, UnlinkUserModal}
};

/// Main Users Section component
#[component]
pub fn UsersSection(
    users: Resource<Result<Vec<rb_types::users::UserGroupInfo>, ServerFnError>>,
    toast: Signal<Option<ToastMessage>>,
    roles: Resource<Result<Vec<rb_types::users::RoleInfo>, ServerFnError>>,
    groups: Resource<Result<Vec<rb_types::users::GroupInfo>, ServerFnError>>,
) -> Element {
    // Delete confirmation state
    let mut delete_confirm_open = use_signal(|| false);
    let mut delete_target_name = use_signal(String::new);
    let mut delete_target_id = use_signal(|| 0i64);

    let mut edit_modal_open = use_signal(|| false);
    let mut editing_user_id = use_signal(|| None::<i64>);
    let mut editing_username = use_signal(|| None::<String>);
    let oidc_refresh_trigger = use_signal(|| 0u32);

    // Manage roles modal state
    let mut manage_roles_modal_open = use_signal(|| false);
    let mut manage_roles_user_id = use_signal(|| 0i64);
    let mut manage_roles_username = use_signal(String::new);
    let mut manage_roles_current = use_signal(Vec::<String>::new);
    let mut manage_roles_available = use_signal(Vec::<String>::new);
    let manage_roles_selected = use_signal(String::new);

    // Group management state
    let mut manage_groups_modal_open = use_signal(|| false);
    let mut manage_groups_user_id = use_signal(|| 0i64);
    let mut manage_groups_username = use_signal(String::new);
    let mut manage_groups_current = use_signal(Vec::<String>::new);
    let mut manage_groups_available = use_signal(Vec::<String>::new);
    let manage_groups_selected = use_signal(String::new);

    let mut open_edit = move |user_id: i64, username: String| {
        editing_user_id.set(Some(user_id));
        editing_username.set(Some(username));
        edit_modal_open.set(true);
    };

    let mut open_manage_roles = move |user_obj: &rb_types::users::UserGroupInfo| {
        manage_roles_user_id.set(user_obj.id);
        manage_roles_username.set(user_obj.username.clone());
        manage_roles_current.set(user_obj.roles.clone());

        if let Some(Ok(all_roles)) = roles.value()().as_ref() {
            let available: Vec<String> = all_roles
                .iter()
                .map(|r| r.name.clone())
                .filter(|r| !user_obj.roles.contains(r))
                .collect();
            manage_roles_available.set(available);
        }

        manage_roles_modal_open.set(true);
    };

    let mut open_manage_groups = move |user_obj: &rb_types::users::UserGroupInfo| {
        manage_groups_user_id.set(user_obj.id);
        manage_groups_username.set(user_obj.username.clone());
        manage_groups_current.set(user_obj.groups.clone());

        if let Some(Ok(all_groups)) = groups.value()().as_ref() {
            let available: Vec<String> = all_groups
                .iter()
                .map(|g| g.name.clone())
                .filter(|g| !user_obj.groups.contains(g))
                .collect();
            manage_groups_available.set(available);
        }

        manage_groups_modal_open.set(true);
    };

    let mut open_delete_confirm = move |target_id: i64, target_name: String| {
        delete_target_id.set(target_id);
        delete_target_name.set(target_name);
        delete_confirm_open.set(true);
    };

    let handle_delete = move |_| {
        let target_id = delete_target_id();
        let target_name = delete_target_name();

        spawn(async move {
            match delete_user(target_id).await {
                Ok(_) => {
                    delete_confirm_open.set(false);
                    toast.set(Some(ToastMessage {
                        message: format!("User '{}' deleted successfully", target_name),
                        toast_type: ToastType::Success,
                    }));
                    users.restart();
                }
                Err(e) => {
                    delete_confirm_open.set(false);
                    toast.set(Some(ToastMessage {
                        message: format!("Failed to delete user: {}", e),
                        toast_type: ToastType::Error,
                    }));
                }
            }
        });
    };

    rsx! {
        Protected {
            claim: Some(ClaimType::Users(ClaimLevel::View)),
            div { class: "card bg-base-200 shadow-xl self-start w-full",
                div { class: "card-body",
                    h2 { class: "card-title", "Users" }
                    p { "Manage system users and their group memberships." }
                    match users() {
                        Some(Ok(user_list)) => rsx! {
                            Table {
                                headers: vec!["Username", "Groups", "Roles", "Claims", "Relays", "SSH Keys", "OIDC", "Actions"],
                                for user in user_list {
                                    tr {
                                        td { class: "text-left", "{user.username}" }
                                        td { class: "text-center",
                                            // Groups Column
                                            StructuredTooltip {
                                                sections: vec![TooltipSection::new("Groups").with_items(user.groups.clone())],
                                                button {
                                                    class: if user.groups.is_empty() {
                                                        "badge badge-ghost whitespace-nowrap cursor-pointer hover:brightness-90"
                                                    } else {
                                                        "badge badge-primary whitespace-nowrap cursor-pointer hover:brightness-90"
                                                    },
                                                    onclick: {
                                                        let u = user.clone();
                                                        move |_| open_manage_groups(&u)
                                                    },
                                                    if user.groups.is_empty() {
                                                        "No groups"
                                                    } else if user.groups.len() == 1 {
                                                        "1 group"
                                                    } else {
                                                        "{user.groups.len()} groups"
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
                                            // Roles Column
                                            StructuredTooltip {
                                                sections: vec![TooltipSection::new("Roles").with_items(user.roles.clone())],
                                                button {
                                                    class: if user.roles.is_empty() {
                                                        "badge badge-ghost whitespace-nowrap cursor-pointer hover:brightness-90"
                                                    } else {
                                                        "badge badge-info whitespace-nowrap cursor-pointer hover:brightness-90"
                                                    },
                                                    onclick: {
                                                        let u = user.clone();
                                                        move |_| open_manage_roles(&u)
                                                    },
                                                    if user.roles.is_empty() {
                                                        "No roles"
                                                    } else if user.roles.len() == 1 {
                                                        "{user.roles[0]}"
                                                    } else {
                                                        "{user.roles.len()} roles"
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
                                            // Claims Column (Effective Claims)
                                            {
                                                let direct_claims = user.claims.clone();

                                                // Collect Role Claims
                                                let mut role_claims = Vec::new();
                                                if let Some(Ok(role_list)) = roles.value()().as_ref() {
                                                    for role_name in &user.roles {
                                                        if let Some(r) = role_list.iter().find(|r| &r.name == role_name) {
                                                            role_claims.extend(r.claims.clone());
                                                        }
                                                    }
                                                }

                                                // Collect Group Claims (Direct + via Group Roles)
                                                let mut group_combined_claims = Vec::new();

                                                if let Some(Ok(group_list)) = groups.value()().as_ref() {
                                                    for group_name in &user.groups {
                                                        if let Some(g) = group_list.iter().find(|g| &g.name == group_name) {
                                                            // Direct group claims
                                                            for claim in &g.claims {
                                                                group_combined_claims.push(claim.to_string());
                                                            }

                                                            // Claims from roles assigned to this group
                                                            if let Some(Ok(role_list)) = roles.value()().as_ref() {
                                                                for role_name in &g.roles {
                                                                    if let Some(r) = role_list.iter().find(|r| &r.name == role_name) {
                                                                        for claim in &r.claims {
                                                                             group_combined_claims.push(format!("{} (via Role)", claim));
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }

                                                // Dedup
                                                group_combined_claims.sort();
                                                group_combined_claims.dedup();

                                                let total_count = direct_claims.len() + role_claims.len() + group_combined_claims.len();

                                                rsx! {
                                                    if total_count == 0 {
                                                        span { class: "badge badge-ghost whitespace-nowrap", "None" }
                                                    } else {
                                                        StructuredTooltip {
                                                            sections: vec![
                                                                TooltipSection::new("Direct Claims").with_items(direct_claims.iter().map(|c| c.to_string()).collect()),
                                                                TooltipSection::new("Role Claims").with_items(role_claims.iter().map(|c| c.to_string()).collect()),
                                                                TooltipSection::new("Group Claims").with_items(group_combined_claims),
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
                                            if user.relays.is_empty() {
                                                span { class: "badge badge-ghost whitespace-nowrap", "No access" }
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
                                                    span { class: "badge badge-warning whitespace-nowrap",
                                                        "{user.relays.len()} "
                                                        {if user.relays.len() == 1 { "relay" } else { "relays" }}
                                                    }
                                                }
                                            }
                                        }
                                        td { class: "text-center",
                                            if user.ssh_key_count > 0 {
                                                span { class: "badge badge-neutral whitespace-nowrap", "{user.ssh_key_count} keys" }
                                            } else {
                                                span { class: "badge badge-ghost text-xs text-center whitespace-nowrap", "None" }
                                            }
                                        }
                                        td { class: "text-center",
                                            OidcStatusCell {
                                                user_id: user.id,
                                                username: user.username.clone(),
                                                oidc_refresh_trigger,
                                                toast,
                                                users,
                                            }
                                        }
                                        td { class: "text-right",
                                            Protected {
                                                any_claims: vec![ClaimType::Users(ClaimLevel::Edit), ClaimType::Users(ClaimLevel::Delete)],
                                                TableActions {
                                                    on_edit: {
                                                        let user_id = user.id;
                                                        let username = user.username.clone();
                                                        move |_| open_edit(user_id, username.clone())
                                                    },
                                                    on_delete: {
                                                        let user_id = user.id;
                                                        let username = user.username.clone();
                                                        move |_| open_delete_confirm(user_id, username.clone())
                                                    }
                                                },
                                            }
                                        }
                                    }
                                }
                            }
                            Protected {
                                any_claims: vec![ClaimType::Users(ClaimLevel::Delete)],
                                ConfirmDeleteUserModal {
                                    user_id: delete_target_id,
                                    username: delete_target_name,
                                    delete_confirm_open,
                                    handle_delete,
                                }
                            }
                            Protected {
                                any_claims: vec![ClaimType::Roles(ClaimLevel::Edit)],
                                ManageUserRolesModal {
                                    roles_modal_open: manage_roles_modal_open,
                                    user_id: manage_roles_user_id,
                                    username: manage_roles_username,
                                    user_roles: manage_roles_current,
                                    available_roles: manage_roles_available,
                                    selected_role_to_add: manage_roles_selected,
                                    roles,
                                    users,
                                    toast,
                                }
                            }
                            Protected {
                                any_claims: vec![ClaimType::Groups(ClaimLevel::Edit)],
                                ManageUserGroupsModal {
                                    groups_modal_open: manage_groups_modal_open,
                                    user_id: manage_groups_user_id,
                                    username: manage_groups_username,
                                    user_groups: manage_groups_current,
                                    available_groups: manage_groups_available,
                                    selected_group_to_add: manage_groups_selected,
                                    users,
                                    groups,
                                    toast,
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

        if editing_username().is_some() {
            EditUserModal {
                open: edit_modal_open,
                user_id: editing_user_id,
                username: editing_username,
                users,
                toast,
                roles,
                groups,
            }
        }
    }
}

/// OIDC Status Cell with unlink functionality
#[component]
fn OidcStatusCell(
    user_id: i64,
    username: String,
    oidc_refresh_trigger: Signal<u32>,
    toast: Signal<Option<ToastMessage>>,
    users: Resource<Result<Vec<rb_types::users::UserGroupInfo>, ServerFnError>>,
) -> Element {
    // Track per-user OIDC status; kept inside its own component to satisfy Dioxus hook ordering rules.
    let mut oidc_status = use_signal(|| None::<OidcLinkStatus>);
    let mut unlink_modal_open = use_signal(|| false);

    // Refresh when the shared trigger bumps (e.g., after unlink) or on initial mount.
    use_effect(move || {
        let trigger = oidc_refresh_trigger();
        spawn(async move {
            let _ = trigger;
            match get_user_oidc_status(user_id).await {
                Ok(status) => oidc_status.set(Some(status)),
                Err(_) => oidc_status.set(None),
            }
        });
    });

    let handle_unlink = {
        let username_for_unlink = username.clone();
        move |_| {
            let username_clone = username_for_unlink.clone();
            spawn(async move {
                match unlink_user_oidc(user_id).await {
                    Ok(_) => {
                        unlink_modal_open.set(false);
                        toast.set(Some(ToastMessage {
                            message: format!("OIDC account unlinked for user '{}'", username_clone),
                            toast_type: ToastType::Success,
                        }));
                        oidc_refresh_trigger.set(oidc_refresh_trigger() + 1);
                        users.restart();
                    }
                    Err(e) => {
                        unlink_modal_open.set(false);
                        toast.set(Some(ToastMessage {
                            message: format!("Failed to unlink OIDC: {}", e),
                            toast_type: ToastType::Error,
                        }));
                    }
                }
            });
        }
    };

    if let Some(status) = oidc_status()
        && status.is_linked
    {
        return rsx! {
            HoverSwapButton {
                on_click: move |_| unlink_modal_open.set(true),
                class: "badge badge-success whitespace-nowrap cursor-pointer hover:brightness-90",
                regular: rsx! {
                    "Linked"
                    icons::LockIcon {}
                },
                hover: rsx! {
                    "Unlink"
                    icons::XIcon {}
                }
            },
            UnlinkUserModal {
                username,
                unlink_modal_open,
                on_unlink: handle_unlink
            }
        };
    }

    rsx! {
        span { class: "badge badge-ghost whitespace-nowrap", "Not linked" }
    }
}
