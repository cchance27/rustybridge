//! Roles section with table and modals
//! Self-contained components for managing roles

use dioxus::prelude::*;
use rb_types::auth::{ClaimLevel, ClaimType};

use crate::{
    app::api::roles::*, components::{Protected, StructuredTooltip, Table, ToastMessage, ToastType, TooltipSection, icons}, pages::access::modals::{ConfirmDeleteRoleModal, EditRoleClaimsModal, ManageRoleGroupsModal, ManageRoleUsersModal}
};

/// Main Roles Section component
#[component]
pub fn RolesSection(
    roles: Resource<Result<Vec<rb_types::users::RoleInfo>, ServerFnError>>,
    users: Resource<Result<Vec<rb_types::users::UserGroupInfo>, ServerFnError>>,
    groups: Resource<Result<Vec<rb_types::users::GroupInfo>, ServerFnError>>,
    toast: Signal<Option<ToastMessage>>,
) -> Element {
    // Delete confirmation state
    let mut delete_confirm_open = use_signal(|| false);
    let mut delete_target_name = use_signal(String::new);

    // Role claims modal state
    let mut role_claims_modal_open = use_signal(|| false);
    let mut claims_role_name = use_signal(String::new);
    let mut role_claims = use_signal(Vec::<rb_types::auth::ClaimType>::new);
    let mut role_selected_claim_to_add = use_signal(String::new);

    // Role users modal state
    let mut users_modal_open = use_signal(|| false);
    let mut users_role_name = use_signal(String::new);
    let mut role_users = use_signal(Vec::<String>::new);
    let mut available_users_for_role = use_signal(Vec::<String>::new);
    let mut selected_user_to_add = use_signal(String::new);

    // Role groups modal state
    let mut groups_modal_open = use_signal(|| false);
    let mut groups_role_name = use_signal(String::new);
    let mut role_groups = use_signal(Vec::<String>::new);
    let mut available_groups_for_role = use_signal(Vec::<String>::new);
    let mut selected_group_to_add = use_signal(String::new);

    let mut open_delete_confirm = move |role_name: String| {
        delete_target_name.set(role_name);
        delete_confirm_open.set(true);
    };

    let mut open_manage_claims = move |role: String| {
        claims_role_name.set(role.clone());
        role_selected_claim_to_add.set(String::new());

        // Find role to get claims
        if let Some(Ok(list)) = roles.value()().as_ref()
            && let Some(r) = list.iter().find(|r| r.name == role)
        {
            role_claims.set(r.claims.clone());
        }

        role_claims_modal_open.set(true);
    };

    let mut open_manage_users = move |role: String| {
        users_role_name.set(role.clone());
        selected_user_to_add.set(String::new());

        // Load users for this role
        spawn(async move {
            if let Ok(user_list) = list_role_users(role.clone()).await {
                role_users.set(user_list.clone());

                // Get all users and filter out those already in the role
                if let Ok(all_users) = crate::app::api::users::list_users().await {
                    let available: Vec<String> = all_users
                        .into_iter()
                        .map(|u| u.username)
                        .filter(|u| !user_list.contains(u))
                        .collect();
                    available_users_for_role.set(available);
                }
            }
            users_modal_open.set(true);
        });
    };

    let mut open_manage_groups = move |role: String| {
        groups_role_name.set(role.clone());
        selected_group_to_add.set(String::new());

        // Load groups for this role
        spawn(async move {
            if let Ok(group_list) = list_role_groups(role.clone()).await {
                role_groups.set(group_list.clone());

                // Get all groups and filter out those already in the role
                if let Ok(all_groups) = crate::app::api::groups::list_groups().await {
                    let available: Vec<String> = all_groups.into_iter().map(|g| g.name).filter(|g| !group_list.contains(g)).collect();
                    available_groups_for_role.set(available);
                }
            }
            groups_modal_open.set(true);
        });
    };

    let handle_delete = move |_| {
        let target_name = delete_target_name();

        spawn(async move {
            match delete_role(target_name.clone()).await {
                Ok(_) => {
                    delete_confirm_open.set(false);
                    toast.set(Some(ToastMessage {
                        message: format!("Role '{}' deleted successfully", target_name),
                        toast_type: ToastType::Success,
                    }));
                    roles.restart();
                    users.restart();
                    groups.restart();
                }
                Err(e) => {
                    delete_confirm_open.set(false);
                    toast.set(Some(ToastMessage {
                        message: format!("Failed to delete role: {}", e),
                        toast_type: ToastType::Error,
                    }));
                }
            }
        });
    };

    rsx! {
        Protected {
            claim: Some(ClaimType::Roles(ClaimLevel::View)),
            div { class: "card bg-base-200 shadow-xl self-start w-full",
                div { class: "card-body",
                    h2 { class: "card-title", "Roles" }
                    p { "Manage roles and assign them to users and groups." }

                    match roles() {
                        Some(Ok(role_list)) => rsx! {
                            Table {
                                headers: vec!["Role Name", "Description", "Users", "Groups", "Claims", "Actions"],
                                for role in role_list {
                                    tr {
                                        td { class: "text-left",
                                            "{role.name}"
                                            if role.name == "Super Admin" {
                                                span { class: "badge badge-warning badge-xs ml-2", "Protected" }
                                            }
                                        }
                                        td { class: "text-center",
                                            if let Some(desc) = &role.description {
                                                "{desc}"
                                            } else {
                                                span { class: "text-gray-500 italic", "No description" }
                                            }
                                        }
                                        td { class: "text-center",
                                            StructuredTooltip {
                                                sections: {
                                                    let mut sections = Vec::new();
                                                    if !role.users.is_empty() {
                                                        sections.push(TooltipSection::new("Users").with_items(role.users.clone()));
                                                    } else {
                                                        sections.push(TooltipSection::without_header().with_empty_message("No users"));
                                                    }
                                                    sections
                                                },
                                                Protected {
                                                    claim: Some(ClaimType::Roles(ClaimLevel::Edit)),
                                                    fallback: rsx! {
                                                        span { class: "badge badge-accent whitespace-nowrap",
                                                            "{role.user_count} "
                                                            {if role.user_count == 1 { "user" } else { "users" }}
                                                        }
                                                    },
                                                    button {
                                                        class: "badge badge-accent cursor-pointer hover:brightness-90 whitespace-nowrap",
                                                        onclick: {
                                                            let r = role.name.clone();
                                                            move |_| open_manage_users(r.clone())
                                                        },
                                                        "{role.user_count} "
                                                        {if role.user_count == 1 { "user" } else { "users" }}
                                                        icons::EditIcon {}
                                                    }
                                                }
                                            }
                                        }
                                        td { class: "text-center",
                                            StructuredTooltip {
                                                sections: {
                                                    let mut sections = Vec::new();
                                                    if !role.groups.is_empty() {
                                                        sections.push(TooltipSection::new("Groups").with_items(role.groups.clone()));
                                                    } else {
                                                        sections.push(TooltipSection::without_header().with_empty_message("No groups"));
                                                    }
                                                    sections
                                                },
                                                Protected {
                                                    claim: Some(ClaimType::Roles(ClaimLevel::Edit)),
                                                    fallback: rsx! {
                                                        span { class: "badge badge-primary whitespace-nowrap",
                                                            "{role.group_count} "
                                                            {if role.group_count == 1 { "group" } else { "groups" }}
                                                        }
                                                    },
                                                    button {
                                                        class: "badge badge-primary cursor-pointer hover:brightness-90 whitespace-nowrap",
                                                        onclick: {
                                                            let r = role.name.clone();
                                                            move |_| open_manage_groups(r.clone())
                                                        },
                                                        "{role.group_count} "
                                                        {if role.group_count == 1 { "group" } else { "groups" }}
                                                        icons::EditIcon {}
                                                    }
                                                }
                                            }
                                        }
                                        td { class: "text-center",
                                            StructuredTooltip {
                                                sections: {
                                                    let mut sections = Vec::new();
                                                    if !role.claims.is_empty() {
                                                        let claim_strs: Vec<String> = role.claims.iter().map(|c| c.to_string()).collect();
                                                        sections.push(TooltipSection::new("Claims").with_items(claim_strs));
                                                    } else {
                                                        sections.push(TooltipSection::without_header().with_empty_message("No claims"));
                                                    }
                                                    sections
                                                },
                                                Protected {
                                                    claim: Some(ClaimType::Roles(ClaimLevel::Edit)),
                                                    fallback: rsx! {
                                                        span { class: "badge badge-success whitespace-nowrap",
                                                            "{role.claims.len()} "
                                                            {if role.claims.len() == 1 { "claim" } else { "claims" }}
                                                        }
                                                    },
                                                    button {
                                                        class: {if role.name == "Super Admin" { "badge cursor-not-allowed whitespace-nowrap hover:brightness-90" } else { "badge badge-success cursor-pointer hover:brightness-90 whitespace-nowrap" }},
                                                        disabled: role.name == "Super Admin",
                                                        title: if role.name == "Super Admin" { "Cannot edit Super Admin role claims" } else { "" },
                                                        onclick: {
                                                            let r = role.name.clone();
                                                            move |_| open_manage_claims(r.clone())
                                                        },
                                                        "{role.claims.len()} "
                                                        {if role.claims.len() == 1 { "claim" } else { "claims" }}
                                                        {if role.name != "Super Admin" { rsx! { icons::EditIcon {} } } else { rsx! {} }}
                                                    }
                                                }
                                            }
                                        }
                                        td { class: "text-right",
                                            Protected {
                                                any_claims: vec![ClaimType::Roles(ClaimLevel::Delete)],
                                                button {
                                                    class: { if role.name == "Super Admin" { "btn btn-xs btn-secondary cursor-not-allowed" } else { "btn btn-xs btn-secondary" } },
                                                    disabled: role.name == "Super Admin",
                                                    title: if role.name == "Super Admin" { "Cannot delete Super Admin role" } else { "" },
                                                    onclick: {
                                                        let r_name = role.name.clone();
                                                        move |_| open_delete_confirm(r_name.clone())
                                                    },
                                                    "Delete"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        Some(Err(e)) => rsx! {
                            div { class: "alert alert-error",
                                span { "Error loading roles: {e}" }
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

        ConfirmDeleteRoleModal {
            role_name: delete_target_name,
            delete_confirm_open,
            handle_delete,
        }

        EditRoleClaimsModal {
            role_claims_modal_open,
            claims_role_name,
            role_claims,
            role_selected_claim_to_add,
            roles,
            toast,
        }

        ManageRoleUsersModal {
            users_modal_open,
            users_role_name,
            role_users,
            available_users: available_users_for_role,
            selected_user_to_add,
            roles,
            users,
            toast,
        }

        ManageRoleGroupsModal {
            groups_modal_open,
            groups_role_name,
            role_groups,
            available_groups: available_groups_for_role,
            selected_group_to_add,
            roles,
            groups,
            toast,
        }
    }
}
