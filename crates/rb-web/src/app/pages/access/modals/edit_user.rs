use std::{collections::HashMap, str::FromStr as _};

use dioxus::prelude::*;
use rb_types::{auth::ClaimType, users::UpdateUserRequest};

use crate::{
    app::api::{
        groups::{add_member_to_group, remove_member_from_group}, roles::{assign_role_to_user, revoke_role_from_user}, users::*
    }, components::{Modal, ToastMessage, ToastType}
};

/// Edit User Modal with password, roles, groups, and claims management
#[component]
pub fn EditUserModal(
    open: Signal<bool>,
    user_id: Signal<Option<i64>>,
    username: Signal<Option<String>>,
    roles: Resource<Result<Vec<rb_types::users::RoleInfo>, ServerFnError>>,
    groups: Resource<Result<Vec<rb_types::users::GroupInfo>, ServerFnError>>,
    users: Resource<Result<Vec<rb_types::users::UserGroupInfo>, ServerFnError>>,
    toast: Signal<Option<ToastMessage>>,
) -> Element {
    let Some(username_str) = username() else {
        return rsx!();
    };
    let Some(user_id_val) = user_id() else {
        return rsx!();
    };

    let mut active_tab = use_signal(|| "general"); // general, groups, roles, claims

    let mut password = use_signal(String::new);
    let mut validation_errors = use_signal(HashMap::<String, String>::new);

    let mut user_claims = use_signal(Vec::<ClaimType>::new);
    let mut selected_claim_to_add = use_signal(String::new);

    let mut user_roles = use_signal(Vec::<String>::new);
    let mut selected_role_to_add = use_signal(String::new);

    let mut user_groups = use_signal(Vec::<String>::new);
    let mut selected_group_to_add = use_signal(String::new);

    // Load user data when modal opens
    let user_id_for_effect = user_id_val;
    let username_for_effect = username_str.clone();
    use_effect(move || {
        let user_id_for_spawn = user_id_for_effect;
        let username_for_spawn = username_for_effect.clone();
        spawn(async move {
            // Need to access current value of open()
            let is_open = open();
            if is_open {
                // Load claims using ID
                if let Ok(claims) = get_user_claims(user_id_for_spawn).await {
                    user_claims.set(claims);
                }

                // Load roles and groups (from users resource if available)
                if let Some(Ok(user_list)) = users.value()().as_ref()
                    && let Some(user) = user_list.iter().find(|u| u.username == username_for_spawn)
                {
                    user_roles.set(user.roles.clone());
                    user_groups.set(user.groups.clone());
                }
            }
        });
    });

    let user_id_for_save = user_id_val;
    let username_for_save = username_str.clone();
    let on_save = {
        move |_| {
            validation_errors.set(HashMap::new());

            let password_val = password();
            let mut errors = HashMap::new();

            if !password_val.trim().is_empty() && password_val.len() < 8 {
                errors.insert("password".to_string(), "Password must be at least 8 characters".to_string());
            }

            if !errors.is_empty() {
                validation_errors.set(errors);
                return;
            }
            let user_id_for_spawn = user_id_for_save;
            let username_for_message = username_for_save.clone();
            let password_val_clone = password_val.clone();
            spawn(async move {
                match update_user(
                    user_id_for_spawn, // Use user ID instead of username
                    UpdateUserRequest {
                        password: if password_val_clone.is_empty() {
                            None
                        } else {
                            Some(password_val_clone)
                        },
                    },
                )
                .await
                {
                    Ok(_) => {
                        open.set(false);
                        password.set(String::new());
                        toast.set(Some(ToastMessage {
                            message: format!("User '{}' updated successfully", username_for_message),
                            toast_type: ToastType::Success,
                        }));
                        users.restart();
                    }
                    Err(e) => {
                        toast.set(Some(ToastMessage {
                            message: format!("Failed to update user: {}", e),
                            toast_type: ToastType::Error,
                        }));
                    }
                }
            });
        }
    };

    // Claims Logic
    let user_id_for_remove_claim = user_id_val;
    let remove_claim_handler = move |claim: ClaimType, user: String| {
        let user_id_for_spawn = user_id_for_remove_claim;
        spawn(async move {
            let claim_str = claim.to_string();
            match remove_user_claim(user_id_for_spawn, claim.clone()).await {
                Ok(_) => {
                    users.restart();
                    let mut current = user_claims();
                    current.retain(|c| c != &claim);
                    user_claims.set(current);
                    toast.set(Some(ToastMessage {
                        message: format!("Removed claim '{}' from user '{}'", claim_str, user),
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

    let user_id_for_add_claim = user_id_val;
    let username_for_add_claim = username_str.clone();
    let add_claim = {
        move |_| {
            let claim_str = selected_claim_to_add();
            if claim_str.is_empty() {
                return;
            }

            let user_id_for_spawn = user_id_for_add_claim;
            let username_for_message = username_for_add_claim.clone();
            spawn(async move {
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

                match add_user_claim(user_id_for_spawn, claim_type.clone()).await {
                    Ok(_) => {
                        users.restart();
                        let mut current = user_claims();
                        if !current.contains(&claim_type) {
                            current.push(claim_type);
                            user_claims.set(current);
                        }
                        selected_claim_to_add.set(String::new());
                        toast.set(Some(ToastMessage {
                            message: format!("Added claim '{}' to user '{}'", claim_str, username_for_message),
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
        }
    };

    // Roles Logic
    let username_for_add_role = username_str.clone();
    let add_role = move |_| {
        let role_name = selected_role_to_add();
        let user_name = username_for_add_role.clone();
        let user_id_for_add = user_id_val;

        if role_name.is_empty() {
            return;
        }

        spawn(async move {
            // Find role ID from role name
            if let Some(Ok(all_roles)) = roles.value()().as_ref()
                && let Some(role) = all_roles.iter().find(|r| r.name == role_name)
            {
                match assign_role_to_user(user_id_for_add, role.id).await {
                    Ok(_) => {
                        users.restart();
                        roles.restart();
                        let mut current = user_roles();
                        current.push(role_name.clone());
                        user_roles.set(current);
                        selected_role_to_add.set(String::new());
                        toast.set(Some(ToastMessage {
                            message: format!("Assigned role '{}' to user '{}'", role_name, user_name),
                            toast_type: ToastType::Success,
                        }));
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

    let remove_role_handler = move |role_name: String, user_name: String| {
        let user_id_for_remove = user_id_val;
        spawn(async move {
            // Find role ID from role name
            if let Some(Ok(all_roles)) = roles.value()().as_ref()
                && let Some(role) = all_roles.iter().find(|r| r.name == role_name)
            {
                match revoke_role_from_user(user_id_for_remove, role.id).await {
                    Ok(_) => {
                        users.restart();
                        roles.restart();
                        let mut current = user_roles();
                        current.retain(|r| r != &role_name);
                        user_roles.set(current);
                        toast.set(Some(ToastMessage {
                            message: format!("Removed role '{}' from user '{}'", role_name, user_name),
                            toast_type: ToastType::Success,
                        }));
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

    // Groups Logic
    let user_id_for_add_group = user_id_val;
    let username_for_add_group = username_str.clone();
    let add_group = move |_| {
        let group_name = selected_group_to_add();
        let username = username_for_add_group.clone();
        let user_id_for_spawn = user_id_for_add_group;

        if group_name.is_empty() {
            return;
        }

        spawn(async move {
            // Find group ID from group name
            if let Some(Ok(all_groups)) = groups.value()().as_ref()
                && let Some(group) = all_groups.iter().find(|g| g.name == group_name)
            {
                match add_member_to_group(group.id, user_id_for_spawn).await {
                    Ok(_) => {
                        users.restart();
                        groups.restart();
                        let mut current = user_groups();
                        current.push(group_name.clone());
                        user_groups.set(current);
                        selected_group_to_add.set(String::new());
                        toast.set(Some(ToastMessage {
                            message: format!("Added user '{}' to group '{}'", username, group_name),
                            toast_type: ToastType::Success,
                        }));
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

    let user_id_for_remove_group = user_id_val;
    let remove_group_handler = move |group_name: String, username: String| {
        let user_id_for_spawn = user_id_for_remove_group;

        spawn(async move {
            // Find group ID from group name
            if let Some(Ok(all_groups)) = groups.value()().as_ref()
                && let Some(group) = all_groups.iter().find(|g| g.name == group_name)
            {
                match remove_member_from_group(group.id, user_id_for_spawn).await {
                    Ok(_) => {
                        users.restart();
                        groups.restart();
                        let mut current = user_groups();
                        current.retain(|g| g != &group_name);
                        user_groups.set(current);
                        toast.set(Some(ToastMessage {
                            message: format!("Removed user '{}' from group '{}'", username, group_name),
                            toast_type: ToastType::Success,
                        }));
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

    // Calculate available items
    let available_roles_list = {
        if let Some(Ok(all_roles)) = roles.value()().as_ref() {
            all_roles
                .iter()
                .map(|r| r.name.clone())
                .filter(|r| !user_roles().contains(r))
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        }
    };

    let available_groups_list = {
        if let Some(Ok(all_groups)) = groups.value()().as_ref() {
            all_groups
                .iter()
                .map(|g| g.name.clone())
                .filter(|g| !user_groups().contains(g))
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        }
    };

    let username_for_rsx = username_str.clone();
    rsx! {
        Modal {
            open: open(),
            on_close: move |_| {
                open.set(false);
                password.set(String::new());
                validation_errors.set(HashMap::new());
                active_tab.set("general");
            },
            title: "Edit User",
            div { class: "flex flex-col gap-4",
                 // Tabs
                div { class: "tabs tabs-boxed",
                    a {
                        class: if active_tab() == "general" { "tab tab-active" } else { "tab" },
                        onclick: move |_| active_tab.set("general"),
                        "General"
                    }
                    a {
                        class: if active_tab() == "groups" { "tab tab-active" } else { "tab" },
                        onclick: move |_| active_tab.set("groups"),
                        "Groups"
                    }
                    a {
                        class: if active_tab() == "roles" { "tab tab-active" } else { "tab" },
                        onclick: move |_| active_tab.set("roles"),
                        "Roles"
                    }
                    a {
                        class: if active_tab() == "claims" { "tab tab-active" } else { "tab" },
                        onclick: move |_| active_tab.set("claims"),
                        "Claims"
                    }
                }

                div { class: "mt-2",
                    if active_tab() == "general" {
                        div { class: "flex flex-col gap-4",
                            div { class: "form-control w-full",
                                div { class: "label", span { class: "label-text", "Username" } }
                                div { class: "text-lg font-semibold py-2", "{username_for_rsx}" }
                            }

                            label { class: "form-control w-full",
                                div { class: "label items-center justify-between",
                                    span { class: "label-text", "Password" }
                                    span { class: "badge badge-warning badge-xs", "Stored • not shown" }
                                }
                                input {
                                    r#type: "password",
                                    class: if validation_errors().contains_key("password") {
                                        "input input-bordered w-full input-error"
                                    } else {
                                        "input input-bordered w-full"
                                    },
                                    placeholder: "••••••••",
                                    value: "{password}",
                                    oninput: move |e| {
                                        password.set(e.value());
                                        if validation_errors().contains_key("password") {
                                            let mut errs = validation_errors();
                                            errs.remove("password");
                                            validation_errors.set(errs);
                                        }
                                    }
                                }
                                if let Some(err) = validation_errors().get("password") {
                                    div { class: "text-error text-sm mt-1", "{err}" }
                                }
                            }
                            p { class: "text-xs text-gray-500",
                                "Secrets are encrypted and not displayed. Leave blank to keep the existing password."
                            }

                            div { class: "flex justify-end mt-4",
                                button { class: "btn btn-primary", onclick: on_save, "Save Password" }
                            }
                        }
                    }

                    if active_tab() == "groups" {
                         div { class: "flex flex-col gap-4",
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
                                                        let u = username_for_rsx.clone();
                                                        move |_| remove_group_handler(g.clone(), u.clone())
                                                    },
                                                    "×"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            div { class: "divider" }
                            div { class: "flex gap-2",
                                select {
                                    class: "select select-bordered flex-1",
                                    value: "{selected_group_to_add}",
                                    onchange: move |e| selected_group_to_add.set(e.value()),
                                    option { value: "", "Select a group..." }
                                    for group in available_groups_list {
                                        option { value: "{group}", "{group}" }
                                    }
                                }
                                button {
                                    class: "btn btn-primary",
                                    disabled: selected_group_to_add().is_empty(),
                                    onclick: add_group,
                                    "Assign"
                                }
                            }
                        }
                    }

                    if active_tab() == "roles" {
                         div { class: "flex flex-col gap-4",
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
                                                        let u = username_for_rsx.clone();
                                                        move |_| remove_role_handler(r.clone(), u.clone())
                                                    },
                                                    "×"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            div { class: "divider" }
                            div { class: "flex gap-2",
                                select {
                                    class: "select select-bordered flex-1",
                                    value: "{selected_role_to_add}",
                                    onchange: move |e| selected_role_to_add.set(e.value()),
                                    option { value: "", "Select a role..." }
                                    for role in available_roles_list {
                                        option { value: "{role}", "{role}" }
                                    }
                                }
                                button {
                                    class: "btn btn-secondary",
                                    disabled: selected_role_to_add().is_empty(),
                                    onclick: add_role,
                                    "Assign"
                                }
                            }
                        }
                    }

                    if active_tab() == "claims" {
                        div { class: "flex flex-col gap-4",
                            div {
                                h4 { class: "font-semibold mb-2", "Direct Claims" }
                                if user_claims().is_empty() {
                                    p { class: "text-gray-500 italic", "No direct claims assigned" }
                                } else {
                                    div { class: "flex flex-wrap gap-2",
                                        for claim in user_claims() {
                                            div { class: "badge badge-lg badge-info gap-2",
                                                span { "{claim}" }
                                                button {
                                                    class: "btn btn-xs btn-circle btn-ghost",
                                                    onclick: {
                                                        let c = claim.clone();
                                                        let u = username_for_rsx.clone();
                                                        move |_| remove_claim_handler(c.clone(), u.clone())
                                                    },
                                                    "×"
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            div { class: "divider" }

                            div { class: "flex gap-2",
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
                                    class: "btn btn-info",
                                    disabled: selected_claim_to_add().is_empty(),
                                    onclick: add_claim,
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
