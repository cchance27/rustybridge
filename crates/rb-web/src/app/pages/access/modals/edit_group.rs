use std::{collections::HashMap, str::FromStr as _};

use dioxus::prelude::*;
use rb_types::{
    auth::ClaimType, users::{GroupInfo, RoleInfo}
};

use crate::{
    app::api::{
        groups::{add_group_claim, remove_group_claim}, roles::{assign_role_to_group, revoke_role_from_group}
    }, components::{Modal, use_toast}, error::ApiError
};

/// Edit Group Modal with name, roles, and claims management
#[component]
pub fn EditGroupModal(
    open: Signal<bool>,
    group_id: Signal<i64>,
    group_name: Signal<String>,
    roles: Resource<Result<Vec<RoleInfo<'static>>, ApiError>>,
    groups: Resource<Result<Vec<GroupInfo<'static>>, ApiError>>,
) -> Element {
    let name = group_name();
    let group_id_val = group_id();
    let mut active_tab = use_signal(|| "general"); // general, roles, claims
    let toast = use_toast();

    // Name state
    let mut edit_name = use_signal(String::new);
    let mut _validation_errors = use_signal(HashMap::<String, String>::new);

    // Roles state
    let mut group_roles = use_signal(Vec::<String>::new);
    let mut selected_role_to_add = use_signal(String::new);

    // Claims state
    let mut group_claims = use_signal(Vec::<ClaimType>::new);
    let mut selected_claim_to_add = use_signal(String::new);

    // Initialize data when modal opens
    use_effect(move || {
        if open() {
            let current_name = group_name();
            edit_name.set(current_name.clone());

            // Load roles and claims from the groups resource if available
            if let Some(Ok(group_list)) = groups.value()().as_ref()
                && let Some(group) = group_list.iter().find(|g| g.name == current_name)
            {
                group_roles.set(group.roles.clone());
                group_claims.set(group.claims.clone());
            }
        }
    });

    let name_for_save = name.clone();
    let on_save_general = move |_| {
        let new_name = edit_name();
        // Rename logic
        if new_name != name_for_save {
            spawn(async move {
                match crate::app::api::groups::update_group(group_id_val, new_name.clone()).await {
                    Ok(_) => {
                        toast.success(&format!("Renamed group to '{}'", new_name));
                        groups.restart();
                        open.set(false);
                    }
                    Err(e) => {
                        toast.error(&format!("Failed to rename group: {}", e));
                    }
                }
            });
        } else {
            open.set(false);
        }
    };

    // Role Handlers
    let add_role_handler = move |_| {
        let role_name = selected_role_to_add();
        let group_id_for_add = group_id_val;
        let group_name = group_name();
        if role_name.is_empty() {
            return;
        }

        spawn(async move {
            // Find role ID from role name
            if let Some(Ok(all_roles)) = roles.value()().as_ref()
                && let Some(role) = all_roles.iter().find(|r| r.name == role_name)
            {
                match assign_role_to_group(role.id, group_id_for_add).await {
                    Ok(_) => {
                        groups.restart();
                        roles.restart(); // Update roles too as counts change
                        let mut current = group_roles();
                        if !current.contains(&role_name) {
                            current.push(role_name.clone());
                            group_roles.set(current);
                        }
                        selected_role_to_add.set(String::new());
                        toast.success(&format!("Assigned role '{}' to group '{}'", role_name, group_name));
                    }
                    Err(e) => {
                        toast.error(&format!("Failed to assign role: {}", e));
                    }
                }
            }
        });
    };

    let remove_role_handler = move |role_name: String| {
        let group_id_for_remove = group_id_val;
        let group_name = group_name();
        spawn(async move {
            // Find role ID from role name
            if let Some(Ok(all_roles)) = roles.value()().as_ref()
                && let Some(role) = all_roles.iter().find(|r| r.name == role_name)
            {
                match revoke_role_from_group(role.id, group_id_for_remove).await {
                    Ok(_) => {
                        groups.restart();
                        roles.restart();
                        let mut current = group_roles();
                        current.retain(|r| r != &role_name);
                        group_roles.set(current);
                        toast.success(&format!("Removed role '{}' from group '{}'", role_name, group_name));
                    }
                    Err(e) => {
                        toast.error(&format!("Failed to remove role: {}", e));
                    }
                }
            }
        });
    };

    // Claim Handlers
    let add_claim_handler = move |_| {
        let claim_str = selected_claim_to_add();
        let group = group_name();
        if claim_str.is_empty() {
            return;
        }

        spawn(async move {
            let claim_type = match ClaimType::from_str(&claim_str) {
                Ok(ct) => ct,
                Err(e) => {
                    toast.error(&format!("Invalid claim format: {}", e));
                    return;
                }
            };

            match add_group_claim(group_id_val, claim_type.clone()).await {
                Ok(_) => {
                    groups.restart();
                    let mut current = group_claims();
                    if !current.contains(&claim_type) {
                        current.push(claim_type);
                        group_claims.set(current);
                    }
                    selected_claim_to_add.set(String::new());
                    toast.success(&format!("Added claim '{}' to group '{}'", claim_str, group));
                }
                Err(e) => {
                    toast.error(&format!("Failed to add claim: {}", e));
                }
            }
        });
    };

    let remove_claim_handler = move |claim: ClaimType<'static>| {
        let group_id_for_remove = group_id_val;
        let group = group_name();
        spawn(async move {
            match remove_group_claim(group_id_for_remove, claim.clone()).await {
                Ok(_) => {
                    groups.restart();
                    let mut current = group_claims();
                    current.retain(|c| c != &claim);
                    group_claims.set(current);
                    toast.success(&format!("Removed claim '{}' from group '{}'", claim, group));
                }
                Err(e) => {
                    toast.error(&format!("Failed to remove claim: {}", e));
                }
            }
        });
    };

    // Helper to calculate available roles
    let available_roles_list = {
        if let Some(Ok(all_roles)) = roles.value()().as_ref() {
            all_roles
                .iter()
                .map(|r| r.name.clone())
                .filter(|r| !group_roles().contains(r))
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        }
    };

    rsx! {
        Modal {
            open: open(),
            on_close: move |_| {
                open.set(false);
                active_tab.set("general");
            },
            title: "Edit Group: {name}",
            div { class: "flex flex-col gap-4",
                // Tabs
                div { class: "tabs tabs-boxed",
                    a {
                        class: if active_tab() == "general" { "tab tab-active" } else { "tab" },
                        onclick: move |_| active_tab.set("general"),
                        "General"
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
                    // General Tab
                    if active_tab() == "general" {
                        div { class: "flex flex-col gap-4",
                            label { class: "form-control w-full",
                                div { class: "label", span { class: "label-text", "Group Name" } }
                                input {
                                    r#type: "text",
                                    class: "input input-bordered w-full",
                                    value: "{edit_name}",
                                    oninput: move |e| edit_name.set(e.value()),
                                }
                            }
                            button {
                                class: "btn btn-primary self-end",
                                onclick: on_save_general,
                                "Save Name"
                            }
                        }
                    }

                    // Roles Tab
                    if active_tab() == "roles" {
                        div { class: "flex flex-col gap-4",
                            div {
                                h4 { class: "font-semibold mb-2", "Assigned Roles" }
                                if group_roles().is_empty() {
                                    p { class: "text-gray-500 italic", "No roles assigned" }
                                } else {
                                    div { class: "flex flex-wrap gap-2",
                                        for role in group_roles() {
                                            div { class: "badge badge-lg badge-secondary gap-2",
                                                span { "{role}" }
                                                button {
                                                    class: "btn btn-xs btn-circle btn-ghost",
                                                    onclick: move |_| remove_role_handler(role.clone()),
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
                                    onclick: add_role_handler,
                                    "Assign"
                                }
                            }
                        }
                    }

                    // Claims Tab
                    if active_tab() == "claims" {
                         div { class: "flex flex-col gap-4",
                            div {
                                h4 { class: "font-semibold mb-2", "Direct Claims" }
                                if group_claims().is_empty() {
                                    p { class: "text-gray-500 italic", "No direct claims assigned" }
                                } else {
                                    div { class: "flex flex-wrap gap-2",
                                        for claim in group_claims() {
                                            div { class: "badge badge-lg badge-info gap-2",
                                                span { "{claim}" }
                                                button {
                                                    class: "btn btn-xs btn-circle btn-ghost",
                                                    onclick: move |_| remove_claim_handler(claim.clone()),
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
                                    onclick: add_claim_handler,
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
