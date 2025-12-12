use std::str::FromStr as _;

use dioxus::prelude::*;
use rb_types::{auth::ClaimType, users::RoleInfo};

use crate::{
    app::api::roles::{add_role_claim, remove_role_claim}, components::{Modal, use_toast}, error::ApiError
};

/// Role Claims Management Modal
#[component]
pub fn EditRoleClaimsModal(
    role_claims_modal_open: Signal<bool>,
    claims_role_id: Signal<i64>,
    claims_role_name: Signal<String>,
    role_claims: Signal<Vec<ClaimType<'static>>>,
    role_selected_claim_to_add: Signal<String>,
    roles: Resource<Result<Vec<RoleInfo<'static>>, ApiError>>,
) -> Element {
    let is_super_admin = claims_role_name() == "Super Admin";
    let role_id_val = claims_role_id();
    let toast = use_toast();

    let add_role_claim_handler = move |claim: String| {
        let role_id = role_id_val;
        let role = claims_role_name();
        spawn(async move {
            // Parse the string into ClaimType
            let claim_type = match ClaimType::from_str(&claim) {
                Ok(ct) => ct,
                Err(e) => {
                    toast.error(&format!("Invalid claim format: {}", e));
                    return;
                }
            };

            match add_role_claim(role_id, claim_type.clone()).await {
                Ok(_) => {
                    roles.restart();
                    let mut current = role_claims();
                    current.push(claim_type);
                    role_claims.set(current);
                    toast.success(&format!("Added claim '{}' to role '{}'", claim, role));
                }
                Err(e) => {
                    toast.error(&format!("Failed to add claim: {}", e));
                }
            }
        });
    };

    let remove_role_claim_handler = move |claim: ClaimType<'static>| {
        let role_id = role_id_val;
        let role = claims_role_name();
        spawn(async move {
            match remove_role_claim(role_id, claim.clone()).await {
                Ok(_) => {
                    roles.restart();
                    let mut current = role_claims();
                    current.retain(|c| c != &claim);
                    role_claims.set(current);
                    toast.success(&format!("Removed claim '{}' from role '{}'", claim, role));
                }
                Err(e) => {
                    toast.error(&format!("Failed to remove claim: {}", e));
                }
            }
        });
    };

    rsx!(
        Modal {
            open: role_claims_modal_open(),
            on_close: move |_| {
                role_claims_modal_open.set(false);
                role_claims.set(Vec::new());
                role_selected_claim_to_add.set(String::new());
            },
            title: "Manage Role Claims: {claims_role_name}",
            div { class: "flex flex-col gap-4",
                if is_super_admin {
                    div { class: "alert alert-warning",
                        p { "⚠️ The Super Admin role's claims cannot be modified." }
                    }
                }

                // Current claims
                div {
                    h4 { class: "font-semibold mb-2", "Current Claims" }
                    if role_claims().is_empty() {
                        p { class: "text-gray-500 italic", "No claims assigned" }
                    } else {
                        div { class: "flex flex-wrap gap-2",
                            for claim in role_claims() {
                                div { class: "badge badge-lg badge-secondary gap-2",
                                    span { "{claim}" }
                                    if !is_super_admin {
                                        button {
                                            class: "btn btn-xs btn-circle btn-ghost",
                                            onclick: {
                                                let c = claim.clone();
                                                move |_| remove_role_claim_handler(c.clone())
                                            },
                                            "×"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if !is_super_admin {
                    div { class: "divider" }

                    // Add claim
                    div {
                        h4 { class: "font-semibold mb-2", "Add Claim" }
                        div { class: "flex gap-2",
                            select {
                                class: "select select-bordered flex-1",
                                value: "{role_selected_claim_to_add}",
                                onchange: move |e| role_selected_claim_to_add.set(e.value()),
                                option { value: "", "Select a claim..." }
                                for claim in ClaimType::all_variants() {
                                    option { value: "{claim}", "{claim}" }
                                }
                            }
                            button {
                                class: "btn btn-sm btn-primary",
                                disabled: role_selected_claim_to_add().is_empty(),
                                onclick: move |_| {
                                    let claim = role_selected_claim_to_add();
                                    add_role_claim_handler(claim.to_string())
                                },
                                "Add Claim"
                            }
                        }
                    }
                }
            }
        }
    )
}
