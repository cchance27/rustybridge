use std::str::FromStr as _;

use dioxus::prelude::*;
use rb_types::auth::ClaimType;

use crate::{
    app::api::groups::{add_group_claim, get_group_claims, remove_group_claim}, components::{Modal, ToastMessage, ToastType}
};

// Group Claims Modal
#[component]
pub fn EditGroupClaimsModal(
    group_claims_modal_open: Signal<bool>,
    claims_group_name: Signal<String>,
    group_claims: Signal<Vec<ClaimType>>,
    group_selected_claim_to_add: Signal<String>,
    groups: Resource<Result<Vec<rb_types::users::GroupInfo>, ServerFnError>>,
    toast: Signal<Option<ToastMessage>>,
) -> Element {
    // Fetch claims when modal opens
    let group_name = claims_group_name.clone();
    use_effect(move || {
        let name = group_name();
        if group_claims_modal_open() && !name.is_empty() {
            spawn(async move {
                match get_group_claims(name).await {
                    Ok(claims) => group_claims.set(claims),
                    Err(e) => println!("Failed to fetch group claims: {}", e),
                }
            });
        }
    });
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

    rsx!(
        Modal {
            open: group_claims_modal_open(),
            on_close: move |_| {
                group_claims_modal_open.set(false);
                group_claims.set(Vec::new());
                group_selected_claim_to_add.set(String::new());
            },
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
                                add_group_claim_handler(claim.to_string())
                            },
                            "Add Claim"
                        }
                    }
                }
            }
        }
    )
}
