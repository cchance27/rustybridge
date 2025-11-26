use std::{collections::HashMap, str::FromStr as _};

use dioxus::prelude::*;
use rb_types::{auth::ClaimType, users::UpdateUserRequest};

use crate::{
    app::api::users::*, components::{Modal, ToastMessage, ToastType}
};

/// Edit User Modal with password and claims management
#[component]
pub fn EditUserModal(
    open: Signal<bool>,
    username: Signal<Option<String>>,
    users: Resource<Result<Vec<rb_types::users::UserGroupInfo>, ServerFnError>>,
    toast: Signal<Option<ToastMessage>>,
) -> Element {
    let Some(username) = username() else {
        return rsx!();
    };

    let mut password = use_signal(String::new);
    let mut validation_errors = use_signal(HashMap::<String, String>::new);
    let mut user_claims = use_signal(Vec::<ClaimType>::new);
    let mut selected_claim_to_add = use_signal(String::new);

    // Load user claims when modal opens
    let username_for_effect = username.clone();
    use_effect(move || {
        let username_for_spawn = username_for_effect.clone();
        spawn(async move {
            // Need to access current value of open()
            let is_open = open();
            if is_open && let Ok(claims) = get_user_claims(username_for_spawn).await {
                user_claims.set(claims);
            }
        });
    });

    let username_for_save = username.clone();
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
            let username_for_spawn = username_for_save.clone();
            let password_val_clone = password_val.clone();
            spawn(async move {
                let username_for_message = username_for_spawn.clone();
                match update_user(
                    username_for_spawn,
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

    let on_delete = |claim: ClaimType| {
        let claim_clone = claim.clone();
        let username_clone = username.clone();
        move |_: Event<MouseData>| {
            let claim_for_spawn = claim_clone.clone();
            let username_for_spawn = username_clone.clone();
            spawn(async move {
                let username_for_message = username_for_spawn.clone();
                let claim_str = claim_for_spawn.to_string();
                match remove_user_claim(username_for_spawn, claim_for_spawn.clone()).await {
                    Ok(_) => {
                        users.restart();
                        let mut current = user_claims();
                        current.retain(|c| c != &claim_for_spawn);
                        user_claims.set(current);
                        toast.set(Some(ToastMessage {
                            message: format!("Removed claim '{}' from user '{}'", claim_str, username_for_message),
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
        }
    };

    let username_for_add = username.clone();
    let add_claim = {
        move |_| {
            let claim_str = selected_claim_to_add();
            if claim_str.is_empty() {
                return;
            }

            let username_for_spawn = username_for_add.clone();
            spawn(async move {
                let username_for_message = username_for_spawn.clone();
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

                match add_user_claim(username_for_spawn, claim_type.clone()).await {
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

    let username_for_rsx = username.clone();
    rsx! {
        Modal {
            open: open(),
            on_close: move |_| {
                open.set(false);
                password.set(String::new());
                validation_errors.set(HashMap::new());
            },
            title: "Edit User",
            actions: rsx! {
                button { class: "btn btn-primary", onclick: on_save, "Save" }
            },
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
                                        onclick: on_delete(claim.clone()),
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
                            onclick: add_claim,
                            "Add Claim"
                        }
                    }
                }
            }
        }
    }
}
