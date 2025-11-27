use std::collections::HashMap;

use dioxus::prelude::*;
use rb_types::{
    credentials::CustomAuthRequest, validation::{CredentialValidationInput, ValidationError}
};

use crate::{
    app::{
        api::relays::{assign_relay_credential, set_custom_auth}, pages::relays::state::RelayState
    }, components::{CredentialForm, Modal, ToastMessage, ToastType}
};

/// Modal for assigning authentication to a relay
#[component]
pub fn AssignCredentialModal(state: RelayState) -> Element {
    let on_save = move |_| {
        let target_id = (state.assign_target_id)();
        let target_name = (state.assign_target_name)();
        let mode = (state.assign_mode)();
        let cred_id = (state.selected_credential_id)();
        let auth_type_val = (state.assign_auth_type)();
        let username_val = (state.assign_username)();
        let password_val = (state.assign_password)();
        let private_key_val = (state.assign_private_key)();
        let public_key_val = (state.assign_public_key)();
        let passphrase_val = (state.assign_passphrase)();

        // Client-side validation for assign modal
        let mut errors = HashMap::new();
        match mode.as_str() {
            "saved" => {
                if cred_id == 0 {
                    errors.insert("credential".to_string(), ValidationError::Required);
                }
            }
            "custom" => {
                errors.extend(
                    CredentialValidationInput {
                        kind: &auth_type_val,
                        username_mode: &(state.assign_username_mode)(),
                        username: &username_val,
                        password_required: (state.assign_password_required)(),
                        password: &password_val,
                        private_key: &private_key_val,
                        public_key: &public_key_val,
                        is_editing: false,
                        has_existing_password: false,
                        has_existing_private_key: false,
                        has_existing_public_key: false,
                    }
                    .validate(),
                );
            }
            _ => {}
        }

        if !errors.is_empty() {
            state.assign_validation_errors.set(errors);
            return;
        }

        state.assign_validation_errors.set(HashMap::new());
        spawn(async move {
            let result = match mode.as_str() {
                "saved" => assign_relay_credential(target_id, cred_id).await,
                "custom" => {
                    set_custom_auth(
                        target_id,
                        CustomAuthRequest {
                            auth_type: auth_type_val.clone(),
                            username: if username_val.is_empty() {
                                None
                            } else {
                                Some(username_val.clone())
                            },
                            username_mode: (state.assign_username_mode)(),
                            password: if password_val.is_empty() {
                                None
                            } else {
                                Some(password_val.clone())
                            },
                            password_required: (state.assign_password_required)(),
                            private_key: if private_key_val.is_empty() {
                                None
                            } else {
                                Some(private_key_val.clone())
                            },
                            passphrase: if passphrase_val.is_empty() {
                                None
                            } else {
                                Some(passphrase_val.clone())
                            },
                            public_key: if public_key_val.is_empty() {
                                None
                            } else {
                                Some(public_key_val.clone())
                            },
                        },
                    )
                    .await
                }
                _ => Ok(()),
            };

            match result {
                Ok(_) => {
                    state.assign_modal_open.set(false);
                    state.toast.set(Some(ToastMessage {
                        message: format!("Authentication assigned to '{}' successfully", target_name),
                        toast_type: ToastType::Success,
                    }));
                    state.relays.restart();
                }
                Err(e) => {
                    state.assign_modal_open.set(false);
                    state.toast.set(Some(ToastMessage {
                        message: format!("Failed to assign credential: {}", e),
                        toast_type: ToastType::Error,
                    }));
                }
            }
        });
    };

    rsx! {
        Modal {
            open: (state.assign_modal_open)(),
            on_close: move |_| state.assign_modal_open.set(false),
            title: "Assign Authentication",
            actions: rsx! {
                button { class: "btn btn-primary", onclick: on_save, "Save" }
            },
            div { class: "flex flex-col gap-2",
                p { "Configure authentication for "{state.assign_target_name}":" }

                // Mode selector
                div { class: "flex flex-row gap-4 form-control",
                    label { class: "label cursor-pointer justify-start gap-2",
                        input {
                            r#type: "radio",
                            name: "assign-mode",
                            class: "radio",
                            checked: (state.assign_mode)() == "saved",
                            onchange: move |_| state.assign_mode.set("saved".to_string())
                        }
                        span { class: "label-text", "Saved Credential" }
                    }
                    label { class: "label cursor-pointer justify-start gap-2",
                        input {
                            r#type: "radio",
                            name: "assign-mode",
                            class: "radio",
                            checked: (state.assign_mode)() == "custom",
                            onchange: move |_| state.assign_mode.set("custom".to_string())
                        }
                        span { class: "label-text", "Custom" }
                    }
                }

                // Saved credential selector
                if (state.assign_mode)() == "saved" {
                    match (state.credentials)() {
                        Some(Ok(creds)) => rsx! {
                            label { class: "form-control w-full",
                                div { class: "label", span { class: "label-text", "Credential" } }
                                select {
                                    class: if (state.assign_validation_errors)().contains_key("credential") { "select select-bordered w-full select-error" } else { "select select-bordered w-full" },
                                    value: "{state.selected_credential_id}",
                                    onchange: move |e| {
                                        if let Ok(id) = e.value().parse::<i64>() {
                                            state.selected_credential_id.set(id);
                                        }
                                    },
                                    option { value: "0", "Select a credential..." }
                                    for cred in creds {
                                        option { value: "{cred.id}", "{cred.name} ({cred.kind})" }
                                    }
                                }
                                if let Some(err) = (state.assign_validation_errors)().get("credential") {
                                    div { class: "text-error text-sm mt-1", "{err}" }
                                }
                            }
                        },
                        Some(Err(e)) => rsx! {
                            div { class: "alert alert-error",
                                span { "Error loading credentials: {e}" }
                            }
                        },
                        None => rsx! {
                            div { class: "flex justify-center p-4",
                                span { class: "loading loading-spinner" }
                            }
                        }
                    }
                } else {
                    div { class: "flex flex-col gap-4 p-2",
                        CredentialForm {
                            cred_type: (state.assign_auth_type)(),
                            on_type_change: move |v| state.assign_auth_type.set(v),
                            username: (state.assign_username)(),
                            on_username_change: move |v| {
                                state.assign_username.set(v);
                                if (state.assign_validation_errors)().contains_key("username") {
                                    let mut errs = (state.assign_validation_errors)();
                                    errs.remove("username");
                                    state.assign_validation_errors.set(errs);
                                }
                            },
                            username_mode: (state.assign_username_mode)(),
                            on_username_mode_change: move |v: String| {
                                state.assign_username_mode.set(v.clone());
                                // If username_mode is not "fixed", force password_required to false
                                if v != "fixed" {
                                    state.assign_password_required.set(false);
                                    state.assign_password.set(String::new()); // Clear password field
                                }
                            },
                            password_required: (state.assign_password_required)(),
                            on_password_required_change: move |v| {
                                state.assign_password_required.set(v);
                                // Clear password field when unchecking "stored"
                                if !v {
                                    state.assign_password.set(String::new());
                                }
                            },
                            password: (state.assign_password)(),
                            on_password_change: move |v| {
                                state.assign_password.set(v);
                                if (state.assign_validation_errors)().contains_key("password") {
                                    let mut errs = (state.assign_validation_errors)();
                                    errs.remove("password");
                                    state.assign_validation_errors.set(errs);
                                }
                            },
                            private_key: (state.assign_private_key)(),
                            on_private_key_change: move |v| {
                                state.assign_private_key.set(v);
                                if (state.assign_validation_errors)().contains_key("private_key") {
                                    let mut errs = (state.assign_validation_errors)();
                                    errs.remove("private_key");
                                    state.assign_validation_errors.set(errs);
                                }
                            },
                            public_key: (state.assign_public_key)(),
                            on_public_key_change: move |v| {
                                state.assign_public_key.set(v);
                                if (state.assign_validation_errors)().contains_key("public_key") {
                                    let mut errs = (state.assign_validation_errors)();
                                    errs.remove("public_key");
                                    state.assign_validation_errors.set(errs);
                                }
                            },
                            passphrase: (state.assign_passphrase)(),
                            on_passphrase_change: move |v| state.assign_passphrase.set(v),
                            validation_errors: (state.assign_validation_errors)(),
                            show_hint: false,
                            is_editing: false,
                            has_existing_password: false,
                            has_existing_private_key: false,
                            has_existing_public_key: false,
                            show_type_selector: true,
                        }
                    }
                }
            }
        }
    }
}
