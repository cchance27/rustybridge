use crate::{
    app::{api::relays::*, pages::relays::state::RelayState},
    components::{CredentialForm, RelayAccessForm, StepModal, use_toast},
};
use dioxus::prelude::*;
use rb_types::{
    credentials::CustomAuthRequest,
    relay::{CreateRelayRequest, UpdateRelayRequest},
    validation::{CredentialValidationInput, ValidationError},
};
use std::collections::HashMap;

/// Modal for creating or editing a relay
#[component]
pub fn EditRelayModal(state: RelayState) -> Element {
    let toast = use_toast();
    // Helper to check if we can proceed to the next step
    let can_proceed = {
        if (state.current_step)() == 1 {
            // Step 1 (Connection) - require name and endpoint
            !(state.name)().trim().is_empty() && !(state.endpoint)().trim().is_empty()
        } else if (state.current_step)() == 2 {
            // Step 2 (Authentication) - validate based on mode
            match (state.auth_mode)().as_str() {
                "none" => true,
                "saved" => (state.selected_credential_id)() > 0,
                "custom" => {
                    let auth_type_val = (state.auth_type)();
                    let username_mode_val = (state.auth_username_mode)();
                    let password_required_val = (state.auth_password_required)();
                    let password_required_changing =
                        (state.editing_id)().is_some() && !(state.auth_original_password_required)() && password_required_val;
                    let effective_has_existing_password = (state.has_existing_password)() && !password_required_changing;

                    CredentialValidationInput {
                        kind: &auth_type_val,
                        username_mode: &username_mode_val,
                        username: &(state.auth_username)(),
                        password_required: password_required_val,
                        password: &(state.auth_password)(),
                        private_key: &(state.auth_private_key)(),
                        public_key: &(state.auth_public_key)(),
                        is_editing: (state.editing_id)().is_some(),
                        has_existing_password: effective_has_existing_password,
                        has_existing_private_key: (state.has_existing_private_key)(),
                        has_existing_public_key: (state.has_existing_public_key)(),
                    }
                    .validate()
                    .is_empty()
                }
                _ => false,
            }
        } else {
            // Step 3 (Access) - always can proceed (optional step)
            true
        }
    };

    let on_next = move |_| {
        // Validate current step before proceeding
        state.validation_errors.set(HashMap::new());

        if (state.current_step)() == 1 {
            // Validate connection fields
            let mut errors = HashMap::new();
            if (state.name)().trim().is_empty() {
                errors.insert("name".to_string(), ValidationError::Required);
            }
            if (state.endpoint)().trim().is_empty() {
                errors.insert("endpoint".to_string(), ValidationError::Required);
            } else if let Some((_, port_str)) = (state.endpoint)().rsplit_once(':') {
                if port_str.parse::<u16>().is_err() {
                    errors.insert(
                        "endpoint".to_string(),
                        ValidationError::InvalidFormat("Port must be a valid number (0-65535)".to_string()),
                    );
                }
            } else {
                errors.insert(
                    "endpoint".to_string(),
                    ValidationError::InvalidFormat("Endpoint must be in format 'host:port'".to_string()),
                );
            }

            if !errors.is_empty() {
                state.validation_errors.set(errors);
                return;
            }
        }

        state.current_step.set((state.current_step)() + 1);
    };

    let on_back = move |_| {
        if (state.current_step)() > 1 {
            state.current_step.set((state.current_step)() - 1);
        }
    };

    let on_save = move |_| {
        // Clear previous validation errors
        state.validation_errors.set(HashMap::new());

        let name_val = (state.name)();
        let endpoint_val = (state.endpoint)();
        let id = (state.editing_id)();
        let mode = (state.auth_mode)();
        let auth_type_val = (state.auth_type)();
        let username_val = (state.auth_username)();
        let password_val = (state.auth_password)();
        let private_key_val = (state.auth_private_key)();
        let passphrase_val = (state.auth_passphrase)();
        let public_key_val = (state.auth_public_key)();
        let selected_cred_id = (state.selected_credential_id)();
        let is_editing = (state.editing_id)().is_some();
        let action_word = if is_editing { "updated" } else { "created" };
        let effective_has_existing_password =
            ((state.auth_original_password_required)() || !(state.auth_password_required)()) && (state.has_existing_password)();

        // Client-side validation for authentication step
        let mut auth_errors = HashMap::new();
        match mode.as_str() {
            "saved" => {
                if selected_cred_id == 0 {
                    auth_errors.insert("credential".to_string(), ValidationError::Required);
                }
            }
            "custom" => {
                auth_errors.extend(
                    CredentialValidationInput {
                        kind: &auth_type_val,
                        username_mode: &(state.auth_username_mode)(),
                        username: &username_val,
                        password_required: (state.auth_password_required)(),
                        password: &password_val,
                        private_key: &private_key_val,
                        public_key: &public_key_val,
                        is_editing,
                        has_existing_password: effective_has_existing_password,
                        has_existing_private_key: (state.has_existing_private_key)(),
                        has_existing_public_key: (state.has_existing_public_key)(),
                    }
                    .validate(),
                );
            }
            _ => {}
        }

        if !auth_errors.is_empty() {
            state.auth_validation_errors.set(auth_errors);
            state.current_step.set(2); // Jump user to auth step to correct inputs
            return;
        }

        state.auth_validation_errors.set(HashMap::new());

        spawn(async move {
            // Step 1: Create/update the relay
            let relay_result = if let Some(id_val) = id {
                update_relay_host(
                    id_val,
                    UpdateRelayRequest {
                        name: name_val.clone(),
                        endpoint: endpoint_val.clone(),
                    },
                )
                .await
                .map(|_| id_val)
                .map_err(|e| ServerFnError::new(e.to_string()))
            } else {
                match create_relay_host(CreateRelayRequest {
                    name: name_val.clone(),
                    endpoint: endpoint_val.clone(),
                })
                .await
                {
                    Ok(_) => {
                        // Get the newly created relay's ID by fetching the list
                        match list_relay_hosts().await {
                            Ok(hosts) => hosts
                                .into_iter()
                                .find(|h| h.name == name_val)
                                .map(|h| h.id)
                                .ok_or_else(|| ServerFnError::new("Failed to find newly created relay")),
                            Err(e) => Err(ServerFnError::new(format!("Failed to list relay hosts: {}", e))),
                        }
                    }
                    Err(e) => Err(ServerFnError::new(format!("Failed to create relay: {}", e))),
                }
            };

            match relay_result {
                Ok(relay_id) => {
                    let created_new = id.is_none();

                    // Step 2: Configure authentication if needed (skip if mode is "none")
                    if mode != "none" {
                        let auth_result = match mode.as_str() {
                            "saved" if selected_cred_id > 0 => assign_relay_credential(relay_id, selected_cred_id).await,
                            "custom" => {
                                set_custom_auth(
                                    relay_id,
                                    CustomAuthRequest {
                                        auth_type: auth_type_val.clone(),
                                        username: if username_val.is_empty() {
                                            None
                                        } else {
                                            Some(username_val.clone())
                                        },
                                        username_mode: (state.auth_username_mode)(),
                                        password: if password_val.is_empty() {
                                            None
                                        } else {
                                            Some(password_val.clone())
                                        },
                                        password_required: (state.auth_password_required)(),
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

                        match auth_result {
                            Ok(_) => {
                                state.is_modal_open.set(false);
                                toast.success(&format!("Relay '{}' {} successfully", name_val, action_word));
                                state.relays.restart();
                                if created_new {
                                    // Trigger hostkey modal
                                    state.refresh_target_id.set(relay_id);
                                    state.refresh_target_name.set(name_val.clone());
                                    state.refresh_review.set(None);
                                    state.refresh_modal_open.set(true);

                                    spawn(async move {
                                        match fetch_relay_hostkey_for_review(relay_id).await {
                                            Ok(review) => state.refresh_review.set(Some(review)),
                                            Err(e) => {
                                                state.refresh_modal_open.set(false);
                                                state.refresh_review.set(None);
                                                toast.error(&format!("Failed to fetch hostkey: {}", e));
                                            }
                                        }
                                    });
                                }
                            }
                            Err(e) => {
                                toast.error(&format!("Relay saved but auth configuration failed: {}", e));
                                state.relays.restart();
                            }
                        }
                    } else {
                        // No auth needed, just close and show success
                        state.is_modal_open.set(false);
                        toast.success(&format!("Relay '{}' {} successfully", name_val, action_word));
                        state.relays.restart();
                        if created_new {
                            // Trigger hostkey modal
                            state.refresh_target_id.set(relay_id);
                            state.refresh_target_name.set(name_val.clone());
                            state.refresh_review.set(None);
                            state.refresh_modal_open.set(true);

                            spawn(async move {
                                match fetch_relay_hostkey_for_review(relay_id).await {
                                    Ok(review) => state.refresh_review.set(Some(review)),
                                    Err(e) => {
                                        state.refresh_modal_open.set(false);
                                        state.refresh_review.set(None);
                                        toast.error(&format!("Failed to fetch hostkey: {}", e));
                                    }
                                }
                            });
                        }
                    }
                }
                Err(e) => {
                    state.is_modal_open.set(false);
                    toast.error(&format!(
                        "Failed to {} relay: {}",
                        if id.is_some() { "update" } else { "create" },
                        e
                    ));
                }
            }
        });
    };

    rsx! {
        StepModal {
            open: (state.is_modal_open)(),
            on_close: move |_| state.is_modal_open.set(false),
            title: if (state.editing_id)().is_some() { "Edit Relay".to_string() } else { "Add Relay".to_string() },
            steps: vec!["Connection".to_string(), "Authentication".to_string(), "Access".to_string()],
            current_step: (state.current_step)() as usize,
            on_next: on_next,
            on_back: on_back,
            on_save: on_save,
            can_proceed: can_proceed,

            // Step content
            if (state.current_step)() == 1 {
                // Step 1: Connection
                div { class: "flex flex-col gap-4",
                    if let Some(err) = (state.error_message)() {
                        div { class: "alert alert-error",
                            span { "{err}" }
                        }
                    }

                    label { class: "form-control w-full",
                        div { class: "label", span { class: "label-text", "Name" } }
                        input {
                            r#type: "text",
                            class: if (state.validation_errors)().contains_key("name") { "input input-bordered w-full input-error" } else { "input input-bordered w-full" },
                            placeholder: "My Relay",
                            value: "{state.name}",
                            oninput: move |e| {
                                state.name.set(e.value());
                                if (state.validation_errors)().contains_key("name") {
                                    let mut errs = (state.validation_errors)();
                                    errs.remove("name");
                                    state.validation_errors.set(errs);
                                }
                            }
                        }
                        if let Some(err) = (state.validation_errors)().get("name") {
                            div { class: "text-error text-sm mt-1", "{err}" }
                        }
                    }

                    label { class: "form-control w-full",
                        div { class: "label", span { class: "label-text", "Endpoint (host:port)" } }
                        input {
                            r#type: "text",
                            class: if (state.validation_errors)().contains_key("endpoint") { "input input-bordered w-full input-error" } else { "input input-bordered w-full" },
                            placeholder: "127.0.0.1:2222",
                            value: "{state.endpoint}",
                            oninput: move |e| {
                                state.endpoint.set(e.value());
                                if (state.validation_errors)().contains_key("endpoint") {
                                    let mut errs = (state.validation_errors)();
                                    errs.remove("endpoint");
                                    state.validation_errors.set(errs);
                                }
                            }
                        }
                        if let Some(err) = (state.validation_errors)().get("endpoint") {
                            div { class: "text-error text-sm mt-1", "{err}" }
                        }
                    }
                }
            } else if (state.current_step)() == 2 {
                // Step 2: Authentication
                div { class: "flex flex-col gap-2",
                    h4 { class: "font-semibold", "Authentication Method" }

                    // Auth mode selector
                    div { class: "flex flex-row gap-4 form-control",
                        label { class: "label cursor-pointer justify-start gap-2",
                            input {
                                r#type: "radio",
                                name: "auth-mode",
                                class: "radio",
                                checked: (state.auth_mode)() == "none",
                                onchange: move |_| {
                                    state.auth_mode.set("none".to_string());
                                    state.auth_validation_errors.set(HashMap::new());
                                }
                            }
                            span { class: "label-text", "None" }
                        }
                        label { class: "label cursor-pointer justify-start gap-2",
                            input {
                                r#type: "radio",
                                name: "auth-mode",
                                class: "radio",
                                checked: (state.auth_mode)() == "saved",
                                onchange: move |_| {
                                    state.auth_mode.set("saved".to_string());
                                    state.auth_validation_errors.set(HashMap::new());
                                }
                            }
                            span { class: "label-text", "Saved Credential" }
                        }
                        label { class: "label cursor-pointer justify-start gap-2",
                            input {
                                r#type: "radio",
                                name: "auth-mode",
                                class: "radio",
                                checked: (state.auth_mode)() == "custom",
                                onchange: move |_| {
                                    state.auth_mode.set("custom".to_string());
                                    state.auth_validation_errors.set(HashMap::new());
                                }
                            }
                            span { class: "label-text", "Custom" }
                        }
                    }

                    // Saved credential selector
                    if (state.auth_mode)() == "saved" {
                        div { class: "form-control w-full",
                            div { class: "label", span { class: "label-text", "Select Credential" } }
                            select {
                                class: if (state.auth_validation_errors)().contains_key("credential") {
                                    "select select-bordered w-full select-error"
                                } else {
                                    "select select-bordered w-full"
                                },
                                value: "{state.selected_credential_id}",
                                onchange: move |e| {
                                    if let Ok(id) = e.value().parse::<i64>() {
                                        state.selected_credential_id.set(id);
                                        if (state.auth_validation_errors)().contains_key("credential") {
                                            let mut errs = (state.auth_validation_errors)();
                                            errs.remove("credential");
                                            state.auth_validation_errors.set(errs);
                                        }
                                    }
                                },
                                option { value: "0", "-- Select a credential --" }
                                {(state.credentials)().and_then(|res| res.ok()).map(|creds| rsx! {
                                    for cred in creds {
                                        option {
                                            value: "{cred.id}",
                                            selected: (state.selected_credential_id)() == cred.id,
                                            "{cred.name} ({cred.kind})"
                                        }
                                    }
                                })}
                            }
                            if let Some(err) = (state.auth_validation_errors)().get("credential") {
                                div { class: "text-error text-sm mt-1", "{err}" }
                            }
                        }
                    }
                    // Custom auth fields
                    if (state.auth_mode)() == "custom" {
                        div { class: "flex flex-col gap-4 p-4 bg-base-300 rounded-lg",
                            CredentialForm {
                                cred_type: (state.auth_type)(),
                                on_type_change: move |v| {
                                    state.auth_type.set(v);
                                    if (state.auth_validation_errors)().contains_key("password")
                                        || (state.auth_validation_errors)().contains_key("private_key")
                                        || (state.auth_validation_errors)().contains_key("public_key")
                                    {
                                        let mut errs = (state.auth_validation_errors)();
                                        errs.remove("password");
                                        errs.remove("private_key");
                                        errs.remove("public_key");
                                        state.auth_validation_errors.set(errs);
                                    }
                                },
                                username: (state.auth_username)(),
                                on_username_change: move |v| {
                                    state.auth_username.set(v);
                                    if (state.auth_validation_errors)().contains_key("username") {
                                        let mut errs = (state.auth_validation_errors)();
                                        errs.remove("username");
                                        state.auth_validation_errors.set(errs);
                                    }
                                },
                                username_mode: (state.auth_username_mode)(),
                                on_username_mode_change: move |v: String| {
                                    state.auth_username_mode.set(v.clone());
                                    // If username_mode is not "fixed", force password_required to false
                                    if v != "fixed" {
                                        state.auth_password_required.set(false);
                                        state.auth_password.set(String::new());
                                        if (state.auth_validation_errors)().contains_key("username") {
                                            let mut errs = (state.auth_validation_errors)();
                                            errs.remove("username");
                                            state.auth_validation_errors.set(errs);
                                        }
                                    }
                                },
                                password_required: (state.auth_password_required)(),
                                on_password_required_change: move |v| {
                                    state.auth_password_required.set(v);
                                    if !v {
                                        state.auth_password.set(String::new());
                                    }
                                },
                                password: (state.auth_password)(),
                                on_password_change: move |v| {
                                    state.auth_password.set(v);
                                    if (state.auth_validation_errors)().contains_key("password") {
                                        let mut errs = (state.auth_validation_errors)();
                                        errs.remove("password");
                                        state.auth_validation_errors.set(errs);
                                    }
                                },
                                private_key: (state.auth_private_key)(),
                                on_private_key_change: move |v| {
                                    state.auth_private_key.set(v);
                                    if (state.auth_validation_errors)().contains_key("private_key") {
                                        let mut errs = (state.auth_validation_errors)();
                                        errs.remove("private_key");
                                        state.auth_validation_errors.set(errs);
                                    }
                                },
                                public_key: (state.auth_public_key)(),
                                on_public_key_change: move |v| {
                                    state.auth_public_key.set(v);
                                    if (state.auth_validation_errors)().contains_key("public_key") {
                                        let mut errs = (state.auth_validation_errors)();
                                        errs.remove("public_key");
                                        state.auth_validation_errors.set(errs);
                                    }
                                },
                                passphrase: (state.auth_passphrase)(),
                                on_passphrase_change: move |v| state.auth_passphrase.set(v),
                                validation_errors: (state.auth_validation_errors)(),
                                show_hint: (state.editing_id)().is_some()
                                    && ((state.has_existing_password)()
                                        || (state.has_existing_private_key)()
                                        || (state.has_existing_public_key)()),
                                is_editing: (state.editing_id)().is_some(),
                                has_existing_password: (state.has_existing_password)(),
                                has_existing_private_key: (state.has_existing_private_key)(),
                                has_existing_public_key: (state.has_existing_public_key)(),
                                show_type_selector: true,
                                original_password_required: (state.auth_original_password_required)(),
                            }
                        }
                    }
                }
            } else {
                // Step 3: Access
                div { class: "flex flex-col gap-4",
                    h4 { class: "font-semibold", "Relay Access" }
                    p { class: "text-sm text-gray-500",
                        "Configure which users and groups can access this relay. This step is optional."
                    }
                    if let Some(id) = (state.editing_id)() {
                        RelayAccessForm {
                            relay_id: id,
                            on_change: move |_| {
                                // Refresh relays list when access changes
                                state.relays.restart();
                            }
                        }
                    } else {
                        div { class: "alert alert-info",
                            span { "Access can be configured after the relay is created." }
                        }
                    }
                }
            }
        }
    }
}
