use std::collections::HashMap;

use dioxus::prelude::*;
use rb_types::{
    auth::{ClaimLevel, ClaimType}, validation::{CredentialValidationInput, ValidationError}, web::{AuthWebConfig, CreateRelayRequest, CustomAuthRequest, PrincipalKind, UpdateRelayRequest}
};

use crate::{
    app::api::{credentials::list_credentials, relays::*}, components::{
        CredentialBadge, CredentialForm, Fab, Layout, Modal, Protected, RelayAccessForm, RequireAuth, StepModal, StructuredTooltip, Table, TableActions, Toast, ToastMessage, ToastType, TooltipSection
    }
};

#[component]
pub fn RelaysPage() -> Element {
    // Load relay hosts from server
    let mut relays = use_resource(|| async move { list_relay_hosts().await });

    // Toast notification state
    let mut toast = use_signal(|| None::<ToastMessage>);

    // Credential assignment state
    let mut assign_modal_open = use_signal(|| false);
    let mut assign_target_id = use_signal(|| 0i64);
    let mut assign_target_name = use_signal(String::new);
    let mut selected_credential_id = use_signal(|| 0i64);
    let credentials = use_resource(|| async move { list_credentials().await });

    // Clear credential state
    let mut clear_modal_open = use_signal(|| false);
    let mut clear_target_id = use_signal(|| 0i64);
    let mut clear_target_name = use_signal(String::new);
    let mut clear_is_inline = use_signal(|| false);

    // Assign modal state (saved vs custom inline)
    let mut assign_mode = use_signal(|| "saved".to_string()); // "saved" | "custom"
    let mut assign_auth_type = use_signal(|| "password".to_string()); // password | ssh_key | agent
    let mut assign_username_mode = use_signal(|| "fixed".to_string());
    let mut assign_password_required = use_signal(|| true);
    let mut assign_username = use_signal(String::new);
    let mut assign_password = use_signal(String::new);
    let mut assign_private_key = use_signal(String::new);
    let mut assign_public_key = use_signal(String::new);
    let mut assign_passphrase = use_signal(String::new);
    let mut assign_validation_errors = use_signal(HashMap::<String, ValidationError>::new);

    // Hostkey refresh state
    let mut refresh_modal_open = use_signal(|| false);
    let mut refresh_target_id = use_signal(|| 0i64);
    let mut refresh_target_name = use_signal(String::new);
    let mut refresh_review = use_signal(|| None::<HostkeyReview>);

    let mut show_hostkey_modal = move |id: i64, name: String| {
        refresh_target_id.set(id);
        refresh_target_name.set(name.clone());
        refresh_review.set(None);
        refresh_modal_open.set(true);

        spawn(async move {
            match fetch_relay_hostkey_for_review(id).await {
                Ok(review) => refresh_review.set(Some(review)),
                Err(e) => {
                    refresh_modal_open.set(false);
                    refresh_review.set(None);
                    toast.set(Some(ToastMessage {
                        message: format!("Failed to fetch hostkey: {}", e),
                        toast_type: ToastType::Error,
                    }));
                }
            }
        });
    };

    // Delete confirmation state
    let mut delete_confirm_open = use_signal(|| false);
    let mut delete_target_id = use_signal(|| 0i64);
    let mut delete_target_name = use_signal(String::new);

    // Access modal state
    let mut access_modal_open = use_signal(|| false);
    let mut access_target_id = use_signal(|| 0i64);
    let mut access_target_name = use_signal(String::new);

    // Modal state
    let mut is_modal_open = use_signal(|| false);
    let mut editing_id = use_signal(|| None::<i64>);
    let mut name = use_signal(String::new);
    let mut endpoint = use_signal(String::new);
    let mut error_message = use_signal(|| None::<String>);
    let mut validation_errors = use_signal(HashMap::<String, ValidationError>::new);

    // Authentication state
    let mut auth_mode = use_signal(|| "none".to_string()); // "none", "saved", "custom"
    let mut auth_type = use_signal(|| "password".to_string()); // "password", "ssh_key", "agent"
    let mut auth_username = use_signal(String::new);
    let mut auth_username_mode = use_signal(|| "fixed".to_string());
    let mut auth_password_required = use_signal(|| true);
    let mut auth_password = use_signal(String::new);
    let mut auth_private_key = use_signal(String::new);
    let mut auth_passphrase = use_signal(String::new);
    let mut auth_public_key = use_signal(String::new);
    let mut auth_original_password_required = use_signal(|| true);
    let mut auth_validation_errors = use_signal(HashMap::<String, ValidationError>::new);
    let mut has_existing_password = use_signal(|| false);
    let mut has_existing_private_key = use_signal(|| false);
    let mut has_existing_passphrase = use_signal(|| false);
    let mut has_existing_public_key = use_signal(|| false);
    let mut current_step = use_signal(|| 1); // 1 = Connection, 2 = Authentication, 3 = Access

    let open_add = move |_| {
        editing_id.set(None);
        name.set(String::new());
        endpoint.set(String::new());
        error_message.set(None);
        validation_errors.set(HashMap::new());
        auth_mode.set("none".to_string());
        auth_type.set("password".to_string());
        auth_username.set(String::new());
        auth_password.set(String::new());
        auth_private_key.set(String::new());
        auth_passphrase.set(String::new());
        auth_public_key.set(String::new());
        auth_password_required.set(true);
        auth_original_password_required.set(true);
        auth_validation_errors.set(HashMap::new());
        has_existing_password.set(false);
        has_existing_private_key.set(false);
        has_existing_passphrase.set(false);
        has_existing_public_key.set(false);
        current_step.set(1);
        is_modal_open.set(true);
    };

    let mut open_edit = move |id: i64, current_name: String, current_endpoint: String, config: Option<AuthWebConfig>| {
        editing_id.set(Some(id));
        name.set(current_name);
        endpoint.set(current_endpoint);
        error_message.set(None);
        validation_errors.set(HashMap::new());

        // Reset auth fields to defaults before applying config
        auth_mode.set("none".to_string());
        auth_type.set("password".to_string());
        auth_username.set(String::new());
        auth_password_required.set(true);
        auth_password.set(String::new());
        auth_private_key.set(String::new());
        auth_passphrase.set(String::new());
        auth_public_key.set(String::new());
        auth_original_password_required.set(true);
        auth_validation_errors.set(HashMap::new());
        has_existing_password.set(false);
        has_existing_private_key.set(false);
        has_existing_passphrase.set(false);
        has_existing_public_key.set(false);

        // Populate auth fields from config
        if let Some(c) = config {
            auth_mode.set(c.mode);
            if let Some(sid) = c.saved_credential_id {
                selected_credential_id.set(sid);
            }
            match c.custom_type {
                Some(ctype) => auth_type.set(ctype),
                None => auth_type.set("password".to_string()),
            }
            match c.username {
                Some(u) => auth_username.set(u),
                None => auth_username.set(String::new()),
            }
            match c.username_mode {
                Some(m) => auth_username_mode.set(m),
                None => auth_username_mode.set("fixed".to_string()),
            }
            if let Some(required) = c.password_required {
                auth_password_required.set(required);
                auth_original_password_required.set(required);
            } else {
                auth_original_password_required.set(true);
            }
            if c.has_password {
                has_existing_password.set(true);
            }
            if c.has_private_key {
                has_existing_private_key.set(true);
            }
            if c.has_passphrase {
                has_existing_passphrase.set(true);
            }
            if c.has_public_key {
                has_existing_public_key.set(true);
            }
            // Do not surface encrypted/sensitive fields in edit forms (keep empty)
        }

        current_step.set(1);
        is_modal_open.set(true);
    };

    let on_next_step = move |_| {
        // Validate current step before proceeding
        validation_errors.set(HashMap::new());

        if current_step() == 1 {
            // Validate connection fields
            let mut errors = HashMap::new();
            if name().trim().is_empty() {
                errors.insert("name".to_string(), ValidationError::Required);
            }
            if endpoint().trim().is_empty() {
                errors.insert("endpoint".to_string(), ValidationError::Required);
            } else if let Some((_, port_str)) = endpoint().rsplit_once(':') {
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
                validation_errors.set(errors);
                return;
            }
        }

        current_step.set(current_step() + 1);
    };

    let on_back_step = move |_| {
        if current_step() > 1 {
            current_step.set(current_step() - 1);
        }
    };

    let on_save = move |_| {
        // Clear previous validation errors
        validation_errors.set(HashMap::new());

        let name_val = name();
        let endpoint_val = endpoint();
        let id = editing_id();
        let mode = auth_mode();
        let auth_type_val = auth_type();
        let username_val = auth_username();
        let password_val = auth_password();
        let private_key_val = auth_private_key();
        let passphrase_val = auth_passphrase();
        let public_key_val = auth_public_key();
        let selected_cred_id = selected_credential_id();
        let is_editing = editing_id().is_some();
        let action_word = if is_editing { "updated" } else { "created" };
        let effective_has_existing_password = has_existing_password() && !(auth_password_required() && !auth_original_password_required());

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
                        username_mode: &auth_username_mode(),
                        username: &username_val,
                        password_required: auth_password_required(),
                        password: &password_val,
                        private_key: &private_key_val,
                        public_key: &public_key_val,
                        is_editing,
                        has_existing_password: effective_has_existing_password,
                        has_existing_private_key: has_existing_private_key(),
                        has_existing_public_key: has_existing_public_key(),
                    }
                    .validate(),
                );
            }
            _ => {}
        }

        if !auth_errors.is_empty() {
            auth_validation_errors.set(auth_errors);
            current_step.set(2); // Jump user to auth step to correct inputs
            return;
        }

        auth_validation_errors.set(HashMap::new());

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
                .map(|_| id_val) // Return the existing ID
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
                                        username_mode: auth_username_mode(),
                                        password: if password_val.is_empty() {
                                            None
                                        } else {
                                            Some(password_val.clone())
                                        },
                                        password_required: auth_password_required(),
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
                            _ => Ok(()), // "none" or invalid - do nothing
                        };

                        match auth_result {
                            Ok(_) => {
                                is_modal_open.set(false);
                                toast.set(Some(ToastMessage {
                                    message: format!("Relay '{}' {} successfully", name_val, action_word),
                                    toast_type: ToastType::Success,
                                }));
                                relays.restart();
                                if created_new {
                                    show_hostkey_modal(relay_id, name_val.clone());
                                }
                            }
                            Err(e) => {
                                toast.set(Some(ToastMessage {
                                    message: format!("Relay saved but auth configuration failed: {}", e),
                                    toast_type: ToastType::Error,
                                }));
                                relays.restart();
                            }
                        }
                    } else {
                        // No auth needed, just close and show success
                        is_modal_open.set(false);
                        toast.set(Some(ToastMessage {
                            message: format!("Relay '{}' {} successfully", name_val, action_word),
                            toast_type: ToastType::Success,
                        }));
                        relays.restart();
                        if created_new {
                            show_hostkey_modal(relay_id, name_val.clone());
                        }
                    }
                }
                Err(e) => {
                    is_modal_open.set(false);
                    toast.set(Some(ToastMessage {
                        message: format!("Failed to {} relay: {}", if id.is_some() { "update" } else { "create" }, e),
                        toast_type: ToastType::Error,
                    }));
                }
            }
        });
    };

    let mut open_delete_confirm = move |id: i64, name: String| {
        delete_target_id.set(id);
        delete_target_name.set(name);
        delete_confirm_open.set(true);
    };

    let mut open_access_modal = move |id: i64, name: String| {
        access_target_id.set(id);
        access_target_name.set(name);
        access_modal_open.set(true);
    };

    let handle_delete = move |_: Event<MouseData>| {
        let target_id = delete_target_id();
        let target_name = delete_target_name();
        spawn(async move {
            match delete_relay_host(target_id).await {
                Ok(_) => {
                    delete_confirm_open.set(false);
                    toast.set(Some(ToastMessage {
                        message: format!("Relay '{}' deleted successfully", target_name),
                        toast_type: ToastType::Success,
                    }));
                    relays.restart();
                }
                Err(e) => {
                    delete_confirm_open.set(false);
                    toast.set(Some(ToastMessage {
                        message: format!("Failed to delete relay: {}", e),
                        toast_type: ToastType::Error,
                    }));
                }
            }
        });
    };

    let mut open_assign_modal = move |id: i64, name: String| {
        assign_target_id.set(id);
        assign_target_name.set(name);
        assign_mode.set("saved".to_string());
        assign_auth_type.set("password".to_string());
        assign_username.set(String::new());
        assign_username_mode.set("fixed".to_string());
        assign_password_required.set(true);
        assign_password.set(String::new());
        assign_private_key.set(String::new());
        assign_public_key.set(String::new());
        assign_passphrase.set(String::new());
        assign_validation_errors.set(HashMap::new());
        assign_modal_open.set(true);
    };

    let handle_assign = move |_| {
        let target_id = assign_target_id();
        let target_name = assign_target_name();
        let mode = assign_mode();
        let cred_id = selected_credential_id();
        let auth_type_val = assign_auth_type();
        let username_val = assign_username();
        let password_val = assign_password();
        let private_key_val = assign_private_key();
        let public_key_val = assign_public_key();
        let passphrase_val = assign_passphrase();

        // Client-side validation for assign modal
        let mut errors = HashMap::new();
        match mode.as_str() {
            "saved" => {
                if cred_id == 0 {
                    errors.insert("credential".to_string(), ValidationError::Required);
                }
            }
            "custom" => {
                // Use shared validation utility
                errors.extend(
                    CredentialValidationInput {
                        kind: &auth_type_val,
                        username_mode: &assign_username_mode(),
                        username: &username_val,
                        password_required: assign_password_required(),
                        password: &password_val,
                        private_key: &private_key_val,
                        public_key: &public_key_val,
                        is_editing: false,               // not editing
                        has_existing_password: false,    // no existing password
                        has_existing_private_key: false, // no existing private key
                        has_existing_public_key: false,  // no existing public key
                    }
                    .validate(),
                );
            }
            _ => {}
        }

        if !errors.is_empty() {
            assign_validation_errors.set(errors);
            return;
        }

        assign_validation_errors.set(HashMap::new());
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
                            username_mode: assign_username_mode(),
                            password: if password_val.is_empty() {
                                None
                            } else {
                                Some(password_val.clone())
                            },
                            password_required: assign_password_required(),
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
                    assign_modal_open.set(false);
                    toast.set(Some(ToastMessage {
                        message: format!("Authentication assigned to '{}' successfully", target_name),
                        toast_type: ToastType::Success,
                    }));
                    relays.restart();
                }
                Err(e) => {
                    assign_modal_open.set(false);
                    toast.set(Some(ToastMessage {
                        message: format!("Failed to assign credential: {}", e),
                        toast_type: ToastType::Error,
                    }));
                }
            }
        });
    };

    let mut open_clear_modal = move |id: i64, name: String, is_inline: bool| {
        clear_target_id.set(id);
        clear_target_name.set(name);
        clear_is_inline.set(is_inline);
        clear_modal_open.set(true);
    };

    let handle_clear = move |_| {
        let target_id = clear_target_id();
        let target_name = clear_target_name();
        let is_inline = clear_is_inline();
        spawn(async move {
            let res = if is_inline {
                clear_relay_auth(target_id).await
            } else {
                clear_relay_credential(target_id).await
            };
            match res {
                Ok(_) => {
                    clear_modal_open.set(false);
                    toast.set(Some(ToastMessage {
                        message: format!("Authentication cleared from '{}' successfully", target_name),
                        toast_type: ToastType::Success,
                    }));
                    relays.restart();
                }
                Err(e) => {
                    clear_modal_open.set(false);
                    toast.set(Some(ToastMessage {
                        message: format!("Failed to clear credential: {}", e),
                        toast_type: ToastType::Error,
                    }));
                }
            }
        });
    };

    let handle_refresh = move |_| {
        if let Some(review) = refresh_review() {
            let target_id = refresh_target_id();
            let target_name = refresh_target_name();
            let key_pem = review.new_key_pem.clone();
            spawn(async move {
                match store_relay_hostkey(target_id, key_pem).await {
                    Ok(_) => {
                        refresh_modal_open.set(false);
                        refresh_review.set(None);
                        toast.set(Some(ToastMessage {
                            message: format!("Hostkey for '{}' stored successfully", target_name),
                            toast_type: ToastType::Success,
                        }));
                        relays.restart();
                    }
                    Err(e) => {
                        refresh_modal_open.set(false);
                        refresh_review.set(None);
                        toast.set(Some(ToastMessage {
                            message: format!("Failed to store hostkey: {}", e),
                            toast_type: ToastType::Error,
                        }));
                    }
                }
            });
        }
    };

    // Helper to render the credential cell consistently
    let render_credential_cell = |host: &rb_types::web::RelayHostInfo| -> Element {
        let badge = if let Some(cred) = &host.credential {
            Some((
                cred.clone(),
                host.credential_kind.clone().unwrap_or_else(|| "password".to_string()),
                host.credential_username_mode.clone(),
                host.credential_password_required,
                "saved".to_string(),
                matches!(host.auth_config.as_ref().map(|c| c.mode.as_str()), Some("custom")),
            ))
        } else if let Some(config) = &host.auth_config {
            if config.mode == "custom" {
                Some((
                    "Custom".to_string(),
                    config.custom_type.clone().unwrap_or_else(|| "password".to_string()),
                    config.username_mode.clone(),
                    config.password_required,
                    "custom".to_string(),
                    true,
                ))
            } else {
                None
            }
        } else {
            None
        };

        rsx! {
            td {
                if let Some((badge_name, badge_kind, badge_username_mode, badge_pw_required, badge_mode, is_inline)) = badge {
                    div { class: "flex items-center gap-2 flex-wrap",
                        Protected {
                            claim: Some(ClaimType::Relays(ClaimLevel::Edit)),
                            fallback: Some(rsx! {
                                CredentialBadge {
                                    name: Some(badge_name.clone()),
                                    kind: badge_kind.clone(),
                                    username_mode: badge_username_mode.clone(),
                                    password_required: badge_pw_required,
                                    kind_prefix: false,
                                    custom_prefix: false,
                                    compound: true,
                                    mode: Some(badge_mode.clone()),
                                    on_clear: None,
                                }
                            }),
                            CredentialBadge {
                                name: Some(badge_name),
                                kind: badge_kind,
                                username_mode: badge_username_mode,
                                password_required: badge_pw_required,
                                kind_prefix: false,
                                custom_prefix: false,
                                compound: true,
                                mode: Some(badge_mode.clone()),
                                on_clear: Some(EventHandler::new({
                                    let id = host.id;
                                    let name = host.name.clone();
                                    let is_inline = is_inline;
                                    move |_| open_clear_modal(id, name.clone(), is_inline)
                                })),
                            }
                        }
                    }
                } else {
                    Protected {
                        claim: Some(ClaimType::Relays(ClaimLevel::Edit)),
                        button {
                            class: "badge badge-primary gap-2 cursor-pointer text-[11px] hover:badge-accent",
                            onclick: {
                                let id = host.id;
                                let name = host.name.clone();
                                move |_| open_assign_modal(id, name.clone())
                            },
                            "Assign"
                        }
                    }
                }
            }
        }
    };

    rsx! {
        RequireAuth {
            any_claims: vec![ClaimType::Relays(ClaimLevel::View)],
            Toast { message: toast }
            Layout {
                div { class: "card bg-base-200 shadow-xl",
                    div { class: "card-body",
                        h2 { class: "card-title", "Relay Hosts" }
                        p { "Manage your relay servers here." }

                        // Show loading state or data
                        match relays() {
                            Some(Ok(hosts)) => rsx! {
                                Table {
                                    headers: vec!["ID", "Name", "Endpoint", "Credential", "Hostkey", "Access", "Actions"],
                                    for host in hosts {
                                        tr {
                                            th { "{host.id}" }
                                            td { "{host.name}" }
                                            td { "{host.ip}:{host.port}" }
                                            { render_credential_cell(&host) }
                                            td {
                                                div { class: "flex items-center gap-2",
                                                    if host.has_hostkey {
                                                        span { class: "badge badge-success", "✓" }
                                                    } else {
                                                        span { class: "badge badge-ghost", "✗" }
                                                    }
                                                    Protected {
                                                        claim: Some(ClaimType::Relays(ClaimLevel::Edit)),
                                                        button {
                                                            class: "btn btn-xs btn-secondary",
                                                            onclick: {
                                                                let id = host.id;
                                                                let name = host.name.clone();
                                                                move |_| show_hostkey_modal(id, name.clone())
                                                            },
                                                            "Refresh"
                                                        }
                                                    }
                                                }
                                            }
                                            td {
                                                // Access column - show count with structured tooltip and edit icon
                                                StructuredTooltip {
                                                    sections: {
                                                        let users: Vec<_> = host.access_principals.iter()
                                                            .filter(|p| p.kind == PrincipalKind::User)
                                                            .map(|p| p.name.clone())
                                                            .collect();
                                                        let groups: Vec<_> = host.access_principals.iter()
                                                            .filter(|p| p.kind == PrincipalKind::Group)
                                                            .map(|p| p.name.clone())
                                                            .collect();

                                                        let mut sections = Vec::new();
                                                        if !users.is_empty() {
                                                            sections.push(TooltipSection::new("Users").with_items(users));
                                                        }
                                                        if !groups.is_empty() {
                                                            sections.push(TooltipSection::new("Groups").with_items(groups));
                                                        }
                                                        if sections.is_empty() {
                                                            sections.push(TooltipSection::without_header().with_empty_message("No access configured"));
                                                        }
                                                        sections
                                                    },
                                                    Protected {
                                                        claim: Some(ClaimType::Relays(ClaimLevel::Edit)),
                                                        fallback: rsx! {
                                                             span {
                                                                class: if host.access_principals.is_empty() {
                                                                    "badge badge-error gap-2"
                                                                } else {
                                                                    "badge badge-primary gap-2"
                                                                },
                                                                "{host.access_principals.len()} "
                                                                {if host.access_principals.len() == 1 { "principal" } else { "principals" }}
                                                             }
                                                        },
                                                        button {
                                                            class: if host.access_principals.is_empty() {
                                                                "badge badge-error gap-2 cursor-pointer hover:badge-accent"
                                                            } else {
                                                                "badge badge-primary gap-2 cursor-pointer hover:badge-accent"
                                                            },
                                                            onclick: {
                                                                let id = host.id;
                                                                let name = host.name.clone();
                                                                move |_| open_access_modal(id, name.clone())
                                                            },
                                                            "{host.access_principals.len()} "
                                                            {if host.access_principals.len() == 1 { "principal" } else { "principals" }}
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
                                                                    d: "M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            td { class: "text-right",
                                                Protected {
                                                    any_claims: vec![ClaimType::Relays(ClaimLevel::Edit), ClaimType::Relays(ClaimLevel::Delete)],
                                                    TableActions {
                                                        on_edit: {
                                                            let host_name = host.name.clone();
                                                            let host_endpoint = format!("{}:{}", host.ip, host.port);
                                                            let auth_config = host.auth_config.clone();
                                                            move |_| open_edit(host.id, host_name.clone(), host_endpoint.clone(), auth_config.clone())
                                                        },
                                                        on_delete: {
                                                            let host_id = host.id;
                                                            let host_name = host.name.clone();
                                                            move |_| open_delete_confirm(host_id, host_name.clone())
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
                                    span { "Error loading relays: {e}" }
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

                Protected {
                    claim: Some(ClaimType::Relays(ClaimLevel::Create)),
                    Fab { onclick: open_add }
                }

                StepModal {
                    open: is_modal_open(),
                    on_close: move |_| is_modal_open.set(false),
                    title: if editing_id().is_some() { "Edit Relay".to_string() } else { "Add Relay".to_string() },
                    steps: vec!["Connection".to_string(), "Authentication".to_string(), "Access".to_string()],
                    current_step: current_step(),
                    on_next: on_next_step,
                    on_back: on_back_step,
                    on_save: on_save,
                    can_proceed: {
                        if current_step() == 1 {
                            // Step 1 (Connection) - require name and endpoint
                            !name().trim().is_empty() && !endpoint().trim().is_empty()
                        } else if current_step() == 2 {
                            // Step 2 (Authentication) - validate based on mode
                            match auth_mode().as_str() {
                                "none" => true,
                                "saved" => selected_credential_id() > 0,
                                "custom" => {
                                    let auth_type_val = auth_type();
                                    let username_mode_val = auth_username_mode();
                                    let password_required_val = auth_password_required();
                                    let password_required_changing =
                                        editing_id().is_some() && !auth_original_password_required() && password_required_val;
                                    let effective_has_existing_password =
                                        has_existing_password() && !password_required_changing;

                                    CredentialValidationInput {
                                        kind: &auth_type_val,
                                        username_mode: &username_mode_val,
                                        username: &auth_username(),
                                        password_required: password_required_val,
                                        password: &auth_password(),
                                        private_key: &auth_private_key(),
                                        public_key: &auth_public_key(),
                                        is_editing: editing_id().is_some(),
                                        has_existing_password: effective_has_existing_password,
                                        has_existing_private_key: has_existing_private_key(),
                                        has_existing_public_key: has_existing_public_key(),
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
                    },

                    // Step content
                    if current_step() == 1 {
                        // Step 1: Connection
                        div { class: "flex flex-col gap-4",
                            if let Some(err) = error_message() {
                                div { class: "alert alert-error",
                                    span { "{err}" }
                                }
                            }

                            label { class: "form-control w-full",
                                div { class: "label", span { class: "label-text", "Name" } }
                                input {
                                    r#type: "text",
                                    class: if validation_errors().contains_key("name") { "input input-bordered w-full input-error" } else { "input input-bordered w-full" },
                                    placeholder: "My Relay",
                                    value: "{name}",
                                    oninput: move |e| {
                                        name.set(e.value());
                                        if validation_errors().contains_key("name") {
                                            let mut errs = validation_errors();
                                            errs.remove("name");
                                            validation_errors.set(errs);
                                        }
                                    }
                                }
                                if let Some(err) = validation_errors().get("name") {
                                    div { class: "text-error text-sm mt-1", "{err}" }
                                }
                            }

                            label { class: "form-control w-full",
                                div { class: "label", span { class: "label-text", "Endpoint (host:port)" } }
                                input {
                                    r#type: "text",
                                    class: if validation_errors().contains_key("endpoint") { "input input-bordered w-full input-error" } else { "input input-bordered w-full" },
                                    placeholder: "127.0.0.1:2222",
                                    value: "{endpoint}",
                                    oninput: move |e| {
                                        endpoint.set(e.value());
                                        if validation_errors().contains_key("endpoint") {
                                            let mut errs = validation_errors();
                                            errs.remove("endpoint");
                                            validation_errors.set(errs);
                                        }
                                    }
                                }
                                if let Some(err) = validation_errors().get("endpoint") {
                                    div { class: "text-error text-sm mt-1", "{err}" }
                                }
                            }
                        }
                    } else if current_step() == 2 {
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
                                        checked: auth_mode() == "none",
                                        onchange: move |_| {
                                            auth_mode.set("none".to_string());
                                            auth_validation_errors.set(HashMap::new());
                                        }
                                    }
                                    span { class: "label-text", "None" }
                                }
                                label { class: "label cursor-pointer justify-start gap-2",
                                    input {
                                        r#type: "radio",
                                        name: "auth-mode",
                                        class: "radio",
                                        checked: auth_mode() == "saved",
                                        onchange: move |_| {
                                            auth_mode.set("saved".to_string());
                                            auth_validation_errors.set(HashMap::new());
                                        }
                                    }
                                    span { class: "label-text", "Saved Credential" }
                                }
                                label { class: "label cursor-pointer justify-start gap-2",
                                    input {
                                        r#type: "radio",
                                        name: "auth-mode",
                                        class: "radio",
                                        checked: auth_mode() == "custom",
                                        onchange: move |_| {
                                            auth_mode.set("custom".to_string());
                                            auth_validation_errors.set(HashMap::new());
                                        }
                                    }
                                    span { class: "label-text", "Custom" }
                                }
                            }

                            // Saved credential selector
                            if auth_mode() == "saved" {
                                div { class: "form-control w-full",
                                    div { class: "label", span { class: "label-text", "Select Credential" } }
                                    select {
                                        class: if auth_validation_errors().contains_key("credential") {
                                            "select select-bordered w-full select-error"
                                        } else {
                                            "select select-bordered w-full"
                                        },
                                        value: "{selected_credential_id}",
                                        onchange: move |e| {
                                            if let Ok(id) = e.value().parse::<i64>() {
                                                selected_credential_id.set(id);
                                                if auth_validation_errors().contains_key("credential") {
                                                    let mut errs = auth_validation_errors();
                                                    errs.remove("credential");
                                                    auth_validation_errors.set(errs);
                                                }
                                            }
                                        },
                                        option { value: "0", "-- Select a credential --" }
                                        {credentials().and_then(|res| res.ok()).map(|creds| rsx! {
                                            for cred in creds {
                                                option {
                                                    value: "{cred.id}",
                                                    selected: selected_credential_id() == cred.id,
                                                    "{cred.name} ({cred.kind})"
                                                }
                                            }
                                        })}
                                    }
                                    if let Some(err) = auth_validation_errors().get("credential") {
                                        div { class: "text-error text-sm mt-1", "{err}" }
                                    }
                                }
                            }
                            // Custom auth fields
                            if auth_mode() == "custom" {
                                div { class: "flex flex-col gap-4 p-4 bg-base-300 rounded-lg",
                                    CredentialForm {
                                        cred_type: auth_type(),
                                        on_type_change: move |v| {
                                            auth_type.set(v);
                                            if auth_validation_errors().contains_key("password")
                                                || auth_validation_errors().contains_key("private_key")
                                                || auth_validation_errors().contains_key("public_key")
                                            {
                                                let mut errs = auth_validation_errors();
                                                errs.remove("password");
                                                errs.remove("private_key");
                                                errs.remove("public_key");
                                                auth_validation_errors.set(errs);
                                            }
                                        },
                                        username: auth_username(),
                                        on_username_change: move |v| {
                                            auth_username.set(v);
                                            if auth_validation_errors().contains_key("username") {
                                                let mut errs = auth_validation_errors();
                                                errs.remove("username");
                                                auth_validation_errors.set(errs);
                                            }
                                        },
                                        username_mode: auth_username_mode(),
                                        on_username_mode_change: move |v: String| {
                                            auth_username_mode.set(v.clone());
                                            // If username_mode is not "fixed", force password_required to false
                                            if v != "fixed" {
                                                auth_password_required.set(false);
                                                auth_password.set(String::new());
                                                if auth_validation_errors().contains_key("username") {
                                                    let mut errs = auth_validation_errors();
                                                    errs.remove("username");
                                                    auth_validation_errors.set(errs);
                                                }
                                            }
                                        },
                                        password_required: auth_password_required(),
                                        on_password_required_change: move |v| {
                                            auth_password_required.set(v);
                                            if !v {
                                                auth_password.set(String::new());
                                            }
                                        },
                                        password: auth_password(),
                                        on_password_change: move |v| {
                                            auth_password.set(v);
                                            if auth_validation_errors().contains_key("password") {
                                                let mut errs = auth_validation_errors();
                                                errs.remove("password");
                                                auth_validation_errors.set(errs);
                                            }
                                        },
                                        private_key: auth_private_key(),
                                        on_private_key_change: move |v| {
                                            auth_private_key.set(v);
                                            if auth_validation_errors().contains_key("private_key") {
                                                let mut errs = auth_validation_errors();
                                                errs.remove("private_key");
                                                auth_validation_errors.set(errs);
                                            }
                                        },
                                        public_key: auth_public_key(),
                                        on_public_key_change: move |v| {
                                            auth_public_key.set(v);
                                            if auth_validation_errors().contains_key("public_key") {
                                                let mut errs = auth_validation_errors();
                                                errs.remove("public_key");
                                                auth_validation_errors.set(errs);
                                            }
                                        },
                                        passphrase: auth_passphrase(),
                                        on_passphrase_change: move |v| auth_passphrase.set(v),
                                        validation_errors: auth_validation_errors(),
                                        show_hint: editing_id().is_some()
                                            && (has_existing_password()
                                                || has_existing_private_key()
                                                || has_existing_public_key()),
                                        is_editing: editing_id().is_some(),
                                        has_existing_password: has_existing_password(),
                                        has_existing_private_key: has_existing_private_key(),
                                        has_existing_public_key: has_existing_public_key(),
                                        show_type_selector: true,
                                        original_password_required: auth_original_password_required(),
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
                            if let Some(id) = editing_id() {
                                RelayAccessForm {
                                    relay_id: id,
                                    on_change: move |_| {
                                        // Refresh relays list when access changes
                                        relays.restart();
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

                // Assign Credential Modal
                Modal {
                    open: assign_modal_open(),
                    on_close: move |_| assign_modal_open.set(false),
                    title: "Assign Authentication",
                    actions: rsx! {
                        button { class: "btn btn-primary", onclick: handle_assign, "Save" }
                    },
                    div { class: "flex flex-col gap-2",
                        p { "Configure authentication for "{assign_target_name()}":" }

                        // Mode selector
                        div { class: "flex flex-row gap-4 form-control",
                            label { class: "label cursor-pointer justify-start gap-2",
                                input {
                                    r#type: "radio",
                                    name: "assign-mode",
                                    class: "radio",
                                    checked: assign_mode() == "saved",
                                    onchange: move |_| assign_mode.set("saved".to_string())
                                }
                                span { class: "label-text", "Saved Credential" }
                            }
                            label { class: "label cursor-pointer justify-start gap-2",
                                input {
                                    r#type: "radio",
                                    name: "assign-mode",
                                    class: "radio",
                                    checked: assign_mode() == "custom",
                                    onchange: move |_| assign_mode.set("custom".to_string())
                                }
                                span { class: "label-text", "Custom" }
                            }
                        }

                        // Saved credential selector
                        if assign_mode() == "saved" {
                            match credentials() {
                                Some(Ok(creds)) => rsx! {
                                    label { class: "form-control w-full",
                                        div { class: "label", span { class: "label-text", "Credential" } }
                                        select {
                                            class: if assign_validation_errors().contains_key("credential") { "select select-bordered w-full select-error" } else { "select select-bordered w-full" },
                                            value: "{selected_credential_id}",
                                            onchange: move |e| {
                                                if let Ok(id) = e.value().parse::<i64>() {
                                                    selected_credential_id.set(id);
                                                }
                                            },
                                            option { value: "0", "Select a credential..." }
                                            for cred in creds {
                                                option { value: "{cred.id}", "{cred.name} ({cred.kind})" }
                                            }
                                        }
                                        if let Some(err) = assign_validation_errors().get("credential") {
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
                                        cred_type: assign_auth_type(),
                                        on_type_change: move |v| assign_auth_type.set(v),
                                        username: assign_username(),
                                        on_username_change: move |v| {
                                            assign_username.set(v);
                                            if assign_validation_errors().contains_key("username") {
                                                let mut errs = assign_validation_errors();
                                                errs.remove("username");
                                                assign_validation_errors.set(errs);
                                            }
                                        },
                                        username_mode: assign_username_mode(),
                                        on_username_mode_change: move |v: String| {
                                            assign_username_mode.set(v.clone());
                                            // If username_mode is not "fixed", force password_required to false
                                            if v != "fixed" {
                                                assign_password_required.set(false);
                                                assign_password.set(String::new()); // Clear password field
                                            }
                                        },
                                        password_required: assign_password_required(),
                                        on_password_required_change: move |v| {
                                            assign_password_required.set(v);
                                            // Clear password field when unchecking "stored"
                                            if !v {
                                                assign_password.set(String::new());
                                            }
                                        },
                                        password: assign_password(),
                                        on_password_change: move |v| {
                                            assign_password.set(v);
                                            if assign_validation_errors().contains_key("password") {
                                                let mut errs = assign_validation_errors();
                                                errs.remove("password");
                                                assign_validation_errors.set(errs);
                                            }
                                        },
                                        private_key: assign_private_key(),
                                        on_private_key_change: move |v| {
                                            assign_private_key.set(v);
                                            if assign_validation_errors().contains_key("private_key") {
                                                let mut errs = assign_validation_errors();
                                                errs.remove("private_key");
                                                assign_validation_errors.set(errs);
                                            }
                                        },
                                        public_key: assign_public_key(),
                                        on_public_key_change: move |v| {
                                            assign_public_key.set(v);
                                            if assign_validation_errors().contains_key("public_key") {
                                                let mut errs = assign_validation_errors();
                                                errs.remove("public_key");
                                                assign_validation_errors.set(errs);
                                            }
                                        },
                                        passphrase: assign_passphrase(),
                                        on_passphrase_change: move |v| assign_passphrase.set(v),
                                        validation_errors: assign_validation_errors(),
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

                // Clear Credential Modal
                Modal {
                    open: clear_modal_open(),
                    on_close: move |_| clear_modal_open.set(false),
                    title: "Clear Authentication",
                    actions: rsx! {
                        button { class: "btn btn-error", onclick: handle_clear, "Clear" }
                    },
                    div { class: "flex flex-col gap-4",
                        p { "Are you sure you want to clear authentication for "{clear_target_name()}"?" }
                        p { class: "text-sm text-gray-500",
                            "This will remove the assigned credential or inline authentication for this relay host."
                        }
                    }
                }

                // Delete Confirmation Modal
                Modal {
                    open: delete_confirm_open(),
                    on_close: move |_| delete_confirm_open.set(false),
                    title: "Delete Relay Host",
                    actions: rsx! {
                        button { class: "btn btn-error", onclick: handle_delete, "Delete" }
                    },
                    div { class: "flex flex-col gap-4",
                        p { "Are you sure you want to delete relay host "{delete_target_name()}"?" }
                        p { class: "text-sm text-gray-500",
                            "This action cannot be undone."
                        }
                    }
                }

                // Refresh Hostkey Modal
                Modal {
                    open: refresh_modal_open(),
                    on_close: move |_| {
                        refresh_modal_open.set(false);
                        refresh_review.set(None);
                    },
                    title: "Refresh Hostkey",
                    actions: rsx! {
                        button { class: "btn btn-secondary", onclick: handle_refresh, "Accept & Store" }
                    },
                    div { class: "flex flex-col gap-4",
                        if let Some(review) = refresh_review() {
                            p { "Fetched hostkey for "{refresh_target_name()}":" }

                            if let Some(old_fp) = review.old_fingerprint {
                                div { class: "alert alert-info",
                                    div {
                                        p { class: "font-semibold", "Current Hostkey:" }
                                        p { class: "text-sm font-mono", "{old_fp}" }
                                        if let Some(old_type) = review.old_key_type {
                                            p { class: "text-xs text-gray-500", "Type: {old_type}" }
                                        }
                                    }
                                }
                            } else {
                                div { class: "alert alert-warning",
                                    p { "No hostkey currently stored for this relay" }
                                }
                            }

                            div { class: "alert alert-success",
                                div {
                                    p { class: "font-semibold", "New Hostkey:" }
                                    p { class: "text-sm font-mono", "{review.new_fingerprint}" }
                                    p { class: "text-xs text-gray-500", "Type: {review.new_key_type}" }
                                }
                            }

                            p { class: "text-sm text-gray-500",
                                "Click 'Accept & Store' to save this hostkey, or 'Cancel' to discard."
                            }
                        } else {
                            div { class: "flex justify-center p-4",
                                span { class: "loading loading-spinner" }
                                span { class: "ml-2", "Fetching hostkey..." }
                            }
                        }
                    }
                }
            }

            // Access modal
            Modal {
                open: access_modal_open(),
                title: format!("Manage Access: {}", access_target_name()),
                on_close: move |_| access_modal_open.set(false),
                actions: rsx! {
                    button {
                        class: "btn",
                        onclick: move |_| access_modal_open.set(false),
                        "Close"
                    }
                },
                RelayAccessForm {
                    relay_id: access_target_id(),
                    on_change: move |_| {
                        // Optionally refresh relays list or users list
                        relays.restart();
                    }
                }
            }
        }
    }
}
