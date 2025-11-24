use std::collections::HashMap;

use dioxus::prelude::*;
use rb_types::{
    auth::{ClaimLevel, ClaimType}, validation::{CredentialValidationInput, ValidationError}, web::{CreateCredentialRequest, UpdateCredentialRequest}
};

use crate::{
    app::api::credentials::*, components::{
        CredentialBadge, CredentialForm, Fab, Layout, Modal, Protected, RequireAuth, StructuredTooltip, Table, TableActions, Toast, ToastMessage, ToastType, TooltipSection
    }
};

#[component]
pub fn CredentialsPage() -> Element {
    // Load credentials from server
    let mut credentials = use_resource(|| async move { list_credentials().await });

    // Toast notification state
    let mut toast = use_signal(|| None::<ToastMessage>);

    // Modal state
    let mut is_modal_open = use_signal(|| false);
    let mut editing_id = use_signal(|| None::<i64>);
    let mut name = use_signal(String::new);
    let mut cred_type = use_signal(|| "password".to_string());
    let mut username = use_signal(String::new);
    let mut username_mode = use_signal(|| "fixed".to_string());
    let mut password_required = use_signal(|| true);
    let mut password = use_signal(String::new);
    let mut private_key = use_signal(String::new);
    let mut public_key = use_signal(String::new);
    let mut passphrase = use_signal(String::new);
    let mut has_existing_password = use_signal(|| false);
    let mut has_existing_private_key = use_signal(|| false);
    let mut has_existing_public_key = use_signal(|| false);
    let mut original_password_required = use_signal(|| true); // Track original value when editing
    let mut error_message = use_signal(|| None::<String>);
    let mut validation_errors = use_signal(HashMap::<String, ValidationError>::new);

    // Delete confirmation state

    let open_add = move |_| {
        editing_id.set(None);
        name.set(String::new());
        cred_type.set("password".to_string());
        username.set(String::new());
        username_mode.set("fixed".to_string());
        password_required.set(true);
        password.set(String::new());
        private_key.set(String::new());
        public_key.set(String::new());
        passphrase.set(String::new());
        has_existing_password.set(false);
        has_existing_private_key.set(false);
        has_existing_public_key.set(false);
        error_message.set(None);
        validation_errors.set(HashMap::new());
        is_modal_open.set(true);
    };

    let mut open_edit = move |id: i64,
                              current_name: String,
                              current_kind: String,
                              current_username: Option<String>,
                              current_username_mode: String,
                              current_password_required: bool,
                              has_secret: bool| {
        // We can't easily get the secrets back, so we leave them empty for the user to replace if they want
        // But we should probably fetch the username if possible.
        // For now, let's just allow resetting them.
        editing_id.set(Some(id));
        name.set(current_name);
        cred_type.set(current_kind.clone());
        username.set(current_username.unwrap_or_default());
        username_mode.set(current_username_mode);
        password_required.set(current_password_required);
        original_password_required.set(current_password_required); // Track original value
        password.set(String::new());
        private_key.set(String::new());
        public_key.set(String::new());
        passphrase.set(String::new());
        has_existing_password.set(has_secret && current_kind == "password");
        has_existing_private_key.set(has_secret && current_kind == "ssh_key");
        has_existing_public_key.set(has_secret && current_kind == "agent");
        error_message.set(None);
        validation_errors.set(HashMap::new());
        is_modal_open.set(true);
    };

    let on_save = move |_| {
        // Clear previous validation errors
        validation_errors.set(HashMap::new());

        let name_val = name();
        let type_val = cred_type();
        let username_val = username();
        let username_mode_val = username_mode();
        let password_required_val = password_required();
        let password_val = password();
        let private_key_val = private_key();
        let public_key_val = public_key();
        let passphrase_val = passphrase();
        let is_editing = editing_id().is_some();

        // Client-side validation
        let mut errors = HashMap::new();

        if name_val.trim().is_empty() {
            errors.insert("name".to_string(), ValidationError::Required);
        }

        // Use shared validation utility
        // If password requirement is changing from false to true, treat old password as blank
        let password_required_changing = is_editing && !*original_password_required.read() && password_required_val;
        let effective_has_existing_password = has_existing_password() && !password_required_changing;

        let field_errors = CredentialValidationInput {
            kind: &type_val,
            username_mode: &username_mode_val,
            username: &username_val,
            password_required: password_required_val,
            password: &password_val,
            private_key: &private_key_val,
            public_key: &public_key_val,
            is_editing: is_editing,
            has_existing_password: effective_has_existing_password,
            has_existing_private_key: has_existing_private_key(),
            has_existing_public_key: has_existing_public_key(),
        }
        .validate();
        errors.extend(field_errors);

        if !errors.is_empty() {
            // Show inline errors, keep modal open
            validation_errors.set(errors);
            return;
        }

        let id = editing_id();

        // Validation passed, proceed with server call
        spawn(async move {
            let result = if let Some(id_val) = id {
                update_credential(
                    id_val,
                    UpdateCredentialRequest {
                        name: name_val.clone(),
                        kind: type_val.clone(),
                        username: if username_val.is_empty() {
                            None
                        } else {
                            Some(username_val.clone())
                        },
                        username_mode: username_mode_val.clone(),
                        password_required: password_required_val,
                        password: if password_val.is_empty() {
                            None
                        } else {
                            Some(password_val.clone())
                        },
                        private_key: if private_key_val.is_empty() {
                            None
                        } else {
                            Some(private_key_val.clone())
                        },
                        public_key: if public_key_val.is_empty() {
                            None
                        } else {
                            Some(public_key_val.clone())
                        },
                        passphrase: if passphrase_val.is_empty() {
                            None
                        } else {
                            Some(passphrase_val.clone())
                        },
                    },
                )
                .await
            } else {
                create_credential(CreateCredentialRequest {
                    name: name_val.clone(),
                    kind: type_val.clone(),
                    username: if username_val.is_empty() {
                        None
                    } else {
                        Some(username_val.clone())
                    },
                    username_mode: username_mode_val.clone(),
                    password_required: password_required_val,
                    password: if password_val.is_empty() {
                        None
                    } else {
                        Some(password_val.clone())
                    },
                    private_key: if private_key_val.is_empty() {
                        None
                    } else {
                        Some(private_key_val.clone())
                    },
                    public_key: if public_key_val.is_empty() {
                        None
                    } else {
                        Some(public_key_val.clone())
                    },
                    passphrase: if passphrase_val.is_empty() {
                        None
                    } else {
                        Some(passphrase_val.clone())
                    },
                })
                .await
            };

            match result {
                Ok(_) => {
                    is_modal_open.set(false);
                    toast.set(Some(ToastMessage {
                        message: format!(
                            "Credential '{}' {} successfully",
                            name_val,
                            if id.is_some() { "updated" } else { "created" }
                        ),
                        toast_type: ToastType::Success,
                    }));
                    credentials.restart(); // Reload data
                }
                Err(e) => {
                    is_modal_open.set(false);
                    toast.set(Some(ToastMessage {
                        message: format!("Failed to {} credential: {}", if id.is_some() { "update" } else { "create" }, e),
                        toast_type: ToastType::Error,
                    }));
                }
            }
        });
    };

    let mut delete_target = use_signal(|| None::<(i64, String)>);
    let mut delete_confirm_open = use_signal(|| false);

    let mut open_delete_confirm = move |id: i64, cred_name: String| {
        delete_target.set(Some((id, cred_name)));
        delete_confirm_open.set(true);
    };

    let handle_delete = move |_| {
        if let Some((id, name)) = delete_target() {
            spawn(async move {
                match delete_credential(id).await {
                    Ok(_) => {
                        delete_confirm_open.set(false);
                        toast.set(Some(ToastMessage {
                            message: format!("Credential '{}' deleted successfully", name),
                            toast_type: ToastType::Success,
                        }));
                        credentials.restart(); // Reload data
                    }
                    Err(e) => {
                        delete_confirm_open.set(false);
                        toast.set(Some(ToastMessage {
                            message: format!("Failed to delete credential: {}", e),
                            toast_type: ToastType::Error,
                        }));
                    }
                }
            });
        }
    };

    rsx! {
        RequireAuth {
            any_claims: vec![ClaimType::Credentials(ClaimLevel::View)],
            Toast { message: toast }
            Layout {
                div { class: "card bg-base-200 shadow-xl",
                    div { class: "card-body",
                        h2 { class: "card-title", "Credentials" }
                        p { "Manage your SSH keys, passwords, and agent credentials." }

                        // Show loading state or data
                        match credentials() {
                            Some(Ok(creds)) => rsx! {
                                Table {
                                    headers: vec!["ID", "Name", "Type", "Assigned", "Actions"],
                                    for cred in creds {
                                        tr {
                                            th { "{cred.id}" }
                                            td { "{cred.name}" }
                                            td {
                                                CredentialBadge {
                                                    kind: cred.kind.clone(),
                                                    username_mode: Some(cred.username_mode.clone()),
                                                    password_required: Some(cred.password_required),
                                                    kind_prefix: true,
                                                    show_type: true,
                                                    name: None,
                                                }
                                            }
                                            td {
                                                StructuredTooltip {
                                                    sections: vec![
                                                        TooltipSection::new("Relays")
                                                            .with_items(cred.assigned_relays.clone())
                                                            .with_empty_message("No relays assigned")
                                                    ],

                                                    div { class: if cred.assigned_relays.is_empty() { "badge badge-warning gap-2" } else { "badge badge-info gap-2" },
                                                        "{cred.assigned_relays.len()} "
                                                        {if cred.assigned_relays.len() == 1 { "relay" } else { "relays" }}
                                                    }
                                                }
                                            }
                                            td {
                                                class: "text-right",
                                                Protected {
                                                    any_claims: vec![ClaimType::Credentials(ClaimLevel::Edit), ClaimType::Credentials(ClaimLevel::Delete)],
                                                    TableActions {
                                                        on_edit: {
                                                            let cred_name = cred.name.clone();
                                                            let cred_kind = cred.kind.clone();
                                                            let cred_username = cred.username.clone();
                                                            let cred_username_mode = cred.username_mode.clone();
                                                            let cred_password_required = cred.password_required;
                                                            let has_secret = cred.has_secret;
                                                            move |_| open_edit(cred.id, cred_name.clone(), cred_kind.clone(), cred_username.clone(), cred_username_mode.clone(), cred_password_required, has_secret)
                                                        },
                                                        on_delete: {
                                                            let cred_name = cred.name.clone();
                                                            move |_| open_delete_confirm(cred.id, cred_name.clone())
                                                        },
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            Some(Err(e)) => rsx! {
                                div { class: "alert alert-error",
                                    span { "Error loading credentials: {e}" }
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
                    claim: ClaimType::Credentials(ClaimLevel::Create),
                    Fab { onclick: open_add }
                }

                // Add/Edit Modal
                Modal {
                    open: is_modal_open(),
                    on_close: move |_| is_modal_open.set(false),
                    title: if editing_id().is_some() { "Edit Credential" } else { "Add Credential" },
                    actions: rsx! {
                        button { class: "btn btn-primary", onclick: on_save, "Save" }
                    },
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
                                placeholder: "my-credential",
                                value: "{name}",
                                readonly: editing_id().is_some(),
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

                        CredentialForm {
                            cred_type: cred_type(),
                            on_type_change: move |v| {
                                cred_type.set(v);
                                if validation_errors().contains_key("password") || validation_errors().contains_key("private_key") || validation_errors().contains_key("public_key") {
                                    let mut errs = validation_errors();
                                    errs.remove("password");
                                    errs.remove("private_key");
                                    errs.remove("public_key");
                                    validation_errors.set(errs);
                                }
                            },
                            username: username(),
                            on_username_change: move |v| {
                                username.set(v);
                                if validation_errors().contains_key("username") {
                                    let mut errs = validation_errors();
                                    errs.remove("username");
                                    validation_errors.set(errs);
                                }
                            },
                            username_mode: username_mode(),
                            on_username_mode_change: move |v: String| {
                                username_mode.set(v.clone());
                                // If username_mode is not "fixed", force password_required to false
                                if v != "fixed" {
                                    password_required.set(false);
                                    password.set(String::new()); // Clear password field
                                }
                            },
                            password_required: password_required(),
                            on_password_required_change: move |v| {
                                password_required.set(v);
                                // Clear password field when unchecking "stored"
                                if !v {
                                    password.set(String::new());
                                }
                            },
                            password: password(),
                            on_password_change: move |v| {
                                password.set(v);
                                if validation_errors().contains_key("password") {
                                    let mut errs = validation_errors();
                                    errs.remove("password");
                                    validation_errors.set(errs);
                                }
                            },
                            private_key: private_key(),
                            on_private_key_change: move |v| {
                                private_key.set(v);
                                if validation_errors().contains_key("private_key") {
                                    let mut errs = validation_errors();
                                    errs.remove("private_key");
                                    validation_errors.set(errs);
                                }
                            },
                            public_key: public_key(),
                            on_public_key_change: move |v| {
                                public_key.set(v);
                                if validation_errors().contains_key("public_key") {
                                    let mut errs = validation_errors();
                                    errs.remove("public_key");
                                    validation_errors.set(errs);
                                }
                            },
                            passphrase: passphrase(),
                            on_passphrase_change: move |v| passphrase.set(v),
                            validation_errors: validation_errors(),
                            show_hint: editing_id().is_some(),
                            is_editing: editing_id().is_some(),
                            has_existing_password: has_existing_password(),
                            has_existing_private_key: has_existing_private_key(),
                            has_existing_public_key: has_existing_public_key(),
                            show_type_selector: true,
                            original_password_required: *original_password_required.read(),
                        }
                    }
                }

                // Delete Confirmation Modal
                Modal {
                    open: delete_confirm_open(),
                    on_close: move |_| delete_confirm_open.set(false),
                    title: "Delete Credential",
                    actions: rsx! {
                        button { class: "btn btn-error", onclick: handle_delete, "Delete" }
                    },
                    div { class: "flex flex-col gap-4",
                     p { class: "py-4", "Are you sure you want to delete credential '{delete_target().map(|(_, n)| n).unwrap_or_default()}'? This action cannot be undone." }
                     p { class: "text-sm text-gray-500",
                            "This action cannot be undone. Make sure no relay hosts are using this credential."
                        }
                    }
                }
            }
        }
    }
}
