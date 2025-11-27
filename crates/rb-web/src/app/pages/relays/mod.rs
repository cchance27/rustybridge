use std::collections::HashMap;

use dioxus::prelude::*;
use rb_types::{
    auth::{ClaimLevel, ClaimType}, credentials::AuthWebConfig
};

use crate::{
    app::api::relays::fetch_relay_hostkey_for_review, components::{Fab, Layout, Protected, RequireAuth, Toast, ToastMessage, ToastType}
};

mod modals;
mod state;
mod table;

use modals::{
    access_modal::AccessManagementModal, assign_modal::AssignCredentialModal, clear_modal::ClearCredentialModal, delete_modal::DeleteRelayModal, edit_modal::EditRelayModal, hostkey_modal::HostkeyReviewModal
};
use state::RelayState;
use table::RelaysTable;

#[component]
pub fn RelaysPage() -> Element {
    // Initialize state
    let mut state = RelayState::new();

    // Create event handlers
    let open_add = move |_| {
        state.editing_id.set(None);
        state.name.set(String::new());
        state.endpoint.set(String::new());
        state.error_message.set(None);
        state.validation_errors.set(HashMap::new());
        state.auth_mode.set("none".to_string());
        state.auth_type.set("password".to_string());
        state.auth_username.set(String::new());
        state.auth_password.set(String::new());
        state.auth_private_key.set(String::new());
        state.auth_passphrase.set(String::new());
        state.auth_public_key.set(String::new());
        state.auth_password_required.set(true);
        state.auth_original_password_required.set(true);
        state.auth_validation_errors.set(HashMap::new());
        state.has_existing_password.set(false);
        state.has_existing_private_key.set(false);
        state.has_existing_passphrase.set(false);
        state.has_existing_public_key.set(false);
        state.current_step.set(1);
        state.is_modal_open.set(true);
    };

    let open_edit = move |(id, current_name, current_endpoint, config): (i64, String, String, Option<AuthWebConfig>)| {
        state.editing_id.set(Some(id));
        state.name.set(current_name);
        state.endpoint.set(current_endpoint);
        state.error_message.set(None);
        state.validation_errors.set(HashMap::new());

        // Reset auth fields to defaults before applying config
        state.auth_mode.set("none".to_string());
        state.auth_type.set("password".to_string());
        state.auth_username.set(String::new());
        state.auth_password_required.set(true);
        state.auth_password.set(String::new());
        state.auth_private_key.set(String::new());
        state.auth_passphrase.set(String::new());
        state.auth_public_key.set(String::new());
        state.auth_original_password_required.set(true);
        state.auth_validation_errors.set(HashMap::new());
        state.has_existing_password.set(false);
        state.has_existing_private_key.set(false);
        state.has_existing_passphrase.set(false);
        state.has_existing_public_key.set(false);

        // Populate auth fields from config
        if let Some(c) = config {
            state.auth_mode.set(c.mode);
            if let Some(sid) = c.saved_credential_id {
                state.selected_credential_id.set(sid);
            }
            match c.custom_type {
                Some(ctype) => state.auth_type.set(ctype),
                None => state.auth_type.set("password".to_string()),
            }
            match c.username {
                Some(u) => state.auth_username.set(u),
                None => state.auth_username.set(String::new()),
            }
            match c.username_mode {
                Some(m) => state.auth_username_mode.set(m),
                None => state.auth_username_mode.set("fixed".to_string()),
            }
            if let Some(required) = c.password_required {
                state.auth_password_required.set(required);
                state.auth_original_password_required.set(required);
            } else {
                state.auth_original_password_required.set(true);
            }
            if c.has_password {
                state.has_existing_password.set(true);
            }
            if c.has_private_key {
                state.has_existing_private_key.set(true);
            }
            if c.has_passphrase {
                state.has_existing_passphrase.set(true);
            }
            if c.has_public_key {
                state.has_existing_public_key.set(true);
            }
        }

        state.current_step.set(1);
        state.is_modal_open.set(true);
    };

    let open_delete_confirm = move |(id, name): (i64, String)| {
        state.delete_target_id.set(id);
        state.delete_target_name.set(name);
        state.delete_confirm_open.set(true);
    };

    let open_access_modal = move |(id, name): (i64, String)| {
        state.access_target_id.set(id);
        state.access_target_name.set(name);
        state.access_modal_open.set(true);
    };

    let show_hostkey_modal = move |(id, name): (i64, String)| {
        state.refresh_target_id.set(id);
        state.refresh_target_name.set(name.clone());
        state.refresh_review.set(None);
        state.refresh_modal_open.set(true);

        spawn(async move {
            match fetch_relay_hostkey_for_review(id).await {
                Ok(review) => state.refresh_review.set(Some(review)),
                Err(e) => {
                    state.refresh_modal_open.set(false);
                    state.refresh_review.set(None);
                    state.toast.set(Some(ToastMessage {
                        message: format!("Failed to fetch hostkey: {}", e),
                        toast_type: ToastType::Error,
                    }));
                }
            }
        });
    };

    let open_clear_modal = move |(id, name, is_inline): (i64, String, bool)| {
        state.clear_target_id.set(id);
        state.clear_target_name.set(name);
        state.clear_is_inline.set(is_inline);
        state.clear_modal_open.set(true);
    };

    let open_assign_modal = move |(id, name): (i64, String)| {
        state.assign_target_id.set(id);
        state.assign_target_name.set(name);
        state.assign_mode.set("saved".to_string());
        state.assign_auth_type.set("password".to_string());
        state.assign_username.set(String::new());
        state.assign_username_mode.set("fixed".to_string());
        state.assign_password_required.set(true);
        state.assign_password.set(String::new());
        state.assign_private_key.set(String::new());
        state.assign_public_key.set(String::new());
        state.assign_passphrase.set(String::new());
        state.assign_validation_errors.set(HashMap::new());
        state.assign_modal_open.set(true);
    };

    rsx! {
            RequireAuth {
                any_claims: vec![ClaimType::Relays(ClaimLevel::View)],
                Toast { message: state.toast }
                Layout {
                    div { class: "card bg-base-200 shadow-xl",
                    div { class: "card-body",
                        h2 { class: "card-title", "Relay Hosts" }
                        p { "Manage your relay servers here." }

                        // Show loading state or data
                        match (state.relays)() {
                            Some(Ok(hosts)) => rsx! {
                                RelaysTable {
                                    hosts: hosts,
                                    open_edit: open_edit,
                                    open_delete_confirm: open_delete_confirm,
                                    open_access_modal: open_access_modal,
                                    show_hostkey_modal: show_hostkey_modal,
                                    open_clear_modal: open_clear_modal,
                                    open_assign_modal: open_assign_modal,
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

                // Modals
                EditRelayModal {
                    state: state,
                }

                AssignCredentialModal {
                    state: state,
                }

                ClearCredentialModal {
                    state: state,
                }

                DeleteRelayModal {
                    state: state,
                }

                HostkeyReviewModal {
                    state: state,
                }

                AccessManagementModal {
                    state: state,
                }
            }
        }
    }
}
