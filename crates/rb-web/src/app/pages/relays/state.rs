use std::collections::HashMap;

use dioxus::prelude::*;
use rb_types::{
    credentials::CredentialInfo, relay::{HostkeyReview, RelayHostInfo}, validation::ValidationError
};

use crate::{app::api::relays::*, error::ApiError};

/// Centralized state management for the Relays page
#[derive(Clone, Copy, PartialEq)]
pub struct RelayState {
    // Relay data and resources
    pub relays: Resource<Result<Vec<RelayHostInfo>, ApiError>>,
    pub credentials: Resource<Result<Vec<CredentialInfo>, ApiError>>,

    // Assign credential modal state
    pub assign_modal_open: Signal<bool>,
    pub assign_target_id: Signal<i64>,
    pub assign_target_name: Signal<String>,
    pub selected_credential_id: Signal<i64>,
    pub assign_mode: Signal<String>,
    pub assign_auth_type: Signal<String>,
    pub assign_username_mode: Signal<String>,
    pub assign_password_required: Signal<bool>,
    pub assign_username: Signal<String>,
    pub assign_password: Signal<String>,
    pub assign_private_key: Signal<String>,
    pub assign_public_key: Signal<String>,
    pub assign_passphrase: Signal<String>,
    pub assign_validation_errors: Signal<HashMap<String, ValidationError>>,

    // Clear credential modal state
    pub clear_modal_open: Signal<bool>,
    pub clear_target_id: Signal<i64>,
    pub clear_target_name: Signal<String>,
    pub clear_is_inline: Signal<bool>,

    // Hostkey refresh modal state
    pub refresh_modal_open: Signal<bool>,
    pub refresh_target_id: Signal<i64>,
    pub refresh_target_name: Signal<String>,
    pub refresh_review: Signal<Option<HostkeyReview>>,

    // Delete confirmation modal state
    pub delete_confirm_open: Signal<bool>,
    pub delete_target_id: Signal<i64>,
    pub delete_target_name: Signal<String>,

    // Access modal state
    pub access_modal_open: Signal<bool>,
    pub access_target_id: Signal<i64>,
    pub access_target_name: Signal<String>,

    // Edit/Create modal state
    pub is_modal_open: Signal<bool>,
    pub editing_id: Signal<Option<i64>>,
    pub name: Signal<String>,
    pub endpoint: Signal<String>,
    pub error_message: Signal<Option<String>>,
    pub validation_errors: Signal<HashMap<String, ValidationError>>,
    pub current_step: Signal<i32>,

    // Authentication state for edit/create modal
    pub auth_mode: Signal<String>,
    pub auth_type: Signal<String>,
    pub auth_username: Signal<String>,
    pub auth_username_mode: Signal<String>,
    pub auth_password_required: Signal<bool>,
    pub auth_password: Signal<String>,
    pub auth_private_key: Signal<String>,
    pub auth_passphrase: Signal<String>,
    pub auth_public_key: Signal<String>,
    pub auth_original_password_required: Signal<bool>,
    pub auth_validation_errors: Signal<HashMap<String, ValidationError>>,
    pub has_existing_password: Signal<bool>,
    pub has_existing_private_key: Signal<bool>,
    pub has_existing_passphrase: Signal<bool>,
    pub has_existing_public_key: Signal<bool>,
}

impl RelayState {
    /// Initialize all state signals for the Relays page
    pub fn new() -> Self {
        Self {
            // Resources
            relays: use_resource(|| async move { list_relay_hosts().await }),
            credentials: use_resource(|| async move { crate::app::api::credentials::list_credentials().await }),

            // Assign modal
            assign_modal_open: use_signal(|| false),
            assign_target_id: use_signal(|| 0i64),
            assign_target_name: use_signal(String::new),
            selected_credential_id: use_signal(|| 0i64),
            assign_mode: use_signal(|| "saved".to_string()),
            assign_auth_type: use_signal(|| "password".to_string()),
            assign_username_mode: use_signal(|| "fixed".to_string()),
            assign_password_required: use_signal(|| true),
            assign_username: use_signal(String::new),
            assign_password: use_signal(String::new),
            assign_private_key: use_signal(String::new),
            assign_public_key: use_signal(String::new),
            assign_passphrase: use_signal(String::new),
            assign_validation_errors: use_signal(HashMap::new),

            // Clear modal
            clear_modal_open: use_signal(|| false),
            clear_target_id: use_signal(|| 0i64),
            clear_target_name: use_signal(String::new),
            clear_is_inline: use_signal(|| false),

            // Refresh modal
            refresh_modal_open: use_signal(|| false),
            refresh_target_id: use_signal(|| 0i64),
            refresh_target_name: use_signal(String::new),
            refresh_review: use_signal(|| None),

            // Delete modal
            delete_confirm_open: use_signal(|| false),
            delete_target_id: use_signal(|| 0i64),
            delete_target_name: use_signal(String::new),

            // Access modal
            access_modal_open: use_signal(|| false),
            access_target_id: use_signal(|| 0i64),
            access_target_name: use_signal(String::new),

            // Edit/Create modal
            is_modal_open: use_signal(|| false),
            editing_id: use_signal(|| None),
            name: use_signal(String::new),
            endpoint: use_signal(String::new),
            error_message: use_signal(|| None),
            validation_errors: use_signal(HashMap::new),
            current_step: use_signal(|| 1),

            // Authentication
            auth_mode: use_signal(|| "none".to_string()),
            auth_type: use_signal(|| "password".to_string()),
            auth_username: use_signal(String::new),
            auth_username_mode: use_signal(|| "fixed".to_string()),
            auth_password_required: use_signal(|| true),
            auth_password: use_signal(String::new),
            auth_private_key: use_signal(String::new),
            auth_passphrase: use_signal(String::new),
            auth_public_key: use_signal(String::new),
            auth_original_password_required: use_signal(|| true),
            auth_validation_errors: use_signal(HashMap::new),
            has_existing_password: use_signal(|| false),
            has_existing_private_key: use_signal(|| false),
            has_existing_passphrase: use_signal(|| false),
            has_existing_public_key: use_signal(|| false),
        }
    }
}
