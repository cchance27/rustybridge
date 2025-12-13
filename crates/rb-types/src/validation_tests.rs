//! Unit tests for credential validation.

use super::*;

#[test]
fn test_password_validation() {
    // Fixed mode, password required, empty password -> Error
    let input = CredentialValidationInput {
        kind: "password",
        username_mode: "fixed",
        username: "user",
        password_required: true,
        password: "",
        ..Default::default()
    };
    let errors = input.validate();
    assert!(errors.contains_key("password"));
    assert_eq!(errors.get("password"), Some(&ValidationError::Required));

    // Fixed mode, password required, password provided -> OK
    let input = CredentialValidationInput {
        kind: "password",
        username_mode: "fixed",
        username: "user",
        password_required: true,
        password: "pass",
        ..Default::default()
    };
    let errors = input.validate();
    assert!(errors.is_empty());

    // Interactive mode, password empty -> OK
    let input = CredentialValidationInput {
        kind: "password",
        username_mode: "blank",
        username: "user",
        password_required: true,
        password: "",
        ..Default::default()
    };
    let errors = input.validate();
    assert!(errors.is_empty());
}

#[test]
fn test_username_validation() {
    // Fixed mode, empty username -> Error
    let input = CredentialValidationInput {
        kind: "password",
        username_mode: "fixed",
        username: "",
        password_required: true,
        password: "pass",
        ..Default::default()
    };
    let errors = input.validate();
    assert!(errors.contains_key("username"));
    assert_eq!(errors.get("username"), Some(&ValidationError::RequiredInFixedMode));

    // Passthrough mode, empty username -> OK
    let input = CredentialValidationInput {
        kind: "password",
        username_mode: "passthrough",
        username: "",
        password_required: true,
        password: "pass",
        ..Default::default()
    };
    let errors = input.validate();
    assert!(errors.is_empty());
}

#[test]
fn test_ssh_key_validation() {
    // SSH key, empty private key -> Error
    let input = CredentialValidationInput {
        kind: "ssh_key",
        username_mode: "fixed",
        username: "user",
        password_required: false,
        password: "",
        ..Default::default()
    };
    let errors = input.validate();
    assert!(errors.contains_key("private_key"));

    // SSH key, editing, existing key -> OK
    let input = CredentialValidationInput {
        kind: "ssh_key",
        username_mode: "fixed",
        username: "user",
        password_required: false,
        password: "",
        is_editing: true,
        has_existing_private_key: true,
        ..Default::default()
    };
    let errors = input.validate();
    assert!(errors.is_empty());
}
