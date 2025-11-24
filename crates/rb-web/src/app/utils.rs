use std::collections::HashMap;

/// Validates credential fields based on type, username mode, and password requirements.
/// Returns a HashMap of field names to error messages.
pub fn validate_credential_fields(
    cred_type: &str,
    username_mode: &str,
    username: &str,
    password_required: bool,
    password: &str,
    private_key: &str,
    public_key: &str,
    is_editing: bool,
    has_existing_password: bool,
    has_existing_private_key: bool,
    has_existing_public_key: bool,
) -> HashMap<String, String> {
    let mut errors = HashMap::new();

    // Validate username for fixed mode
    if username_mode == "fixed" && username.trim().is_empty() {
        errors.insert("username".to_string(), "Username is required in fixed mode".to_string());
    }

    match cred_type {
        "password" => {
            // Only require password if:
            // 1. username_mode is "fixed" (not interactive/passthrough)
            // 2. password_required is true (stored mode)
            // 3. password field is empty
            // 4. Not editing with existing password
            if username_mode == "fixed" && password_required && password.trim().is_empty() && !(is_editing && has_existing_password) {
                errors.insert("password".to_string(), "Password is required".to_string());
            }
            // For non-fixed modes (interactive/passthrough), password is never required
        }
        "ssh_key" => {
            if private_key.trim().is_empty() && !(is_editing && has_existing_private_key) {
                errors.insert("private_key".to_string(), "Private key is required".to_string());
            }
        }
        "agent" => {
            if public_key.trim().is_empty() && !(is_editing && has_existing_public_key) {
                errors.insert("public_key".to_string(), "Public key is required".to_string());
            }
        }
        _ => {}
    }

    errors
}
