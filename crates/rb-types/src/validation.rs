use std::{collections::HashMap, fmt};

/// High-level validation errors used by credential input checks.
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationError {
    Required,
    RequiredInFixedMode,
    InvalidFormat(String),
    Other(String),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::Required => write!(f, "This field is required"),
            ValidationError::RequiredInFixedMode => write!(f, "Username is required in fixed mode"),
            ValidationError::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
            ValidationError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

/// Input wrapper for credential validation routines.
#[derive(Debug, Clone, Default)]
pub struct CredentialValidationInput<'a> {
    /// Credential kind: "password", "ssh_key", or "agent".
    pub kind: &'a str,
    /// Username handling mode ("fixed", "blank", "passthrough").
    pub username_mode: &'a str,
    /// Username value.
    pub username: &'a str,
    /// Whether a password is required (password type).
    pub password_required: bool,
    /// Password value (password type).
    pub password: &'a str,
    /// Private key content (ssh_key type).
    pub private_key: &'a str,
    /// Public key content (agent type).
    pub public_key: &'a str,
    /// Whether this represents an edit/update operation.
    pub is_editing: bool,
    /// Whether a password already exists (edit mode).
    pub has_existing_password: bool,
    /// Whether a private key already exists (edit mode).
    pub has_existing_private_key: bool,
    /// Whether a public key already exists (edit mode).
    pub has_existing_public_key: bool,
}

impl<'a> CredentialValidationInput<'a> {
    /// Construct with required fields, defaulting the optional flags to safe values.
    pub fn new(kind: &'a str, username_mode: &'a str) -> Self {
        Self {
            kind,
            username_mode,
            username: "",
            password_required: true,
            password: "",
            private_key: "",
            public_key: "",
            is_editing: false,
            has_existing_password: false,
            has_existing_private_key: false,
            has_existing_public_key: false,
        }
    }

    /// Validate the credential input, returning a field->error map.
    pub fn validate(&self) -> HashMap<String, ValidationError> {
        let mut errors = HashMap::new();

        // Validate username for fixed mode
        if self.username_mode == "fixed" && self.username.trim().is_empty() {
            errors.insert("username".to_string(), ValidationError::RequiredInFixedMode);
        }

        match self.kind {
            "password" => {
                // Only require password if:
                // 1. username_mode is "fixed" (not interactive/passthrough)
                // 2. password_required is true (stored mode)
                // 3. password field is empty
                // 4. Not editing with existing password
                if self.username_mode == "fixed"
                    && self.password_required
                    && self.password.trim().is_empty()
                    && !(self.is_editing && self.has_existing_password)
                {
                    errors.insert("password".to_string(), ValidationError::Required);
                }
                // For non-fixed modes (interactive/passthrough), password is never required
            }
            "ssh_key" => {
                if self.private_key.trim().is_empty() && !(self.is_editing && self.has_existing_private_key) {
                    errors.insert("private_key".to_string(), ValidationError::Required);
                }
            }
            "agent" => {
                if self.public_key.trim().is_empty() && !(self.is_editing && self.has_existing_public_key) {
                    errors.insert("public_key".to_string(), ValidationError::Required);
                }
            }
            _ => {}
        }

        errors
    }
}

/// Render a human-readable string from a map of validation errors.
pub fn format_errors(errors: &HashMap<String, ValidationError>) -> String {
    errors.iter().map(|(k, v)| format!("{}: {}", k, v)).collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
#[path = "validation_tests.rs"]
mod tests;
