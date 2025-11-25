//! Credential domain types and web-facing auth configuration.
use serde::{Deserialize, Serialize};

/// Authentication configuration surfaced to the web UI for editing.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthWebConfig {
    /// Mode selector: "none", "saved", or "custom".
    pub mode: String,
    /// ID of saved credential (when `mode == "saved"`).
    pub saved_credential_id: Option<i64>,
    /// Custom auth type when in custom mode: "password", "ssh_key", or "agent".
    pub custom_type: Option<String>,
    /// Username value when applicable.
    pub username: Option<String>,
    /// Username handling strategy ("fixed", "blank", "passthrough").
    pub username_mode: Option<String>,
    /// Presence flags only; sensitive data is never returned to the web client.
    pub has_password: bool,
    pub has_private_key: bool,
    pub has_passphrase: bool,
    pub has_public_key: bool,
    #[serde(default)]
    /// Whether password is required for password-type custom auth; `None` if unknown/not applicable.
    pub password_required: Option<bool>,
}

/// Credential summary for listing.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CredentialInfo {
    /// Primary key identifier.
    pub id: i64,
    /// Unique credential name.
    pub name: String,
    /// Credential type: "password", "ssh_key", or "agent".
    pub kind: String,
    /// Optional fixed username.
    pub username: Option<String>,
    /// Username handling mode ("fixed", "blank", "passthrough").
    pub username_mode: String,
    /// Whether a password must be provided (password type only).
    pub password_required: bool,
    /// Whether secret material is present (password/private key).
    pub has_secret: bool,
    /// Relay names this credential is assigned to.
    pub assigned_relays: Vec<String>,
}

/// Request payload for creating a credential.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CreateCredentialRequest {
    /// Name of the credential.
    pub name: String,
    /// Credential type: "password", "ssh_key", or "agent".
    pub kind: String,
    /// Optional username value.
    pub username: Option<String>,
    /// Username mode ("fixed", "blank", "passthrough").
    pub username_mode: String,
    /// Whether a password is required (password type only).
    pub password_required: bool,
    /// Password secret (password type).
    pub password: Option<String>,
    /// Private key material (ssh_key type).
    pub private_key: Option<String>,
    /// Public key material (agent type).
    pub public_key: Option<String>,
    /// Private key passphrase (ssh_key type, optional).
    pub passphrase: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
/// Request payload for updating a credential.
pub struct UpdateCredentialRequest {
    /// Name of the credential.
    pub name: String,
    /// Credential type: "password", "ssh_key", or "agent".
    pub kind: String,
    /// Optional username value.
    pub username: Option<String>,
    /// Username mode ("fixed", "blank", "passthrough").
    pub username_mode: String,
    /// Whether a password is required (password type only).
    pub password_required: bool,
    /// Password secret (password type).
    pub password: Option<String>,
    /// Private key material (ssh_key type).
    pub private_key: Option<String>,
    /// Public key material (agent type).
    pub public_key: Option<String>,
    /// Private key passphrase (ssh_key type, optional).
    pub passphrase: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
/// Request payload for setting inline/custom authentication on a relay.
pub struct CustomAuthRequest {
    /// Custom auth type: "password", "ssh_key", or "agent".
    pub auth_type: String,
    /// Optional username value.
    pub username: Option<String>,
    /// Username mode ("fixed", "blank", "passthrough").
    pub username_mode: String,
    /// Password secret (password type).
    pub password: Option<String>,
    /// Whether password is required (password type only).
    pub password_required: bool,
    /// Private key material (ssh_key type).
    pub private_key: Option<String>,
    /// Private key passphrase (ssh_key type, optional).
    pub passphrase: Option<String>,
    /// Public key material (agent type).
    pub public_key: Option<String>,
}

/// Encrypted secret blob stored in the server database (salt + nonce + ciphertext).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedBlob {
    /// KDF salt (16 bytes).
    pub salt: Vec<u8>,
    /// XChaCha20-Poly1305 nonce (24 bytes).
    pub nonce: Vec<u8>,
    /// Ciphertext + tag produced by encryption.
    pub ciphertext: Vec<u8>,
}
