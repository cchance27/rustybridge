mod claims;

pub use claims::{ClaimLevel, ClaimType};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
/// Login payload submitted to authentication endpoints.
pub struct LoginRequest {
    /// Username submitted by the client.
    pub username: String,
    /// Plaintext password submitted by the client.
    pub password: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
/// Response returned after processing a login request.
pub struct LoginResponse {
    /// Whether authentication succeeded.
    pub success: bool,
    /// Human-readable status or error message.
    pub message: String,
    /// Populated with user info when authentication succeeds.
    pub user: Option<AuthUserInfo>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
/// Authenticated user details returned to clients.
pub struct AuthUserInfo {
    /// Stable user identifier.
    pub id: i64,
    /// Username.
    pub username: String,
    /// Claims granted to the user.
    pub claims: Vec<ClaimType>,
    /// Convenience flag for UI gating (has any management claims).
    pub has_management_access: bool,
}

/// Parsed login target in `user[:relay]` form used by server-side auth flows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginTarget {
    /// Username supplied during SSH auth.
    pub username: String,
    /// Optional relay name suffix after a colon.
    pub relay: Option<String>,
}

/// Simple auth decision enum used by the SSH server when validating credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthDecision {
    Accept,
    Reject,
}

/// Minimal prompt event used by non-TUI frontends (e.g., Web UI) to drive interactive auth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthPromptEvent {
    /// Prompt text to present to the user.
    pub prompt: String,
    /// Whether input should be echoed.
    pub echo: bool,
}
