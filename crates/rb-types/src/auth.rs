mod claims;

pub use claims::{ATTACH_ANY_CLAIM, ATTACH_ANY_STR, ClaimLevel, ClaimType};
use serde::{Deserialize, Serialize};
pub mod oidc;
pub mod ssh;

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
pub struct LoginResponse<'a> {
    /// Whether authentication succeeded.
    pub success: bool,
    /// Human-readable status or error message.
    pub message: String,
    /// Populated with user info when authentication succeeds.
    pub user: Option<AuthUserInfo<'a>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default, Eq, Hash)]
/// Authenticated user details returned to clients.
pub struct AuthUserInfo<'a> {
    /// Stable user identifier.
    pub id: i64,
    /// Username.
    pub username: String,
    /// Password hash (if using password auth).
    pub password_hash: Option<String>,
    /// Claims granted to the user.
    pub claims: Vec<ClaimType<'a>>,
    /// Convenience flag for UI gating (has any management claims).
    pub name: Option<String>,
    /// User's profile picture URL from OIDC.
    pub picture: Option<String>,
}

impl<'a> std::fmt::Display for AuthUserInfo<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.username)
    }
}

impl<'a> AuthUserInfo<'a> {
    /// Check if this user has a specific claim
    /// Uses the satisfies method to handle wildcards and claim level hierarchies
    pub fn has_claim(&self, claim: &ClaimType<'a>) -> bool {
        self.claims.iter().any(|c| c.satisfies(claim))
    }

    /// Check if this user has any of the specified claims
    pub fn has_any_claim(&self, claims: &[ClaimType<'a>]) -> bool {
        claims
            .iter()
            .any(|required_claim| self.claims.iter().any(|user_claim| user_claim.satisfies(required_claim)))
    }

    /// Check if this user has all of the specified claims
    pub fn has_all_claims(&self, claims: &[ClaimType]) -> bool {
        claims
            .iter()
            .all(|required_claim| self.claims.iter().any(|user_claim| user_claim.satisfies(required_claim)))
    }

    /// Check if user has management access (any :view claim or wildcard)
    pub fn has_management_access(&self) -> bool {
        self.claims.iter().any(|c| {
            let claim_str = c.to_string();
            claim_str.ends_with(":view") || claim_str.ends_with(":*")
        })
    }
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuthPromptEvent {
    /// Prompt text to present to the user.
    pub prompt: String,
    /// Whether input should be echoed.
    pub echo: bool,
}

/// Basic authentication row for a user.
#[derive(Debug, Clone)]
pub struct UserAuthRecord {
    pub id: i64,
    pub username: String,
    pub password_hash: Option<String>,
}

/// Latest OIDC profile (name/picture) for a user, if linked.
#[derive(Debug, Clone, Default)]
pub struct OidcProfile {
    pub name: Option<String>,
    pub picture: Option<String>,
}

/// OIDC link row for a user (latest entry).
#[derive(Debug, Clone)]
pub struct OidcLinkInfo {
    pub user_id: i64,
    pub provider_id: String,
    pub subject_id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub picture: Option<String>,
}
