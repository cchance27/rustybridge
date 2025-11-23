use dioxus::prelude::*;
use rb_types::auth::ClaimType;

use super::context::AuthState;

/// Get current auth state from context
pub fn use_auth() -> Signal<AuthState> {
    use_context::<Signal<AuthState>>()
}

/// Check if user has a specific claim
pub fn use_has_claim(claim: &ClaimType) -> bool {
    let auth = use_auth();
    let auth_state = auth.read();

    if let Some(user) = &auth_state.user {
        user.claims.iter().any(|c| c == "*" || c == claim)
    } else {
        false
    }
}

/// Check if user has any of the specified claims
pub fn use_has_any_claim(claims: Vec<ClaimType>) -> bool {
    let auth = use_auth();
    let auth_state = auth.read();

    if let Some(user) = &auth_state.user {
        if user.claims.iter().any(|c| c == "*") {
            return true;
        }
        claims.iter().any(|claim| user.claims.iter().any(|c| c == claim))
    } else {
        false
    }
}

/// Check if user has all of the specified claims
pub fn use_has_all_claims(claims: Vec<ClaimType>) -> bool {
    let auth = use_auth();
    let auth_state = auth.read();

    if let Some(user) = &auth_state.user {
        if user.claims.iter().any(|c| c == "*") {
            return true;
        }
        claims.iter().all(|claim| user.claims.iter().any(|c| c == claim))
    } else {
        false
    }
}

/// Check if user has management access (any :view claim)
pub fn use_has_management_access() -> bool {
    let auth = use_auth();
    let auth_state = auth.read();

    if let Some(user) = &auth_state.user {
        user.has_management_access
    } else {
        false
    }
}
