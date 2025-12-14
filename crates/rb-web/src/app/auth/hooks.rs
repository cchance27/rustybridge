use super::context::AuthState;
use dioxus::prelude::*;
use rb_types::auth::ClaimType;

/// Get current auth state from context
pub fn use_auth() -> Signal<AuthState<'static>> {
    use_context::<Signal<AuthState<'static>>>()
}

/// Check if user has a specific claim
/// Delegates to WebUser::has_claim()
pub fn use_has_claim(claim: &ClaimType) -> bool {
    let auth = use_auth();
    let auth_state = auth.read();

    if let Some(user) = &auth_state.user {
        user.has_claim(claim)
    } else {
        false
    }
}

/// Check if user has any of the specified claims
/// Delegates to WebUser::has_any_claim()
pub fn use_has_any_claim(claims: Vec<ClaimType>) -> bool {
    let auth = use_auth();
    let auth_state = auth.read();

    if let Some(user) = &auth_state.user {
        user.has_any_claim(&claims)
    } else {
        false
    }
}

/// Check if user has all of the specified claims
/// Delegates to WebUser::has_all_claims()
pub fn use_has_all_claims(claims: Vec<ClaimType>) -> bool {
    let auth = use_auth();
    let auth_state = auth.read();

    if let Some(user) = &auth_state.user {
        user.has_all_claims(&claims)
    } else {
        false
    }
}

/// Check if user has management access (any :view claim)
/// Delegates to WebUser::has_management_access()
pub fn use_has_management_access() -> bool {
    let auth = use_auth();
    let auth_state = auth.read();

    if let Some(user) = &auth_state.user {
        user.has_management_access()
    } else {
        false
    }
}
