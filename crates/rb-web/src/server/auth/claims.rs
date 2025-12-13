use rb_types::auth::{AuthUserInfo, ClaimType};

/// Check if a user has a specific claim
/// Delegates to WebUser::has_claim()
pub fn has_claim(user: &AuthUserInfo, claim: &ClaimType) -> bool {
    user.has_claim(claim)
}

/// Check if a user has any of the specified claims
/// Delegates to WebUser::has_any_claim()
pub fn has_any_claim(user: &AuthUserInfo, claims: &[ClaimType]) -> bool {
    user.has_any_claim(claims)
}

/// Check if a user has all of the specified claims
/// Delegates to WebUser::has_all_claims()
pub fn has_all_claims(user: &AuthUserInfo, claims: &[ClaimType]) -> bool {
    user.has_all_claims(claims)
}

/// Check if user has management access (any :view claim or wildcard)
/// Delegates to WebUser::has_management_access()
pub fn has_management_access(user: &AuthUserInfo) -> bool {
    user.has_management_access()
}

#[cfg(test)]
#[path = "claims_tests.rs"]
mod tests;
