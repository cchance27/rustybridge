use rb_types::auth::ClaimType;

use super::types::WebUser;

/// Check if a user has a specific claim
/// Supports wildcard (*) matching
pub fn has_claim(user: &WebUser, claim: &ClaimType) -> bool {
    user.claims.iter().any(|c| c == "*" || c == claim)
}

/// Check if a user has any of the specified claims
pub fn has_any_claim(user: &WebUser, claims: &[ClaimType]) -> bool {
    if user.claims.iter().any(|c| c == "*") {
        return true;
    }

    claims.iter().any(|claim| user.claims.contains(claim))
}

/// Check if a user has all of the specified claims
pub fn has_all_claims(user: &WebUser, claims: &[ClaimType]) -> bool {
    if user.claims.iter().any(|c| c == "*") {
        return true;
    }

    claims.iter().all(|claim| user.claims.contains(claim))
}

/// Check if user has management access (any :view claim or wildcard)
pub fn has_management_access(user: &WebUser) -> bool {
    user.claims.iter().any(|c| {
        let claim_str = c.to_string();
        claim_str == "*" || claim_str.ends_with(":view")
    })
}

#[cfg(test)]
mod tests {
    use rb_types::auth::ClaimType;

    use super::*;

    fn test_user(claims: Vec<ClaimType>) -> WebUser {
        WebUser {
            id: 1,
            username: "test".to_string(),
            password_hash: None,
            claims,
            name: None,
            picture: None,
        }
    }

    #[test]
    fn test_wildcard_claim() {
        use std::str::FromStr;
        let user = test_user(vec![ClaimType::from_str("*").unwrap()]);
        assert!(has_claim(&user, &ClaimType::from_str("users:view").unwrap()));
        assert!(has_claim(&user, &ClaimType::from_str("anything").unwrap()));
    }

    #[test]
    fn test_specific_claim() {
        use std::str::FromStr;
        let user = test_user(vec![ClaimType::from_str("users:view").unwrap()]);
        assert!(has_claim(&user, &ClaimType::from_str("users:view").unwrap()));
        assert!(!has_claim(&user, &ClaimType::from_str("users:create").unwrap()));
    }

    #[test]
    fn test_any_claim() {
        use std::str::FromStr;
        let user = test_user(vec![
            ClaimType::from_str("users:view").unwrap(),
            ClaimType::from_str("groups:view").unwrap(),
        ]);
        assert!(has_any_claim(
            &user,
            &[
                ClaimType::from_str("users:view").unwrap(),
                ClaimType::from_str("roles:view").unwrap()
            ]
        ));
        assert!(!has_any_claim(
            &user,
            &[
                ClaimType::from_str("roles:view").unwrap(),
                ClaimType::from_str("relays:view").unwrap()
            ]
        ));
    }

    #[test]
    fn test_all_claims() {
        use std::str::FromStr;
        let user = test_user(vec![
            ClaimType::from_str("users:view").unwrap(),
            ClaimType::from_str("groups:view").unwrap(),
        ]);
        assert!(has_all_claims(
            &user,
            &[
                ClaimType::from_str("users:view").unwrap(),
                ClaimType::from_str("groups:view").unwrap()
            ]
        ));
        assert!(!has_all_claims(
            &user,
            &[
                ClaimType::from_str("users:view").unwrap(),
                ClaimType::from_str("roles:view").unwrap()
            ]
        ));
    }

    #[test]
    fn test_management_access() {
        use std::str::FromStr;
        let admin = test_user(vec![ClaimType::from_str("*").unwrap()]);
        let manager = test_user(vec![ClaimType::from_str("users:view").unwrap()]);
        let basic_user = test_user(vec![ClaimType::from_str("relay:connect").unwrap()]);

        assert!(has_management_access(&admin));
        assert!(has_management_access(&manager));
        assert!(!has_management_access(&basic_user));
    }
}
