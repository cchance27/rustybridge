//! Unit tests for claim checking helper wrappers.

use super::*;
use rb_types::auth::{AuthUserInfo, ClaimType};

fn test_user(claims: Vec<ClaimType>) -> AuthUserInfo {
    AuthUserInfo {
        id: 1,
        username: "test".to_string(),
        password_hash: None,
        claims,
        name: None,
        picture: None,
    }
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
    let manager = test_user(vec![ClaimType::from_str("users:view").unwrap()]);
    let basic_user = test_user(vec![ClaimType::from_str("relay:connect").unwrap()]);

    assert!(has_management_access(&manager));
    assert!(!has_management_access(&basic_user));
}
