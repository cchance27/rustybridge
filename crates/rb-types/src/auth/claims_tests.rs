//! Unit tests for claim type parsing and comparison.

use super::*;
use std::{borrow::Cow, str::FromStr};

#[test]
fn test_claim_string_representation() {
    // Test Display
    assert_eq!(ClaimType::Relays(ClaimLevel::View).to_string(), "relays:view");
    assert_eq!(ClaimType::Users(ClaimLevel::Edit).to_string(), "users:edit");
    assert_eq!(ClaimType::Groups(ClaimLevel::Delete).to_string(), "groups:delete");
    assert_eq!(
        ClaimType::Custom(Cow::Owned("custom:claim".to_string())).to_string(),
        "custom:claim"
    );

    // Test FromStr
    assert_eq!(ClaimType::from_str("relays:view").unwrap(), ClaimType::Relays(ClaimLevel::View));
    assert_eq!(ClaimType::from_str("users:edit").unwrap(), ClaimType::Users(ClaimLevel::Edit));
    assert_eq!(ClaimType::from_str("groups:delete").unwrap(), ClaimType::Groups(ClaimLevel::Delete));
    assert_eq!(
        ClaimType::from_str("custom:claim").unwrap(),
        ClaimType::Custom(Cow::Owned("custom:claim".to_string()))
    );

    // Test Wildcards
    assert_eq!(ClaimType::Relays(ClaimLevel::Wildcard).to_string(), "relays:*");

    assert_eq!(ClaimType::from_str("relays:*").unwrap(), ClaimType::Relays(ClaimLevel::Wildcard));

    // Test case insensitivity
    assert_eq!(ClaimType::from_str("RELAYS:VIEW").unwrap(), ClaimType::Relays(ClaimLevel::View));
}

#[test]
fn test_claim_string_comparison() {
    // Test ClaimType == &str
    assert!(ClaimType::Relays(ClaimLevel::View) == "relays:view");

    // Test &str == ClaimType
    assert!("users:edit" == ClaimType::Users(ClaimLevel::Edit));

    // Test inequality
    assert!(ClaimType::Relays(ClaimLevel::View) != "relays:edit");
    assert!("users:view" != ClaimType::Users(ClaimLevel::Edit));
}
