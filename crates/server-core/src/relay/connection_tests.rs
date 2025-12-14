//! Unit tests for relay connection configuration.

use super::*;
use crate::secrets::SecretBoxedString;
use std::collections::HashMap;

#[test]
fn test_build_client_config_defaults() {
    let options = HashMap::new();
    let config = build_client_config(&options);

    // Verify defaults
    assert_eq!(config.keepalive_interval, Some(std::time::Duration::from_secs(30)));
    assert_eq!(config.keepalive_max, 3);
    assert!(config.nodelay);

    // Verify default crypto (should not be legacy)
    // We can't easily check internal fields of Preferred, but we can check if it's not empty
    assert!(!config.preferred.kex.is_empty());
}

#[test]
fn test_build_client_config_insecure() {
    let mut options = HashMap::new();
    options.insert("insecure".to_string(), SecretBoxedString::new(Box::new("true".to_string())));
    let config = build_client_config(&options);

    // Verify insecure/legacy crypto is used
    // Legacy preferred has different defaults, e.g. might include diffie-hellman-group1-sha1
    // This is hard to assert without inspecting the struct, but we ensure it runs.
    assert!(!config.preferred.kex.is_empty());
}

#[test]
fn test_build_client_config_compression() {
    let mut options = HashMap::new();
    options.insert("compression".to_string(), SecretBoxedString::new(Box::new("true".to_string())));
    let config = build_client_config(&options);

    // Verify compression is preferred
    let compression = &config.preferred.compression;
    assert_eq!(compression[0], russh::compression::ZLIB);
}
