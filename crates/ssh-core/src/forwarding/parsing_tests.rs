//! Unit tests for forwarding spec parsing.

use super::*;

#[test]
fn parses_local_forward_with_bind_host() {
    let spec = parse_local_tcp("127.0.0.1:2222:server:22").unwrap();
    assert_eq!(spec.bind_address.as_deref(), Some("127.0.0.1"));
    assert_eq!(spec.bind_port, 2222);
    assert_eq!(spec.target_host, "server");
    assert_eq!(spec.target_port, 22);
}

#[test]
fn parses_dynamic_forward_ipv6() {
    let spec = parse_dynamic_socks("[::1]:1080").unwrap();
    assert_eq!(spec.bind_address.as_deref(), Some("::1"));
    assert_eq!(spec.bind_port, 1080);
}

#[test]
fn rejects_invalid_env_name() {
    assert!(parse_env_entry("LANG-TEST").is_err());
}
