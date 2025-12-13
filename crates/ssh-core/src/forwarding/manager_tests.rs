//! Unit tests for forwarding manager.

use std::path::PathBuf;

use rb_types::ssh::{
    DynamicSocksForward, EnvEntry, LocalTcpForward, LocalUnixForward, LocaleMode, RemoteTcpForward, RemoteUnixForward, SubsystemRequest
};

use super::*;

#[test]
fn descriptors_include_all_forward_types() {
    let mut config = ForwardingConfig::default();
    config.local_tcp.push(LocalTcpForward {
        bind_address: Some("127.0.0.1".into()),
        bind_port: 8080,
        target_host: "internal".into(),
        target_port: 80,
    });
    config.remote_tcp.push(RemoteTcpForward {
        bind_address: Some("0.0.0.0".into()),
        bind_port: 9090,
        target_host: "remote".into(),
        target_port: 9090,
    });
    config.dynamic_socks.push(DynamicSocksForward {
        bind_address: None,
        bind_port: 1080,
    });
    config.local_unix.push(LocalUnixForward {
        local_socket: PathBuf::from("/tmp/local.sock"),
        remote_socket: PathBuf::from("/var/run/remote.sock"),
    });
    config.remote_unix.push(RemoteUnixForward {
        remote_socket: PathBuf::from("/tmp/remote.sock"),
        local_socket: PathBuf::from("/tmp/local2.sock"),
    });
    config.subsystems.push(SubsystemRequest { name: "sftp".into() });
    config.env.entries.push(EnvEntry {
        name: "LANG".into(),
        value: Some("en_US.UTF-8".into()),
    });
    config.env.locale_mode = LocaleMode::All;
    let manager = ForwardingManager::new(config);
    let descriptors = manager.descriptors();
    assert!(descriptors.iter().any(|d| d.starts_with("local 127.0.0.1:8080")));
    assert!(descriptors.iter().any(|d| d.contains("remote 0.0.0.0:9090")));
    assert!(descriptors.iter().any(|d| d.contains("socks 127.0.0.1:1080")));
    assert!(descriptors.iter().any(|d| d.contains("local unix /tmp/local.sock")));
    assert!(descriptors.iter().any(|d| d.contains("remote unix /tmp/remote.sock")));
    assert!(descriptors.iter().any(|d| d == "subsystem sftp"));
    assert!(descriptors.iter().any(|d| d == "env"));
    assert!(descriptors.iter().any(|d| d == "locale:all"));
}
