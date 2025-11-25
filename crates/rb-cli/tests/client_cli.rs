use std::{env, path::PathBuf, sync::Mutex};

use anyhow::{Result, anyhow};
use clap::{CommandFactory, Parser};
use rb_cli::client_cli::ClientArgs;
use rb_types::{client::ClientConfig, ssh::LocaleMode};
use serial_test::serial;

static ENV_GUARD: Mutex<()> = Mutex::new(());

struct Case {
    name: &'static str,
    argv: Vec<&'static str>,
    assert_fn: fn(ClientConfig),
}

#[test]
#[serial]
fn forwarding_arg_matrix_parses_expected_configs() {
    let mut cases = vec![
        Case {
            name: "tcp_mix",
            argv: vec![
                "-L",
                "8080:internal.service:80",
                "-L",
                "[::1]:9090:dest.local:443",
                "-R",
                "0.0.0.0:6200:jump:6200",
                "-R",
                "6001:backend:6001",
                "-D",
                "[::1]:1080",
                "demo",
            ],
            assert_fn: assert_tcp_matrix,
        },
        Case {
            name: "dynamic_only",
            argv: vec!["-D", "1081", "tunnel.example"],
            assert_fn: assert_dynamic_only,
        },
    ];
    #[cfg(unix)]
    cases.push(Case {
        name: "unix_pairs",
        argv: vec![
            "--local-unix-forward",
            "/tmp/rb.sock=/var/run/d.sock",
            "--remote-unix-forward",
            "/remote.sock=/tmp/local.sock",
            "unix.example",
        ],
        assert_fn: assert_unix_pairs,
    });

    for case in cases {
        let cfg = parse_config(&case.argv).expect(case.name);
        (case.assert_fn)(cfg);
    }
}

#[test]
#[serial]
fn invalid_forward_specs_error() {
    match parse_config(&["-L", "bad-spec", "demo"]) {
        Err(err) => assert!(
            err.to_string().contains("invalid local TCP forward spec"),
            "unexpected error: {err:?}"
        ),
        Ok(cfg) => panic!("expected local forward error, got {:?}", cfg.forwarding),
    }

    match parse_config(&["-D", "addr:too:many:fields", "demo"]) {
        Err(err) => assert!(
            err.to_string().contains("invalid dynamic SOCKS forward spec"),
            "unexpected error: {err:?}"
        ),
        Ok(cfg) => panic!("expected dynamic forward error, got {:?}", cfg.forwarding),
    }
}

#[test]
#[serial]
fn rekey_bytes_bounds() {
    match parse_config(&["--rekey-bytes=0", "demo"]) {
        Err(err) => assert!(err.to_string().contains("greater than zero")),
        Ok(cfg) => panic!("expected error, got {:?}", cfg.rekey_bytes),
    }
    match parse_config(&["--rekey-bytes=1073741825", "demo"]) {
        Err(err) => assert!(err.to_string().contains("<= 1073741824")),
        Ok(cfg) => panic!("expected error, got {:?}", cfg.rekey_bytes),
    }
    let cfg = parse_config(&["--rekey-bytes=1073741824", "demo"]).expect("max boundary should succeed");
    assert_eq!(cfg.rekey_bytes, Some(1073741824));
}

#[test]
#[serial]
fn agent_flags_require_socket() {
    match parse_config(&["--agent-auth", "demo"]) {
        Err(err) => assert!(err.to_string().contains("SSH_AUTH_SOCK must be set")),
        Ok(_) => panic!("agent-auth should error without socket"),
    }
    match parse_config(&["--forward-agent", "demo"]) {
        Err(err) => assert!(err.to_string().contains("SSH_AUTH_SOCK must be set")),
        Ok(_) => panic!("forward-agent should error without socket"),
    }

    let cfg = parse_config_with_env(
        &["--agent-auth", "--forward-agent", "demo"],
        &[("SSH_AUTH_SOCK", Some("/tmp/agent.sock"))],
    )
    .expect("agent flags should succeed with socket");
    assert!(cfg.agent_auth);
    assert!(cfg.forward_agent);
    assert_eq!(cfg.ssh_agent_socket, Some(PathBuf::from("/tmp/agent.sock")));
}

#[test]
#[serial]
fn target_parsing_matrix() {
    let cfg = parse_config(&["user@example.com:2222", "cmd"]).expect("user host port");
    assert_eq!(cfg.host, "example.com");
    assert_eq!(cfg.port, 2222);
    assert_eq!(cfg.username, "user");

    let cfg = parse_config(&["host-only", "cmd"]).expect("host default port");
    assert_eq!(cfg.host, "host-only");
    assert_eq!(cfg.port, 22);

    let cfg = parse_config(&["[fe80::1]:2200", "cmd"]).expect("ipv6 port");
    assert_eq!(cfg.host, "fe80::1");
    assert_eq!(cfg.port, 2200);

    let cfg = parse_config(&["user@[fe80::2]", "cmd"]).expect("ipv6 user default port");
    assert_eq!(cfg.host, "fe80::2");
    assert_eq!(cfg.port, 22);
    assert_eq!(cfg.username, "user");
}

#[test]
#[serial]
fn locale_forwarding_descriptors() {
    let cfg = parse_config(&["--forward-locale=lang", "demo"]).expect("locale lang");
    assert!(matches!(cfg.forwarding.env.locale_mode, LocaleMode::Lang));

    let cfg = parse_config(&["--forward-locale=all", "demo"]).expect("locale all");
    assert!(matches!(cfg.forwarding.env.locale_mode, LocaleMode::All));
}

#[test]
#[serial]
fn send_env_and_subsystem_parsing() {
    let cfg = parse_config(&[
        "--send-env",
        "LANG=en_US.UTF-8",
        "--subsystem",
        "sftp",
        "--subsystem",
        "metrics",
        "demo",
    ])
    .expect("env and subsystems");
    assert_eq!(cfg.forwarding.subsystems.len(), 2);
    assert_eq!(cfg.forwarding.subsystems[0].name, "sftp");
    assert_eq!(cfg.forwarding.env.entries.len(), 1);
    assert_eq!(cfg.forwarding.env.entries[0].name, "LANG");
    assert_eq!(cfg.forwarding.env.entries[0].value.as_deref(), Some("en_US.UTF-8"));

    match parse_config(&["--send-env", "INVALID-NAME", "demo"]) {
        Err(err) => assert!(err.to_string().contains("invalid environment variable name")),
        Ok(_) => panic!("invalid env name should fail"),
    }
}

#[test]
#[serial]
fn subsystem_rejects_remote_command() {
    match parse_config(&["--subsystem", "sftp", "demo", "ls"]) {
        Err(err) => assert!(
            err.to_string().contains("--subsystem cannot be combined"),
            "unexpected error: {err:?}"
        ),
        Ok(_) => panic!("subsystem flag should reject remote commands"),
    }
}

#[test]
#[serial]
fn x11_flags_are_rejected() {
    match parse_config(&["--forward-x11", "demo"]) {
        Err(err) => assert!(
            err.to_string().contains("X11 forwarding flags are unimplemented"),
            "unexpected error: {err:?}"
        ),
        Ok(cfg) => panic!("expected x11 guard error, got {:?}", cfg.forwarding),
    }
}

#[test]
#[serial]
fn unix_flag_visibility_matches_platform() {
    let mut command = ClientArgs::command();
    let usage = command.render_help().to_string();
    #[cfg(unix)]
    {
        assert!(
            usage.contains("--local-unix-forward"),
            "unix forward flag should be documented on unix platforms"
        );
        assert!(
            usage.contains("--remote-unix-forward"),
            "remote unix flag should be documented on unix platforms"
        );
    }
    #[cfg(not(unix))]
    {
        assert!(
            !usage.contains("--local-unix-forward"),
            "unix flags must be omitted on non-unix platforms"
        );
        assert!(
            !usage.contains("--remote-unix-forward"),
            "remote unix flags must be omitted on non-unix platforms"
        );
    }
}

fn assert_tcp_matrix(cfg: ClientConfig) {
    assert_eq!(cfg.forwarding.local_tcp.len(), 2, "expected two local TCP forwards");
    let first_local = &cfg.forwarding.local_tcp[0];
    assert_eq!(first_local.bind_address.as_deref(), None);
    assert_eq!(first_local.bind_port, 8080);
    assert_eq!(first_local.target_host, "internal.service");
    assert_eq!(first_local.target_port, 80);

    let second_local = &cfg.forwarding.local_tcp[1];
    assert_eq!(second_local.bind_address.as_deref(), Some("::1"));
    assert_eq!(second_local.bind_port, 9090);
    assert_eq!(second_local.target_host, "dest.local");
    assert_eq!(second_local.target_port, 443);

    assert_eq!(cfg.forwarding.remote_tcp.len(), 2);
    let remote = &cfg.forwarding.remote_tcp[0];
    assert_eq!(remote.bind_address.as_deref(), Some("0.0.0.0"));
    assert_eq!(remote.bind_port, 6200);
    assert_eq!(remote.target_host, "jump");
    assert_eq!(remote.target_port, 6200);

    let remote_two = &cfg.forwarding.remote_tcp[1];
    assert_eq!(remote_two.bind_address, None);
    assert_eq!(remote_two.bind_port, 6001);
    assert_eq!(remote_two.target_host, "backend");
    assert_eq!(remote_two.target_port, 6001);

    assert_eq!(cfg.forwarding.dynamic_socks.len(), 1);
    let socks = &cfg.forwarding.dynamic_socks[0];
    assert_eq!(socks.bind_address.as_deref(), Some("::1"));
    assert_eq!(socks.bind_port, 1080);
}

fn assert_dynamic_only(cfg: ClientConfig) {
    assert!(cfg.forwarding.local_tcp.is_empty());
    assert!(cfg.forwarding.remote_tcp.is_empty());
    assert_eq!(cfg.forwarding.dynamic_socks.len(), 1);
    let spec = &cfg.forwarding.dynamic_socks[0];
    assert_eq!(spec.bind_address, None);
    assert_eq!(spec.bind_port, 1081);
}

#[cfg(unix)]
fn assert_unix_pairs(cfg: ClientConfig) {
    assert_eq!(cfg.forwarding.local_unix.len(), 1);
    let local = &cfg.forwarding.local_unix[0];
    assert_eq!(local.local_socket, PathBuf::from("/tmp/rb.sock"));
    assert_eq!(local.remote_socket, PathBuf::from("/var/run/d.sock"));

    assert_eq!(cfg.forwarding.remote_unix.len(), 1);
    let remote = &cfg.forwarding.remote_unix[0];
    assert_eq!(remote.remote_socket, PathBuf::from("/remote.sock"));
    assert_eq!(remote.local_socket, PathBuf::from("/tmp/local.sock"));
}

fn parse_config(args: &[&str]) -> Result<ClientConfig> {
    parse_config_with_env(args, &[])
}

fn parse_config_with_env(args: &[&str], overrides: &[(&str, Option<&str>)]) -> Result<ClientConfig> {
    with_clean_env(|| {
        for (key, value) in overrides {
            match value {
                Some(v) => unsafe { env::set_var(key, v) },
                None => unsafe { env::remove_var(key) },
            }
        }
        let mut argv = vec!["rb"];
        argv.extend_from_slice(args);
        let cli = ClientArgs::try_parse_from(&argv).map_err(|err| anyhow!(err.to_string()))?;
        ClientConfig::try_from(cli)
    })
}

fn with_clean_env<T>(f: impl FnOnce() -> T) -> T {
    let guard = ENV_GUARD.lock().expect("env guard poisoned");
    let prev_user = env::var("RB_USER").ok();
    let prev_password = env::var("RB_PASSWORD").ok();
    let prev_sock = env::var_os("SSH_AUTH_SOCK");
    unsafe {
        env::set_var("RB_USER", "cli-test");
        env::remove_var("RB_PASSWORD");
        env::remove_var("SSH_AUTH_SOCK");
    }
    let result = f();
    if let Some(value) = prev_user {
        unsafe { env::set_var("RB_USER", value) };
    } else {
        unsafe { env::remove_var("RB_USER") };
    }
    if let Some(value) = prev_password {
        unsafe { env::set_var("RB_PASSWORD", value) };
    }
    if let Some(value) = prev_sock {
        unsafe { env::set_var("SSH_AUTH_SOCK", value) };
    }
    drop(guard);
    result
}
