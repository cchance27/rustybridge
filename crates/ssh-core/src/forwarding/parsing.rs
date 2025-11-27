use std::path::PathBuf;

use rb_types::ssh::{
    DynamicSocksForward, EnvEntry, LocalTcpForward, LocalUnixForward, RemoteTcpForward, RemoteUnixForward, SubsystemRequest
};

/// Parse a local TCP forward specification.
///
/// Format: `[bind_address:]port:host:hostport`
pub fn parse_local_tcp(spec: &str) -> crate::SshResult<LocalTcpForward> {
    let fields = split_colon_parts(spec);
    if fields.len() == 4 {
        Ok(LocalTcpForward {
            bind_address: normalize_host(&fields[0]),
            bind_port: parse_port(&fields[1])?,
            target_host: normalize_host(&fields[2]).unwrap_or_else(|| "127.0.0.1".to_string()),
            target_port: parse_port(&fields[3])?,
        })
    } else if fields.len() == 3 {
        Ok(LocalTcpForward {
            bind_address: None,
            bind_port: parse_port(&fields[0])?,
            target_host: normalize_host(&fields[1]).unwrap_or_else(|| "127.0.0.1".to_string()),
            target_port: parse_port(&fields[2])?,
        })
    } else {
        Err(crate::SshCoreError::invalid_forward(
            "local TCP",
            "spec must be [bind_address:]port:host:hostport",
        ))
    }
}

/// Parse a remote TCP forward specification.
///
/// Format: `[bind_address:]port:host:hostport`
pub fn parse_remote_tcp(spec: &str) -> crate::SshResult<RemoteTcpForward> {
    let fields = split_colon_parts(spec);
    if fields.len() == 4 {
        Ok(RemoteTcpForward {
            bind_address: normalize_host(&fields[0]),
            bind_port: parse_port(&fields[1])?,
            target_host: normalize_host(&fields[2]).unwrap_or_else(|| "127.0.0.1".to_string()),
            target_port: parse_port(&fields[3])?,
        })
    } else if fields.len() == 3 {
        Ok(RemoteTcpForward {
            bind_address: None,
            bind_port: parse_port(&fields[0])?,
            target_host: normalize_host(&fields[1]).unwrap_or_else(|| "127.0.0.1".to_string()),
            target_port: parse_port(&fields[2])?,
        })
    } else {
        Err(crate::SshCoreError::invalid_forward(
            "remote TCP",
            "spec must be [bind_address:]port:host:hostport",
        ))
    }
}

/// Parse a dynamic SOCKS forward specification.
///
/// Format: `[bind_address:]port`
pub fn parse_dynamic_socks(spec: &str) -> crate::SshResult<DynamicSocksForward> {
    let fields = split_colon_parts(spec);
    if fields.is_empty() || fields.len() > 2 {
        return Err(crate::SshCoreError::invalid_forward(
            "dynamic SOCKS",
            "spec must be [bind_address:]port",
        ));
    }
    let bind_address = if fields.len() == 2 { normalize_host(&fields[0]) } else { None };
    let port_str = fields.last().expect("port field present");
    Ok(DynamicSocksForward {
        bind_address,
        bind_port: parse_port(port_str)?,
    })
}

/// Parse a local Unix socket forward specification.
///
/// Format: `local_socket=remote_socket`
pub fn parse_local_unix(spec: &str) -> crate::SshResult<LocalUnixForward> {
    let (local, remote) = split_socket_pair(spec)?;
    Ok(LocalUnixForward {
        local_socket: local,
        remote_socket: remote,
    })
}

/// Parse a remote Unix socket forward specification.
///
/// Format: `remote_socket=local_socket`
pub fn parse_remote_unix(spec: &str) -> crate::SshResult<RemoteUnixForward> {
    let (remote, local) = split_socket_pair(spec)?;
    Ok(RemoteUnixForward {
        remote_socket: remote,
        local_socket: local,
    })
}

/// Parse an environment variable entry.
///
/// Format: `NAME[=value]`
pub fn parse_env_entry(entry: &str) -> crate::SshResult<EnvEntry> {
    let (name, value) = if let Some((name, value)) = entry.split_once('=') {
        (name.trim(), Some(value.to_string()))
    } else {
        (entry.trim(), None)
    };
    if name.is_empty() {
        return Err(crate::SshCoreError::empty("environment variable name"));
    }
    if !name.chars().all(|c| c == '_' || c.is_ascii_alphanumeric()) {
        return Err(crate::SshCoreError::InvalidEnvVar(name.to_string()));
    }
    Ok(EnvEntry {
        name: name.to_string(),
        value,
    })
}

/// Parse a subsystem request.
pub fn parse_subsystem(name: &str) -> crate::SshResult<SubsystemRequest> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(crate::SshCoreError::empty("subsystem name"));
    }
    Ok(SubsystemRequest { name: trimmed.to_string() })
}

// Helper functions

fn split_socket_pair(spec: &str) -> crate::SshResult<(PathBuf, PathBuf)> {
    let (lhs, rhs) = spec
        .split_once('=')
        .ok_or_else(|| crate::SshCoreError::invalid_forward("unix", "spec must use local=remote format"))?;
    if lhs.trim().is_empty() || rhs.trim().is_empty() {
        return Err(crate::SshCoreError::invalid_forward("unix", "spec must not contain empty paths"));
    }
    Ok((PathBuf::from(lhs.trim()), PathBuf::from(rhs.trim())))
}

fn parse_port(value: &str) -> crate::SshResult<u16> {
    value
        .trim()
        .parse::<u16>()
        .map_err(|_| crate::SshCoreError::InvalidPort(value.to_string()))
}

fn normalize_host(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let no_brackets = trimmed
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .map(|inner| inner.to_string());
    no_brackets.or_else(|| Some(trimmed.to_string()))
}

fn split_colon_parts(input: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut bracket_depth = 0;
    for ch in input.chars() {
        match ch {
            ':' if bracket_depth == 0 => {
                parts.push(current.trim().to_string());
                current.clear();
            }
            '[' => {
                bracket_depth += 1;
                current.push(ch);
            }
            ']' => {
                if bracket_depth > 0 {
                    bracket_depth -= 1;
                }
                current.push(ch);
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        parts.push(current.trim().to_string());
    }
    parts.into_iter().filter(|p| !p.is_empty()).collect()
}

#[cfg(test)]
mod tests {
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
}
