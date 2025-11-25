//! Network/endpoint parsing helpers shared across RustyBridge binaries.
//!
//! These types stay dependency-light so they can be reused by CLI tools,
//! services, and tests without dragging in heavyweight parsing crates.

use std::{error::Error, fmt};

/// Parsed endpoint components derived from a user-supplied target string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetParts {
    /// Hostname or IP address portion of the target.
    pub host: String,
    /// TCP port number; defaults to 22 when absent.
    pub port: u16,
    /// Username inferred from a `user@host` prefix when present.
    pub inferred_username: Option<String>,
}
// TODO: (TargetParts) We should probably find any endpoints and replace them with this type, also we should add a nice display for this to show as clean endpoint style.

/// Errors that can occur while parsing a target string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TargetParseError {
    /// The input was empty or only whitespace.
    EmptyTarget,
    /// Host portion was empty after parsing.
    EmptyHost,
    /// Port failed to parse into a valid `u16`.
    InvalidPort(String),
}

impl fmt::Display for TargetParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetParseError::EmptyTarget => write!(f, "target must not be empty"),
            TargetParseError::EmptyHost => write!(f, "target host is missing"),
            TargetParseError::InvalidPort(p) => write!(f, "invalid port: {p}"),
        }
    }
}

impl Error for TargetParseError {}

/// Parse a user-supplied target string of the form `[user@]host[:port]`.
///
/// * IPv6 literals must be wrapped in brackets, e.g. `user@[fe80::1]:2222`.
/// * When no port is supplied, the default of 22 is used.
pub fn parse_target(input: &str) -> Result<TargetParts, TargetParseError> {
    if input.trim().is_empty() {
        return Err(TargetParseError::EmptyTarget);
    }

    let (username_part, host_part) = if let Some((user, host)) = input.rsplit_once('@') {
        (Some(user.to_string()), host.to_string())
    } else {
        (None, input.to_string())
    };

    let (host, port) = if host_part.starts_with('[') {
        parse_bracketed_host(&host_part)?
    } else if let Some((host, port_str)) = host_part.rsplit_once(':') {
        let port = port_str
            .parse::<u16>()
            .map_err(|_| TargetParseError::InvalidPort(port_str.to_string()))?;
        (host.to_string(), port)
    } else {
        (host_part, 22)
    };

    if host.is_empty() {
        return Err(TargetParseError::EmptyHost);
    }

    Ok(TargetParts {
        host,
        port,
        inferred_username: username_part,
    })
}

/// Parse an IPv6-literal target of the form `[addr]` or `[addr]:port`.
///
/// Returns the host string (without brackets) and the parsed port, defaulting to 22 when omitted.
fn parse_bracketed_host(input: &str) -> Result<(String, u16), TargetParseError> {
    if let Some((host, port)) = input.rsplit_once("]:") {
        let host = host.trim_start_matches('[');
        let port = port.parse::<u16>().map_err(|_| TargetParseError::InvalidPort(port.to_string()))?;
        Ok((host.to_string(), port))
    } else {
        let host = input.trim_start_matches('[').trim_end_matches(']');
        Ok((host.to_string(), 22))
    }
}
