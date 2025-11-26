//! Shared SSH-related configuration types used across RustyBridge.
//!
//! These structs/enums are intentionally dependency-light so they can be
//! reused by CLI parsing, config loaders, and runtimes without pulling in
//! protocol implementations.

use std::path::PathBuf;

#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
/// Newline translation modes for interactive terminals.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NewlineMode {
    /// Leave newline bytes untouched (LF).
    #[default]
    Lf,
    /// Map newlines to CR.
    Cr,
    /// Map newlines to CRLF.
    CrLf,
}

/// Collection of forwarding and environment directives for an SSH session.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ForwardingConfig {
    /// Local TCP forwards.
    pub local_tcp: Vec<LocalTcpForward>,
    /// Remote TCP forwards requested from the server.
    pub remote_tcp: Vec<RemoteTcpForward>,
    /// Dynamic SOCKS forwards.
    pub dynamic_socks: Vec<DynamicSocksForward>,
    /// Local Unix domain socket forwards.
    pub local_unix: Vec<LocalUnixForward>,
    /// Remote Unix domain socket forwards.
    pub remote_unix: Vec<RemoteUnixForward>,
    /// X11 forwarding configuration.
    pub x11: Option<X11Forward>,
    /// Subsystems to request.
    pub subsystems: Vec<SubsystemRequest>,
    /// Environment/locale propagation rules.
    pub env: EnvPropagation,
}

impl ForwardingConfig {
    /// Returns true when no forwarding/env directives are present.
    pub fn is_empty(&self) -> bool {
        self.local_tcp.is_empty()
            && self.remote_tcp.is_empty()
            && self.dynamic_socks.is_empty()
            && self.local_unix.is_empty()
            && self.remote_unix.is_empty()
            && self.x11.is_none()
            && self.subsystems.is_empty()
            && self.env.entries.is_empty()
            && matches!(self.env.locale_mode, LocaleMode::None)
    }
}

/// Local TCP forward specification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalTcpForward {
    /// Optional local bind address.
    pub bind_address: Option<String>,
    /// Local bind port.
    pub bind_port: u16,
    /// Target host to reach through the tunnel.
    pub target_host: String,
    /// Target port to reach through the tunnel.
    pub target_port: u16,
}

/// Remote TCP forward specification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteTcpForward {
    /// Optional remote bind address requested on the server.
    pub bind_address: Option<String>,
    /// Remote bind port requested on the server.
    pub bind_port: u16,
    /// Target host to receive connections.
    pub target_host: String,
    /// Target port to receive connections.
    pub target_port: u16,
}

/// Dynamic SOCKS proxy specification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DynamicSocksForward {
    /// Optional bind address for SOCKS proxy.
    pub bind_address: Option<String>,
    /// Bind port for SOCKS proxy.
    pub bind_port: u16,
}

/// Local Unix domain socket forward specification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalUnixForward {
    /// Local Unix socket path to listen on.
    pub local_socket: PathBuf,
    /// Remote Unix socket path to connect to.
    pub remote_socket: PathBuf,
}

/// Remote Unix domain socket forward specification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteUnixForward {
    /// Remote Unix socket path to listen on.
    pub remote_socket: PathBuf,
    /// Local Unix socket path to forward back to.
    pub local_socket: PathBuf,
}

/// X11 forwarding options.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X11Forward {
    /// Optional DISPLAY override (e.g., `:1`).
    pub display: Option<String>,
    /// Whether to request trusted cookies.
    pub trusted: bool,
    /// Restrict to a single connection.
    pub single_connection: bool,
}

/// Environment propagation policy (variables and locale mode).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnvPropagation {
    /// Environment variables to forward.
    pub entries: Vec<EnvEntry>,
    /// Locale forwarding strategy.
    pub locale_mode: LocaleMode,
}

/// Environment variable entry to forward.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvEntry {
    /// Environment variable name.
    pub name: String,
    /// Optional value; `None` means forward only the name.
    pub value: Option<String>,
}

/// Locale forwarding strategy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LocaleMode {
    /// Do not forward locale variables.
    #[default]
    None,
    /// Forward LANG only.
    Lang,
    /// Forward LANG and LC_* variables.
    All,
}

/// Subsystem request descriptor (e.g., "sftp").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubsystemRequest {
    /// Subsystem name to request (e.g., "sftp").
    pub name: String,
}

// Public key for SSH authentication
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SshKey {
    pub id: i64,
    pub public_key: String,
    pub comment: Option<String>,
    pub created_at: i64,
}
