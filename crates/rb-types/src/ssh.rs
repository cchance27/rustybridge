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

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum SessionStateSummary {
    Attached,
    Detached,
    Closed,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SessionKind {
    TUI,   // Direct SSH to bridge
    Relay, // SSH via bridge to target
    Web,   // Web Dashboard Presence
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum TUIApplication {
    Management,
    RelaySelector,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConnectionAmounts {
    pub web: u32,
    pub ssh: u32,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UserSessionSummary {
    pub relay_id: i64,
    pub relay_name: String,
    pub session_number: u32,
    pub kind: SessionKind,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub state: SessionStateSummary,
    /// Whether the user has been active (typed) recently
    #[serde(default)]
    pub active_recent: bool,
    /// The name of the active TUI application (e.g. "Management", "Relay Selector")
    #[serde(default)]
    pub active_app: Option<TUIApplication>,
    /// When the session was detached (if applicable)
    #[serde(default)]
    pub detached_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Timeout for detached sessions in seconds (if applicable)
    #[serde(default)]
    pub detached_timeout_secs: Option<u32>,
    pub connections: ConnectionAmounts,
    pub viewers: ConnectionAmounts,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_active_at: chrono::DateTime<chrono::Utc>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AdminSessionSummary {
    pub user_id: i64,
    pub username: String,
    #[serde(flatten)]
    pub session: UserSessionSummary,
}

/// Session origin tracking - where the session was created from
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum SessionOrigin {
    /// Session created from web UI
    Web { user_id: i64 },
    /// Session created from SSH client
    Ssh { user_id: i64 },
}

/// Connection type for tracking web vs SSH connections
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    Web,
    Ssh,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub enum SshControl {
    Close,
    Resize { cols: u32, rows: u32 },
    Minimize(bool),
    Ready { cols: u32, rows: u32 },
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct SshClientMsg {
    pub cmd: Option<SshControl>,
    pub data: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct SshServerMsg {
    pub data: Vec<u8>,
    pub eof: bool,
    pub exit_status: Option<i32>,
    pub session_id: Option<u32>, // Session number for this connection
    pub relay_id: Option<i64>,   // Relay ID for this connection
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct WebSessionMeta {
    pub id: String, // Unique ID for the connection
    pub user_id: i64,
    pub username: String,
    pub ip: String,
    pub user_agent: Option<String>,
    pub connected_at: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum SessionEvent {
    Created(i64, UserSessionSummary),
    Updated(i64, UserSessionSummary),
    Removed { user_id: i64, relay_id: i64, session_number: u32 },
    List(Vec<UserSessionSummary>),
    Presence(i64, Vec<WebSessionMeta>),
}
