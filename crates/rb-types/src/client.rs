//! Client-side shared types for the RustyBridge SSH client.
//!
//! These structs remain dependency-light so they can be reused by CLI parsing,
//! auth helpers, or future UIs without pulling in the full client runtime.

#[cfg(feature = "secrecy")]
use crate::ssh::{ForwardingConfig, NewlineMode};
#[cfg(feature = "secrecy")]
use secrecy::SecretString;
use std::path::PathBuf;

/// Public-key identity and optional certificate to present during SSH auth.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientIdentity {
    /// Path to the private key file (PEM/OpenSSH).
    pub key_path: PathBuf,
    /// Optional path to a corresponding OpenSSH certificate.
    pub cert_path: Option<PathBuf>,
}

/// Top-level SSH client configuration derived from CLI or other frontends.
///
/// This shape is purely data; the client runtime in `client-core` performs all
/// I/O and protocol work. Enabled behind the `client-config` feature to avoid
/// pulling additional dependencies into `rb-types` unintentionally.
#[cfg(feature = "secrecy")]
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// Target host or IP.
    pub host: String,
    /// Target SSH port.
    pub port: u16,
    /// Remote username to authenticate as.
    pub username: String,
    /// Optional password provided up front.
    pub password: Option<SecretString>,
    /// Optional remote command to execute.
    pub command: Option<String>,
    /// How to map newline input/output.
    pub newline_mode: NewlineMode,
    /// Whether to enable local echo during the session.
    pub local_echo: bool,
    /// Prefer compression (zlib) during the session.
    pub prefer_compression: bool,
    /// Rekey interval in wall-clock time.
    pub rekey_interval: Option<std::time::Duration>,
    /// Rekey after this many bytes.
    pub rekey_bytes: Option<usize>,
    /// Keepalive probe interval.
    pub keepalive_interval: Option<std::time::Duration>,
    /// Max unanswered keepalives before disconnect.
    pub keepalive_max: Option<usize>,
    /// Accept unknown host key for this session only.
    pub accept_hostkey_once: bool,
    /// Accept and store unknown host key.
    pub accept_store_hostkey: bool,
    /// Replace any cached host key before connecting.
    pub replace_hostkey: bool,
    /// Allow legacy/insecure crypto.
    pub insecure: bool,
    /// Key (and optional cert) identities to try.
    pub identities: Vec<ClientIdentity>,
    /// Allow keyboard-interactive auth.
    pub allow_keyboard_interactive: bool,
    /// Use SSH agent for auth.
    pub agent_auth: bool,
    /// Forward agent to the remote side.
    pub forward_agent: bool,
    /// Path to the SSH agent socket if used.
    pub ssh_agent_socket: Option<PathBuf>,
    /// Prompt interactively for password if needed.
    pub prompt_password: bool,
    /// Optional custom prompt string when asking for password.
    pub password_prompt: Option<String>,
    /// Port-forwarding and env forwarding directives.
    pub forwarding: ForwardingConfig,
}

/// Authentication preferences gathered from user input.
#[cfg(feature = "secrecy")]
#[derive(Clone, Debug)]
pub struct AuthPreferences<'a> {
    /// Username to authenticate as.
    pub username: &'a str,
    /// Optional password provided up front.
    pub password: Option<&'a SecretString>,
    /// Whether to prompt for a password if none supplied.
    pub prompt_password: bool,
    /// Optional custom prompt text for password collection.
    pub password_prompt: Option<&'a str>,
    /// Identities to attempt for public-key auth.
    pub identities: &'a [ClientIdentity],
    /// Whether keyboard-interactive is allowed.
    pub allow_keyboard_interactive: bool,
    /// Whether to use the SSH agent.
    pub use_agent_auth: bool,
    /// Optional agent socket path.
    pub agent_socket: Option<&'a std::path::Path>,
}
