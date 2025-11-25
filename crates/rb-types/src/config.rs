//! Configuration structs for server and web frontends.
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Runtime configuration for the embedded SSH relay server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfig {
    /// IP address or hostname to bind the SSH listener to (e.g. `127.0.0.1`).
    pub bind: String,
    /// TCP port the SSH server should listen on (defaults to 2222 in the CLI).
    pub port: u16,
    /// When true, delete any cached host key on startup and generate a new one.
    pub roll_hostkey: bool,
}

/// TLS configuration for serving the management UI over native HTTPS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebTlsConfig {
    /// Filesystem path to a PEM‑encoded certificate.
    pub cert_path: PathBuf,
    /// Filesystem path to the PEM‑encoded private key that matches `cert_path`.
    pub key_path: PathBuf,
}

/// Top‑level configuration for the embedded web server that fronts RustyBridge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebServerConfig {
    /// Address (IP or host) to bind the HTTP listener to.
    pub bind: String,
    /// TCP port to serve the web UI on.
    pub port: u16,
    /// Optional override for where static assets are loaded from (useful in dev).
    pub static_dir: Option<PathBuf>,
    /// Optional native TLS configuration; when absent the server runs HTTP only.
    pub tls: Option<WebTlsConfig>,
    /// Public mount path where built assets are exposed (defaults to `/assets`).
    pub assets_mount: String,
}

impl Default for WebServerConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1".to_string(),
            port: 8080,
            static_dir: None,
            tls: None,
            assets_mount: "/assets".to_string(),
        }
    }
}
