use std::path::PathBuf;

/// TLS configuration for native HTTPS (optional; reverse proxy remains the
/// default deployment mode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebTlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

/// Top-level configuration for the web server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebServerConfig {
    pub bind: String,
    pub port: u16,
    pub static_dir: Option<PathBuf>,
    pub tls: Option<WebTlsConfig>,
    /// Public mount path for built assets (defaults to /assets)
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
