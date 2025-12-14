use std::path::PathBuf;
use thiserror::Error;

/// Errors that can occur in SSH core operations
#[derive(Error, Debug)]
pub enum SshCoreError {
    /// Invalid port number
    #[error("port must be a valid number between 0-65535: {0}")]
    InvalidPort(String),

    /// Invalid forwarding specification
    #[error("invalid {kind} forward spec: {message}")]
    InvalidForwardSpec { kind: String, message: String },

    /// Invalid environment variable name
    #[error("invalid environment variable name: {0}")]
    InvalidEnvVar(String),

    /// Empty value where one is required
    #[error("{field} must not be empty")]
    EmptyValue { field: String },

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// SSH protocol error
    #[error("SSH protocol error: {0}")]
    Ssh(#[from] russh::Error),

    /// Network binding failed
    #[error("failed to bind {address}: {source}")]
    BindFailed {
        address: String,
        #[source]
        source: std::io::Error,
    },

    /// Connection failed
    #[error("failed to connect to {address}: {source}")]
    ConnectionFailed {
        address: String,
        #[source]
        source: std::io::Error,
    },

    /// Unix socket operation failed (Unix only)
    #[error("unix socket operation failed for {path}: {source}")]
    UnixSocketFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Platform not supported for operation
    #[error("{operation} is only supported on Unix platforms")]
    PlatformNotSupported { operation: String },

    /// Generic error with context
    #[error("{0}")]
    Other(String),
}

/// Result type alias for SSH core operations
pub type SshResult<T> = Result<T, SshCoreError>;

impl SshCoreError {
    /// Create an invalid forward spec error
    pub fn invalid_forward(kind: impl Into<String>, message: impl Into<String>) -> Self {
        Self::InvalidForwardSpec {
            kind: kind.into(),
            message: message.into(),
        }
    }

    /// Create an empty value error
    pub fn empty(field: impl Into<String>) -> Self {
        Self::EmptyValue { field: field.into() }
    }
}
