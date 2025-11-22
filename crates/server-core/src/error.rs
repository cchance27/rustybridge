use thiserror::Error;

/// Errors that can occur in server-core operations
#[derive(Error, Debug)]
pub enum ServerError {
    /// Database error
    #[error("database error: {0}")]
    Database(#[from] state_store::DbError),

    /// SSH error
    #[error("SSH error: {0}")]
    Ssh(#[from] russh::Error),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Cryptographic error
    #[error("cryptographic error: {0}")]
    Crypto(String),

    /// Secret encryption/decryption failed
    #[error("failed to {operation} secret: {reason}")]
    SecretOperation { operation: String, reason: String },

    /// Invalid master key or passphrase
    #[error("invalid master key or passphrase")]
    InvalidMasterSecret,

    /// Missing required environment variable
    #[error("missing required environment variable: {0}")]
    MissingEnvVar(String),

    /// Invalid configuration
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// Resource not found
    #[error("{resource} not found: {name}")]
    NotFound { resource: String, name: String },

    /// Resource already exists
    #[error("{resource} already exists: {name}")]
    AlreadyExists { resource: String, name: String },

    /// Operation not permitted
    #[error("{operation} not permitted: {reason}")]
    NotPermitted { operation: String, reason: String },

    /// Invalid endpoint format
    #[error("invalid endpoint format: {0}")]
    InvalidEndpoint(String),

    /// Password hashing failed
    #[error("password hashing failed: {0}")]
    PasswordHash(String),

    /// JSON serialization/deserialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Base64 encoding/decoding error
    #[error("base64 error: {0}")]
    Base64(String),

    /// Generic error with context
    #[error("{0}")]
    Other(String),
}

/// Result type alias for server-core operations
pub type ServerResult<T> = Result<T, ServerError>;

impl ServerError {
    /// Create a not found error
    pub fn not_found(resource: impl Into<String>, name: impl Into<String>) -> Self {
        Self::NotFound {
            resource: resource.into(),
            name: name.into(),
        }
    }

    /// Create an already exists error
    pub fn already_exists(resource: impl Into<String>, name: impl Into<String>) -> Self {
        Self::AlreadyExists {
            resource: resource.into(),
            name: name.into(),
        }
    }

    /// Create a not permitted error
    pub fn not_permitted(operation: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::NotPermitted {
            operation: operation.into(),
            reason: reason.into(),
        }
    }

    /// Create a secret operation error
    pub fn secret_op(operation: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::SecretOperation {
            operation: operation.into(),
            reason: reason.into(),
        }
    }
}

// Allow conversion from sqlx::Error
impl From<sqlx::Error> for ServerError {
    fn from(err: sqlx::Error) -> Self {
        ServerError::Database(state_store::DbError::from(err))
    }
}
