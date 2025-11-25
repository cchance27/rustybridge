use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("SSH error: {0}")]
    Ssh(#[from] russh::Error),

    #[error("OIDC error: {0}")]
    Oidc(String),

    #[error("OIDC discovery error: {0}")]
    OidcDiscovery(#[from] openidconnect::DiscoveryError<openidconnect::reqwest::Error<reqwest::Error>>),

    #[error("OIDC configuration error: {0}")]
    OidcConfig(#[from] openidconnect::ConfigurationError),

    #[error("OIDC request error: {0}")]
    OidcRequest(#[from] openidconnect::reqwest::Error<reqwest::Error>),

    #[error("OIDC url parse error: {0}")]
    OidcUrlParse(#[from] openidconnect::url::ParseError),

    #[error("SSH Key error: {0}")]
    SshKey(#[from] ssh_key::Error),

    #[error("Cryptography error: {0}")]
    Crypto(String),

    #[error("Base64 error: {0}")]
    Base64(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Invalid endpoint: {0}")]
    InvalidEndpoint(String),

    #[error("{0} '{1}' not found")]
    NotFound(String, String),

    #[error("{0} '{1}' already exists")]
    AlreadyExists(String, String),

    #[error("State store error: {0}")]
    StateStore(#[from] state_store::DbError),

    #[error("Password hash error: {0}")]
    PasswordHash(#[from] password_hash::Error),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Other error: {0}")]
    Other(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Permission denied: {0}")]
    NotPermitted(String),

    #[error("Invalid master secret: {0}")]
    InvalidMasterSecret(String),

    #[error("Missing environment variable: {0}")]
    MissingEnvVar(String),

    #[error("Secret operation failed: {0}")]
    SecretOp(String),
}

impl ServerError {
    pub fn not_found(kind: &str, name: impl AsRef<str>) -> Self {
        Self::NotFound(kind.to_string(), name.as_ref().to_string())
    }

    pub fn already_exists(kind: &str, name: impl AsRef<str>) -> Self {
        Self::AlreadyExists(kind.to_string(), name.as_ref().to_string())
    }

    pub fn not_permitted(msg: impl Into<String>) -> Self {
        Self::NotPermitted(msg.into())
    }

    pub fn secret_op(msg: impl Into<String>) -> Self {
        Self::SecretOp(msg.into())
    }
}

pub type ServerResult<T> = Result<T, ServerError>;
