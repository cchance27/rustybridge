use thiserror::Error;

/// Errors that can occur in client-core operations
#[derive(Error, Debug)]
pub enum ClientError {
    /// Database error
    #[error("database error: {0}")]
    Database(#[from] state_store::DbError),

    /// SSH error
    #[error("SSH error: {0}")]
    Ssh(#[from] russh::Error),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Authentication failed
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    /// Host key verification failed
    #[error("host key verification failed: {0}")]
    HostKeyFailed(String),

    /// Cryptographic error
    #[error("cryptographic error: {0}")]
    Crypto(String),

    /// Generic error with context
    #[error("{0}")]
    Other(String),
}

/// Result type alias for client-core operations
pub type ClientResult<T> = Result<T, ClientError>;

// Allow conversion from sqlx::Error
impl From<sqlx::Error> for ClientError {
    fn from(err: sqlx::Error) -> Self {
        ClientError::Database(state_store::DbError::from(err))
    }
}

// Allow conversion from SshCoreError
impl From<ssh_core::SshCoreError> for ClientError {
    fn from(err: ssh_core::SshCoreError) -> Self {
        ClientError::Other(err.to_string())
    }
}
