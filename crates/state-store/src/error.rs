use std::path::PathBuf;

use thiserror::Error;

/// Errors that can occur when interacting with the state store.
#[derive(Error, Debug)]
pub enum DbError {
    /// Failed to connect to the database
    #[error("failed to open database at {path}: {source}")]
    ConnectionFailed {
        path: String,
        #[source]
        source: sqlx::Error,
    },

    /// Database migration failed
    #[error("migration failed: {0}")]
    MigrationFailed(#[from] sqlx::migrate::MigrateError),

    /// Invalid database URL
    #[error("invalid database URL: {0}")]
    InvalidUrl(String),

    /// I/O error during database operations
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// SQLx error during query execution
    #[error("database query error: {0}")]
    Query(#[from] sqlx::Error),

    /// Relay host not found
    #[error("relay host '{name}' not found")]
    RelayHostNotFound { name: String },

    /// User not found
    #[error("user '{username}' not found")]
    UserNotFound { username: String },

    /// Group not found
    #[error("group '{group}' not found")]
    GroupNotFound { group: String },

    /// Invalid file path for SQLite database
    #[error("invalid sqlite path: {0}")]
    InvalidPath(PathBuf),

    #[error("unsupported principal kind: {0}")]
    UnsupportedPrincipalKind(String),

    /// Failed to create database directory
    #[error("failed to create directory {path}: {source}")]
    DirectoryCreationFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Failed to create database file
    #[error("failed to create database file {path}: {source}")]
    FileCreationFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Spawn blocking task panicked
    #[error("background task panicked: {0}")]
    TaskPanicked(String),

    /// Invalid environment variable value
    #[error("invalid value for {var}: {message}")]
    InvalidEnvVar { var: String, message: String },

    /// Invalid operation (e.g., violates business constraints)
    #[error("invalid operation '{operation}': {reason}")]
    InvalidOperation { operation: String, reason: String },

    /// Invalid principal kind for ACL operations
    #[error("invalid principal kind: {kind}")]
    InvalidPrincipalKind { kind: String },

    /// JSON serialization/deserialization error
    #[error("JSON serialization error in {context}: {source}")]
    JsonSerialization {
        context: String,
        #[source]
        source: serde_json::Error,
    },
}

/// Result type alias for database operations
pub type DbResult<T> = Result<T, DbError>;
