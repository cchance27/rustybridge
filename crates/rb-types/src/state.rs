//! Shared state-store data models.
//!
//! These lightweight structs describe rows we persist in SQLite. They live in
//! `rb-types` so other crates can exchange structured data without depending
//! on the state-store implementation details.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
#[cfg(feature = "sqlx")]
use sqlx::{FromRow, SqlitePool};

/// Relay credential record as stored in the database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(FromRow))]
pub struct RelayCredentialRow {
    /// Primary key identifier.
    pub id: i64,
    /// Unique credential name (human-friendly handle).
    pub name: String,
    /// Credential kind, e.g. `password`, `ssh_key`, or `agent`.
    pub kind: String,
    /// Per-credential salt used for envelope encryption.
    pub salt: Vec<u8>,
    /// Nonce used for encrypting the secret payload.
    pub nonce: Vec<u8>,
    /// Encrypted credential material (ciphertext).
    pub secret: Vec<u8>,
    /// Optional serialized metadata (format is kind-specific).
    pub meta: Option<String>,
    /// Username handling mode (`fixed`, `blank`, `passthrough`).
    pub username_mode: String,
    /// Whether a password is required (only meaningful for password creds).
    pub password_required: bool,
}

/// Role information used for RBAC management.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(FromRow))]
pub struct Role {
    /// Primary key identifier.
    pub id: i64,
    /// Unique role name.
    pub name: String,
    /// Optional human-friendly description.
    pub description: Option<String>,
    /// Unix timestamp (seconds) when the role was created.
    pub created_at: i64,
}

/// Wrapper around a pooled SQLite connection plus metadata about its origin.
#[cfg(feature = "sqlx")]
#[derive(Clone, Debug)]
pub struct DbHandle {
    /// Shared connection pool used by callers.
    pub pool: SqlitePool,
    /// Connection URL used to construct the pool (file:// or sqlite::memory:).
    pub url: String,
    /// Filesystem path when backed by a local file; `None` for pure URLs.
    pub path: Option<PathBuf>,
    /// True when the database file (or in-memory DB) was just created.
    pub freshly_created: bool,
}

#[cfg(feature = "sqlx")]
impl DbHandle {
    /// Consume the handle and return the underlying pool.
    pub fn into_pool(self) -> SqlitePool {
        self.pool
    }
}

/// Concrete location details for a SQLite-backed state store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DbLocation {
    /// Connection URL (e.g., `sqlite:///tmp/rb-server.db` or `sqlite::memory:`).
    pub url: String,
    /// Local filesystem path when the database is file-backed; `None` for pure URLs.
    pub path: Option<PathBuf>,
    /// Flag indicating the database was just created (used to trigger migrations/logs).
    pub freshly_created: bool,
}
