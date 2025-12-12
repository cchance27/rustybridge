//! State management for RustyBridge - database operations and persistence.
//!
//! This crate provides database operations for both client and server components,
//! organizing functionality into focused submodules for better maintainability.
//!
//! ## Module Structure
//!
//! - `db`: Database initialization, migration, and connection management
//! - `relay`: Relay host management operations  
//! - `users`: User and group management operations
//! - `rbac`: Role-based access control (RBAC) operations
//! - `auth`: Authentication and OIDC operations
//! - `credentials`: Relay credential management
//! - `ssh_keys`: SSH public key management
//! - `config`: Server configuration and options management
//! - `error`: Error types and results

pub mod audit;
mod auth;
mod config;
mod credentials;
mod db;
mod rbac;
mod relay;
mod ssh_keys;
mod users;

mod error;

// Re-export error types for use by submodules
// Re-export all public functions and types from submodules
pub use audit::*;
pub use auth::*;
pub use config::*;
pub use credentials::*;
pub use db::*;
pub use error::{DbError, DbResult};
// Re-export types from rb-types
pub use rb_types::access::{PrincipalKind, RelayAclPrincipal};
pub use rb_types::{
    auth::{ClaimLevel, ClaimType, OidcLinkInfo, OidcProfile, UserAuthRecord}, relay::RelayInfo, state::{DbHandle, RelayCredentialRow, Role}
};
pub use rbac::*;
pub use relay::*;
pub use ssh_keys::*;
pub use users::*;

#[cfg(feature = "test-support")]
pub mod test_support;

/// The ID of the Super Admin role (always 1).
pub const SUPER_ADMIN_ROLE_ID: i64 = 1;

/// Helper to execute a function within a database transaction.
/// If the function returns Ok, the transaction is committed.
/// If the function returns Err, the transaction is rolled back.
pub async fn execute_transaction<T, F, Fut>(pool: &sqlx::SqlitePool, f: F) -> DbResult<T>
where
    F: FnOnce(&mut sqlx::Transaction<'_, sqlx::Sqlite>) -> Fut,
    Fut: std::future::Future<Output = DbResult<T>>,
{
    let mut tx = pool.begin().await?;
    match f(&mut tx).await {
        Ok(result) => {
            tx.commit().await?;
            Ok(result)
        }
        Err(e) => {
            tx.rollback().await?;
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests_rbac;
