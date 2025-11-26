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

#[cfg(test)]
mod tests_rbac;
