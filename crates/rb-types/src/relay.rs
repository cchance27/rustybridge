//! Relay host domain types.
use serde::{Deserialize, Serialize};
#[cfg(feature = "sqlx")]
use sqlx::FromRow;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(FromRow))]
/// Minimal relay record (DB-facing).
pub struct RelayInfo {
    /// Primary key identifier.
    pub id: i64,
    /// Human-readable relay name.
    pub name: String,
    /// Relay IP or host.
    pub ip: String,
    /// Relay SSH port.
    pub port: i64,
}

/// Extended relay host info with credential and hostkey status.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RelayHostInfo {
    /// Primary key identifier.
    pub id: i64,
    /// Human-readable relay name.
    pub name: String,
    /// Relay IP or host.
    pub ip: String,
    /// Relay SSH port.
    pub port: i64,
    /// Assigned credential name (display only).
    pub credential: Option<String>,
    /// Assigned credential kind.
    pub credential_kind: Option<String>,
    /// Username mode of the assigned credential.
    pub credential_username_mode: Option<String>,
    /// Whether password is required for the assigned credential.
    pub credential_password_required: Option<bool>,
    /// Indicates whether a host key is stored.
    pub has_hostkey: bool,
    /// Full auth config for UI editing.
    pub auth_config: Option<crate::credentials::AuthWebConfig>,
    /// Principals with access to this relay.
    pub access_principals: Vec<crate::access::RelayAccessPrincipal>,
}

/// Request payload for creating a relay.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CreateRelayRequest {
    /// Relay name.
    pub name: String,
    /// Endpoint in `ip:port` format.
    pub endpoint: String,
}

/// Request payload for updating an existing relay.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UpdateRelayRequest {
    /// Relay name.
    pub name: String,
    /// Endpoint in `ip:port` format.
    pub endpoint: String,
}

/// Host key review payload used by the two-step fetch/store flow in the web UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostkeyReview {
    /// Relay identifier.
    pub host_id: i64,
    /// Relay name.
    pub host: String,
    /// Previously stored fingerprint (if any).
    pub old_fingerprint: Option<String>,
    /// Previously stored key type (if any).
    pub old_key_type: Option<String>,
    /// Newly fetched fingerprint.
    pub new_fingerprint: String,
    /// Newly fetched key type.
    pub new_key_type: String,
    /// Newly fetched public key PEM.
    pub new_key_pem: String,
}
