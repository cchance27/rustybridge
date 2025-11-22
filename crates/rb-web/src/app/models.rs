// Shared data models for rb_web
// These models are used by both client and server, so they cannot depend on server-only crates

use serde::{Deserialize, Serialize};

// Define RelayHost locally to avoid dependency on state_store (server-only)
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RelayHost {
    pub id: i64,
    pub name: String,
    pub ip: String,
    pub port: i64,
}

/// Authentication configuration for UI editing
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthConfig {
    pub mode: String, // "none", "saved", "custom"
    pub saved_credential_id: Option<i64>,
    pub custom_type: Option<String>, // "password", "ssh_key", "agent"
    pub username: Option<String>,
    // Presence flags only; sensitive data is never returned to the web client
    pub has_password: bool,
    pub has_private_key: bool,
    pub has_passphrase: bool,
    pub has_public_key: bool,
}

/// Extended relay host info with credential and hostkey status
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RelayHostInfo {
    pub id: i64,
    pub name: String,
    pub ip: String,
    pub port: i64,
    pub credential: Option<String>, // credential name if assigned (display only)
    pub has_hostkey: bool,
    pub auth_config: Option<AuthConfig>,              // Full auth config for editing
    pub access_principals: Vec<RelayAccessPrincipal>, // Users and groups with access
}

/// Credential summary for listing
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CredentialInfo {
    pub id: i64,
    pub name: String,
    pub kind: String, // "password", "ssh_key", "agent"
    pub username: Option<String>,
    pub has_secret: bool,
    pub assigned_relays: Vec<String>,
}

/// User info
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UserInfo {
    pub username: String,
}

/// Enhanced user info with group memberships
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UserGroupInfo {
    pub username: String,
    pub groups: Vec<String>,          // List of group names the user belongs to
    pub relays: Vec<UserRelayAccess>, // List of relays the user can access
}

/// Relay access info for a user
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UserRelayAccess {
    pub relay_name: String,               // Name of the relay (e.g., "production-server")
    pub relay_endpoint: String,           // Endpoint (e.g., "192.168.1.10:22")
    pub access_source: RelayAccessSource, // How the user has access
}

/// How a user has access to a relay
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum RelayAccessSource {
    Direct,           // User has direct access
    ViaGroup(String), // User has access via a group (group name)
    Both(String),     // User has both direct and group access (group name)
}

/// Group info with statistics
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GroupInfo {
    pub name: String,
    pub member_count: i64,
    pub relay_count: i64,     // Number of relays this group has access to
    pub members: Vec<String>, // List of member usernames
    pub relays: Vec<String>,  // List of relay names (host:port)
}

/// Principal for relay ACL (user or group)
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RelayAccessPrincipal {
    pub kind: String, // "user" or "group"
    pub name: String,
}

/// Request to grant relay access
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GrantAccessRequest {
    pub principal_kind: String, // "user" or "group"
    pub principal_name: String,
}

// ===== Request DTOs =====

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CreateRelayRequest {
    pub name: String,
    pub endpoint: String, // "ip:port" format
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UpdateRelayRequest {
    pub name: String,
    pub endpoint: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CreateCredentialRequest {
    pub name: String,
    pub kind: String,
    pub username: Option<String>,
    pub password: Option<String>,    // for password type
    pub private_key: Option<String>, // for ssh_key type
    pub public_key: Option<String>,  // for agent type
    pub passphrase: Option<String>,  // for ssh_key type (optional, only if private key is encrypted)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UpdateUserRequest {
    pub password: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UpdateCredentialRequest {
    pub name: String,
    pub kind: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub passphrase: Option<String>, // for ssh_key type (optional, only if private key is encrypted)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CustomAuthRequest {
    pub auth_type: String, // "password", "ssh_key", "agent"
    pub username: Option<String>,
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub passphrase: Option<String>,
    pub public_key: Option<String>,
}
