use std::{convert::Infallible, fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::auth::ClaimType;

// TODO: custom_type, username_mode should be enums to strongly type with proper impl's for display, from, to etc.

/// Authentication configuration for UI editing
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthWebConfig {
    pub mode: String, // "none", "saved", "custom"
    pub saved_credential_id: Option<i64>,
    pub custom_type: Option<String>, // "password", "ssh_key", "agent"
    pub username: Option<String>,
    pub username_mode: Option<String>,
    // Presence flags only; sensitive data is never returned to the web client
    pub has_password: bool,
    pub has_private_key: bool,
    pub has_passphrase: bool,
    pub has_public_key: bool,
    #[serde(default)]
    pub password_required: Option<bool>, // only meaningful for password custom auth; None when unknown/not applicable
}

/// Extended relay host info with credential and hostkey status
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RelayHostInfo {
    pub id: i64,
    pub name: String,
    pub ip: String,
    pub port: i64,
    pub credential: Option<String>, // credential name if assigned (display only)
    pub credential_kind: Option<String>,
    pub credential_username_mode: Option<String>,
    pub credential_password_required: Option<bool>,
    pub has_hostkey: bool,
    pub auth_config: Option<AuthWebConfig>,           // Full auth config for editing
    pub access_principals: Vec<RelayAccessPrincipal>, // Users and groups with access
}

/// Credential summary for listing
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CredentialInfo {
    pub id: i64,
    pub name: String,
    pub kind: String, // "password", "ssh_key", "agent"
    pub username: Option<String>,
    pub username_mode: String,   // "fixed", "blank", "passthrough"
    pub password_required: bool, // only relevant for password type
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
    pub claims: Vec<ClaimType>,       // List of claims the user has
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
    pub relay_count: i64,       // Number of relays this group has access to
    pub members: Vec<String>,   // List of member usernames
    pub relays: Vec<String>,    // List of relay names (host:port)
    pub claims: Vec<ClaimType>, // List of claims the group has
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrincipalKind {
    User,
    Group,
    Other,
}

impl PrincipalKind {
    pub fn as_str(&self) -> &str {
        match self {
            PrincipalKind::User => "user",
            PrincipalKind::Group => "group",
            PrincipalKind::Other => "other",
        }
    }
}

impl Display for PrincipalKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PrincipalKind {
    type Err = Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user" => Ok(PrincipalKind::User),
            "group" => Ok(PrincipalKind::Group),
            _ => Ok(PrincipalKind::Other),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayAclPrincipal {
    pub kind: PrincipalKind,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayAccessPrincipal {
    pub kind: PrincipalKind,
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
    pub username_mode: String,       // "fixed", "blank", "passthrough"
    pub password_required: bool,     // only relevant for password type
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
    pub username_mode: String,   // "fixed", "blank", "passthrough"
    pub password_required: bool, // only relevant for password type
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub passphrase: Option<String>, // for ssh_key type (optional, only if private key is encrypted)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CustomAuthRequest {
    pub auth_type: String, // "password", "ssh_key", "agent"
    pub username: Option<String>,
    pub username_mode: String, // "fixed", "blank", "passthrough"
    pub password: Option<String>,
    pub password_required: bool,
    pub private_key: Option<String>,
    pub passphrase: Option<String>,
    pub public_key: Option<String>,
}
