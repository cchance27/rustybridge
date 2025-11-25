//! User and group domain types plus web DTOs.
use serde::{Deserialize, Serialize};

use crate::{access::UserRelayAccess, auth::ClaimType};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
/// Minimal user summary.
pub struct UserInfo {
    /// Username.
    pub username: String,
}

/// Enhanced user info with group memberships.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UserGroupInfo {
    pub id: i64,
    /// Username.
    pub username: String,
    /// List of group names the user belongs to.
    pub groups: Vec<String>,
    /// Relays the user can access (with access source).
    pub relays: Vec<UserRelayAccess>,
    /// Claims granted to the user.
    pub claims: Vec<ClaimType>,
}

/// Group info with statistics.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GroupInfo {
    /// Group name.
    pub name: String,
    /// Number of members in this group.
    pub member_count: i64,
    /// Number of relays this group can access.
    pub relay_count: i64,
    /// Member usernames.
    pub members: Vec<String>,
    /// Relay names (host:port) this group can access.
    pub relays: Vec<String>,
    /// Claims granted to the group.
    pub claims: Vec<ClaimType>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
/// Request payload for creating a user.
pub struct CreateUserRequest {
    /// Username to create.
    pub username: String,
    /// Plaintext password for the new user.
    pub password: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
/// Request payload for updating a user.
pub struct UpdateUserRequest {
    /// New password (optional).
    pub password: Option<String>,
}
