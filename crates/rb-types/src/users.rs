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
pub struct UserGroupInfo<'a> {
    pub id: i64,
    /// Username.
    pub username: String,
    /// List of group names the user belongs to.
    pub groups: Vec<String>,
    /// Relays the user can access (with access source).
    pub relays: Vec<UserRelayAccess>,
    /// Claims granted to the user.
    pub claims: Vec<ClaimType<'a>>,
    /// Number of SSH public keys.
    pub ssh_key_count: i64,
    /// List of role names assigned to the user.
    pub roles: Vec<String>,
}

/// Group info with statistics.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GroupInfo<'a> {
    /// Group ID.
    pub id: i64,
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
    pub claims: Vec<ClaimType<'a>>,
    /// List of role names assigned to the group.
    pub roles: Vec<String>,
}

/// Role info with statistics.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RoleInfo<'a> {
    /// Role ID.
    pub id: i64,
    /// Role name.
    pub name: String,
    /// Role description.
    pub description: Option<String>,
    /// Number of users assigned this role.
    pub user_count: i64,
    /// Number of groups assigned this role.
    pub group_count: i64,
    /// Usernames with this role.
    pub users: Vec<String>,
    /// Group names with this role.
    pub groups: Vec<String>,
    /// Claims granted by the role.
    pub claims: Vec<ClaimType<'a>>,
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
