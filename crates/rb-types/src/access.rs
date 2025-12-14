//! Access control and principal-related types.
use crate::auth::ClaimType;
use serde::{Deserialize, Serialize};
use std::{fmt::Display, str::FromStr};

/// Distinguishes whether an ACL principal represents a user, group, or other kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrincipalKind {
    User,
    Group,
    Other,
}

impl FromStr for PrincipalKind {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user" => Ok(PrincipalKind::User),
            "group" => Ok(PrincipalKind::Group),
            "other" => Ok(PrincipalKind::Other),
            _ => Err(()),
        }
    }
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
        write!(f, "{}", self.as_str())
    }
}

/// Principal entry stored on a relay ACL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayAclPrincipal {
    /// Principal category: user, group, or other.
    pub kind: PrincipalKind,
    pub id: i64,
    /// Principal identifier (username or group name).
    pub name: String,
}

/// Principal visible in relay access listings (post-resolution).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayAccessPrincipal {
    /// Principal category: user, group, or other.
    pub kind: PrincipalKind,
    pub id: i64,
    /// Principal identifier (username or group name).
    pub name: String,
}

/// Relay access info for a user.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UserRelayAccess {
    /// Name of the relay (e.g., "production-server").
    pub relay_name: String,
    /// Endpoint in `host:port` form (e.g., `192.168.1.10:22`).
    pub relay_endpoint: String,
    /// How the user is authorized to access this relay.
    pub access_source: RelayAccessSource,
}

/// How a user has access to a relay.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum RelayAccessSource {
    /// Direct ACL entry for the user.
    Direct,
    /// Access inherited from the given group name.
    ViaGroup(String),
    /// User has both direct ACL and group inheritance from the given group.
    Both(String),
}

/// Request to grant relay access.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GrantAccessRequest {
    /// Principal kind string: "user" or "group".
    pub principal_kind: String,
    /// Principal identifier (username or group name).
    pub principal_id: i64,
}

/// Role/group claims listing for web UIs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GroupClaims<'a> {
    /// Group name.
    pub group: String,
    /// Claims assigned to the group.
    pub claims: Vec<ClaimType<'a>>,
}
