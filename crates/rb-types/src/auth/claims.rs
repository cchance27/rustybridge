use std::{borrow::Cow, fmt, str::FromStr};

use serde::{Deserialize, Serialize};

pub const ATTACH_ANY_STR: &str = "server:attach_any";
pub const ATTACH_ANY_CLAIM: ClaimType<'static> = ClaimType::Custom(Cow::Borrowed(ATTACH_ANY_STR));

/// CRUD-like claim levels applied to resource types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ClaimLevel {
    Create,
    View,
    Edit,
    Delete,
    Wildcard,
}

impl fmt::Display for ClaimLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClaimLevel::Create => write!(f, "create"),
            ClaimLevel::View => write!(f, "view"),
            ClaimLevel::Edit => write!(f, "edit"),
            ClaimLevel::Delete => write!(f, "delete"),
            ClaimLevel::Wildcard => write!(f, "*"),
        }
    }
}

impl ClaimLevel {
    fn as_str(&self) -> &'static str {
        match self {
            ClaimLevel::Create => "create",
            ClaimLevel::View => "view",
            ClaimLevel::Edit => "edit",
            ClaimLevel::Delete => "delete",
            ClaimLevel::Wildcard => "*",
        }
    }
}

impl FromStr for ClaimLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "create" => Ok(ClaimLevel::Create),
            "view" => Ok(ClaimLevel::View),
            "edit" => Ok(ClaimLevel::Edit),
            "delete" => Ok(ClaimLevel::Delete),
            "*" => Ok(ClaimLevel::Wildcard),
            _ => Err(format!("Invalid claim level: {}", s)),
        }
    }
}

/// Claim kinds the RBAC system understands; serialized as `type:level`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(tag = "type", content = "level", rename_all = "lowercase")]
pub enum ClaimType<'a> {
    Relays(ClaimLevel),
    Users(ClaimLevel),
    Groups(ClaimLevel),
    Roles(ClaimLevel),
    Credentials(ClaimLevel),
    Server(ClaimLevel),
    // Fallback for unknown claims to preserve data
    Custom(Cow<'a, str>),
}

impl<'a> fmt::Display for ClaimType<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClaimType::Relays(level) => write!(f, "relays:{}", level),
            ClaimType::Users(level) => write!(f, "users:{}", level),
            ClaimType::Groups(level) => write!(f, "groups:{}", level),
            ClaimType::Roles(level) => write!(f, "roles:{}", level),
            ClaimType::Credentials(level) => write!(f, "credentials:{}", level),
            ClaimType::Server(level) => write!(f, "server:{}", level),
            ClaimType::Custom(s) => write!(f, "{}", s),
        }
    }
}

impl<'a> FromStr for ClaimType<'a> {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Ok(ClaimType::Custom(Cow::Owned(s.to_string())));
        }

        // Try to parse as a standard claim
        let level_result = ClaimLevel::from_str(parts[1]);

        match (parts[0].to_lowercase().as_str(), level_result) {
            ("relays", Ok(level)) => Ok(ClaimType::Relays(level)),
            ("users", Ok(level)) => Ok(ClaimType::Users(level)),
            ("groups", Ok(level)) => Ok(ClaimType::Groups(level)),
            ("roles", Ok(level)) => Ok(ClaimType::Roles(level)),
            ("credentials", Ok(level)) => Ok(ClaimType::Credentials(level)),
            ("server", Ok(level)) => Ok(ClaimType::Server(level)),
            // If it looks like a standard claim but has an invalid level, or is an unknown prefix, treat as custom
            _ => Ok(ClaimType::Custom(Cow::Owned(s.to_string()))),
        }
    }
}

// Allow comparing ClaimType with string slices
impl<'a> PartialEq<str> for ClaimType<'a> {
    fn eq(&self, other: &str) -> bool {
        self.eq_str(other)
    }
}

impl<'a> PartialEq<&str> for ClaimType<'a> {
    fn eq(&self, other: &&str) -> bool {
        self.eq_str(other)
    }
}

impl<'a> PartialEq<ClaimType<'a>> for str {
    fn eq(&self, other: &ClaimType<'a>) -> bool {
        other.eq_str(self)
    }
}

impl<'a> PartialEq<ClaimType<'a>> for &str {
    fn eq(&self, other: &ClaimType<'a>) -> bool {
        other.eq_str(self)
    }
}

impl<'a> ClaimType<'a> {
    fn eq_str(&self, other: &str) -> bool {
        match self {
            ClaimType::Custom(value) => value == other,
            ClaimType::Relays(level) => ClaimType::compare_parts("relays", level, other),
            ClaimType::Users(level) => ClaimType::compare_parts("users", level, other),
            ClaimType::Groups(level) => ClaimType::compare_parts("groups", level, other),
            ClaimType::Roles(level) => ClaimType::compare_parts("roles", level, other),
            ClaimType::Credentials(level) => ClaimType::compare_parts("credentials", level, other),
            ClaimType::Server(level) => ClaimType::compare_parts("server", level, other),
        }
    }

    fn compare_parts(prefix: &'static str, level: &ClaimLevel, other: &str) -> bool {
        let mut parts = other.splitn(2, ':');
        match (parts.next(), parts.next()) {
            (Some(left), Some(right)) => left == prefix && right == level.as_str(),
            _ => false,
        }
    }

    /// Check if this claim satisfies a required claim.
    /// Handles wildcard levels and claim hierarchies.
    ///
    /// Examples:
    /// - `relays:*` satisfies `relays:view`, `relays:edit`, etc.
    /// - `relays:delete` satisfies `relays:view` and `relays:edit`
    /// - `relays:edit` satisfies `relays:view`
    pub fn satisfies(&self, required: &ClaimType) -> bool {
        match (self, required) {
            // Exact match always satisfies
            (a, b) if a == b => true,

            // Wildcard level satisfies any level for the same resource type
            (ClaimType::Relays(ClaimLevel::Wildcard), ClaimType::Relays(_)) => true,
            (ClaimType::Users(ClaimLevel::Wildcard), ClaimType::Users(_)) => true,
            (ClaimType::Groups(ClaimLevel::Wildcard), ClaimType::Groups(_)) => true,
            (ClaimType::Roles(ClaimLevel::Wildcard), ClaimType::Roles(_)) => true,
            (ClaimType::Credentials(ClaimLevel::Wildcard), ClaimType::Credentials(_)) => true,
            (ClaimType::Server(ClaimLevel::Wildcard), ClaimType::Server(_)) => true,

            // Check level hierarchy for same resource type
            (ClaimType::Relays(have), ClaimType::Relays(need)) => Self::level_satisfies(have, need),
            (ClaimType::Users(have), ClaimType::Users(need)) => Self::level_satisfies(have, need),
            (ClaimType::Groups(have), ClaimType::Groups(need)) => Self::level_satisfies(have, need),
            (ClaimType::Roles(have), ClaimType::Roles(need)) => Self::level_satisfies(have, need),
            (ClaimType::Credentials(have), ClaimType::Credentials(need)) => Self::level_satisfies(have, need),
            (ClaimType::Server(have), ClaimType::Server(need)) => Self::level_satisfies(have, need),

            // Different resource types or custom claims don't satisfy each other
            _ => false,
        }
    }

    /// Check if a claim level satisfies a required level based on hierarchy.
    /// Hierarchy: Delete > Edit > View, Create stands alone
    fn level_satisfies(have: &ClaimLevel, need: &ClaimLevel) -> bool {
        match (have, need) {
            // Wildcard satisfies everything
            (ClaimLevel::Wildcard, _) => true,
            // Delete satisfies Edit and View
            (ClaimLevel::Delete, ClaimLevel::Edit) => true,
            (ClaimLevel::Delete, ClaimLevel::View) => true,
            // Edit satisfies View
            (ClaimLevel::Edit, ClaimLevel::View) => true,
            // Otherwise, must be exact match
            (a, b) => a == b,
        }
    }

    pub fn all_variants() -> Vec<ClaimType<'static>> {
        let levels = vec![ClaimLevel::View, ClaimLevel::Edit, ClaimLevel::Delete, ClaimLevel::Create];
        let mut claims = Vec::new();

        for level in &levels {
            claims.push(ClaimType::Relays(*level));
        }
        for level in &levels {
            claims.push(ClaimType::Users(*level));
        }
        for level in &levels {
            claims.push(ClaimType::Groups(*level));
        }
        for level in &levels {
            claims.push(ClaimType::Roles(*level));
        }
        for level in &levels {
            claims.push(ClaimType::Credentials(*level));
        }
        for level in &levels {
            claims.push(ClaimType::Server(*level));
        }
        claims.push(ATTACH_ANY_CLAIM);
        claims
    }
}

#[cfg(test)]
#[path = "claims_tests.rs"]
mod tests;
