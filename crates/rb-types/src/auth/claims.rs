use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(tag = "type", content = "level", rename_all = "lowercase")]
pub enum ClaimType {
    Relays(ClaimLevel),
    Users(ClaimLevel),
    Groups(ClaimLevel),
    Credentials(ClaimLevel),
    Wildcard(ClaimLevel),
    // Fallback for unknown claims to preserve data
    Custom(String),
}

impl fmt::Display for ClaimType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClaimType::Relays(level) => write!(f, "relays:{}", level),
            ClaimType::Users(level) => write!(f, "users:{}", level),
            ClaimType::Groups(level) => write!(f, "groups:{}", level),
            ClaimType::Credentials(level) => write!(f, "credentials:{}", level),
            ClaimType::Wildcard(level) => write!(f, "*:{}", level),
            ClaimType::Custom(s) => write!(f, "{}", s),
        }
    }
}

impl FromStr for ClaimType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Ok(ClaimType::Custom(s.to_string()));
        }

        // Try to parse as a standard claim
        let level_result = ClaimLevel::from_str(parts[1]);

        match (parts[0].to_lowercase().as_str(), level_result) {
            ("relays", Ok(level)) => Ok(ClaimType::Relays(level)),
            ("users", Ok(level)) => Ok(ClaimType::Users(level)),
            ("groups", Ok(level)) => Ok(ClaimType::Groups(level)),
            ("credentials", Ok(level)) => Ok(ClaimType::Credentials(level)),
            ("*", Ok(level)) => Ok(ClaimType::Wildcard(level)),
            // If it looks like a standard claim but has an invalid level, or is an unknown prefix, treat as custom
            _ => Ok(ClaimType::Custom(s.to_string())),
        }
    }
}

// Allow comparing ClaimType with string slices
impl PartialEq<str> for ClaimType {
    fn eq(&self, other: &str) -> bool {
        self.eq_str(other)
    }
}

impl PartialEq<&str> for ClaimType {
    fn eq(&self, other: &&str) -> bool {
        self.eq_str(other)
    }
}

impl PartialEq<ClaimType> for str {
    fn eq(&self, other: &ClaimType) -> bool {
        other.eq_str(self)
    }
}

impl PartialEq<ClaimType> for &str {
    fn eq(&self, other: &ClaimType) -> bool {
        other.eq_str(self)
    }
}

impl ClaimType {
    fn eq_str(&self, other: &str) -> bool {
        match self {
            ClaimType::Custom(value) => value == other,
            ClaimType::Relays(level) => ClaimType::compare_parts("relays", level, other),
            ClaimType::Users(level) => ClaimType::compare_parts("users", level, other),
            ClaimType::Groups(level) => ClaimType::compare_parts("groups", level, other),
            ClaimType::Credentials(level) => ClaimType::compare_parts("credentials", level, other),
            ClaimType::Wildcard(level) => ClaimType::compare_parts("*", level, other),
        }
    }

    fn compare_parts(prefix: &'static str, level: &ClaimLevel, other: &str) -> bool {
        let mut parts = other.splitn(2, ':');
        match (parts.next(), parts.next()) {
            (Some(left), Some(right)) => left == prefix && right == level.as_str(),
            _ => false,
        }
    }

    pub fn all_variants() -> Vec<ClaimType> {
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
            claims.push(ClaimType::Credentials(*level));
        }
        for level in &levels {
            claims.push(ClaimType::Wildcard(*level));
        }

        claims
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claim_string_representation() {
        // Test Display
        assert_eq!(ClaimType::Relays(ClaimLevel::View).to_string(), "relays:view");
        assert_eq!(ClaimType::Users(ClaimLevel::Edit).to_string(), "users:edit");
        assert_eq!(ClaimType::Groups(ClaimLevel::Delete).to_string(), "groups:delete");
        assert_eq!(ClaimType::Custom("custom:claim".to_string()).to_string(), "custom:claim");

        // Test FromStr
        assert_eq!(ClaimType::from_str("relays:view").unwrap(), ClaimType::Relays(ClaimLevel::View));
        assert_eq!(ClaimType::from_str("users:edit").unwrap(), ClaimType::Users(ClaimLevel::Edit));
        assert_eq!(ClaimType::from_str("groups:delete").unwrap(), ClaimType::Groups(ClaimLevel::Delete));
        assert_eq!(
            ClaimType::from_str("custom:claim").unwrap(),
            ClaimType::Custom("custom:claim".to_string())
        );

        // Test Wildcards
        assert_eq!(ClaimType::Relays(ClaimLevel::Wildcard).to_string(), "relays:*");
        assert_eq!(ClaimType::Wildcard(ClaimLevel::View).to_string(), "*:view");
        assert_eq!(ClaimType::Wildcard(ClaimLevel::Wildcard).to_string(), "*:*");

        assert_eq!(ClaimType::from_str("relays:*").unwrap(), ClaimType::Relays(ClaimLevel::Wildcard));
        assert_eq!(ClaimType::from_str("*:view").unwrap(), ClaimType::Wildcard(ClaimLevel::View));
        assert_eq!(ClaimType::from_str("*:*").unwrap(), ClaimType::Wildcard(ClaimLevel::Wildcard));

        // Test case insensitivity
        assert_eq!(ClaimType::from_str("RELAYS:VIEW").unwrap(), ClaimType::Relays(ClaimLevel::View));
    }

    #[test]
    fn test_claim_string_comparison() {
        // Test ClaimType == &str
        assert!(ClaimType::Custom("*".to_string()) == "*");
        assert!(ClaimType::Relays(ClaimLevel::View) == "relays:view");
        assert!(ClaimType::Wildcard(ClaimLevel::Wildcard) == "*:*");

        // Test &str == ClaimType
        assert!("*" == ClaimType::Custom("*".to_string()));
        assert!("users:edit" == ClaimType::Users(ClaimLevel::Edit));

        // Test inequality
        assert!(ClaimType::Relays(ClaimLevel::View) != "relays:edit");
        assert!("users:view" != ClaimType::Users(ClaimLevel::Edit));
    }
}
