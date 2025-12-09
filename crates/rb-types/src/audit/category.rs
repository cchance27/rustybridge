//! Event categories for high-level grouping of audit events.

use serde::{Deserialize, Serialize};

/// High-level category for grouping related audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventCategory {
    /// Authentication events (login, logout, failures)
    Authentication,
    /// Authorization events (permission checks, claim grants)
    Authorization,
    /// User lifecycle and management operations
    UserManagement,
    /// Group lifecycle and membership operations
    GroupManagement,
    /// Role-based access control operations
    RoleManagement,
    /// Relay host lifecycle and configuration
    RelayManagement,
    /// Credential lifecycle and assignments
    CredentialManagement,
    /// Access control list operations
    AccessControl,
    /// Session lifecycle and recording
    Session,
    /// System configuration changes
    Configuration,
    /// System-level events (startup, shutdown, migrations)
    System,
}

impl EventCategory {
    /// Returns the string representation of the category.
    pub fn as_str(&self) -> &'static str {
        match self {
            EventCategory::Authentication => "authentication",
            EventCategory::Authorization => "authorization",
            EventCategory::UserManagement => "user_management",
            EventCategory::GroupManagement => "group_management",
            EventCategory::RoleManagement => "role_management",
            EventCategory::RelayManagement => "relay_management",
            EventCategory::CredentialManagement => "credential_management",
            EventCategory::AccessControl => "access_control",
            EventCategory::Session => "session",
            EventCategory::Configuration => "configuration",
            EventCategory::System => "system",
        }
    }
}

impl std::fmt::Display for EventCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
