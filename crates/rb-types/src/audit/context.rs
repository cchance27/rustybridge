//! Audit context for tracking who/what/where/when of operations.

use serde::{Deserialize, Serialize};

/// Source of an operation for audit tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "source_type", rename_all = "snake_case")]
pub enum AuditContext {
    /// Operation performed via web interface
    Web {
        /// User ID performing the action
        user_id: i64,
        /// Username for display
        username: String,
        /// IP address of the web client
        ip_address: String,
        /// Web session ID (e.g. specific tab/connection)
        session_id: String,
        /// Parent session ID (e.g. Axum cookie session)
        parent_session_id: Option<String>,
    },
    /// Operation performed via SSH/TUI session
    Ssh {
        /// User ID performing the action
        user_id: i64,
        /// Username for display
        username: String,
        /// IP address of SSH client
        ip_address: String,
        /// Logical Session ID (e.g. ssh_session_{n})
        session_id: String,
        /// Parent Session ID (Connection UUID)
        parent_session_id: Option<String>,
    },
    /// Operation performed via server CLI (local admin)
    ServerCli {
        /// Optional user context if running as specific user
        user_id: Option<i64>,
        /// Hostname where CLI was executed
        hostname: String,
        /// Process ID for tracking
        pid: u32,
    },
    /// System-initiated operation (migrations, automated tasks)
    System {
        /// Description of what initiated this
        initiator: String,
        /// Process ID if applicable
        pid: Option<u32>,
    },
}

impl AuditContext {
    /// Create a web context.
    pub fn web(
        user_id: i64,
        username: impl Into<String>,
        ip_address: impl Into<String>,
        session_id: impl Into<String>,
        parent_session_id: Option<String>,
    ) -> Self {
        Self::Web {
            user_id,
            username: username.into(),
            ip_address: ip_address.into(),
            session_id: session_id.into(),
            parent_session_id,
        }
    }

    /// Create an SSH context.
    pub fn ssh(
        user_id: i64,
        username: impl Into<String>,
        ip_address: impl Into<String>,
        session_id: impl Into<String>,
        parent_session_id: Option<String>,
    ) -> Self {
        Self::Ssh {
            user_id,
            username: username.into(),
            ip_address: ip_address.into(),
            session_id: session_id.into(),
            parent_session_id,
        }
    }

    /// Create a server CLI context.
    pub fn server_cli(user_id: Option<i64>, hostname: impl Into<String>) -> Self {
        Self::ServerCli {
            user_id,
            hostname: hostname.into(),
            pid: std::process::id(),
        }
    }

    /// Create a system context.
    pub fn system(initiator: impl Into<String>) -> Self {
        Self::System {
            initiator: initiator.into(),
            pid: Some(std::process::id()),
        }
    }

    /// Get the actor user ID if this context has one.
    pub fn actor_id(&self) -> Option<i64> {
        match self {
            AuditContext::Web { user_id, .. } => Some(*user_id),
            AuditContext::Ssh { user_id, .. } => Some(*user_id),
            AuditContext::ServerCli { user_id, .. } => *user_id,
            AuditContext::System { .. } => None,
        }
    }

    /// Get the username if available.
    pub fn username(&self) -> Option<&str> {
        match self {
            AuditContext::Web { username, .. } => Some(username),
            AuditContext::Ssh { username, .. } => Some(username),
            AuditContext::ServerCli { .. } => None,
            AuditContext::System { .. } => None,
        }
    }

    /// Get the IP address if applicable.
    pub fn ip_address(&self) -> Option<&str> {
        match self {
            AuditContext::Web { ip_address, .. } => Some(ip_address),
            AuditContext::Ssh { ip_address, .. } => Some(ip_address),
            AuditContext::ServerCli { .. } => None,
            AuditContext::System { .. } => None,
        }
    }

    /// Get the session/connection ID if applicable.
    pub fn session_id(&self) -> Option<&str> {
        match self {
            AuditContext::Web { session_id, .. } => Some(session_id),
            AuditContext::Ssh { session_id, .. } => Some(session_id),
            AuditContext::ServerCli { .. } => None,
            AuditContext::System { .. } => None,
        }
    }

    /// Get the parent session ID if applicable.
    pub fn parent_session_id(&self) -> Option<&str> {
        match self {
            AuditContext::Web { parent_session_id, .. } => parent_session_id.as_deref(),
            AuditContext::Ssh { parent_session_id, .. } => parent_session_id.as_deref(),
            AuditContext::ServerCli { .. } => None,
            AuditContext::System { .. } => None,
        }
    }

    /// Get a human-readable description of the context.
    pub fn description(&self) -> String {
        match self {
            AuditContext::Web { username, ip_address, .. } => {
                format!("web:{} from {}", username, ip_address)
            }
            AuditContext::Ssh { username, ip_address, .. } => {
                format!("ssh:{} from {}", username, ip_address)
            }
            AuditContext::ServerCli { hostname, .. } => {
                format!("cli:{}", hostname)
            }
            AuditContext::System { initiator, .. } => {
                format!("system:{}", initiator)
            }
        }
    }

    /// Check if this is a system context (no user).
    pub fn is_system(&self) -> bool {
        matches!(self, AuditContext::System { .. })
    }

    /// Check if this is a user-initiated context.
    pub fn is_user_initiated(&self) -> bool {
        self.actor_id().is_some()
    }
}

impl std::fmt::Display for AuditContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}
