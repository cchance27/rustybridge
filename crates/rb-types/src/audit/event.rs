//! Audit event type definitions and builders.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{AuditContext, EventCategory};
use crate::auth::ClaimType;

/// Authentication method used for login events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    Password,
    PublicKey,
    Oidc,
}

/// Client type for session events (SSH client vs Web browser).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum ClientType {
    #[default]
    Ssh,
    Web,
}


/// Specific audit event types with associated structured data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, strum::IntoStaticStr)]
#[serde(tag = "type", rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum EventType {
    // ==================== Authentication Events ====================
    /// Successful login event
    LoginSuccess {
        method: AuthMethod,
        connection_id: String,
        username: String,
        #[serde(default)]
        client_type: ClientType,
    },
    /// Failed login attempt
    LoginFailure {
        method: AuthMethod,
        reason: String,
        username: Option<String>,
        #[serde(default)]
        client_type: ClientType,
    },
    /// User logout or disconnection
    Logout {
        username: String,
        reason: String,
        #[serde(default)]
        client_type: ClientType,
    },

    // ==================== User Management Events ====================
    /// New user account created
    UserCreated { username: String },
    /// User account deleted
    UserDeleted { username: String, user_id: i64 },
    /// User password changed
    UserPasswordChanged { username: String, user_id: i64 },
    /// SSH public key added to user account
    UserSshKeyAdded {
        username: String,
        user_id: i64,
        key_id: i64,
        fingerprint: Option<String>,
    },
    /// SSH public key removed from user account
    UserSshKeyRemoved { username: String, user_id: i64, key_id: i64 },
    /// Direct claim added to user
    UserClaimAdded {
        username: String,
        user_id: i64,
        claim: ClaimType<'static>,
    },
    /// Direct claim removed from user
    UserClaimRemoved {
        username: String,
        user_id: i64,
        claim: ClaimType<'static>,
    },
    /// OIDC account linked to user
    OidcLinked {
        username: String,
        user_id: i64,
        provider: String,
        subject: String,
    },
    /// OIDC account unlinked from user
    OidcUnlinked { username: String, user_id: i64, provider: String },

    // ==================== Group Management Events ====================
    /// New group created
    GroupCreated { name: String },
    /// Group updated (renamed)
    GroupUpdated { group_id: i64, old_name: String, new_name: String },
    /// Group deleted
    GroupDeleted { name: String, group_id: i64 },
    /// User added to group
    UserAddedToGroup {
        username: String,
        user_id: i64,
        group_name: String,
        group_id: i64,
    },
    /// User removed from group
    UserRemovedFromGroup {
        username: String,
        user_id: i64,
        group_name: String,
        group_id: i64,
    },
    /// Claim added to group
    GroupClaimAdded {
        group_name: String,
        group_id: i64,
        claim: ClaimType<'static>,
    },
    /// Claim removed from group
    GroupClaimRemoved {
        group_name: String,
        group_id: i64,
        claim: ClaimType<'static>,
    },

    // ==================== Role Management Events (RBAC) ====================
    /// New role created
    RoleCreated { name: String, description: Option<String> },
    /// Role deleted
    RoleDeleted { name: String, role_id: i64 },
    /// Role assigned to user
    RoleAssignedToUser {
        role_name: String,
        role_id: i64,
        username: String,
        user_id: i64,
    },
    /// Role revoked from user
    RoleRevokedFromUser {
        role_name: String,
        role_id: i64,
        username: String,
        user_id: i64,
    },
    /// Role assigned to group
    RoleAssignedToGroup {
        role_name: String,
        role_id: i64,
        group_name: String,
        group_id: i64,
    },
    /// Role revoked from group
    RoleRevokedFromGroup {
        role_name: String,
        role_id: i64,
        group_name: String,
        group_id: i64,
    },
    /// Claim added to role
    RoleClaimAdded {
        role_name: String,
        role_id: i64,
        claim: ClaimType<'static>,
    },
    /// Claim removed from role
    RoleClaimRemoved {
        role_name: String,
        role_id: i64,
        claim: ClaimType<'static>,
    },

    // ==================== Relay Host Management Events ====================
    /// Relay host added to system
    RelayHostCreated { name: String, endpoint: String },
    /// Relay host deleted from system
    RelayHostDeleted { name: String, relay_id: i64, endpoint: String },
    /// Host key captured during relay host addition
    RelayHostKeyCaptured {
        name: String,
        relay_id: i64,
        key_type: String,
        fingerprint: String,
    },
    /// Relay host updated (name or endpoint change)
    RelayHostUpdated {
        relay_id: i64,
        old_name: String,
        new_name: String,
        old_endpoint: String,
        new_endpoint: String,
    },
    /// Host key refreshed for relay
    RelayHostKeyRefreshed { name: String, relay_id: i64 },
    /// Relay host option set or updated
    RelayOptionSet {
        relay_name: String,
        relay_id: i64,
        key: String,
        is_secure: bool,
    },
    /// Relay host option cleared
    RelayOptionCleared { relay_name: String, relay_id: i64, key: String },

    // ==================== Credential Management Events ====================
    /// New credential created
    CredentialCreated { name: String, kind: String },
    /// Credential updated
    CredentialUpdated { name: String, cred_id: i64, kind: String },
    /// Credential deleted
    CredentialDeleted { name: String, cred_id: i64, kind: String },
    /// Credential assigned to relay host
    CredentialAssigned {
        cred_name: String,
        cred_id: i64,
        relay_name: String,
        relay_id: i64,
    },
    /// Credential unassigned from relay host
    CredentialUnassigned { relay_name: String, relay_id: i64 },
    /// Secret rotated (v1 to v2 encryption)
    SecretRotated { resource_type: String, resource_id: String },

    // ==================== Access Control Events (ACL) ====================
    /// Access granted to relay host
    AccessGranted {
        relay_name: String,
        relay_id: i64,
        principal_kind: String,
        principal_name: String,
        principal_id: i64,
    },
    /// Access revoked from relay host
    AccessRevoked {
        relay_name: String,
        relay_id: i64,
        principal_kind: String,
        principal_name: String,
        principal_id: i64,
    },

    // ==================== Session Events ====================
    /// SSH session started
    SessionStarted {
        session_id: String,
        relay_name: String,
        relay_id: i64,
        username: String,
        #[serde(default)]
        client_type: ClientType,
    },
    /// SSH session ended
    SessionEnded {
        session_id: String,
        relay_name: String,
        relay_id: i64,
        username: String,
        duration_ms: i64,
        #[serde(default)]
        client_type: ClientType,
    },
    /// Session timed out after being detached
    SessionTimedOut {
        session_id: String,
        relay_name: String,
        relay_id: i64,
        username: String,
        duration_ms: i64,
        reason: String, // e.g., "detach_timeout" or "zombie_cleanup"
    },
    /// Session PTY resized
    SessionResized {
        session_id: String,
        relay_id: i64,
        cols: u32,
        rows: u32,
    },
    /// Relay connection established (web/ssh)
    SessionRelayConnected {
        session_id: String,
        relay_id: i64,
        relay_name: String,
        username: String,
        #[serde(default)]
        client_type: ClientType,
    },
    /// Relay connection closed (web/ssh)
    SessionRelayDisconnected {
        session_id: String,
        relay_id: i64,
        relay_name: String,
        username: String,
        #[serde(default)]
        client_type: ClientType,
    },
    /// Admin viewer added to session
    AdminViewerAdded {
        session_id: String,
        admin_username: String,
        admin_user_id: i64,
    },
    /// Admin viewer removed from session
    AdminViewerRemoved {
        session_id: String,
        admin_username: String,
        admin_user_id: i64,
    },
    /// User started actively viewing session terminal (not just connected)
    SessionViewerJoined {
        session_id: String,
        username: String,
        user_id: i64,
        is_admin: bool,
        #[serde(default)]
        client_type: ClientType,
    },
    /// User stopped actively viewing session terminal (minimized or disconnected)
    SessionViewerLeft {
        session_id: String,
        username: String,
        user_id: i64,
        is_admin: bool,
        duration_ms: i64,
        #[serde(default)]
        client_type: ClientType,
    },
    /// Session force-closed by admin
    SessionForceClosed {
        session_id: String,
        session_number: u32,
        relay_id: i64,
        relay_name: String,
        target_username: String,
        reason: String,
    },
    /// User transferred from TUI management session to relay connection
    SessionTransferToRelay {
        from_session_id: String,
        to_session_id: String,
        relay_name: String,
        relay_id: i64,
        username: String,
        #[serde(default)]
        client_type: ClientType,
    },

    // ==================== Configuration Events ====================
    /// Server host key generated or regenerated
    ServerHostKeyGenerated,
    /// OIDC configuration updated
    OidcConfigured { issuer: String },

    // ==================== System Events ====================
    /// Server started
    ServerStarted { version: String },
    /// Server stopped gracefully
    ServerStopped,
    /// Database migration applied
    DatabaseMigrated { database: String, version: String },
    /// Server settings updated (e.g., retention config)
    ServerSettingsUpdated { setting_name: String },
    /// Audit data cleaned per-table (retention policy applied)
    /// Logged for each table that had data deleted
    AuditTableCleaned {
        table_name: String,
        rows_deleted: u64,
        /// true = automated by background timer, false = admin-triggered
        is_automated: bool,
    },
    /// Audit table completely purged (manual admin action)
    AuditTablePurged { table_name: String, rows_deleted: u64 },
    /// Full retention cleanup run completed (summary event)
    AuditRetentionRun {
        #[serde(default)]
        total_deleted: u64,
        #[serde(default)]
        sessions_deleted: u64,
        #[serde(default)]
        client_sessions_deleted: u64,
        #[serde(default)]
        session_events_deleted: u64,
        #[serde(default)]
        orphan_events_deleted: u64,
        /// true = automated by background timer, false = admin-triggered
        #[serde(default)]
        is_automated: bool,
    },
    /// Database vacuumed to reclaim disk space
    DatabaseVacuumed {
        /// Which database: "audit" or "server"
        #[serde(default)]
        database: String,
        /// dbstat internal size before vacuum (KB)
        #[serde(default)]
        size_before_kb: u64,
        /// dbstat internal size after vacuum (KB)
        #[serde(default)]
        size_after_kb: u64,
        /// Actual on-disk file size before vacuum (KB)
        #[serde(default)]
        file_size_before_kb: u64,
        /// Actual on-disk file size after vacuum (KB)
        #[serde(default)]
        file_size_after_kb: u64,
    },
}

impl EventType {
    /// Returns the category this event type belongs to.
    pub fn category(&self) -> EventCategory {
        match self {
            EventType::LoginSuccess { .. } | EventType::LoginFailure { .. } | EventType::Logout { .. } => EventCategory::Authentication,
            EventType::UserCreated { .. }
            | EventType::UserDeleted { .. }
            | EventType::UserPasswordChanged { .. }
            | EventType::UserSshKeyAdded { .. }
            | EventType::UserSshKeyRemoved { .. }
            | EventType::UserClaimAdded { .. }
            | EventType::UserClaimRemoved { .. }
            | EventType::OidcLinked { .. }
            | EventType::OidcUnlinked { .. } => EventCategory::UserManagement,
            EventType::GroupCreated { .. }
            | EventType::GroupUpdated { .. }
            | EventType::GroupDeleted { .. }
            | EventType::UserAddedToGroup { .. }
            | EventType::UserRemovedFromGroup { .. }
            | EventType::GroupClaimAdded { .. }
            | EventType::GroupClaimRemoved { .. } => EventCategory::GroupManagement,
            EventType::RoleCreated { .. }
            | EventType::RoleDeleted { .. }
            | EventType::RoleAssignedToUser { .. }
            | EventType::RoleRevokedFromUser { .. }
            | EventType::RoleAssignedToGroup { .. }
            | EventType::RoleRevokedFromGroup { .. }
            | EventType::RoleClaimAdded { .. }
            | EventType::RoleClaimRemoved { .. } => EventCategory::RoleManagement,
            EventType::RelayHostCreated { .. }
            | EventType::RelayHostDeleted { .. }
            | EventType::RelayHostKeyCaptured { .. }
            | EventType::RelayHostUpdated { .. }
            | EventType::RelayHostKeyRefreshed { .. }
            | EventType::RelayOptionSet { .. }
            | EventType::RelayOptionCleared { .. } => EventCategory::RelayManagement,
            EventType::CredentialCreated { .. }
            | EventType::CredentialUpdated { .. }
            | EventType::CredentialDeleted { .. }
            | EventType::CredentialAssigned { .. }
            | EventType::CredentialUnassigned { .. }
            | EventType::SecretRotated { .. } => EventCategory::CredentialManagement,
            EventType::AccessGranted { .. } | EventType::AccessRevoked { .. } => EventCategory::AccessControl,
            EventType::SessionStarted { .. }
            | EventType::SessionEnded { .. }
            | EventType::SessionTimedOut { .. }
            | EventType::SessionResized { .. }
            | EventType::SessionRelayConnected { .. }
            | EventType::SessionRelayDisconnected { .. }
            | EventType::AdminViewerAdded { .. }
            | EventType::AdminViewerRemoved { .. }
            | EventType::SessionViewerJoined { .. }
            | EventType::SessionViewerLeft { .. }
            | EventType::SessionForceClosed { .. }
            | EventType::SessionTransferToRelay { .. } => EventCategory::Session,
            EventType::ServerHostKeyGenerated | EventType::OidcConfigured { .. } => EventCategory::Configuration,
            EventType::ServerStarted { .. }
            | EventType::ServerStopped
            | EventType::DatabaseMigrated { .. }
            | EventType::ServerSettingsUpdated { .. }
            | EventType::AuditTableCleaned { .. }
            | EventType::AuditTablePurged { .. }
            | EventType::AuditRetentionRun { .. }
            | EventType::DatabaseVacuumed { .. } => EventCategory::System,
        }
    }

    /// Returns a short action type string for database indexing.
    /// This is the discriminant name (e.g., "user_created").
    pub fn action_type(&self) -> &'static str {
        self.into()
    }
}

/// Complete audit event record ready for persistence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditEvent {
    /// Unique event identifier (UUIDv7)
    pub id: String,
    /// Unix timestamp in milliseconds
    pub timestamp: i64,
    /// User ID who performed the action (None for system events)
    pub actor_id: Option<i64>,
    /// Event category for grouping
    pub category: EventCategory,
    /// Specific event type with structured data
    pub event_type: EventType,
    /// Generic resource identifier (for filtering)
    pub resource_id: Option<String>,
    /// Actor's IP address if available
    pub ip_address: Option<String>,
    /// Associated session/connection ID if applicable
    pub session_id: Option<String>,
    /// Parent session ID (e.g. Axum session for web events)
    pub parent_session_id: Option<String>,
}

impl AuditEvent {
    /// Create a new audit event with automatic ID and timestamp generation.
    pub fn new(actor_id: Option<i64>, event_type: EventType) -> Self {
        let category = event_type.category();
        Self {
            id: Uuid::now_v7().to_string(),
            timestamp: Utc::now().timestamp_millis(),
            actor_id,
            category,
            event_type,
            resource_id: None,
            ip_address: None,
            session_id: None,
            parent_session_id: None,
        }
    }

    /// Create a new audit event from a context (RECOMMENDED).
    ///
    /// This is the preferred way to create events as it ensures all context
    /// information (IP, session, actor) is properly captured.
    pub fn from_context(ctx: &AuditContext, event_type: EventType) -> Self {
        let category = event_type.category();
        Self {
            id: Uuid::now_v7().to_string(),
            timestamp: Utc::now().timestamp_millis(),
            actor_id: ctx.actor_id(),
            category,
            event_type,
            resource_id: None,
            ip_address: ctx.ip_address().map(|s| s.to_string()),
            session_id: ctx.session_id().map(|s| s.to_string()),
            parent_session_id: ctx.parent_session_id().map(|s| s.to_string()),
        }
    }

    /// Builder: Set the resource ID for this event.
    pub fn with_resource_id(mut self, resource_id: impl Into<String>) -> Self {
        self.resource_id = Some(resource_id.into());
        self
    }

    /// Builder: Set the IP address for this event.
    pub fn with_ip_address(mut self, ip_address: impl Into<String>) -> Self {
        self.ip_address = Some(ip_address.into());
        self
    }

    /// Builder: Set the session ID for this event.
    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Builder: Set the parent session ID for this event.
    pub fn with_parent_session_id(mut self, parent_session_id: impl Into<String>) -> Self {
        self.parent_session_id = Some(parent_session_id.into());
        self
    }
}
