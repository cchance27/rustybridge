//! Audit log hint for automatic tracing integration.
//!
//! When an `EventType` has a log hint, the `audit!()` macro will automatically
//! emit a corresponding `tracing` event in addition to persisting the audit.

/// Log level for audit-to-tracing integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditLogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// Hint for automatic tracing emission from audit events.
///
/// When an `EventType` returns `Some(AuditLogHint)` from `log_hint()`,
/// the `audit!()` macro will emit a corresponding `tracing` event.
#[derive(Debug, Clone, Copy)]
pub struct AuditLogHint {
    /// Log level to emit
    pub level: AuditLogLevel,
    /// Human-readable message template
    pub message: &'static str,
}

impl AuditLogHint {
    /// Create a new log hint with INFO level.
    pub const fn info(message: &'static str) -> Self {
        Self {
            level: AuditLogLevel::Info,
            message,
        }
    }

    /// Create a new log hint with WARN level.
    pub const fn warn(message: &'static str) -> Self {
        Self {
            level: AuditLogLevel::Warn,
            message,
        }
    }

    /// Create a new log hint with ERROR level.
    pub const fn error(message: &'static str) -> Self {
        Self {
            level: AuditLogLevel::Error,
            message,
        }
    }

    /// Create a new log hint with DEBUG level.
    pub const fn debug(message: &'static str) -> Self {
        Self {
            level: AuditLogLevel::Debug,
            message,
        }
    }

    /// Create a new log hint with TRACE level.
    pub const fn trace(message: &'static str) -> Self {
        Self {
            level: AuditLogLevel::Trace,
            message,
        }
    }
}
