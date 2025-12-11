//! Audit logging macro with automatic tracing integration.
//!
//! The `audit!` macro logs events to the audit database and optionally
//! emits a `tracing` event based on the event type's `log_hint()`.

/// Log an audit event using the provided context.
///
/// This macro:
/// 1. Creates the event type with the provided fields
/// 2. If the event has a `log_hint()`, emits a corresponding `tracing` event
/// 3. Persists the event to the audit database
///
/// # Usage
/// ```ignore
/// audit!(ctx, UserCreated { username });
/// audit!(ctx, ServerStopped);
/// ```
#[macro_export]
macro_rules! audit {
    ($ctx:expr, $variant:ident { $($field:ident $(: $value:expr)?),* $(,)? }) => {{
        use rb_types::audit::AuditLogLevel;
        use tracing::{trace, debug, info, warn, error};

        let event_type = rb_types::audit::EventType::$variant {
            $($field $(: $value)?),*
        };

        // Emit tracing event if log hint is present
        if let Some(hint) = event_type.log_hint() {
            let action = event_type.action_type();
            match hint.level {
                AuditLogLevel::Trace => {
                    trace!(audit_action = action, context = %$ctx, "{}", hint.message);
                }
                AuditLogLevel::Debug => {
                    debug!(audit_action = action, context = %$ctx, "{}", hint.message);
                }
                AuditLogLevel::Info => {
                    info!(audit_action = action, context = %$ctx, "{}", hint.message);
                }
                AuditLogLevel::Warn => {
                    warn!(audit_action = action, context = %$ctx, "{}", hint.message);
                }
                AuditLogLevel::Error => {
                    error!(audit_action = action, context = %$ctx, "{}", hint.message);
                }
            }
        }

        // Persist to audit database
        $crate::audit::log_event_from_context_best_effort($ctx, event_type).await
    }};
    // Support for unit variants (e.g., ServerStopped)
    ($ctx:expr, $variant:ident) => {{
        use rb_types::audit::AuditLogLevel;
        use tracing::{trace, debug, info, warn, error};

        let event_type = rb_types::audit::EventType::$variant;

        // Emit tracing event if log hint is present
        if let Some(hint) = event_type.log_hint() {
            let action = event_type.action_type();
            match hint.level {
                AuditLogLevel::Trace => {
                    trace!(audit_action = action, context = %$ctx, "{}", hint.message);
                }
                AuditLogLevel::Debug => {
                    debug!(audit_action = action, context = %$ctx, "{}", hint.message);
                }
                AuditLogLevel::Info => {
                    info!(audit_action = action, context = %$ctx, "{}", hint.message);
                }
                AuditLogLevel::Warn => {
                    warn!(audit_action = action, context = %$ctx, "{}", hint.message);
                }
                AuditLogLevel::Error => {
                    error!(audit_action = action, context = %$ctx, "{}", hint.message);
                }
            }
        }

        // Persist to audit database
        $crate::audit::log_event_from_context_best_effort($ctx, event_type).await
    }};
}
