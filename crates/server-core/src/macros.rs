/// Log an audit event using the provided context.
///
/// Usage:
/// ```ignore
/// audit!(ctx, UserCreated { username });
/// ```
#[macro_export]
macro_rules! audit {
    ($ctx:expr, $variant:ident { $($field:ident $(: $value:expr)?),* $(,)? }) => {
        $crate::audit::log_event_from_context_best_effort(
            $ctx,
            rb_types::audit::EventType::$variant {
                $($field $(: $value)?),*
            }
        ).await
    };
    // Support for unit variants
    ($ctx:expr, $variant:ident) => {
        $crate::audit::log_event_from_context_best_effort(
            $ctx,
            rb_types::audit::EventType::$variant
        ).await
    };
}
