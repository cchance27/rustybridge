//! Platform-aware logging initialization.
//!
//! This module provides unified logging setup for both WASM (browser) and
//! server builds. For WASM, it routes `tracing` events to the browser console.

use std::sync::Once;

static INIT: Once = Once::new();

/// Initialize logging for the current platform.
///
/// For web builds, this sets up a tracing subscriber that routes to browser console.
/// For server builds, this is a no-op (server logging is configured in rb-cli).
///
/// This function is idempotent - it can be called multiple times but will only
/// initialize once.
pub fn init() {
    INIT.call_once(|| {
        #[cfg(feature = "web")]
        init_web_logging();
    });
}

#[cfg(feature = "web")]
static RELOAD_HANDLE: std::sync::OnceLock<
    tracing_subscriber::reload::Handle<tracing_subscriber::filter::LevelFilter, tracing_subscriber::Registry>,
> = std::sync::OnceLock::new();

#[cfg(feature = "web")]
fn init_web_logging() {
    console_error_panic_hook::set_once();
    use tracing_subscriber::{filter::LevelFilter, prelude::*};
    use tracing_web::MakeWebConsoleWriter;

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_writer(MakeWebConsoleWriter::new())
        .without_time(); // WASM doesn't have std::time

    // Default to WARN for web unless overridden
    let initial_level = get_stored_log_level().unwrap_or(LevelFilter::WARN);

    let (filter, handle) = tracing_subscriber::reload::Layer::new(initial_level);
    let _ = RELOAD_HANDLE.set(handle);

    tracing_subscriber::registry().with(filter).with(fmt_layer).init();
}

#[cfg(feature = "web")]
fn get_stored_log_level() -> Option<tracing::level_filters::LevelFilter> {
    let window = web_sys::window()?;
    let storage = window.local_storage().ok()??;
    let level_str = storage.get_item("rb_web_log_level").ok()??;

    match level_str.as_str() {
        "error" => Some(tracing::level_filters::LevelFilter::ERROR),
        "warn" => Some(tracing::level_filters::LevelFilter::WARN),
        "info" => Some(tracing::level_filters::LevelFilter::INFO),
        "debug" => Some(tracing::level_filters::LevelFilter::DEBUG),
        "trace" => Some(tracing::level_filters::LevelFilter::TRACE),
        _ => None,
    }
}

pub fn set_log_level(_level: tracing::level_filters::LevelFilter) {
    #[cfg(feature = "web")]
    {
        // Use the variable (remove underscore for local usage if needed, or just use it with underscore)
        let level = _level;
        if let Some(handle) = RELOAD_HANDLE.get() {
            let _ = handle.reload(level);
        }

        // Persist to local storage
        if let Some(window) = web_sys::window() {
            if let Ok(Some(storage)) = window.local_storage() {
                let level_str = match level {
                    tracing::level_filters::LevelFilter::ERROR => "error",
                    tracing::level_filters::LevelFilter::WARN => "warn",
                    tracing::level_filters::LevelFilter::INFO => "info",
                    tracing::level_filters::LevelFilter::DEBUG => "debug",
                    tracing::level_filters::LevelFilter::TRACE => "trace",
                    _ => "warn",
                };
                let _ = storage.set_item("rb_web_log_level", level_str);
            }
        }
    }
}

pub fn get_log_level() -> tracing::level_filters::LevelFilter {
    #[cfg(feature = "web")]
    return get_stored_log_level().unwrap_or(tracing::level_filters::LevelFilter::WARN);

    #[cfg(not(feature = "web"))]
    return tracing::level_filters::LevelFilter::INFO;
}
