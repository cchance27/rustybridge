use std::sync::atomic::{AtomicI32, Ordering};

use once_cell::sync::OnceCell;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{EnvFilter, Registry, reload};

static RELOAD: OnceCell<reload::Handle<EnvFilter, Registry>> = OnceCell::new();
static BASE_FILTER: OnceCell<String> = OnceCell::new();
static CURRENT_IDX: AtomicI32 = AtomicI32::new(2); // 0=error,1=warn,2=info,3=debug,4=trace

const LEVELS: [LevelFilter; 5] = [
    LevelFilter::ERROR,
    LevelFilter::WARN,
    LevelFilter::INFO,
    LevelFilter::DEBUG,
    LevelFilter::TRACE,
];

pub fn set_reload_handle(handle: reload::Handle<EnvFilter, Registry>, initial: LevelFilter, base_filter: String) {
    let _ = RELOAD.set(handle);
    let _ = BASE_FILTER.set(base_filter);
    let idx = level_to_idx(initial);
    CURRENT_IDX.store(idx, Ordering::Relaxed);
}

pub fn increase_verbosity() -> Option<LevelFilter> {
    adjust_by(1)
}

pub fn decrease_verbosity() -> Option<LevelFilter> {
    adjust_by(-1)
}

fn adjust_by(delta: i32) -> Option<LevelFilter> {
    let mut idx = CURRENT_IDX.load(Ordering::Relaxed);
    idx = (idx + delta).clamp(0, 4);
    let level = LEVELS[idx as usize];

    if !reload_with_level(level) {
        return None;
    }

    CURRENT_IDX.store(idx, Ordering::Relaxed);
    Some(level)
}

pub fn set_level(level: LevelFilter) {
    if !reload_with_level(level) {
        return;
    }

    let idx = level_to_idx(level);
    CURRENT_IDX.store(idx, Ordering::Relaxed);
}

fn level_to_idx(level: LevelFilter) -> i32 {
    match level {
        LevelFilter::ERROR => 0,
        LevelFilter::WARN => 1,
        LevelFilter::INFO => 2,
        LevelFilter::DEBUG => 3,
        LevelFilter::TRACE => 4,
        _ => 2,
    }
}

fn reload_with_level(level: LevelFilter) -> bool {
    let handle = match RELOAD.get() {
        Some(handle) => handle,
        None => return false,
    };

    let filter = if let Some(base) = BASE_FILTER.get() {
        filter_with_level(level, base)
    } else {
        EnvFilter::new(level_to_str(level))
    };

    handle.reload(filter).is_ok()
}

fn filter_with_level(level: LevelFilter, base: &str) -> EnvFilter {
    let level_str = level_to_str(level);
    let mut parts: Vec<String> = base
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    if parts.is_empty() {
        return EnvFilter::new(level_str);
    }

    if let Some(first) = parts.first_mut() {
        if first.contains('=') {
            parts.insert(0, level_str.to_string());
        } else {
            *first = level_str.to_string();
        }
    }

    let filter_str = parts.join(",");
    EnvFilter::new(filter_str)
}

fn level_to_str(level: LevelFilter) -> &'static str {
    match level {
        LevelFilter::ERROR => "error",
        LevelFilter::WARN => "warn",
        LevelFilter::INFO => "info",
        LevelFilter::DEBUG => "debug",
        LevelFilter::TRACE => "trace",
        _ => "info",
    }
}

pub fn disable_logging() {
    if let Some(handle) = RELOAD.get() {
        let _ = handle.reload(EnvFilter::new("off"));
    }
}

pub fn enable_logging(level: LevelFilter) {
    let _ = reload_with_level(level);
}
