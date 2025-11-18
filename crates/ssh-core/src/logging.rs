use std::sync::atomic::{AtomicI32, Ordering};

use once_cell::sync::OnceCell;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{reload, EnvFilter, Registry};

static RELOAD: OnceCell<reload::Handle<EnvFilter, Registry>> = OnceCell::new();
static CURRENT_IDX: AtomicI32 = AtomicI32::new(2); // 0=error,1=warn,2=info,3=debug,4=trace

const LEVELS: [LevelFilter; 5] = [
    LevelFilter::ERROR,
    LevelFilter::WARN,
    LevelFilter::INFO,
    LevelFilter::DEBUG,
    LevelFilter::TRACE,
];

pub fn set_reload_handle(handle: reload::Handle<EnvFilter, Registry>, initial: LevelFilter) {
    let _ = RELOAD.set(handle);
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
    let handle = RELOAD.get()?;
    let mut idx = CURRENT_IDX.load(Ordering::Relaxed);
    idx = (idx + delta).clamp(0, 4);
    CURRENT_IDX.store(idx, Ordering::Relaxed);
    let level = LEVELS[idx as usize];
    let _ = handle.reload(EnvFilter::new(level_to_str(level)));
    Some(level)
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
