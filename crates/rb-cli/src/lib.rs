pub mod client_cli;
pub mod server_cli;
pub mod tui_input;

pub fn init_tracing() {
    use tracing::level_filters::LevelFilter;
    use tracing_subscriber::{fmt, prelude::*, reload, EnvFilter};

    // Set up panic hook to route panics through tracing
    std::panic::set_hook(Box::new(tracing_panic::panic_hook));

    let default_filter_str = "info,axum_session=warn".to_string();
    let rust_log = std::env::var("RUST_LOG")
        .ok()
        .filter(|s| !s.trim().is_empty());

    let (base_filter_str, env_filter) = match rust_log {
        Some(s) => match EnvFilter::try_new(&s) {
            Ok(f) => (s, f),
            Err(_) => (default_filter_str.clone(), EnvFilter::new(&default_filter_str)),
        },
        None => (default_filter_str.clone(), EnvFilter::new(&default_filter_str)),
    };

    let (reload_layer, handle) = reload::Layer::new(env_filter.clone());
    let _ = tracing_subscriber::registry().with(reload_layer).with(fmt::layer()).try_init();

    // Derive an initial level from RUST_LOG if possible, else default to info.
    let initial = std::env::var("RUST_LOG")
        .ok()
        .and_then(|s| {
            let l = s.to_ascii_lowercase();
            if l.contains("trace") {
                Some(LevelFilter::TRACE)
            } else if l.contains("debug") {
                Some(LevelFilter::DEBUG)
            } else if l.contains("info") {
                Some(LevelFilter::INFO)
            } else if l.contains("warn") {
                Some(LevelFilter::WARN)
            } else if l.contains("error") {
                Some(LevelFilter::ERROR)
            } else {
                None
            }
        })
        .unwrap_or(LevelFilter::INFO);

    ssh_core::logging::set_reload_handle(handle, initial, base_filter_str);
}
