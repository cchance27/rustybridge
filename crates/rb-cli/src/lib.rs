pub mod client_cli;
pub mod server_cli;

pub fn init_tracing() {
    use tracing::level_filters::LevelFilter;
    use tracing_subscriber::{EnvFilter, fmt, prelude::*, reload};
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
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

    ssh_core::logging::set_reload_handle(handle, initial);
}
