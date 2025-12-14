use crate::error::ServerResult;
use tracing::level_filters::LevelFilter;

/// Set the server log level, persisting it to the database and applying it immediately.
pub async fn set_server_log_level(level: &str) -> ServerResult<()> {
    // Validate level string
    let parsed_level = match level.to_lowercase().as_str() {
        "error" => LevelFilter::ERROR,
        "warn" => LevelFilter::WARN,
        "info" => LevelFilter::INFO,
        "debug" => LevelFilter::DEBUG,
        "trace" => LevelFilter::TRACE,
        _ => LevelFilter::INFO,
    };

    // Update database
    let db = state_store::server_db().await?;
    let pool = db.into_pool();
    state_store::set_server_option(&pool, "log_level", level).await?;

    // Apply to runtime only when RUST_LOG is not set (or is empty) so that
    // environment configuration continues to take precedence over persisted settings.
    let has_rust_log = matches!(
        std::env::var("RUST_LOG"),
        Ok(s) if !s.trim().is_empty()
    );
    if !has_rust_log {
        ssh_core::logging::set_level(parsed_level);
    }

    Ok(())
}

/// Get the current server log level from the database.
pub async fn get_server_log_level() -> ServerResult<String> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    // Fetch option, default to "info"
    let level = state_store::get_server_option(&pool, "log_level")
        .await?
        .unwrap_or_else(|| "info".to_string());

    Ok(level)
}
