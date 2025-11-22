// Server functions need to be declared for Dioxus RPC, but implementations are server-only
pub mod relay_list;
pub mod ssh_websocket;

#[cfg(feature = "server")]
use crate::WebServerConfig;
#[cfg(feature = "server")]
use axum::Router;
#[cfg(feature = "server")]
use dioxus::prelude::*;
#[cfg(feature = "server")]
pub mod config;

/// Start the Dioxus fullstack web server with Axum integration.
#[cfg(feature = "server")]
pub async fn run_web_server(config: WebServerConfig, app: fn() -> Element) -> anyhow::Result<()> {
    if config.tls.is_some() {
        tracing::warn!("native TLS requested but not yet implemented; serving HTTP");
    }

    let addr = format!("{}:{}", config.bind, config.port);

    // Create router with custom WebSocket route for SSH terminal
    let router = Router::new()
        .route("/api/ssh/{relay_name}", axum::routing::get(ssh_websocket::ssh_terminal_ws))
        .serve_dioxus_application(ServeConfig::new(), app)
        .into_make_service();

    let listener = tokio::net::TcpListener::bind(&addr).await?;

    tracing::info!(%addr, "starting web server (HTTP) with Dioxus fullstack");
    axum::serve(listener, router).await?;

    Ok(())
}
