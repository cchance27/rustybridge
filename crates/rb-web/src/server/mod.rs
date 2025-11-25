pub mod auth;
pub mod ssh_websocket;

#[cfg(feature = "server")]
use axum::Router;
use dioxus::prelude::*;

/// Start the Dioxus fullstack web server with Axum integration.
#[cfg(feature = "server")]
pub async fn run_web_server(config: rb_types::config::WebServerConfig, app: fn() -> Element) -> anyhow::Result<()> {
    use axum_session::{SameSite, SessionLayer, SessionStore};
    use axum_session_auth::AuthSessionLayer;
    use axum_session_sqlx::SessionSqlitePool;
    use sqlx::SqlitePool;

    use crate::server::auth::WebUser;

    if config.tls.is_some() {
        tracing::warn!("native TLS requested but not yet implemented; serving HTTP");
    }

    let addr = format!("{}:{}", config.bind, config.port);

    // Initialize DB for session store
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    // Session Layer
    #[cfg(debug_assertions)]
    let session_config = axum_session::SessionConfig::default()
        .with_table_name("sessions")
        .with_cookie_same_site(SameSite::Lax)
        .with_http_only(true)
        .with_secure(false)
        .with_cookie_path("/");

    #[cfg(not(debug_assertions))]
    let session_config = axum_session::SessionConfig::default()
        .with_table_name("sessions")
        .with_cookie_same_site(SameSite::Strict)
        .with_http_only(true)
        .with_secure(true)
        .with_cookie_path("/");

    let sqlite_pool = SessionSqlitePool::from(pool.clone());
    let session_store = SessionStore::new(Some(sqlite_pool), session_config).await?;
    let session_layer = SessionLayer::new(session_store);

    // Auth Layer
    let auth_config = axum_session_auth::AuthConfig::<i64>::default();
    let auth_layer = AuthSessionLayer::<WebUser, i64, SessionSqlitePool, SqlitePool>::new(Some(pool.clone())).with_config(auth_config);

    // Create router with custom WebSocket route for SSH terminal
    let router = Router::new()
        .route("/api/ssh/{relay_name}", axum::routing::get(ssh_websocket::ssh_terminal_ws))
        .route(
            "/api/ssh/{relay_name}/status",
            axum::routing::get(ssh_websocket::ssh_terminal_status),
        )
        .route("/api/auth/oidc/login", axum::routing::get(auth::oidc::oidc_login))
        .route("/api/auth/oidc/callback", axum::routing::get(auth::oidc::oidc_callback))
        .route("/api/auth/oidc/link", axum::routing::get(auth::oidc_link::oidc_link_start))
        .route(
            "/api/auth/oidc/callback/link",
            axum::routing::get(auth::oidc_link::oidc_link_callback),
        )
        //.route("/api/auth/oidc/unlink", axum::routing::post(auth::oidc_unlink::oidc_unlink))
        .serve_dioxus_application(ServeConfig::new(), app)
        .layer(axum::Extension(pool.clone()))
        .layer(auth_layer)
        .layer(session_layer)
        .into_make_service();

    let listener = tokio::net::TcpListener::bind(&addr).await?;

    tracing::info!(%addr, "starting web server (HTTP) with Dioxus fullstack");
    axum::serve(listener, router).await?;

    Ok(())
}
