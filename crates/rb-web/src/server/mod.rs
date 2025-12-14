pub mod audit;
pub mod auth;

#[cfg(feature = "server")]
use axum::Router;
use dioxus::prelude::*;
use tracing::{info, warn};

/// Create the configured Axum router with all middleware layers.
///
/// This function sets up:
/// - Session layer (SQLite-backed cookie sessions)
/// - Auth session layer (user authentication)
/// - OIDC routes (login, callback, linking)
/// - Audit export routes
/// - ServerContext and SessionRegistry extensions
///
/// Used by both `run_web_server()` (production via rb-cli) and `dioxus::serve`
/// (development via dx serve).
#[cfg(feature = "server")]
pub async fn create_app_router(
    app: fn() -> Element,
    registry: std::sync::Arc<server_core::sessions::SessionRegistry>,
    secure_cookies: bool,
) -> anyhow::Result<Router> {
    use axum_session::{SameSite, SessionLayer, SessionStore};
    use axum_session_auth::AuthSessionLayer;

    use crate::{app::api, server::auth::WebUser};

    // Initialize DB for session store
    let db_handle = server_core::api::server_db_handle().await?;
    let server_ctx = server_core::ServerContext::new(
        db_handle.clone(),
        registry.audit_db.clone(),
        server_core::secrets::master_key_from_env()?,
    );

    // Session Layer
    // OIDC redirects arrive as cross-site navigations, so SameSite must allow the
    // callback to carry the session cookie. Lax is sufficient for top-level GET
    // redirects while still blocking most CSRF vectors. We only mark cookies as
    // secure when TLS is configured (avoids browsers dropping the cookie on HTTP).
    let session_config = axum_session::SessionConfig::default()
        .with_table_name("sessions")
        .with_cookie_same_site(SameSite::Lax)
        .with_http_only(true)
        .with_secure(secure_cookies)
        .with_cookie_path("/");

    let session_manager = server_core::sessions::web::create_web_session_manager(&db_handle);
    let session_store = SessionStore::new(Some(session_manager), session_config).await?;
    let session_layer = SessionLayer::new(session_store);

    // Auth Layer
    let auth_config = axum_session_auth::AuthConfig::<i64>::default();
    let auth_layer =
        AuthSessionLayer::<WebUser, i64, server_core::sessions::web::WebSessionManager, ()>::new(None).with_config(auth_config);

    // Create router with custom WebSocket route for SSH terminal
    let router = Router::new()
        // We're using a fixed axum route for export, we should see if we can bring this into dioxus server #[get]
        .route(
            "/api/audit/sessions/{id}/export/{export_type}",
            axum::routing::get(api::audit::export_session),
        )
        .serve_dioxus_application(ServeConfig::new(), app)
        .layer(axum::Extension(registry))
        .layer(axum::Extension(server_ctx))
        .layer(auth_layer)
        .layer(session_layer);

    Ok(router)
}

/// Start the Dioxus fullstack web server with Axum integration.
///
/// This is the production entry point used by rb-cli when running with --web.
/// For development via `dx serve`, the app uses `dioxus::serve` with `create_app_router`.
#[cfg(feature = "server")]
pub async fn run_web_server(
    config: rb_types::config::WebServerConfig,
    app: fn() -> Element,
    registry: std::sync::Arc<server_core::sessions::SessionRegistry>,
) -> anyhow::Result<()> {
    if config.tls.is_some() {
        warn!("native TLS requested but not yet implemented; serving HTTP");
    }

    let addr = format!("{}:{}", config.bind, config.port);
    let secure_cookies = config.tls.is_some();

    let router = create_app_router(app, registry, secure_cookies)
        .await?
        .into_make_service_with_connect_info::<std::net::SocketAddr>();

    let listener = tokio::net::TcpListener::bind(&addr).await?;

    info!(%addr, "starting web server (HTTP) with Dioxus fullstack");
    axum::serve(listener, router).await?;
    Ok(())
}
