use rb_web::app_root::app_root;

fn main() {
    // Initialize platform-specific logging
    rb_web::app::logging::init();

    // When running on the server (dx serve or cargo run), set up the full
    // web server with session/auth layers. Otherwise just launch the client.
    #[cfg(feature = "server")]
    {
        dioxus::serve(|| async {
            use std::sync::Arc;

            // Run database migrations
            server_core::migrate_server_db().await?;

            // Run startup cleanup (clear stale sessions, etc.)
            server_core::startup_cleanup::run_startup_cleanup().await?;

            // Create session registry with audit DB
            let audit_db = server_core::audit_db_handle().await?;
            let registry = Arc::new(server_core::sessions::SessionRegistry::new(audit_db));

            // Create the configured router with all middleware layers
            // secure_cookies = false for development (HTTP, not HTTPS)
            rb_web::create_app_router(app_root, registry, false).await
        });
    }

    #[cfg(not(feature = "server"))]
    dioxus::launch(app_root);
}
