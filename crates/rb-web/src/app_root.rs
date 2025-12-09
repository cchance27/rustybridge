use dioxus::prelude::*;

use crate::{
    app::{
        auth::context::use_auth_provider, session::{components::global_chrome::SessionGlobalChrome, provider::use_session_provider}
    }, components::SessionPlayer, pages::{
        AccessPage, CredentialsPage, DashboardPage, LoginPage, LogoutPage, NotFoundPage, OidcErrorPage, ProfilePage, RelaysPage, ServerPage, SshSuccessPage, admin::{AuditEvents, RelaySessionTimelinePage, SessionHistory}
    }
};

/// Root shell: wraps the router and global providers.
#[component]
pub fn app_root() -> Element {
    // Initialize auth state and provide it to context
    let auth = use_auth_provider();
    use_context_provider(|| auth);

    use crate::app::components::ToastProvider;

    rsx! {
        document::Title { "RustyBridge Web UI" }
        // FIXME: hash suffix is disabled for now because it breaks when we use cargo run
        // FIXME: we also have to use `clean_asset_path` to strip the absolute path when running via cargo run
        document::Stylesheet { href: clean_asset_path(asset!("/assets/tailwind.css", AssetOptions::builder().with_hash_suffix(false)).to_string()) }
        document::Stylesheet { href: "/xterm/xterm.css"}
        // FIXME: Only include these if we're logged in they aren't needed if we aren't logged in or for oidc/login etc pages.
        document::Script { src: "/xterm/xterm.js"}
        document::Script { src: "/xterm/xterm-init.js"}
        document::Script { src: "/xterm/addon-fit.js"}
        document::Script { src: "/xterm/addon-web-links.js"}
        document::Script { src: "/xterm/addon-webgl.js"}

        ToastProvider {
            SessionProviderShell {}
        }
    }
}

#[component]
fn AuthenticatedLayout() -> Element {
    rsx! {
        SessionGlobalChrome {
            Outlet::<Routes> {}
        }
    }
}

#[component]
fn SessionProviderShell() -> Element {
    // Initialize session provider after toast context is available
    let _session = use_session_provider();

    // Auto-restore sessions is now handled by the SessionProvider WebSocket connection
    use crate::app::server_status::ServerStatusProvider;

    rsx! {
        ServerStatusProvider {
            Router::<Routes> {}
        }
    }
}

#[derive(Clone, Routable, PartialEq)]
pub enum Routes {
    #[layout(AuthenticatedLayout)]
    #[route("/")]
    DashboardPage {},
    #[route("/relays")]
    RelaysPage {},
    #[route("/credentials")]
    CredentialsPage {},
    #[route("/profile")]
    ProfilePage {},
    #[route("/access")]
    AccessPage {},
    #[route("/server")]
    ServerPage {},
    #[route("/admin/sessions")]
    SessionHistory {},
    #[route("/admin/events")]
    AuditEvents {},
    #[route("/admin/sessions/:session_id/replay")]
    SessionPlayer { session_id: String },
    #[route("/admin/sessions/:session_id/timeline")]
    RelaySessionTimelinePage { session_id: String },
    #[end_layout]
    #[route("/login")]
    LoginPage {},
    #[route("/logout")]
    LogoutPage {},
    #[route("/oidc/error")]
    OidcErrorPage {},
    #[route("/auth/ssh-success")]
    SshSuccessPage {},
    #[route("/:..route")]
    NotFoundPage { route: Vec<String> },
}

pub fn clean_asset_path(path: String) -> String {
    // When running via `cargo run`, the asset! macro returns an absolute path
    // We want to strip everything up to /assets/
    if let Some(idx) = path.find("/assets/") {
        path[idx..].to_string()
    } else {
        path
    }
}
