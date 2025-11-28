use dioxus::prelude::*;

use crate::{
    app::auth::context::use_auth_provider,
    app::session::provider::use_session_provider,
    app::session::components::global_chrome::SessionGlobalChrome,
    pages::{
        AccessPage, CredentialsPage, DashboardPage, LoginPage, LogoutPage, NotFoundPage, OidcErrorPage, ProfilePage, RelaysPage, SshSuccessPage
    }
};

/// Root shell: wraps the router and global providers.
#[component]
pub fn app_root() -> Element {
    // Initialize auth state and provide it to context
    let auth = use_auth_provider();
    use_context_provider(|| auth);

    // Initialize session provider
    let _session = use_session_provider();

    rsx! {
        document::Title { "RustyBridge Web UI" }
        // FIXME: hash suffix is disabled for now because it breaks when we use cargo run
        // FIXME: we also have to use `clean_asset_path` to strip the absolute path when running via cargo run
        document::Stylesheet { href: clean_asset_path(asset!("/assets/tailwind.css", AssetOptions::builder().with_hash_suffix(false)).to_string()) }
        
        SessionGlobalChrome {
            Router::<Routes> {}
        }
    }
}

#[derive(Clone, Routable, PartialEq)]
pub enum Routes {
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
