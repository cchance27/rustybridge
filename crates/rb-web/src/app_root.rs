use dioxus::prelude::*;

use crate::app::{
    self, session::{SessionProvider, SessionState}
};

/// Root shell: wraps the router and global providers.
#[component]
pub fn app_root() -> Element {
    let session = use_signal(|| SessionState::Unauthenticated);

    use_effect(move || {
        let _current = session();
    });

    rsx! {
        document::Title { "RustyBridge Web UI" }
        // FIXME: hash suffix is disabled for now because it breaks when we use cargo run
        // FIXME: we also have to use `clean_asset_path` to strip the absolute path when running via cargo run
        document::Stylesheet { href: clean_asset_path(asset!("/assets/tailwind.css", AssetOptions::builder().with_hash_suffix(false)).to_string()) }
        div {
            SessionProvider { session, children: rsx!( app::routes::AppRouter {} ) }
        }
    }
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
