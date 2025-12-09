mod sessions;

use dioxus::prelude::*;
use rb_types::auth::{ClaimLevel, ClaimType};

use crate::components::{Layout, RequireAuth};

#[component]
pub fn ServerPage() -> Element {
    rsx! {
        RequireAuth {
            any_claims: vec![ClaimType::Server(ClaimLevel::View)],
            Layout {
                div { class: "grid grid-cols-1 gap-6",
                    sessions::SessionsSection {}
                }
            }
        }
    }
}
