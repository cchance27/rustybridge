mod sessions;

use crate::components::{Layout, RequireAuth};
use dioxus::prelude::*;
use rb_types::auth::{ClaimLevel, ClaimType};

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
