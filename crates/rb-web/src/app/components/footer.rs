use dioxus::prelude::*;

#[component]
pub fn Footer() -> Element {
    rsx! {
        footer { class: "footer footer-center text-base-content p-4",
            aside {
                p { "Copyright © 2026 - All right reserved by Defer To Expertise" }
            }
        }
    }
}
