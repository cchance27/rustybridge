use crate::app::components::{Layout, RequireAuth};
use dioxus::prelude::*;

#[component]
pub fn DashboardPage() -> Element {
    rsx! {
        RequireAuth {
            Layout {
                div { class: "flex flex-col h-full p-4 gap-4 items-center justify-center min-h-[50vh]",
                    div { class: "text-center space-y-6 max-w-md",
                        h1 { class: "text-4xl font-bold text-base-content", "RustyBridge Terminal" }
                        p { class: "text-base-content/70",
                            "Secure, web-based SSH access to your registered relays. "
                            "Use the sidebar tabs to connect to relays or manage open sessions."
                        }

                        div { class: "flex gap-4 justify-center",
                            div { class: "text-center",
                                div { class: "text-sm text-base-content/50 mb-2", "← Left sidebar" }
                                div { class: "font-semibold", "Open Sessions" }
                            }
                            div { class: "text-center",
                                div { class: "text-sm text-base-content/50 mb-2", "Right sidebar →" }
                                div { class: "font-semibold", "Connect to Relay" }
                            }
                        }
                    }
                }
            }
        }
    }
}
