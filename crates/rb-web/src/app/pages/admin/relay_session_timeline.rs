//! Session Timeline Page
//!
//! Displays the multi-track timeline view for a session's audit events.

use crate::app::components::{Layout, RelaySessionTimeline};
use dioxus::prelude::*;

/// Session timeline page component
#[component]
pub fn RelaySessionTimelinePage(session_id: String) -> Element {
    rsx! {
        Layout {
            div { class: "container mx-auto p-6",
                // Back button
                div { class: "mb-4",
                    Link {
                        to: "/admin/session-history",
                        class: "btn btn-ghost btn-sm gap-2",
                        "← Back to Session History"
                    }
                }

                // Timeline component
                RelaySessionTimeline { session_id }
            }
        }
    }
}
