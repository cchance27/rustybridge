use crate::app::components::{GroupedEventView, Layout, VirtualizedEventList};
use dioxus::prelude::*;

/// Admin page for viewing all audit events with filtering and grouping
#[component]
pub fn AuditEvents() -> Element {
    // Filter state
    let mut category_filter = use_signal(|| None::<String>);

    // Grouping state: None = flat list, Some("actor"/etc) = drill-down view
    let mut group_by = use_signal(|| None::<String>);

    // Category options for dropdown
    let categories = vec![
        ("", "All Categories"),
        ("authentication", "Authentication"),
        ("user_management", "User Management"),
        ("group_management", "Group Management"),
        ("role_management", "Role Management"),
        ("relay_management", "Relay Management"),
        ("credential_management", "Credential Management"),
        ("access_control", "Access Control"),
        ("session", "Session"),
        ("configuration", "Configuration"),
        ("system", "System"),
    ];

    rsx! {
        Layout {
            div { class: "container mx-auto p-6 h-full flex flex-col",
                div { class: "flex justify-between items-center mb-4",
                    h1 { class: "text-3xl font-bold", "Audit Events" }

                    // Filters row
                    div { class: "flex gap-4 items-center",
                        // Category dropdown
                        select {
                            class: "select select-bordered select-sm",
                            value: category_filter().unwrap_or_default(),
                            onchange: move |evt| {
                                let val = evt.value();
                                category_filter.set(if val.is_empty() { None } else { Some(val) });
                            },
                            for (key, label) in categories.clone() {
                                option { value: "{key}", "{label}" }
                            }
                        }

                        // Grouping dropdown
                        select {
                            class: "select select-bordered select-sm",
                            value: group_by().unwrap_or_default(),
                            onchange: move |evt| {
                                let val = evt.value();
                                group_by.set(if val.is_empty() { None } else { Some(val) });
                            },
                            option { value: "", "No Grouping" }
                            option { value: "actor", "Group by Actor" }
                            option { value: "session", "Group by Session" }
                            option { value: "category", "Group by Category" }
                        }
                    }
                }

                // Content area - either flat list or grouped drill-down
                div { class: "flex-1 min-h-0",
                    match group_by() {
                        None => rsx! {
                            // Flat infinite scroll (no grouping)
                            VirtualizedEventList {
                                group_by: None,
                                category_filter: category_filter(),
                            }
                        },
                        Some(group_mode) => rsx! {
                            // Drill-down grouped view
                            GroupedEventView {
                                group_by: group_mode,
                                category_filter: category_filter(),
                            }
                        }
                    }
                }
            }
        }
    }
}
