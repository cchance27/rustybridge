//! Virtualized event list component with infinite scroll, windowing, and collapsible groups.

use crate::app::api::{
    audit::{GroupSummary, GroupedEvent, StreamEventsQuery, stream_audit_events},
    users::list_users,
};
use dioxus::prelude::*;
use rb_types::audit::EventCategory;
use std::collections::{HashMap, HashSet};

/// Window size - how many events to keep in memory at once
const WINDOW_SIZE: usize = 200;
/// How many to load per batch
const BATCH_SIZE: i64 = 50;

/// Virtualized event list with infinite scroll and collapsible groups
#[component]
pub fn VirtualizedEventList(
    /// Grouping mode: "actor", "session", "category", or None
    group_by: Option<String>,
    /// Category filter
    category_filter: Option<String>,
) -> Element {
    // Core state
    let mut events = use_signal(Vec::<GroupedEvent>::new);
    let mut groups = use_signal(Vec::<GroupSummary>::new);
    let mut collapsed = use_signal(HashSet::<String>::new);
    let mut cursor = use_signal(|| None::<i64>);
    let mut has_more = use_signal(|| true);
    let mut loading = use_signal(|| false);
    let mut initialized = use_signal(|| false);

    // Track last loaded filter to detect changes
    let mut last_group_by = use_signal(|| group_by.clone());
    let mut last_category = use_signal(|| category_filter.clone());

    // User cache for username resolution
    let users_resource = use_resource(|| async move {
        match list_users().await {
            Ok(users) => users
                .into_iter()
                .map(|u| (u.id, u.username.to_string()))
                .collect::<HashMap<i64, String>>(),
            Err(_) => HashMap::new(),
        }
    });

    let user_map = users_resource.read().clone().unwrap_or_default();

    // Detect prop changes and reset state to trigger reload
    if *last_group_by.read() != group_by || *last_category.read() != category_filter {
        // Props changed - trigger a fresh load
        last_group_by.set(group_by.clone());
        last_category.set(category_filter.clone());
        initialized.set(false); // Force re-initialization
        events.set(vec![]); // Clear old events
        cursor.set(None); // Reset cursor
        has_more.set(true); // Reset pagination
    }

    // Load data function
    let group_by_clone = group_by.clone();

    #[cfg(feature = "web")]
    let category_filter_clone = category_filter.clone();

    // Clone for use_effect
    let group_by_for_effect = group_by.clone();
    let cat_for_effect = category_filter.clone();

    let load_data = move |use_cursor: bool, group: Option<String>, cat: Option<String>| {
        let cur = if use_cursor { cursor() } else { None };
        spawn(async move {
            loading.set(true);
            let response = stream_audit_events(StreamEventsQuery {
                limit: Some(BATCH_SIZE),
                cursor: cur,
                group_by: group.clone(),
                category: cat,
                ..Default::default()
            })
            .await;

            match response {
                Ok(data) => {
                    if use_cursor {
                        // Append new events
                        events.write().extend(data.events);
                    } else {
                        // Replace events (initial load or filter change)
                        events.set(data.events);
                        groups.set(data.groups.clone());
                        // Start all groups collapsed if we have grouping
                        if group.is_some() {
                            collapsed.set(data.groups.iter().map(|g| g.key.clone()).collect());
                        } else {
                            collapsed.set(HashSet::new());
                        }
                    }
                    cursor.set(data.next_cursor);
                    has_more.set(data.has_more);

                    // Apply windowing - drop oldest if over limit
                    if events.read().len() > WINDOW_SIZE {
                        let excess = events.read().len() - WINDOW_SIZE;
                        events.write().drain(0..excess);
                    }
                }
                Err(_e) => {
                    // Error logged to console by server function
                }
            }
            loading.set(false);
            initialized.set(true);
        });
    };

    // Initial load
    use_effect(move || {
        if !initialized() {
            load_data(false, group_by_for_effect.clone(), cat_for_effect.clone());
        }
    });

    // Toggle group collapse
    let mut toggle_group = move |key: String| {
        let mut set = collapsed.write();
        if set.contains(&key) {
            set.remove(&key);
        } else {
            set.insert(key);
        }
    };

    // For rsx conditional checks
    let has_grouping = group_by_clone.is_some();

    // State for selected event details modal
    let mut selected_event = use_signal(|| None::<rb_types::audit::AuditEvent>);

    rsx! {
        div { class: "flex flex-col h-full relative",
            // Group summaries bar (collapsed groups)
            if !groups.read().is_empty() && has_grouping {
                div { class: "flex flex-wrap gap-2 mb-4 p-2 bg-base-200 rounded-lg",
                    for group in groups.read().iter() {
                        {
                            let key = group.key.clone();
                            let is_collapsed = collapsed.read().contains(&key);
                            let label = resolve_group_label(&group.key, &user_map);
                            let icon = get_group_icon(&group.key);
                            rsx! {
                                button {
                                    class: if is_collapsed { "btn btn-sm btn-ghost opacity-60" } else { "btn btn-sm btn-primary" },
                                    onclick: move |_| toggle_group(key.clone()),
                                    "{icon} {label} ({group.count})"
                                }
                            }
                        }
                    }
                }
            }

            // Event list
            div {
                class: "overflow-y-auto flex-1",
                style: "max-height: calc(100vh - 300px);",
                onscroll: move |_evt| {
                    // Check if near bottom to trigger load more
                    #[cfg(feature = "web")]
                    {
                        use dioxus::web::WebEventExt;
                        use web_sys::wasm_bindgen::JsCast;
                        if let Some(target) = _evt.as_web_event().target() {
                            if let Some(el) = target.dyn_ref::<web_sys::Element>() {
                                let scroll_top = el.scroll_top() as f64;
                                let scroll_height = el.scroll_height() as f64;
                                let client_height = el.client_height() as f64;
                                // Load more when near bottom (within 100px)
                                if scroll_height - scroll_top - client_height < 100.0 && !loading() && has_more() {
                                    load_data(true, group_by_clone.clone(), category_filter_clone.clone());
                                }
                            }
                        }
                    }
                },
                table { class: "table table-zebra w-full table-sm",
                thead {
                        tr {
                            th { class: "w-48", "Time" }
                            th { "Actor" }
                            th { "Category" }
                            th { "Event" }
                            th { "IP" }
                            th { class: "w-10", "" } // Action column
                        }
                    }
                    tbody {
                        if !initialized() {
                            tr {
                                td { colspan: "7", class: "text-center py-8",
                                    span { class: "loading loading-spinner loading-lg" }
                                }
                            }
                        } else if events.read().is_empty() {
                            tr {
                                td { colspan: "7", class: "text-center py-8",
                                    div { class: "alert alert-info inline-block",
                                        "No events found."
                                    }
                                }
                            }
                        } else {
                            for ge in events.read().iter() {
                                {
                                    let is_collapsed = collapsed.read().contains(&ge.group_key);
                                    let show_header = ge.is_group_start && has_grouping;
                                    let key = ge.group_key.clone();
                                    let evt = ge.event.clone();
                                    rsx! {
                                        if show_header {
                                            tr {
                                                class: "bg-base-300 cursor-pointer hover:bg-base-200",
                                                onclick: move |_| toggle_group(key.clone()),
                                                td { colspan: "7", class: "font-bold py-2",
                                                    span { class: "mr-2",
                                                        if is_collapsed { "▶" } else { "▼" }
                                                    }
                                                    "{get_group_icon(&ge.group_key)} {resolve_group_label(&ge.group_key, &user_map)}"
                                                }
                                            }
                                        }
                                        if !is_collapsed {
                                            EventRow {
                                                event: ge.event.clone(),
                                                user_map: user_map.clone(),
                                                on_click: move |_| selected_event.set(Some(evt.clone()))
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if loading() && initialized() {
                            tr {
                                td { colspan: "7", class: "text-center py-4",
                                    span { class: "loading loading-spinner loading-md" }
                                }
                            }
                        }
                    }
                }
            }

            // Detail Modal
            if let Some(evt) = selected_event() {
                EventDetailModal {
                    event: evt,
                    on_close: move |_| selected_event.set(None)
                }
            }
        }
    }
}

#[component]
fn EventRow(event: rb_types::audit::AuditEvent, user_map: HashMap<i64, String>, on_click: EventHandler<()>) -> Element {
    let timestamp = format_timestamp(event.timestamp);
    let actor = event
        .actor_id
        .and_then(|id| user_map.get(&id).cloned())
        .or_else(|| event.actor_id.map(|id| format!("User #{}", id)))
        .unwrap_or_else(|| "System".to_string());
    let category = format!("{:?}", event.category);
    let event_type = event.event_type.action_type().replace('_', " ");
    // We arent actively using the db resource field yet.
    //let resource = event.resource_id.clone().unwrap_or_else(|| "-".to_string());
    let ip = event.ip_address.clone().unwrap_or_else(|| "-".to_string());

    let category_class = match event.category {
        EventCategory::Authentication => "badge-info",
        EventCategory::Session => "badge-success",
        EventCategory::UserManagement | EventCategory::GroupManagement => "badge-primary",
        EventCategory::RelayManagement | EventCategory::CredentialManagement => "badge-secondary",
        EventCategory::AccessControl => "badge-warning",
        EventCategory::System | EventCategory::Configuration => "badge-neutral",
        _ => "badge-ghost",
    };

    rsx! {
        tr {
            class: "hover hover:bg-base-200 cursor-pointer transition-colors",
            onclick: move |_| on_click.call(()),
            td { class: "text-xs font-mono", "{timestamp}" }
            td { class: "text-center",
                span { class: "font-mono text-xs", "{actor}" }
            }
            td { class: "text-center",
                span { class: "badge badge-xs {category_class}", "{category}" }
            }
            td { class: "text-center",
                span { class: "font-mono text-xs", "{event_type}" }
            }
            td { class: "text-center",
                span { class: "font-mono text-xs opacity-70", "{ip}" }
            }
            td { class: "text-center",
                button {
                    class: "btn btn-ghost btn-xs",
                    title: "View Details",
                    "🔍"
                }
            }
        }
    }
}

#[component]
fn EventDetailModal(event: rb_types::audit::AuditEvent, on_close: EventHandler<()>) -> Element {
    let json_content = serde_json::to_string_pretty(&event).unwrap_or_else(|_| "Error serializing event".to_string());

    rsx! {
        div { class: "modal modal-open",
            div { class: "modal-box w-11/12 max-w-5xl",
                h3 { class: "font-bold text-lg flex justify-between items-center",
                    "Event Details"
                    button { class: "btn btn-sm btn-circle btn-ghost", onclick: move |_| on_close.call(()), "✕" }
                }
                div { class: "py-4",
                    pre { class: "bg-base-300 p-4 rounded-lg overflow-x-auto font-mono text-xs",
                        "{json_content}"
                    }
                }
                div { class: "modal-action",
                    button { class: "btn", onclick: move |_| on_close.call(()), "Close" }
                }
            }
            div { class: "modal-backdrop", onclick: move |_| on_close.call(()) }
        }
    }
}

fn resolve_group_label(key: &str, user_map: &HashMap<i64, String>) -> String {
    if let Some(id_str) = key.strip_prefix("actor:") {
        if id_str == "system" {
            return "System".to_string();
        }
        if let Ok(id) = id_str.parse::<i64>() {
            return user_map.get(&id).cloned().unwrap_or_else(|| format!("User #{}", id));
        }
        id_str.to_string()
    } else if let Some(session) = key.strip_prefix("session:") {
        if session == "none" {
            "No Session".to_string()
        } else if session.len() > 16 {
            format!("{}...", &session[..16])
        } else {
            session.to_string()
        }
    } else if let Some(cat) = key.strip_prefix("category:") {
        cat.to_string()
    } else {
        key.to_string()
    }
}

fn get_group_icon(key: &str) -> &'static str {
    if key.starts_with("actor:") {
        "👤"
    } else if key.starts_with("session:") {
        "📁"
    } else if key.starts_with("category:") {
        if key.contains("Authentication") {
            "🔐"
        } else if key.contains("Session") {
            "💻"
        } else if key.contains("User") || key.contains("Group") {
            "👥"
        } else if key.contains("Relay") {
            "🔌"
        } else if key.contains("Credential") {
            "🔑"
        } else if key.contains("Access") {
            "🛡️"
        } else if key.contains("System") || key.contains("Config") {
            "⚙️"
        } else {
            "📋"
        }
    } else {
        "📋"
    }
}

fn format_timestamp(ms: i64) -> String {
    use chrono::{Local, TimeZone};

    if let Some(dt) = Local.timestamp_millis_opt(ms).single() {
        dt.format("%Y-%m-%d %H:%M:%S").to_string()
    } else {
        "Invalid date".to_string()
    }
}
