//! Grouped event view with drill-down navigation.
//! Shows group summaries first, then drills into a selected group's events.

use std::collections::HashMap;

use dioxus::prelude::*;
use rb_types::audit::EventCategory;

use crate::app::api::{
    audit::{GroupSummaryQuery, GroupSummaryWithCount, GroupedEvent, StreamEventsQuery, get_event_groups, stream_audit_events}, users::list_users
};

/// Window size - how many events to keep in memory at once
#[cfg(feature = "web")]
const WINDOW_SIZE: usize = 200;
/// How many to load per batch
const BATCH_SIZE: i64 = 50;

/// Grouped event view with drill-down - shows group summaries or detail view
#[component]
pub fn GroupedEventView(
    /// Grouping mode: "actor", "session", "category"
    group_by: String,
    /// Category filter
    category_filter: Option<String>,
) -> Element {
    // State: which group is selected for drill-down (None = summary view)
    let mut selected_group = use_signal(|| None::<GroupSummaryWithCount>);

    // Track previous props to detect changes
    let mut last_group_by = use_signal(|| group_by.clone());

    // Reset to summary view ONLY when group_by changes (not category_filter)
    // Category filter changes are handled by the child components directly
    if *last_group_by.read() != group_by {
        selected_group.set(None);
        last_group_by.set(group_by.clone());
    }

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

    rsx! {
        div { class: "flex flex-col h-full",
            match selected_group() {
                None => rsx! {
                    GroupSummaryView {
                        group_by: group_by.clone(),
                        category_filter: category_filter.clone(),
                        user_map: user_map.clone(),
                        on_select_group: move |group| {
                            selected_group.set(Some(group));
                        },
                    }
                },
                Some(group) => rsx! {
                    GroupDetailView {
                        group: group.clone(),
                        group_by: group_by.clone(),
                        category_filter: category_filter.clone(),
                        user_map: user_map.clone(),
                        on_back: move |_| {
                            selected_group.set(None);
                        },
                    }
                }
            }
        }
    }
}

/// Summary view showing all groups with counts
#[component]
fn GroupSummaryView(
    group_by: String,
    category_filter: Option<String>,
    user_map: HashMap<i64, String>,
    on_select_group: EventHandler<GroupSummaryWithCount>,
) -> Element {
    let mut groups = use_signal(Vec::<GroupSummaryWithCount>::new);
    let mut loading = use_signal(|| true);
    let mut search = use_signal(String::new);
    let mut initialized = use_signal(|| false);

    // Clone for use in closures
    let group_by_for_render = group_by.clone();
    let group_by_for_effect = group_by.clone();
    let cat_for_effect = category_filter.clone();

    // Track props to detect changes
    let mut last_group_by = use_signal(|| group_by.clone());
    let mut last_category = use_signal(|| category_filter.clone());

    // Clone for prop change reload
    let group_by_for_reload = group_by.clone();
    let cat_for_reload = category_filter.clone();

    // Detect prop changes (group_by OR category_filter) and reload
    if *last_group_by.read() != group_by || *last_category.read() != category_filter {
        last_group_by.set(group_by.clone());
        last_category.set(category_filter.clone());
        groups.set(vec![]);

        // Spawn reload directly
        let gb = group_by_for_reload.clone();
        let cat = cat_for_reload.clone();
        spawn(async move {
            loading.set(true);
            let result = get_event_groups(GroupSummaryQuery {
                group_by: gb,
                category: cat,
                limit: None,
                ..Default::default()
            })
            .await;

            if let Ok(data) = result {
                groups.set(data);
            }
            loading.set(false);
        });
    }

    // Load groups on mount (only if not already initialized)
    use_effect(move || {
        if !initialized() {
            let gb = group_by_for_effect.clone();
            let cat = cat_for_effect.clone();
            spawn(async move {
                loading.set(true);
                let result = get_event_groups(GroupSummaryQuery {
                    group_by: gb,
                    category: cat,
                    limit: None, // Get all groups
                    ..Default::default()
                })
                .await;

                if let Ok(data) = result {
                    groups.set(data);
                }
                loading.set(false);
                initialized.set(true);
            });
        }
    });

    // Filter groups by search
    let search_term = search().to_lowercase();
    let filtered_groups: Vec<_> = groups
        .read()
        .iter()
        .filter(|g| {
            if search_term.is_empty() {
                return true;
            }
            // Resolve label for searching
            let label = resolve_group_label(&group_by_for_render, g, &user_map).to_lowercase();
            label.contains(&search_term)
        })
        .cloned()
        .collect();

    // Split into "top 10" and "rest"
    let top_groups: Vec<_> = filtered_groups.iter().take(10).cloned().collect();
    let rest_groups: Vec<_> = filtered_groups.iter().skip(10).cloned().collect();
    let mut show_all = use_signal(|| false);

    let group_icon = match group_by.as_str() {
        "actor" => "👤",
        "session" => "📁",
        "category" => "📋",
        _ => "📋",
    };

    rsx! {
        div { class: "p-4",
            // Header
            div { class: "flex items-center justify-between mb-4",
                h2 { class: "text-xl font-bold",
                    "Select a {&group_by_for_render} to view events"
                }
                div { class: "text-sm text-base-content/60",
                    "{filtered_groups.len()} groups found"
                }
            }

            // Search box
            div { class: "mb-4",
                input {
                    class: "input input-bordered w-full max-w-md",
                    r#type: "text",
                    placeholder: "Search groups...",
                    value: "{search()}",
                    oninput: move |evt| search.set(evt.value()),
                }
            }

            if loading() {
                div { class: "flex justify-center py-8",
                    span { class: "loading loading-spinner loading-lg" }
                }
            } else if filtered_groups.is_empty() {
                div { class: "alert alert-info",
                    "No groups found matching your search."
                }
            } else {
                // Top groups
                div { class: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3",
                    for group in top_groups.iter() {
                        {
                            let label = resolve_group_label(&group_by, group, &user_map);
                            let g = group.clone();
                            rsx! {
                                button {
                                    class: "btn btn-outline btn-lg justify-between h-auto py-3",
                                    onclick: move |_| on_select_group.call(g.clone()),
                                    div { class: "flex items-center gap-2",
                                        span { "{group_icon}" }
                                        span { class: "font-semibold", "{label}" }
                                    }
                                    div { class: "badge badge-primary",
                                        "{group.count} events"
                                    }
                                }
                            }
                        }
                    }
                }

                // Show more section
                if !rest_groups.is_empty() {
                    div { class: "mt-4",
                        button {
                            class: "btn btn-ghost btn-sm",
                            onclick: move |_| show_all.set(!show_all()),
                            if show_all() {
                                "▼ Hide {rest_groups.len()} more groups"
                            } else {
                                "▶ Show {rest_groups.len()} more groups"
                            }
                        }

                        if show_all() {
                            div { class: "mt-2 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2",
                                for group in rest_groups.iter() {
                                    {
                                        let label = resolve_group_label(&group_by_for_render, group, &user_map);
                                        let g = group.clone();
                                        rsx! {
                                            button {
                                                class: "btn btn-outline btn-sm justify-between",
                                                onclick: move |_| on_select_group.call(g.clone()),
                                                span { "{group_icon} {label}" }
                                                span { class: "badge badge-sm", "{group.count}" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Detail view for a single group with infinite scroll
#[component]
fn GroupDetailView(
    group: GroupSummaryWithCount,
    group_by: String,
    category_filter: Option<String>,
    user_map: HashMap<i64, String>,
    on_back: EventHandler<()>,
) -> Element {
    let mut events = use_signal(Vec::<GroupedEvent>::new);
    let mut cursor = use_signal(|| None::<i64>);
    let mut has_more = use_signal(|| true);
    let mut loading = use_signal(|| false);
    let mut initialized = use_signal(|| false);

    // Track category filter to detect changes
    let mut last_category = use_signal(|| category_filter.clone());

    // State for selected event details modal
    let mut selected_event = use_signal(|| None::<rb_types::audit::AuditEvent>);

    // Clone values for closures - must be before any async spawn
    let group_for_effect = group.clone();
    let cat_for_effect = category_filter.clone();

    #[cfg(feature = "web")]
    let group_for_scroll = group.clone();

    #[cfg(feature = "web")]
    let cat_for_scroll = category_filter.clone();

    // Clone for category change reload
    let group_for_reload = group.clone();
    let cat_for_reload = category_filter.clone();

    // Detect category filter changes and reload
    if *last_category.read() != category_filter {
        last_category.set(category_filter.clone());
        events.set(vec![]);
        cursor.set(None);
        has_more.set(true);

        // Spawn reload directly instead of relying on use_effect
        let g = group_for_reload.clone();
        let cat_filter = cat_for_reload.clone();
        spawn(async move {
            loading.set(true);
            let category_for_query = if g.category_key.is_some() {
                g.category_key.clone()
            } else {
                cat_filter
            };
            // Determine null filters for System actor or No Session
            let actor_is_null = g.actor_id.is_none() && g.session_id.is_none() && g.category_key.is_none() && g.key == "system";
            let session_is_null = g.session_id.as_ref().map(|s| s == "system" || s.is_empty()).unwrap_or(false)
                || (g.session_id.is_none() && g.actor_id.is_none() && g.category_key.is_none() && g.key == "system");
            let query = StreamEventsQuery {
                limit: Some(BATCH_SIZE),
                cursor: None,
                group_by: None,
                category: category_for_query,
                actor_id: g.actor_id,
                actor_is_null: if actor_is_null { Some(true) } else { None },
                session_id: if session_is_null { None } else { g.session_id.clone() },
                session_is_null: if session_is_null { Some(true) } else { None },
                ..Default::default()
            };

            if let Ok(data) = stream_audit_events(query).await {
                events.set(data.events);
                cursor.set(data.next_cursor);
                has_more.set(data.has_more);
            }
            loading.set(false);
            initialized.set(true);
        });
    }

    // Initial load on mount (only if not already initialized)
    use_effect(move || {
        if !initialized() {
            let g = group_for_effect.clone();
            let cat_filter = cat_for_effect.clone();
            spawn(async move {
                loading.set(true);
                // Use the appropriate filter based on grouping type
                let category_for_query = if g.category_key.is_some() {
                    g.category_key.clone()
                } else {
                    cat_filter
                };
                // Determine null filters for System actor or No Session
                let actor_is_null = g.actor_id.is_none() && g.session_id.is_none() && g.category_key.is_none() && g.key == "system";
                let session_is_null = g.session_id.as_ref().map(|s| s == "system" || s.is_empty()).unwrap_or(false)
                    || (g.session_id.is_none() && g.actor_id.is_none() && g.category_key.is_none() && g.key == "system");
                let query = StreamEventsQuery {
                    limit: Some(BATCH_SIZE),
                    cursor: None,
                    group_by: None,
                    category: category_for_query,
                    actor_id: g.actor_id,
                    actor_is_null: if actor_is_null { Some(true) } else { None },
                    session_id: if session_is_null { None } else { g.session_id.clone() },
                    session_is_null: if session_is_null { Some(true) } else { None },
                    ..Default::default()
                };

                if let Ok(data) = stream_audit_events(query).await {
                    events.set(data.events);
                    cursor.set(data.next_cursor);
                    has_more.set(data.has_more);
                }
                loading.set(false);
                initialized.set(true);
            });
        }
    });

    // Load more function for scroll
    #[cfg(feature = "web")]
    let load_more = move || {
        if loading() || !has_more() {
            return;
        }
        let g = group_for_scroll.clone();
        let cat_filter = cat_for_scroll.clone();
        let cur = cursor();
        spawn(async move {
            loading.set(true);
            // Use the appropriate filter based on grouping type
            let category_for_query = if g.category_key.is_some() {
                g.category_key.clone()
            } else {
                cat_filter
            };
            // Determine null filters for System actor or No Session
            let actor_is_null = g.actor_id.is_none() && g.session_id.is_none() && g.category_key.is_none() && g.key == "system";
            let session_is_null = g.session_id.as_ref().map(|s| s == "system" || s.is_empty()).unwrap_or(false)
                || (g.session_id.is_none() && g.actor_id.is_none() && g.category_key.is_none() && g.key == "system");
            let query = StreamEventsQuery {
                limit: Some(BATCH_SIZE),
                cursor: cur,
                group_by: None,
                category: category_for_query,
                actor_id: g.actor_id,
                actor_is_null: if actor_is_null { Some(true) } else { None },
                session_id: if session_is_null { None } else { g.session_id.clone() },
                session_is_null: if session_is_null { Some(true) } else { None },
                ..Default::default()
            };

            if let Ok(data) = stream_audit_events(query).await {
                events.write().extend(data.events);
                cursor.set(data.next_cursor);
                has_more.set(data.has_more);

                // Apply windowing
                if events.read().len() > WINDOW_SIZE {
                    let excess = events.read().len() - WINDOW_SIZE;
                    events.write().drain(0..excess);
                }
            }
            loading.set(false);
        });
    };

    let label = resolve_group_label(&group_by, &group, &user_map);
    let group_icon = match group_by.as_str() {
        "actor" => "👤",
        "session" => "📁",
        "category" => "📋",
        _ => "📋",
    };

    rsx! {
        div { class: "flex flex-col h-full relative",
            // Header with back button
            div { class: "flex items-center gap-4 p-4 border-b border-base-300",
                button {
                    class: "btn btn-ghost btn-sm",
                    onclick: move |_| on_back.call(()),
                    "← Back"
                }
                h2 { class: "text-xl font-bold",
                    "{group_icon} {label}"
                }
                // Show filtered count if category filter is active and not matching group's category
                if category_filter.is_some() && group.category_key.is_none() {
                    div { class: "badge badge-secondary",
                        "{events.read().len()} events (filtered)"
                        if has_more() {
                            "+"
                        }
                    }
                } else {
                    // Show live count from fetched events instead of stale group.count
                    div { class: "badge badge-primary",
                        "{events.read().len()}"
                        if has_more() {
                            "+ events"
                        } else {
                            " total events"
                        }
                    }
                }
            }

            // Event list with infinite scroll
            div {
                class: "overflow-y-auto flex-1 p-4",
                style: "max-height: calc(100vh - 250px);",
                onscroll: move |_evt| {
                    #[cfg(feature = "web")]
                    {
                        use dioxus::web::WebEventExt;
                        use web_sys::wasm_bindgen::JsCast;
                        if let Some(target) = _evt.as_web_event().target() {
                            if let Some(el) = target.dyn_ref::<web_sys::Element>() {
                                let scroll_top = el.scroll_top() as f64;
                                let scroll_height = el.scroll_height() as f64;
                                let client_height = el.client_height() as f64;
                                if scroll_height - scroll_top - client_height < 100.0 && !loading() && has_more() {
                                    load_more();
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
                            th { "Resource" }
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
                                    let evt = ge.event.clone();
                                    rsx! {
                                        EventRow {
                                            event: ge.event.clone(),
                                            user_map: user_map.clone(),
                                            on_click: move |_| selected_event.set(Some(evt.clone()))
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
    let resource = event.resource_id.clone().unwrap_or_else(|| "-".to_string());
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
            td { class: "text-xs", "{timestamp}" }
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
                span { class: "font-mono text-xs opacity-70 max-w-24 truncate inline-block", title: "{resource}",
                    "{resource}"
                }
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

fn resolve_group_label(group_by: &str, group: &GroupSummaryWithCount, user_map: &HashMap<i64, String>) -> String {
    match group_by {
        "actor" => {
            if let Some(actor_id) = group.actor_id {
                user_map.get(&actor_id).cloned().unwrap_or_else(|| format!("User #{}", actor_id))
            } else {
                "System".to_string()
            }
        }
        "session" => {
            if group.key == "system" || group.key.is_empty() {
                "No Session".to_string()
            } else if group.key.len() > 20 {
                format!("{}...", &group.key[..20])
            } else {
                group.key.clone()
            }
        }
        "category" => group.key.clone(),
        _ => group.key.clone(),
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
