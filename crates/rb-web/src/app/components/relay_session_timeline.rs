//! Session Timeline Component
//!
//! Multi-track timeline visualization for session audit events.

use crate::app::{
    api::relay_session_timeline::{RelaySessionTimelineData, TimelineEvent, get_relay_session_timeline},
    components::icons::{BrowserIcon, TerminalIcon},
};
use dioxus::prelude::*;
use std::collections::HashMap;
/// Track configuration for styling
struct TrackConfig {
    icon: &'static str,
    label: &'static str,
    color: &'static str,
    bg_color: &'static str,
}

fn get_track_config(track: &str) -> TrackConfig {
    match track {
        "lifecycle" => TrackConfig {
            icon: "🔑",
            label: "Session Lifecycle",
            color: "text-success",
            bg_color: "bg-success/20",
        },
        "connections" => TrackConfig {
            icon: "🌐",
            label: "Relay Connections",
            color: "text-info",
            bg_color: "bg-info/20",
        },
        "viewers" => TrackConfig {
            icon: "👁",
            label: "Admin Viewers",
            color: "text-secondary",
            bg_color: "bg-secondary/20",
        },
        _ => TrackConfig {
            // "events" + any other track
            icon: "⚡",
            label: "Events",
            color: "text-warning",
            bg_color: "bg-warning/20",
        },
    }
}

/// Main timeline component
#[component]
pub fn RelaySessionTimeline(session_id: String) -> Element {
    let mut timeline_resource = use_resource(move || {
        let sid = session_id.clone();
        async move { get_relay_session_timeline(sid).await }
    });
    let show_debug = use_signal(|| false);
    let auto_refresh = use_signal(|| false);
    let mut last_updated = use_signal(chrono::Utc::now);

    // Auto-refresh logic
    use_coroutine(move |_: UnboundedReceiver<()>| {
        let mut timeline_resource = timeline_resource;
        async move {
            loop {
                #[cfg(feature = "web")]
                gloo_timers::future::TimeoutFuture::new(5000).await;
                #[cfg(feature = "server")]
                tokio::time::sleep(tokio::time::Duration::from_millis(5000)).await;
                if auto_refresh() {
                    let should_refresh = if let Some(Ok(data)) = &*timeline_resource.read() {
                        data.session_info.status == "Active"
                    } else {
                        false
                    };

                    if should_refresh {
                        timeline_resource.restart();
                        last_updated.set(chrono::Utc::now());
                    }
                }
            }
        }
    });

    // Manual refresh handler
    let refresh = move |_| {
        timeline_resource.restart();
        last_updated.set(chrono::Utc::now());
    };

    rsx! {
        match &*timeline_resource.read_unchecked() {
            Some(Ok(data)) => rsx! {
                TimelineView {
                    data: data.clone(),
                    show_debug,
                    auto_refresh,
                    last_updated: last_updated(),
                    on_refresh: refresh,
                }
            },
            Some(Err(e)) => rsx! {
                div { class: "alert alert-error",
                    "Error loading timeline: {e}"
                }
            },
            None => rsx! {
                div { class: "flex justify-center items-center p-12",
                    span { class: "loading loading-spinner loading-lg" }
                }
            }
        }
    }
}

/// Timeline visualization
#[component]
fn TimelineView(
    data: RelaySessionTimelineData,
    show_debug: Signal<bool>,
    auto_refresh: Signal<bool>,
    last_updated: chrono::DateTime<chrono::Utc>,
    on_refresh: EventHandler<()>,
) -> Element {
    let info = &data.session_info;
    let is_active = info.status == "Active";

    // Determine effective end time (use current time if active)
    let effective_end_time = if is_active {
        // Use last_updated (now) if it's later than start_time
        last_updated.timestamp_millis().max(info.start_time + 1000)
    } else {
        info.end_time.unwrap_or(info.start_time + 60000)
    };

    // Calculate time range
    let (start_time, end_time) = if data.events.is_empty() {
        (info.start_time, effective_end_time)
    } else {
        let min_ts = data.events.iter().map(|e| e.timestamp).min().unwrap_or(info.start_time);
        let max_event_ts = data
            .events
            .iter()
            .map(|e| e.end_timestamp.unwrap_or(e.timestamp))
            .max()
            .unwrap_or(min_ts);

        let max_ts = effective_end_time.max(max_event_ts);

        (min_ts.min(info.start_time), max_ts)
    };

    // Group events by track
    let mut tracks: HashMap<String, Vec<TimelineEvent>> = HashMap::new();
    for event in &data.events {
        // Merge viewers into connections for stacked display, but keep track name if beneficial
        let track_key = if event.track == "viewers" { "connections" } else { &event.track };
        tracks.entry(track_key.to_string()).or_default().push(event.clone());
    }

    // Order tracks
    let track_order = ["lifecycle", "connections", "viewers", "events"];

    rsx! {
        div { class: "flex flex-col gap-4",
            // Header
            SessionHeader {
                info: info.clone(),
                auto_refresh,
                last_updated,
                on_refresh,
            }

            // Time axis
            TimeAxis { start_time, end_time }

            // Tracks
            div { class: "flex flex-col gap-2",
                for track_name in track_order.iter().filter(|t| **t != "viewers") {
                    if tracks.contains_key(*track_name) || *track_name == "lifecycle" {
                        if *track_name == "connections" {
                             StackedConnectionsTrack {
                                events: tracks.get("connections").cloned().unwrap_or_default(),
                                start_time,
                                end_time,
                                is_active,
                            }
                        } else {
                            TimelineTrack {
                                track: track_name.to_string(),
                                events: tracks.get(*track_name).cloned().unwrap_or_default(),
                                start_time,
                                end_time,
                                session_start: info.start_time,
                                session_end: if is_active { None } else { info.end_time }, // Force None if active to use end_time logic
                                is_active,
                            }
                        }
                    }
                }
            }

            // Legend
            Legend {}

            // Debug toggle and table
            div { class: "mt-4",
                button {
                    class: "btn btn-sm btn-ghost",
                    onclick: move |_| show_debug.set(!show_debug()),
                    if show_debug() { "▼ Hide Debug Events" } else { "▶ Show Debug Events ({data.events.len()})" }
                }

                if show_debug() {
                    DebugEventsTable { events: data.events.clone() }
                }
            }
        }
    }
}

/// Session header with metadata
#[component]
fn SessionHeader(
    info: crate::app::api::relay_session_timeline::SessionInfo,
    auto_refresh: Signal<bool>,
    last_updated: chrono::DateTime<chrono::Utc>,
    on_refresh: EventHandler<()>,
) -> Element {
    let username = info.username.as_deref().unwrap_or("Unknown");
    let relay = info.relay_name.as_deref().unwrap_or("Unknown");

    let is_active = info.status == "Active";

    // Use current time for duration if active, otherwise use end_time
    let end_ts_for_duration = if is_active {
        Some(last_updated.timestamp_millis())
    } else {
        info.end_time
    };

    let duration_str = end_ts_for_duration.map(|end| {
        let secs = (end - info.start_time) / 1000;
        if secs >= 3600 {
            format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
        } else if secs >= 60 {
            format!("{}m {}s", secs / 60, secs % 60)
        } else {
            format!("{}s", secs)
        }
    });

    let last_updated_local: chrono::DateTime<chrono::Local> = chrono::DateTime::from(last_updated);
    let last_updated_str = last_updated_local.format("%H:%M:%S").to_string();

    rsx! {
        div { class: "card bg-base-200 shadow-lg",
            div { class: "card-body p-4",
                div { class: "flex flex-wrap items-center justify-between gap-4",
                    div { class: "flex flex-wrap items-center gap-4",
                        h2 { class: "card-title text-xl",
                            "📋 Session Timeline"
                        }
                        div { class: "flex flex-wrap gap-2",
                            span { class: "badge badge-lg badge-primary",
                                "👤 {username}"
                            }
                            span { class: "badge badge-lg badge-secondary",
                                "🖥 {relay}"
                            }
                            span { class: "badge badge-lg badge-neutral",
                                "#{info.session_number}"
                            }
                            if let Some(dur) = duration_str {
                                span { class: "badge badge-lg badge-accent",
                                    "⏱ {dur}"
                                }
                            }
                            span {
                                class: if info.status == "Ended" { "badge badge-lg badge-success" } else { "badge badge-lg badge-info" },
                                "{info.status}"
                            }
                        }
                    }

                    // Controls
                    div { class: "flex items-center gap-3",
                        div { class: "text-xs opacity-50",
                            "Updated: {last_updated_str}"
                        }
                        if is_active {
                            div { class: "form-control",
                                label { class: "label cursor-pointer gap-2",
                                    span { class: "label-text text-xs", "Auto-refresh" }
                                    input {
                                        type: "checkbox",
                                        class: "toggle toggle-sm toggle-primary",
                                        checked: "{auto_refresh}",
                                        onchange: move |e| auto_refresh.set(e.checked()),
                                    }
                                }
                            }
                        }
                        button {
                            class: "btn btn-sm btn-ghost btn-square",
                            title: "Refresh now",
                            onclick: move |_| on_refresh.call(()),
                            "🔄"
                        }
                    }
                }
            }
        }
    }
}

/// Time axis at top of timeline
#[component]
fn TimeAxis(start_time: i64, end_time: i64) -> Element {
    let format_time = |ts: i64| {
        // Convert timestamp (ms) to Local DateTime
        if let Some(dt) = chrono::DateTime::from_timestamp_millis(ts) {
            let local_dt: chrono::DateTime<chrono::Local> = chrono::DateTime::from(dt);
            local_dt.format("%H:%M").to_string()
        } else {
            "--:--".to_string()
        }
    };

    let duration_secs = (end_time - start_time) / 1000;
    let duration_label = if duration_secs >= 3600 {
        format!("{}h {}m", duration_secs / 3600, (duration_secs % 3600) / 60)
    } else if duration_secs >= 60 {
        format!("{}m {}s", duration_secs / 60, duration_secs % 60)
    } else {
        format!("{}s", duration_secs)
    };

    rsx! {
        div { class: "flex items-center gap-2 px-4 py-2 bg-base-200 rounded-lg",
            span { class: "text-sm font-mono opacity-70", "◀ {format_time(start_time)}" }
            div { class: "flex-1 h-1 bg-base-300 rounded relative",
                div { class: "absolute inset-0 bg-gradient-to-r from-primary/50 via-secondary/50 to-accent/50 rounded" }
            }
            span { class: "text-sm font-mono opacity-70", "{format_time(end_time)} ▶" }
            span { class: "badge badge-sm", "Window: {duration_label}" }
        }
    }
}

/// Single timeline track
#[component]
fn TimelineTrack(
    track: String,
    events: Vec<TimelineEvent>,
    start_time: i64,
    end_time: i64,
    session_start: i64,
    session_end: Option<i64>,
    is_active: bool,
) -> Element {
    let config = get_track_config(&track);
    let time_range = (end_time - start_time).max(1) as f64;

    // Calculate position as percentage
    let calc_position = move |ts: i64| -> f64 { ((ts - start_time) as f64 / time_range * 100.0).clamp(0.0, 100.0) };

    rsx! {
        div { class: "flex items-stretch gap-2 min-h-12",
            // Track label
            div { class: "w-40 flex items-center gap-2 px-2 shrink-0 user-select-none",
                span { "{config.icon}" }
                span { class: "text-sm font-medium truncate", "{config.label}" }
            }

            // Track timeline
            div { class: "flex-1 relative bg-base-200 rounded-lg min-h-10 overflow-hidden",
                // Session span for lifecycle track
                if track == "lifecycle" {
                    {
                        let start_pct = calc_position(session_start);
                        // If session_end is None and it's active, it extends to the end of the timeline (now)
                        let end_ts = session_end.unwrap_or(if is_active { end_time } else { session_start });
                        let end_pct = calc_position(end_ts);
                        let width_pct = (end_pct - start_pct).max(0.5); // Ensure at least visible if very short
                        rsx! {
                            div {
                                class: "absolute top-1/2 -translate-y-1/2 h-2 bg-success/30 rounded",
                                style: "left: {start_pct}%; width: {width_pct}%;"
                            }
                        }
                    }
                }

                // Event markers
                for event in events.iter() {
                    {
                        let pos = calc_position(event.timestamp);
                        if let Some(end_ts_val) = event.end_timestamp {
                             // Closed span
                             let end_pos = calc_position(end_ts_val);
                             let width = (end_pos - pos).max(0.2);
                             rsx! {
                                 div {
                                     key: "{event.id}",
                                     class: "absolute top-1/2 -translate-y-1/2 h-4 {config.bg_color} border border-current {config.color} rounded cursor-pointer hover:brightness-110 transition-all",
                                     style: "left: {pos}%; width: {width}%;",
                                     title: "{event.label}",
                                 }
                             }
                        } else if is_active && (event.event_type.contains("connected") || event.event_type.contains("joined") || event.event_type.contains("started")) {
                             // Open span (active) - extends to end_time
                             let end_pos = calc_position(end_time);
                             let width = (end_pos - pos).max(0.2);
                             rsx! {
                                 div {
                                     key: "{event.id}",
                                     class: "absolute top-1/2 -translate-y-1/2 h-4 {config.bg_color} border border-current {config.color} rounded cursor-pointer hover:brightness-110 transition-all opacity-80",
                                     style: "left: {pos}%; width: {width}%;",
                                     title: "{event.label} (Active)",
                                 }
                             }
                        } else {
                            // Point marker
                            rsx! {
                                div {
                                    key: "{event.id}",
                                    class: "absolute top-1/2 -translate-y-1/2 w-3 h-3 rounded-full {config.color} bg-current cursor-pointer hover:scale-150 transition-transform z-10",
                                    style: "left: {pos}%;",
                                    title: "{event.label}",
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Legend for track colors
#[component]
fn Legend() -> Element {
    let tracks = vec!["lifecycle", "connections", "viewers", "events"];

    rsx! {
        div { class: "flex flex-wrap gap-4 justify-center p-4 bg-base-200 rounded-lg",
            for track in tracks {
                {
                    let config = get_track_config(track);
                    rsx! {
                        div { class: "flex items-center gap-2",
                            span { class: "text-lg", "{config.icon}" }
                            span { class: "text-sm {config.color}", "{config.label}" }
                        }
                    }
                }
            }
        }
    }
}

/// Debug table showing raw events for troubleshooting
#[component]
fn DebugEventsTable(events: Vec<TimelineEvent>) -> Element {
    let format_time = |ts: i64| {
        if let Some(dt) = chrono::DateTime::from_timestamp_millis(ts) {
            let local_dt: chrono::DateTime<chrono::Local> = chrono::DateTime::from(dt);
            local_dt.format("%H:%M:%S").to_string()
        } else {
            "Invalid".to_string()
        }
    };

    rsx! {
        div { class: "mt-2 overflow-x-auto bg-base-200 rounded-lg",
            table { class: "table table-xs table-zebra w-full",
                thead {
                    tr {
                        th { "Time" }
                        th { "Track" }
                        th { "Client" }
                        th { "Type" }
                        th { "Label" }
                        th { "Duration" }
                        th { "Details" }
                    }
                }
                tbody {
                    for event in events.iter() {
                        tr { key: "{event.id}",
                            td { class: "font-mono text-xs whitespace-nowrap", "{format_time(event.timestamp)}" }
                            td {
                                span { class: "badge badge-xs {get_track_config(&event.track).color}",
                                    "{event.track}"
                                }
                            }
                            td { class: "flex items-center gap-1",
                                {
                                    let client_type = event.details.get("client_type").and_then(|v| v.as_str());
                                    match client_type {
                                        Some("ssh") => rsx! {
                                            span { class: "w-4 h-4", TerminalIcon {} }
                                        },
                                        Some("web") => rsx! {
                                            span { class: "w-4 h-4", BrowserIcon {} }
                                        },
                                        _ => rsx! { span { "-" } },
                                    }
                                }
                            }
                            td { class: "text-xs", "{event.event_type}" }
                            td { class: "text-xs max-w-48 truncate", "{event.label}" }
                            td { class: "font-mono text-xs",
                                if let Some(end) = event.end_timestamp {
                                    { format!("{}ms", end - event.timestamp) }
                                }
                            }
                            td { class: "text-xs opacity-50 max-w-64 truncate",
                                "{event.details}"
                            }
                        }
                    }
                }
            }
            if events.is_empty() {
                div { class: "p-4 text-center text-sm opacity-50",
                    "No events found for this session"
                }
            }
        }
    }
}

/// Stacked track for connections and viewers
#[component]
fn StackedConnectionsTrack(events: Vec<TimelineEvent>, start_time: i64, end_time: i64, is_active: bool) -> Element {
    let config = get_track_config("connections");
    let time_range = (end_time - start_time).max(1) as f64;
    let calc_position = move |ts: i64| -> f64 { ((ts - start_time) as f64 / time_range * 100.0).clamp(0.0, 100.0) };

    // Group by session_id
    let mut session_groups: HashMap<String, Vec<TimelineEvent>> = HashMap::new();
    for event in &events {
        if let Some(sid) = event.details.get("session_id").and_then(|v| v.as_str()) {
            session_groups.entry(sid.to_string()).or_default().push(event.clone());
        }
    }

    // Sort groups by their start time
    let mut sorted_groups: Vec<(String, Vec<TimelineEvent>)> = session_groups.into_iter().collect();
    sorted_groups.sort_by_key(|(_, evts)| evts.iter().map(|e| e.timestamp).min().unwrap_or(0));

    rsx! {
        div { class: "flex items-stretch gap-2",
             // Label
            div { class: "w-40 flex items-center gap-2 px-2 shrink-0 py-2 user-select-none",
                span { "{config.icon}" }
                span { class: "text-sm font-medium truncate", "{config.label}" }
            }

            // Track area
            div { class: "flex-1 relative bg-base-200 rounded-lg overflow-hidden flex flex-col gap-1 p-1 min-h-[3rem]",
                 if sorted_groups.is_empty() {
                     div { class: "text-xs opacity-50 p-2", "No connections" }
                 }
                 for (_sid, group_events) in sorted_groups {
                     {
                         // Find connection span
                         let conn_event = group_events.iter().find(|e| e.event_type.contains("connected"));
                         // Find viewer spans
                         let view_events: Vec<_> = group_events.iter().filter(|e| e.event_type.contains("viewer_joined")).collect();

                         // Determine row range
                         // let row_start = group_events.iter().map(|e| e.timestamp).min().unwrap_or(start_time);

                         // Check if admin
                         let is_admin = group_events.iter().any(|e| e.details.get("is_admin").and_then(|v| v.as_bool()).unwrap_or(false))
                                     || group_events.iter().any(|e| e.event_type.contains("admin")); // legacy check

                         let username = conn_event.and_then(|e| e.details.get("username").and_then(|v| v.as_str())).unwrap_or("Unknown");

                         rsx! {
                             div { class: "relative h-8 w-full hover:bg-base-300/50 rounded transition-colors",
                                 // Connection line
                                 if let Some(conn) = conn_event {
                                     {
                                         let pos = calc_position(conn.timestamp);
                                         // If open and active, extend to now (end_time)
                                         let end_ts = conn.end_timestamp.unwrap_or(if is_active { end_time } else { conn.timestamp });
                                         let end_pos = calc_position(end_ts);
                                         let width = (end_pos - pos).max(0.1);
                                          let line_bg = if is_admin { "bg-error/40" } else { "bg-info/40" };
                                          rsx! {
                                              div {
                                                  class: "absolute top-1/2 -translate-y-1/2 h-1 {line_bg} rounded opacity-70",
                                                  style: "left: {pos}%; width: {width}%;",
                                              }
                                          }
                                     }
                                 }

                                 // Viewer boxes
                                 for view in view_events {
                                     {
                                         let pos = calc_position(view.timestamp);
                                         // If open and active, extend to now (end_time)
                                         let end_ts = view.end_timestamp.unwrap_or(if is_active { end_time } else { view.timestamp });
                                         let end_pos = calc_position(end_ts);
                                         let width = (end_pos - pos).max(0.5);

                                         let bg_color = if is_admin { "bg-error/20 border-error text-error" } else { "bg-info/20 border-info text-info" };
                                         let border_color = if is_admin { "border-error" } else { "border-info" };

                                          // Tooltip info
                                          let viewer_username = view.details.get("username").and_then(|v| v.as_str()).unwrap_or(username);
                                          // use current duration if active open
                                          let duration_ms = end_ts - view.timestamp;
                                          let tooltip = format!("{} viewed for {}ms", viewer_username, duration_ms);

                                         rsx! {
                                             div {
                                                 class: "absolute top-1/2 -translate-y-1/2 h-6 {bg_color} border {border_color} rounded text-xs px-2 flex items-center overflow-hidden whitespace-nowrap cursor-help transition-all hover:z-10 hover:brightness-110 shadow-sm",
                                                 style: "left: {pos}%; width: {width}%; min-width: 4px;",
                                                  title: "{tooltip}",
                                                  // Client type icon
                                                  {
                                                      let client_type = view.details.get("client_type").and_then(|v| v.as_str());
                                                      match client_type {
                                                          Some("ssh") => rsx! {
                                                              span { class: "w-3 h-3 mr-1 flex-shrink-0", TerminalIcon {} }
                                                          },
                                                          Some("web") => rsx! {
                                                              span { class: "w-3 h-3 mr-1 flex-shrink-0", BrowserIcon {} }
                                                          },
                                                          _ => rsx! {},
                                                      }
                                                  }
                                                  span { class: "font-bold mr-1", "{viewer_username}" }
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
