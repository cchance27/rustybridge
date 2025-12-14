use crate::app::{
    api::audit::{ListSessionsQuery, RecordedSession, list_sessions},
    components::{Layout, PaginationConfig, SortDirection, Table, TableColumn},
};
use dioxus::prelude::*;

#[component]
pub fn SessionHistory() -> Element {
    let mut page = use_signal(|| 1i64);
    let limit = use_signal(|| 10i64);
    let mut sort_by = use_signal(|| Some("start_time".to_string()));
    let mut sort_dir = use_signal(|| SortDirection::Desc);
    let mut username_filter = use_signal(String::new);
    let mut relay_name_filter = use_signal(String::new);

    let sessions_resource = use_resource(move || {
        let page_val = page();
        let limit_val = limit();
        let sort_by_val = sort_by().clone();
        let sort_dir_val = match sort_dir() {
            SortDirection::Asc => "asc",
            SortDirection::Desc => "desc",
        }
        .to_string();
        let username_val = username_filter();
        let relay_name_val = relay_name_filter();

        async move {
            list_sessions(ListSessionsQuery {
                page: Some(page_val),
                limit: Some(limit_val),
                sort_by: sort_by_val,
                sort_dir: Some(sort_dir_val),
                username_contains: if username_val.is_empty() { None } else { Some(username_val) },
                relay_name_contains: if relay_name_val.is_empty() { None } else { Some(relay_name_val) },
                ..Default::default()
            })
            .await
        }
    });

    let columns = vec![
        TableColumn::new("Time").with_sort("start_time").align_left(),
        TableColumn::new("User").with_sort("user_id").with_filter("username"),
        TableColumn::new("Relay").with_sort("relay_id").with_filter("relay_name"),
        TableColumn::new("Session #").with_width("w-24"),
        TableColumn::new("Size").with_sort("original_size_bytes"),
        TableColumn::new("Duration").with_sort("duration"),
        TableColumn::new("Status"),
        TableColumn::new("Actions").align_right(),
    ];

    rsx! {
        Layout {
            div { class: "container mx-auto p-6",
                div { class: "flex justify-between items-center mb-6",
                    h1 { class: "text-3xl font-bold", "Session History" }
                }

                match &*sessions_resource.read_unchecked() {
                    Some(Ok(paged)) => rsx! {
                        Table {
                            class: "table table-zebra w-full",
                            columns: columns,
                            sort_by: sort_by(),
                            sort_direction: sort_dir(),
                            pagination: PaginationConfig {
                                current_page: page(),
                                total_pages: (paged.total as f64 / limit() as f64).ceil().max(1.0) as i64,
                                limit: limit(),
                            },
                            on_sort: move |key: String| {
                                if sort_by() == Some(key.clone()) {
                                    sort_dir.set(match sort_dir() {
                                        SortDirection::Asc => SortDirection::Desc,
                                        SortDirection::Desc => SortDirection::Asc,
                                    });
                                } else {
                                    sort_by.set(Some(key));
                                    sort_dir.set(SortDirection::Asc);
                                }
                            },
                            on_filter: move |(key, value): (String, String)| {
                                if key == "username" {
                                    username_filter.set(value);
                                    page.set(1);
                                } else if key == "relay_name" {
                                    relay_name_filter.set(value);
                                    page.set(1);
                                }
                            },
                            on_page_change: move |new_page| {
                                page.set(new_page);
                            },
                            if paged.sessions.is_empty() {
                                tr {
                                    td { colspan: "8", class: "text-center py-8",
                                        div { class: "alert alert-info inline-block",
                                            "No sessions found matching your criteria."
                                        }
                                    }
                                }
                            } else {
                                for session in &paged.sessions {
                                    SessionRow { session: session.clone() }
                                }
                            }
                        }
                    },
                    Some(Err(e)) => rsx! {
                        div { class: "alert alert-error",
                            "Error loading sessions: {e}"
                        }
                    },
                    None => rsx! {
                        div { class: "flex justify-center p-8",
                            span { class: "loading loading-spinner loading-lg" }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn SessionRow(session: RecordedSession) -> Element {
    let start_time = format_timestamp(session.start_time);
    let duration = if let Some(end) = session.end_time {
        format_duration(end - session.start_time)
    } else {
        "Active".to_string()
    };

    let status = if session.end_time.is_some() { "Completed" } else { "Active" };

    // Export dropdown with format selection
    let export_dropdown = rsx! {
        div { class: "dropdown dropdown-end",
            div {
                tabindex: "0",
                role: "button",
                class: "btn btn-sm btn-ghost",
                "Export ▼"
            }
            ul {
                tabindex: "0",
                class: "dropdown-content menu bg-base-300 border-1 mt-3 rounded-box z-[1] w-52 p-2 shadow-xl",
                li {
                    a {
                        href: "/api/audit/sessions/{session.id}/export/cast",
                        target: "_blank",
                        rel: "external",
                        download: "session.cast",
                        "Asciicinema (.cast)"
                    }
                }
                li {
                    a {
                        href: "/api/audit/sessions/{session.id}/export/txt",
                        target: "_blank",
                        rel: "external",
                        download: "session.txt",
                        "Plain Text (.txt)"
                    }
                }
            }
        }
    };

    rsx! {
        tr {
            td { "{start_time}" }
            td { class: "text-center",
                span { class: "font-mono text-sm",
                    {session.username.as_deref().unwrap_or("Unknown")}
                }
            }
            td { class: "text-center",
                span { class: "font-mono text-sm",
                    {session.relay_name.as_deref().unwrap_or("Unknown")}
                }
            }
            td { class: "text-center",
                span { class: "badge badge-neutral",
                    "#{session.session_number}"
                }
            }
            td { class: "text-center",
                div { class: "flex flex-col",
                    span { class: "font-mono text-sm opacity-70",
                        {session.original_size_bytes.map(format_bytes).unwrap_or_else(|| "-".to_string())}
                    }
                    if let (Some(orig), Some(comp)) = (session.original_size_bytes, session.compressed_size_bytes) {
                        if orig > 0 {
                            {
                                let ratio = (1.0 - (comp as f64 / orig as f64)) * 100.0;
                                rsx! {
                                    span { class: "text-xs text-success", "(-{ratio:.0}%)" }
                                }
                            }
                        }
                    }
                }
            }
            td { class: "text-center", "{duration}" }
            td { class: "text-center",
                span {
                    class: if session.end_time.is_some() { "badge badge-success" } else { "badge badge-info" },
                    "{status}"
                }
            }
            td { class: "text-right",
                div { class: "flex gap-2 justify-end",
                    {export_dropdown}
                    Link {
                        to: "/admin/sessions/{session.id}/timeline",
                        class: "btn btn-sm btn-ghost",
                        "📋 Timeline"
                    }
                    Link {
                        to: "/admin/sessions/{session.id}/replay",
                        class: "btn btn-sm btn-primary",
                        "▶ Replay"
                    }
                }
            }
        }
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

fn format_duration(ms: i64) -> String {
    let seconds = ms / 1000;
    let minutes = seconds / 60;
    let hours = minutes / 60;

    if hours > 0 {
        format!("{}h {}m", hours, minutes % 60)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds % 60)
    } else {
        format!("{}s", seconds)
    }
}

fn format_bytes(bytes: i64) -> String {
    const UNIT: i64 = 1024;
    if bytes < UNIT {
        return format!("{} B", bytes);
    }
    let exp = (bytes as f64).ln() / (UNIT as f64).ln();
    let pre = "KMGTPE".chars().nth(exp as usize - 1).unwrap_or('?');
    format!("{:.1} {}B", bytes as f64 / (UNIT as f64).powi(exp as i32), pre)
}
