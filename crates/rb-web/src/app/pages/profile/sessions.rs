use chrono::{Duration, Utc};
use dioxus::{
    fullstack::{WebSocketOptions, use_websocket}, prelude::*
};
use rb_types::ssh::SessionEvent;

use crate::app::{
    api::{
        sessions::{close_session, list_my_sessions}, ws::session_events::ssh_web_events
    }, auth::context::AuthState, components::{StructuredTooltip, Table, TooltipSection, use_toast}, session::provider::use_session
};

#[component]
pub fn SessionsSection() -> Element {
    let mut sessions = use_resource(|| async move { list_my_sessions().await });
    let toast = use_toast();
    let auth = use_context::<Signal<AuthState>>();
    let session = use_session();
    let client_id = session.current_client_id.read().clone();
    let tick = use_signal(|| 0u64);

    // Drive a 1s ticker to refresh relative time/countdown displays
    #[cfg(feature = "web")]
    {
        use gloo_timers::future::TimeoutFuture;
        let mut tick = tick.clone();
        use_coroutine(move |_rx: UnboundedReceiver<()>| async move {
            loop {
                TimeoutFuture::new(1000).await;
                tick += 1;
            }
        });
    }

    let mut ws = use_websocket(move || {
        let client_id = client_id.clone();
        async move { ssh_web_events(client_id, None, WebSocketOptions::new()).await }
    });

    {
        let mut sessions_handle = sessions;
        use_coroutine(move |_rx: UnboundedReceiver<()>| async move {
            while let Ok(event) = ws.recv().await {
                if matches!(
                    event,
                    SessionEvent::Created(_, _) | SessionEvent::Updated(_, _) | SessionEvent::Removed { .. }
                ) {
                    sessions_handle.restart();
                }
            }
        });
    }

    let handle_close = move |relay_id: i64, session_number: u32| {
        let user_id = if let Some(user) = &auth.read().user { user.id } else { return };
        spawn(async move {
            match close_session(user_id, relay_id, session_number).await {
                Ok(_) => {
                    toast.success("Session closed successfully");
                    sessions.restart();
                }
                Err(e) => {
                    toast.error(&format!("Failed to close session: {}", e));
                }
            }
        });
    };

    rsx! {
        match sessions() {
            Some(Ok(list)) => {
                let relay_sessions: Vec<_> = list.iter().filter(|s| matches!(s.kind, rb_types::ssh::SessionKind::Relay)).cloned().collect();
                let shell_sessions: Vec<_> = list.iter().filter(|s| matches!(s.kind, rb_types::ssh::SessionKind::TUI)).cloned().collect();
                let web_sessions: Vec<_> = list.iter().filter(|s| matches!(s.kind, rb_types::ssh::SessionKind::Web)).cloned().collect();

                rsx! {
                    if list.is_empty() {
                        div { class: "card bg-base-200 shadow-xl self-start w-full",
                            div { class: "card-body",
                                h2 { class: "card-title", "Active Sessions" }
                                p { class: "text-sm opacity-70", "Manage your active SSH and Web sessions." }
                                div { class: "text-center py-8 opacity-50", "No active sessions." }
                            }
                        }
                    } else {
                        if !relay_sessions.is_empty() {
                            div { class: "card bg-base-200 shadow-xl self-start w-full",
                                div { class: "card-body",
                                    h2 { class: "card-title", "Active Relay Sessions" }
                                    p { class: "text-sm opacity-70", "Manage your active SSH relays." }
                                    div {
                                        h3 { class: "text-lg font-semibold mb-2", "Relay Sessions" }
                                        Table {
                                            class: "table table-zebra",
                                            headers: vec!["Relay", "Origin", "Session #", "IP", "State", "Conns", "Viewers", "Created", "Last Active", "Actions"],
                                            for session in relay_sessions {
                                                {
                                                    let created = format_local(session.created_at);
                                                    let last_active_abs = format_local(session.last_active_at);
                                                    let last_active = format_relative(session.last_active_at);
                                                    let detached_remain = detached_remaining(&session);
                                                    let detached_tip = detached_tooltip(&session, detached_remain);
                                                    let active_tip = active_tooltip(session.created_at, tick());
                                                    let origin = if session.user_agent.is_some() { "Web" } else { "SSH" };
                                                    rsx! {
                                                        tr {
                                                            td { class: "text-center", "{session.relay_name}" }
                                                            td { class: "text-center", "{origin}" }
                                                            td { class: "text-center", "{session.session_number}" }
                                                            td { class: "text-center text-sm",
                                                                {session.ip_address.as_deref().unwrap_or("N/A")}
                                                            }
                                                            td { class: "text-center",
                                                                match session.state {
                                                                    rb_types::ssh::SessionStateSummary::Attached => rsx! {
                                                                        StructuredTooltip {
                                                                            sections: vec![TooltipSection::without_header().with_items(vec![active_tip.clone()])],
                                                                            span { class: "badge badge-success", "Attached" }
                                                                        }
                                                                    },
                                                                    rb_types::ssh::SessionStateSummary::Detached => rsx! {
                                                                        StructuredTooltip {
                                                                            sections: vec![TooltipSection::without_header().with_items(vec![detached_tip.clone()])],
                                                                            span { class: "badge badge-warning", "Detached" }
                                                                        }
                                                                    },
                                                                    rb_types::ssh::SessionStateSummary::Closed => rsx! { span { class: "badge badge-ghost", "Closed" } },
                                                                }
                                                            }
                                                            td { class: "text-center", "{session.active_connections}" }
                                                            td { class: "text-center", "{session.active_viewers}" }
                                                            td { class: "text-sm text-center", "{created}" }
                                                            td { class: "text-sm text-center", title: "{last_active_abs}",
                                                                { if session.active_recent {
                                                                    "Active now".to_string()
                                                                } else {
                                                                    last_active.clone()
                                                                } }
                                                            }
                                                            td { class: "text-right",
                                                                button {
                                                                    class: "btn btn-xs btn-error",
                                                                    onclick: move |_| handle_close(session.relay_id, session.session_number),
                                                                    "Close"
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

                        if !shell_sessions.is_empty() {
                            div { class: "card bg-base-200 shadow-xl self-start w-full",
                                div { class: "card-body",
                                    h2 { class: "card-title", "Active SSH TUI Sessions" }
                                    p { class: "text-sm opacity-70", "Manage your active SSH TUI sessions." }
                                    div {
                                        h3 { class: "text-lg font-semibold mb-2", "Shell Sessions" }
                                        Table {
                                            class: "table table-zebra",
                                            headers: vec!["Session #", "App", "IP", "State", "Conns", "Viewers", "Created", "Last Active", "Actions"],
                                            for session in shell_sessions {
                                                {
                                                    let created = format_local(session.created_at);
                                                    let last_active_abs = format_local(session.last_active_at);
                                                    let last_active = format_relative(session.last_active_at);
                                                    let detached_remain = detached_remaining(&session);
                                                    let detached_tip = detached_tooltip(&session, detached_remain);
                                                    let active_tip = active_tooltip(session.created_at, tick());
                                                    let app_label = match session.active_app.as_ref() {
                                                        Some(rb_types::ssh::TUIApplication::Management) => "Management",
                                                        Some(rb_types::ssh::TUIApplication::RelaySelector) => "Relay Selector",
                                                        None => "Unknown",
                                                    };
                                                    rsx! {
                                                        tr {
                                                            td { class: "text-center", "{session.session_number}" }
                                                            td { class: "text-center", "{app_label}" }
                                                            td { class: "text-center text-sm",
                                                                {session.ip_address.as_deref().unwrap_or("N/A")}
                                                            }
                                                            td { class: "text-center",
                                                                match session.state {
                                                                    rb_types::ssh::SessionStateSummary::Attached => rsx! {
                                                                        StructuredTooltip {
                                                                            sections: vec![TooltipSection::without_header().with_items(vec![active_tip.clone()])],
                                                                            span { class: "badge badge-success", "Attached" }
                                                                        }
                                                                    },
                                                                    rb_types::ssh::SessionStateSummary::Detached => rsx! {
                                                                        StructuredTooltip {
                                                                            sections: vec![TooltipSection::without_header().with_items(vec![detached_tip.clone()])],
                                                                            span { class: "badge badge-warning", "Detached" }
                                                                        }
                                                                    },
                                                                    rb_types::ssh::SessionStateSummary::Closed => rsx! { span { class: "badge badge-ghost", "Closed" } },
                                                                }
                                                            }
                                                            td { class: "text-center", "{session.active_connections}" }
                                                            td { class: "text-center", "{session.active_viewers}" }
                                                            td { class: "text-sm text-center", "{created}" }
                                                            td { class: "text-sm text-center", title: "{last_active_abs}",
                                                                { if session.active_recent {
                                                                    "Active now".to_string()
                                                                } else {
                                                                    last_active.clone()
                                                                } }
                                                            }
                                                            td { class: "text-right",
                                                                button {
                                                                    class: "btn btn-xs btn-error",
                                                                    onclick: move |_| handle_close(session.relay_id, session.session_number),
                                                                    "Close"
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

                        if !web_sessions.is_empty() {
                            div { class: "card bg-base-200 shadow-xl self-start w-full",
                                div { class: "card-body",
                                    h2 { class: "card-title", "Active Web Sessions" }
                                    p { class: "text-sm opacity-70", "Manage your active web sessions." }
                                    div {
                                        h3 { class: "text-lg font-semibold mb-2", "Web Sessions" }
                                        Table {
                                            class: "table table-zebra",
                                            headers: vec!["IP", "Created", "Last Active"],
                                            for session in web_sessions {
                                                {
                                                    let created = format_local(session.created_at);
                                                    let last_active_abs = format_local(session.last_active_at);
                                                    let last_active = format_relative(session.last_active_at);
                                                    rsx! {
                                                        tr {
                                                            td { class: "text-center text-sm",
                                                                {session.ip_address.as_deref().unwrap_or("N/A")}
                                                            }
                                                            td { class: "text-sm text-center", "{created}" }
                                                            td { class: "text-sm text-center", title: "{last_active_abs}",
                                                                { if session.active_recent {
                                                                    "Active now".to_string()
                                                                } else {
                                                                    last_active.clone()
                                                                } }
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
            },
                    Some(Err(e)) => rsx! {
                        div { class: "alert alert-error", "Error loading sessions: {e}" }
                    },
                    None => rsx! {
                        div { class: "flex justify-center p-4", span { class: "loading loading-spinner" } }
                    }
                }
    }
}

fn format_relative(dt: chrono::DateTime<chrono::Utc>) -> String {
    let now = Utc::now();
    let diff = now - dt;
    if diff.num_seconds() < 0 {
        return "just now".to_string();
    }
    let seconds = diff.num_seconds();
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    let secs = seconds % 60;

    if days > 0 {
        format!("{days}d {hours}h ago")
    } else if hours > 0 {
        format!("{hours}h {minutes}m ago")
    } else if minutes > 0 {
        format!("{minutes}m {secs}s ago")
    } else {
        format!("{secs}s ago")
    }
}

fn format_local(dt: chrono::DateTime<chrono::Utc>) -> String {
    #[cfg(feature = "web")]
    {
        use web_sys::wasm_bindgen::JsValue;
        let js_date = js_sys::Date::new(&JsValue::from_f64(dt.timestamp_millis() as f64));
        let time = js_date.get_time();
        if time.is_nan() {
            return dt.to_rfc3339();
        }
        let year = js_date.get_full_year();
        let month = js_date.get_month() + 1; // JS months are 0-based
        let day = js_date.get_date();
        let hour = js_date.get_hours();
        let minute = js_date.get_minutes();
        let second = js_date.get_seconds();
        return format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}");
    }
    #[cfg(not(feature = "web"))]
    {
        dt.to_rfc3339()
    }
}

fn detached_remaining(summary: &rb_types::ssh::UserSessionSummary) -> Option<Duration> {
    match (summary.detached_timeout_secs, summary.detached_at) {
        (Some(timeout_secs), Some(detached_at)) => {
            let elapsed = Utc::now().signed_duration_since(detached_at);
            let remaining = Duration::seconds(timeout_secs as i64) - elapsed;
            Some(if remaining.num_seconds() < 0 {
                Duration::seconds(0)
            } else {
                remaining
            })
        }
        _ => None,
    }
}

fn detached_tooltip(summary: &rb_types::ssh::UserSessionSummary, remaining: Option<Duration>) -> String {
    match (summary.detached_timeout_secs, remaining) {
        (Some(total_secs), Some(rem)) => {
            let total_dur = Duration::seconds(total_secs as i64);
            format!("Will close in {} (timeout {} mins)", human_duration(rem), total_dur.num_minutes())
        }
        _ => "Detached".to_string(),
    }
}

fn countup_since(dt: chrono::DateTime<chrono::Utc>, tick_secs: u64) -> String {
    let _ = tick_secs; // used to trigger re-render
    let elapsed = Utc::now() - dt;
    human_duration(elapsed)
}

fn active_tooltip(dt: chrono::DateTime<chrono::Utc>, tick_secs: u64) -> String {
    format!("Connected for {}", countup_since(dt, tick_secs))
}

fn human_duration(dur: Duration) -> String {
    let secs = dur.num_seconds().max(0);
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let minutes = (secs % 3_600) / 60;
    let seconds = secs % 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}
