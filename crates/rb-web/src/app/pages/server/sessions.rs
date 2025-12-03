use chrono::{Duration, Utc};
use dioxus::{
    fullstack::{WebSocketOptions, use_websocket}, prelude::*
};
use rb_types::ssh::SessionEvent;

use crate::app::{
    api::{
        sessions::{close_session, list_all_sessions}, ws::session_events::ssh_web_events
    }, auth::hooks::use_auth, components::{
        StructuredTooltip, Table, TooltipSection, icons::{BrowserIcon, TerminalIcon}, use_toast
    }, session::provider::use_session
};

#[component]
pub fn SessionsSection() -> Element {
    let mut sessions = use_resource(|| async move {
        #[cfg(feature = "web")]
        web_sys::console::log_1(&"ServerSessions: Fetching session list".into());

        list_all_sessions().await
    });

    let toast = use_toast();
    let session_ctx = use_session();
    let auth = use_auth();
    let current_user_id = auth.read().user.as_ref().map(|u| u.id);
    let client_id = session_ctx.current_client_id.read().clone();
    let tick = use_signal(|| 0u64);

    // Fallback: If resource hasn't loaded after a reasonable time and WebSocket fails,
    // attempt to restart the resource
    #[cfg(feature = "web")]
    {
        use gloo_timers::future::TimeoutFuture;
        let mut sessions_fallback = sessions;
        use_effect(move || {
            spawn(async move {
                TimeoutFuture::new(5000).await; // Wait 5 seconds
                // Check if resource value is None (still loading)
                if sessions_fallback.value().read().is_none() {
                    #[cfg(feature = "web")]
                    web_sys::console::warn_1(&"ServerSessions: Resource still loading after 5s, attempting restart".into());
                    sessions_fallback.restart();
                }
            });
        });
    }

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

    // Listen for server-wide session changes and refresh the table when events arrive.
    let mut ws = use_websocket(move || {
        let client_id = client_id.clone();
        #[cfg(feature = "web")]
        web_sys::console::log_1(&format!("ServerSessions: Opening WebSocket with client_id: {}", client_id).into());
        async move { ssh_web_events(client_id, Some("all".to_string()), WebSocketOptions::new()).await }
    });

    // Log component lifecycle for debugging
    use_effect(move || {
        #[cfg(feature = "web")]
        web_sys::console::log_1(&"ServerSessions mounted, WebSocket connection active".into());
    });

    {
        let mut sessions_handle = sessions;
        use_coroutine(move |_rx: UnboundedReceiver<()>| async move {
            #[cfg(feature = "web")]
            web_sys::console::log_1(&"ServerSessions: WebSocket event listener starting".into());

            let mut connected = false;
            let mut pending_refresh = false;

            loop {
                // Use a timeout to batch multiple events together
                #[cfg(feature = "server")]
                let event_result = tokio::time::timeout(std::time::Duration::from_millis(100), ws.recv()).await;

                #[cfg(feature = "web")]
                let event_result = {
                    use futures::future::{Either, select};
                    use gloo_timers::future::TimeoutFuture;

                    let recv = Box::pin(ws.recv());
                    let timer = Box::pin(TimeoutFuture::new(100));

                    match select(recv, timer).await {
                        Either::Left((val, _)) => Ok(val),
                        Either::Right(_) => Err(()),
                    }
                };

                match event_result {
                    Ok(Ok(event)) => {
                        if !connected {
                            connected = true;
                            #[cfg(feature = "web")]
                            web_sys::console::log_1(&"ServerSessions: WebSocket connected and receiving events".into());
                        }

                        if matches!(
                            event,
                            SessionEvent::Created(_, _)
                                | SessionEvent::Updated(_, _)
                                | SessionEvent::Removed { .. }
                                | SessionEvent::Presence(_, _)
                        ) {
                            pending_refresh = true;
                        }
                    }
                    Ok(Err(_)) => {
                        #[cfg(feature = "web")]
                        web_sys::console::log_1(&"ServerSessions: WebSocket event listener ended".into());
                        break;
                    }
                    Err(_) => {
                        // Timeout - if we have pending refresh, do it now
                        if pending_refresh {
                            #[cfg(feature = "web")]
                            web_sys::console::log_1(&"ServerSessions: Refreshing session list (debounced)".into());
                            sessions_handle.restart();
                            pending_refresh = false;
                        }
                    }
                }
            }
        });
    }

    let handle_close = move |user_id: i64, relay_id: i64, session_number: u32| {
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
                let relay_sessions: Vec<_> = list.iter().filter(|s| matches!(s.session.kind, rb_types::ssh::SessionKind::Relay)).cloned().collect();
                let shell_sessions: Vec<_> = list.iter().filter(|s| matches!(s.session.kind, rb_types::ssh::SessionKind::TUI)).cloned().collect();
                let web_sessions: Vec<_> = list.iter().filter(|s| matches!(s.session.kind, rb_types::ssh::SessionKind::Web)).cloned().collect();

                rsx! {
                    if list.is_empty() {
                        div { class: "card bg-base-200 shadow-xl self-start w-full",
                            div { class: "card-body",
                                h2 { class: "card-title", "Active Sessions" }
                                p { class: "text-sm opacity-70", "Live view of active Relay, Web and TUI sesions across all users." }
                                div { class: "text-center py-8 opacity-50", "No active sessions." }
                            }
                        }
                    } else {
                        div { class: "card bg-base-200 shadow-xl self-start w-full",
                            div { class: "card-body",
                                h2 { class: "card-title", "Active Relay Sessions" }
                                p { class: "text-sm opacity-70", "Live view of active SSH relays across all users." }
                                if !relay_sessions.is_empty() {
                                div { class: "mb-6",
                                    h3 { class: "text-lg font-semibold mb-2", "Relay Sessions" }
                                    Table {
                                        class: "table table-zebra",
                                        headers: vec!["User", "Relay", "Session #", "IP", "State", "Conns (S/W)", "Viewers (total)", "Created", "Last Active", "Actions"],
                                        for session in relay_sessions {
                                            {
                                                let created = format_local(session.session.created_at);
                                                let last_active_abs = format_local(session.session.last_active_at);
                                                let last_active = format_relative(session.session.last_active_at);
                                                let detached_tip = detached_tooltip(&session.session, tick());
                                                let active_tip = active_tooltip(session.session.created_at, tick());
                                                rsx! {
                                                    tr {
                                                        td { class: "text-center", "{session.username}" }
                                                        td { class: "text-center", "{session.session.relay_name}" }
                                                        td { class: "text-center", "{session.session.session_number}" }
                                                        td { class: "text-center text-sm",
                                                            {session.session.ip_address.as_deref().unwrap_or("N/A")}
                                                        }
                                                        td { class: "text-center",
                                                            match session.session.state {
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
                                                            td { class: "text-center",
                                                                div { class: "flex flex-row items-center gap-1 justify-center",
                                                                div { class: "w-5 h-5 inline-flex", TerminalIcon {} } span { "{session.session.connections.ssh}" }
                                                                div { class: "w-5 h-5 mt-1 inline-flex ml-2", BrowserIcon {} } span { "{session.session.connections.web}" }
                                                        }
                                                    }
                                                        td { class: "text-center",
                                                                div { class: "flex flex-row items-center gap-1 justify-center",
                                                                div { class: "w-5 h-5 inline-flex", TerminalIcon {} } span { "{session.session.viewers.ssh}" }
                                                                div { class: "w-5 h-5 mt-1 inline-flex ml-2", BrowserIcon {} } span { "{session.session.viewers.web}" }
                                                        }}
                                                        td { class: "text-sm text-center", "{created}" }
                                                        td { class: "text-sm text-center", title: "{last_active_abs}",
                                                            { if session.session.active_recent {
                                                                "Active now".to_string()
                                                            } else {
                                                                last_active.clone()
                                                            } }
                                                        }
                                                        td { class: "text-right flex gap-1 justify-end",
                                                            if current_user_id != Some(session.user_id) {
                                                                button {
                                                                    class: "btn btn-xs btn-secondary",
                                                                    onclick: move |_| {
                                                                        session_ctx.open_restored(
                                                                            session.user_id,
                                                                            session.session.relay_name.clone(),
                                                                            session.session.relay_id,
                                                                            session.session.session_number,
                                                                            false,
                                                                            session.session.connections,
                                                                            session.session.viewers,
                                                                            true,
                                                                            Some(session.user_id),
                                                                            Some(session.username.clone()),
                                                                        );
                                                                    },
                                                                    "Attach"
                                                                }
                                                            }
                                                            button {
                                                                class: "btn btn-xs btn-error",
                                                                onclick: move |_| handle_close(session.user_id, session.session.relay_id, session.session.session_number),
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
                            },
                        },
                        div { class: "card bg-base-200 shadow-xl self-start w-full",
                            div { class: "card-body",
                                h2 { class: "card-title", "Active SSH TUI Sessions" }
                                p { class: "text-sm opacity-70", "Live view of active SSH TUI sessions across all users." }
                                if !shell_sessions.is_empty() {
                                div { class: "mb-6",
                                    h3 { class: "text-lg font-semibold mb-2", "Shell Sessions" }
                                    Table {
                                        class: "table table-zebra",
                                        headers: vec!["User", "App", "Session #", "IP", "State", "Conns", "Viewers", "Created", "Last Active", "Actions"],
                                        for session in shell_sessions {
                                            {
                                                let created = format_local(session.session.created_at);
                                                let last_active_abs = format_local(session.session.last_active_at);
                                                let last_active = format_relative(session.session.last_active_at);
                                                let detached_tip = detached_tooltip(&session.session, tick());
                                                let active_tip = active_tooltip(session.session.created_at, tick());
                                                let app_label = match session.session.active_app.as_ref() {
                                                    Some(rb_types::ssh::TUIApplication::Management) => "Management",
                                                    Some(rb_types::ssh::TUIApplication::RelaySelector) => "Relay Selector",
                                                    None => "Unknown",
                                                };
                                                rsx! {
                                                    tr {
                                                        td { class: "text-center", "{session.username}" }
                                                        td { class: "text-center", "{app_label}" }
                                                        td { class: "text-center", "{session.session.session_number}" }
                                                        td { class: "text-center text-sm",
                                                            {session.session.ip_address.as_deref().unwrap_or("N/A")}
                                                        }
                                                        td { class: "text-center",
                                                            match session.session.state {
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
                                                        td { class: "text-center", "{session.session.connections.web + session.session.connections.ssh}" }
                                                        td { class: "text-center", "{session.session.viewers.web + session.session.viewers.ssh}" }
                                                        td { class: "text-sm text-center", "{created}" }
                                                        td { class: "text-sm text-center", title: "{last_active_abs}",
                                                            { if session.session.active_recent {
                                                                "Active now".to_string()
                                                            } else {
                                                                last_active.clone()
                                                            } }
                                                        }
                                                        td { class: "text-right",
                                                            button {
                                                                class: "btn btn-xs btn-error",
                                                                onclick: move |_| handle_close(session.user_id, session.session.relay_id, session.session.session_number),
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
                            },
                        },
                        div { class: "card bg-base-200 shadow-xl self-start w-full",
                            div { class: "card-body",
                                h2 { class: "card-title", "Active Web Sessions" }
                                p { class: "text-sm opacity-70", "Live view of active web sessions across all users." }
                                if !web_sessions.is_empty() {
                                div {
                                    h3 { class: "text-lg font-semibold mb-2", "Web Sessions" }
                                    Table {
                                        class: "table table-zebra",
                                        headers: vec!["User", "IP", "Created", "Last Active"],
                                        for session in web_sessions {
                                            {
                                                let created = format_local(session.session.created_at);
                                                let last_active_abs = format_local(session.session.last_active_at);
                                                let last_active = format_relative(session.session.last_active_at);
                                                rsx! {
                                                    tr {
                                                        td { class: "text-center", "{session.username}" }
                                                        td { class: "text-center text-sm",
                                                            {session.session.ip_address.as_deref().unwrap_or("N/A")}
                                                        }
                                                        td { class: "text-sm text-center", "{created}" }
                                                        td { class: "text-sm text-center", title: "{last_active_abs}",
                                                            { if session.session.active_recent {
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

fn detached_tooltip(summary: &rb_types::ssh::UserSessionSummary, _tick: u64) -> String {
    if let Some(detached_at) = summary.detached_at {
        let elapsed = Utc::now().signed_duration_since(detached_at);
        let elapsed_str = human_duration(elapsed);

        if let Some(timeout_secs) = summary.detached_timeout_secs {
            let total_dur = Duration::seconds(timeout_secs as i64);
            format!("Detached for {} (timeout {}m)", elapsed_str, total_dur.num_minutes())
        } else {
            format!("Detached for {}", elapsed_str)
        }
    } else {
        "Detached".to_string()
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
