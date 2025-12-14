//! Server Settings admin page for retention configuration and database management.

use crate::app::{
    api::settings::{get_database_stats, get_retention_settings, run_cleanup, update_retention_settings, vacuum_all_databases},
    components::{Layout, toast::use_toast},
};
use dioxus::prelude::*;
use rb_types::audit::{DatabaseStats, RetentionConfig, RetentionPolicy};

/// Admin page for server settings including retention policies
#[component]
pub fn ServerSettings() -> Element {
    // Load current settings and stats
    let settings = use_resource(get_retention_settings);
    let mut stats = use_resource(get_database_stats);
    let mut server_log_level = use_resource(crate::app::api::settings::get_server_log_level);

    // Original config from server (for change detection)
    let mut original_config = use_signal(|| None::<RetentionConfig>);
    // Editable config state
    let mut config = use_signal(RetentionConfig::default);
    let mut save_error = use_signal(|| None::<String>);

    let toast = use_toast();

    // Sync loaded settings to both original and edit state
    use_effect(move || {
        if let Some(Ok(loaded)) = settings() {
            original_config.set(Some(loaded.clone()));
            config.set(loaded);
        }
    });

    // Compute has_changes by comparing to original
    let has_changes = original_config().is_some_and(|orig| orig != config());

    rsx! {
        Layout {
            div { class: "container mx-auto p-6",
                h1 { class: "text-3xl font-bold mb-6", "Server Settings" }

                // Loading state
                if settings().is_none() {
                    div { class: "flex justify-center",
                        span { class: "loading loading-spinner loading-lg" }
                    }
                }

                // Main content
                if settings().is_some() {

                    // Server Log Level Section
                    div { class: "card bg-base-200 p-6 mb-8",
                        div { class: "flex justify-between items-center",
                            div {
                                h2 { class: "text-xl font-semibold", "Logging Configuration" }
                                p { class: "text-sm opacity-70", "Control the verbosity of server-side logs." }
                                match server_log_level() {
                                    Some(Ok(info)) if info.overridden_by_env => rsx! {
                                        p { class: "text-xs opacity-70 mt-1 text-warning",
                                            "Note: the RUST_LOG environment variable is set; runtime log output follows RUST_LOG and may not reflect changes made here."
                                        }
                                    },
                                    _ => rsx! {},
                                }
                            }

                            match server_log_level() {
                                Some(Ok(current_level)) => rsx! {
                                    div { class: "dropdown dropdown-end",
                                        div { tabindex: "0", role: "button", class: "btn m-1",
                                            "{current_level.level.to_uppercase()}"
                                            svg { xmlns: "http://www.w3.org/2000/svg", class: "h-4 w-4 ml-2", fill: "none", view_box: "0 0 24 24", stroke: "currentColor",
                                                path { stroke_linecap: "round", stroke_linejoin: "round", stroke_width: "2", d: "M19 9l-7 7-7-7" }
                                            }
                                        }
                                        ul { tabindex: "0", class: "dropdown-content z-[1] menu p-2 shadow bg-base-100 rounded-box w-52",
                                            for level in ["error", "warn", "info", "debug", "trace"] {
                                                li {
                                                    a {
                                                        class: if current_level.level.to_lowercase() == level { "active" } else { "" },
                                                        onclick: move |_| {
                                                            let lvl = level.to_string();
                                                            spawn(async move {
                                                                use crate::app::api::settings::update_server_log_level;
                                                                match update_server_log_level(lvl).await {
                                                                    Ok(_) => {
                                                                        server_log_level.restart();
                                                                        use_toast().success("Server log level updated");
                                                                    }
                                                                    Err(e) => {
                                                                         use_toast().error(&format!("Failed to update log level: {}", e));
                                                                    }
                                                                }
                                                            });
                                                        },
                                                        "{level.to_uppercase()}"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                },
                                _ => rsx! { span { class: "loading loading-spinner" } }
                            }
                        }
                    }

                    // Retention Policy Section
                    RetentionSection {
                        config: config(),
                        on_change: move |new_config: RetentionConfig| {
                            config.set(new_config);
                        },
                    }

                    // Save button (only shown when there are actual changes)
                    if has_changes {
                        div { class: "mt-6 flex gap-4",
                            button {
                                class: "btn btn-primary",
                                onclick: move |_| {
                                    let cfg = config();
                                    spawn(async move {
                                        match update_retention_settings(cfg.clone()).await {
                                            Ok(()) => {
                                                original_config.set(Some(cfg));
                                                save_error.set(None);
                                                toast.success("Settings saved successfully!");
                                            }
                                            Err(e) => {
                                                save_error.set(Some(e.to_string()));
                                                toast.error(&format!("Failed to save: {}", e));
                                            }
                                        }
                                    });
                                },
                                "Save Changes"
                            }
                            button {
                                class: "btn btn-ghost",
                                onclick: move |_| {
                                    if let Some(orig) = original_config() {
                                        config.set(orig);
                                    }
                                },
                                "Reset"
                            }
                        }
                    }

                    // Error message
                    if let Some(err) = save_error() {
                        div { class: "mt-4",
                            div { class: "alert alert-error",
                                span { "Error: {err}" }
                            }
                        }
                    }

                    // Database Stats Section
                    div { class: "divider mt-8" }
                    DatabaseStatsSection {
                        stats: stats().and_then(|r| r.ok()),
                        on_cleanup: move || {
                            let toast = toast;
                            spawn(async move {
                                match run_cleanup().await {
                                    Ok(res) => {
                                        let msg = format!(
                                            "Cleanup complete ({}ms): {} sessions, {} connections, {} session events, {} orphan events deleted",
                                            res.duration_ms,
                                            res.sessions_deleted,
                                            res.client_sessions_deleted,
                                            res.session_events_deleted,
                                            res.orphan_events_deleted
                                        );
                                        toast.success(&msg);
                                    }
                                    Err(e) => {
                                        toast.error(&format!("Cleanup failed: {}", e));
                                    }
                                }
                                stats.restart();
                            });
                        },
                        on_vacuum: move || {
                            let toast = toast;
                            spawn(async move {
                                match vacuum_all_databases().await {
                                    Ok(res) => {
                                        for res in res {
                                            let msg = format!(
                                                "{} vacuum: file {} KB → {} KB (reclaimed {})",
                                                res.database,
                                                res.file_size_before_kb,
                                                res.file_size_after_kb,
                                                if res.bytes_reclaimed() > 0 {
                                                    format!("{} bytes", res.bytes_reclaimed())
                                                } else {
                                                    "0 bytes".to_string()
                                                }
                                            );
                                            toast.success(&msg);
                                        }
                                    }
                                    Err(e) => {
                                        toast.error(&format!("Vacuum failed: {}", e));
                                    }
                                }
                                stats.restart();
                            });
                        },
                    }
                }
            }
        }
    }
}

/// Retention policy configuration section with 2 policies
#[component]
fn RetentionSection(config: RetentionConfig, on_change: EventHandler<RetentionConfig>) -> Element {
    rsx! {
        div { class: "card bg-base-200 p-6",
            h2 { class: "text-xl font-semibold mb-4", "Retention Policies" }
            p { class: "text-sm opacity-70 mb-6",
                "Configure how long audit data is retained. Leave fields empty to disable a limit."
            }

            // Scheduled tasks configuration - two matching boxes
            div { class: "grid gap-4 grid-cols-1 xl:grid-cols-2 mb-6",
                // Cleanup task configuration
                div { class: "p-4 bg-base-300 rounded-lg",
                    h3 { class: "font-medium mb-4", "Cleanup Task" }
                    p { class: "text-sm opacity-70 mb-4", "Deletes old sessions and events based on retention policies" }

                    div { class: "flex items-center gap-4",
                        label { class: "label", "Interval (seconds)" }
                        input {
                            r#type: "number",
                            class: "input input-bordered input-sm w-32",
                            min: "30",
                            value: "{config.cleanup_interval_secs}",
                            oninput: {
                                let config = config.clone();
                                move |evt| {
                                    if let Ok(val) = evt.value().parse::<u64>() {
                                        let mut new_config = config.clone();
                                        new_config.cleanup_interval_secs = val.max(30);
                                        on_change.call(new_config);
                                    }
                                }
                            },
                        }
                        span { class: "text-sm opacity-70", "Min: 30s, Default: 3600 (1h)" }
                    }
                }

                // Vacuum task configuration
                div { class: "p-4 bg-base-300 rounded-lg",
                    h3 { class: "font-medium mb-4", "Vacuum Task" }
                    p { class: "text-sm opacity-70 mb-4", "Checkpoints WAL and compacts databases to reclaim disk space (causes db-lock, use caution)" }

                    // Enable checkboxes
                    div { class: "flex gap-4 mb-4",
                        label { class: "label cursor-pointer gap-2",
                            input {
                                r#type: "checkbox",
                                class: "checkbox checkbox-sm",
                                checked: config.vacuum.enabled_audit_db,
                                onchange: {
                                    let config = config.clone();
                                    move |evt: FormEvent| {
                                        let mut new_config = config.clone();
                                        new_config.vacuum.enabled_audit_db = evt.checked();
                                        on_change.call(new_config);
                                    }
                                },
                            }
                            span { class: "label-text", "Audit DB" }
                        }
                        label { class: "label cursor-pointer gap-2",
                            input {
                                r#type: "checkbox",
                                class: "checkbox checkbox-sm",
                                checked: config.vacuum.enabled_server_db,
                                onchange: {
                                    let config = config.clone();
                                    move |evt: FormEvent| {
                                        let mut new_config = config.clone();
                                        new_config.vacuum.enabled_server_db = evt.checked();
                                        on_change.call(new_config);
                                    }
                                },
                            }
                            span { class: "label-text", "Server DB" }
                        }
                    }

                    // Interval input
                    div { class: "flex items-center gap-4",
                        label { class: "label", "Interval (seconds)" }
                        input {
                            r#type: "number",
                            class: "input input-bordered input-sm w-32",
                            min: "300",
                            value: "{config.vacuum.interval_secs}",
                            oninput: {
                                let config = config.clone();
                                move |evt| {
                                    if let Ok(val) = evt.value().parse::<u64>() {
                                        let mut new_config = config.clone();
                                        new_config.vacuum.interval_secs = val.max(300);
                                        on_change.call(new_config);
                                    }
                                }
                            },
                        }
                        span { class: "text-sm opacity-70", "Min: 300s (5m), Default: 86400 (24h)" }
                    }
                }
            }

            // Two policy cards
            div { class: "grid gap-6 md:grid-cols-2",
                PolicyCard {
                    title: "Session Data",
                    description: "Relay sessions, recordings, and related events",
                    policy: config.sessions.clone(),
                    on_change: {
                        let config = config.clone();
                        move |p| {
                            let mut new_config = config.clone();
                            new_config.sessions = p;
                            on_change.call(new_config);
                        }
                    },
                }
                PolicyCard {
                    title: "System Events",
                    description: "Events not tied to sessions (logins, config changes, etc.)",
                    policy: config.orphan_events.clone(),
                    on_change: {
                        let config = config.clone();
                        move |p| {
                            let mut new_config = config.clone();
                            new_config.orphan_events = p;
                            on_change.call(new_config);
                        }
                    },
                }
            }
        }
    }
}

/// Individual policy card
#[component]
fn PolicyCard(
    title: &'static str,
    description: &'static str,
    policy: RetentionPolicy,
    on_change: EventHandler<RetentionPolicy>,
) -> Element {
    rsx! {
        div { class: "card bg-base-100 shadow-sm p-4",
            h3 { class: "font-medium mb-2", "{title}" }
            p { class: "text-xs opacity-60 mb-3", "{description}" }

            // Enabled toggle
            div { class: "form-control",
                label { class: "label cursor-pointer justify-start gap-2",
                    input {
                        r#type: "checkbox",
                        class: "toggle toggle-primary",
                        checked: policy.enabled,
                        onchange: {
                            let policy = policy.clone();
                            move |evt: Event<FormData>| {
                                let mut p = policy.clone();
                                p.enabled = evt.checked();
                                on_change.call(p);
                            }
                        },
                    }
                    span { class: "label-text", "Enabled" }
                }
            }

            // Max age
            div { class: "form-control mt-2",
                label { class: "label py-1",
                    span { class: "label-text text-sm", "Max Age (days)" }
                }
                input {
                    r#type: "number",
                    class: "input input-sm input-bordered w-full",
                    placeholder: "No limit",
                    value: policy.max_age_days.map(|v| v.to_string()).unwrap_or_default(),
                    oninput: {
                        let policy = policy.clone();
                        move |evt| {
                            let mut p = policy.clone();
                            p.max_age_days = evt.value().parse().ok();
                            on_change.call(p);
                        }
                    },
                }
            }

            // Max size
            div { class: "form-control mt-2",
                label { class: "label py-1",
                    span { class: "label-text text-sm", "Max Size (KB)" }
                }
                input {
                    r#type: "number",
                    class: "input input-sm input-bordered w-full",
                    placeholder: "No limit",
                    value: policy.max_size_kb.map(|v| v.to_string()).unwrap_or_default(),
                    oninput: {
                        let policy = policy.clone();
                        move |evt| {
                            let mut p = policy.clone();
                            p.max_size_kb = evt.value().parse().ok();
                            on_change.call(p);
                        }
                    },
                }
            }
        }
    }
}

/// Database statistics section with size breakdown
#[component]
fn DatabaseStatsSection(stats: Option<DatabaseStats>, on_cleanup: EventHandler<()>, on_vacuum: EventHandler<()>) -> Element {
    rsx! {
        div { class: "card bg-base-200 p-6",
            div { class: "flex justify-between items-center mb-4",
                h2 { class: "text-xl font-semibold", "Database Statistics" }
                div { class: "flex gap-2",
                    button {
                        class: "btn btn-sm btn-primary",
                        onclick: move |_| on_cleanup.call(()),
                        "Run Cleanup"
                    }
                    button {
                        class: "btn btn-sm btn-secondary",
                        onclick: move |_| on_vacuum.call(()),
                        "Truncate + Vacuum DB"
                    }
                }
            }

            match stats {
                Some(s) => rsx! {
                    // Session Data breakdown
                    div { class: "mb-4",
                        h3 { class: "font-medium text-sm opacity-70 mb-2", "Session Data" }
                        div { class: "stats stats-vertical lg:stats-horizontal shadow w-full",
                            div { class: "stat",
                                div { class: "stat-title", "Total Session Data" }
                                div { class: "stat-value text-lg", "{s.session_data.total_kb} KB" }
                            }
                            div { class: "stat",
                                div { class: "stat-title", "Recordings" }
                                div { class: "stat-value text-sm", "{s.session_data.session_chunks_kb} KB" }
                                div { class: "stat-desc", "{s.row_counts.session_chunks} chunks" }
                            }
                            div { class: "stat",
                                div { class: "stat-title", "Sessions" }
                                div { class: "stat-value text-sm", "{s.session_data.relay_sessions_kb} KB" }
                                div { class: "stat-desc", "{s.row_counts.relay_sessions} sessions" }
                            }
                            div { class: "stat",
                                div { class: "stat-title", "Connections" }
                                div { class: "stat-value text-sm", "{s.session_data.client_sessions_kb} KB" }
                                div { class: "stat-desc", "{s.row_counts.client_sessions} clients" }
                            }
                            div { class: "stat",
                                div { class: "stat-title", "Participants" }
                                div { class: "stat-value text-sm", "{s.session_data.participants_kb} KB" }
                                div { class: "stat-desc", "{s.row_counts.participants} entries" }
                            }
                            div { class: "stat",
                                div { class: "stat-title", "Session Audit Events" }
                                div { class: "stat-value text-sm", "{s.session_data.session_events_kb} KB" }
                                div { class: "stat-desc", "Linked audit events" }
                            }
                        }
                    }

                    // Generic events
                    div { class: "mb-4",
                        h3 { class: "font-medium text-sm opacity-70 mb-2", "System Events (Non-Session Related)" }
                        div { class: "stats shadow",
                            div { class: "stat",
                                div { class: "stat-title", "Generic Audit Events" }
                                div { class: "stat-value text-lg", "{s.orphan_events.events_kb} KB" }
                                div { class: "stat-desc", "{s.row_counts.orphan_events} events" }
                            }
                        }
                    }

                    // Totals summary
                    div { class: "mt-4 text-sm opacity-70 space-y-1",
                        div { "Data total: {s.session_data.total_kb + s.orphan_events.events_kb} KB (sum of tables above)" }
                        div { "Database size: {s.total_size_kb} KB (internal pages)" }
                        div { class: "font-medium", "On-disk size: {s.file_size_kb} KB (includes WAL + unvacuumed space)" }
                    }
                },
                None => rsx! {
                    div { class: "flex justify-center p-8",
                        span { class: "loading loading-spinner" }
                    }
                },
            }
        }
    }
}
