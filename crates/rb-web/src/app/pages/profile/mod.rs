use dioxus::prelude::*;
mod sessions;

use crate::{
    app::{
        api::{
            audit::{RecordedSession, list_my_sessions}, ssh_keys::{add_my_ssh_key, delete_my_ssh_key, get_my_ssh_keys}
        }, auth::oidc::get_oidc_link_status, components::{Layout, Modal, Table, use_toast}, session::provider::use_session, storage::{BrowserStorage, StorageType}
    }, components::RequireAuth
};

#[component]
pub fn ProfilePage() -> Element {
    // Resources
    let mut ssh_keys = use_resource(|| async move { get_my_ssh_keys().await });
    let mut oidc_status = use_resource(|| async move { get_oidc_link_status().await.ok() });

    // State
    let toast = use_toast();
    let mut is_add_key_modal_open = use_signal(|| false);
    let mut new_key_value = use_signal(String::new);
    let mut new_key_comment = use_signal(String::new);
    let mut key_validation_error = use_signal(|| None::<String>);
    let mut delete_key_target = use_signal(|| None::<(i64, String)>); // (id, comment/preview)
    let mut oidc_unlink_confirm_open = use_signal(|| false);

    // Actions
    let open_add_key = move |_| {
        new_key_value.set(String::new());
        new_key_comment.set(String::new());
        key_validation_error.set(None);
        is_add_key_modal_open.set(true);
    };

    let handle_add_key = move |_| {
        let key = new_key_value();
        let comment = new_key_comment();

        // Validate SSH key format
        if key.trim().is_empty() {
            key_validation_error.set(Some("Public key is required".to_string()));
            return;
        }

        // Check if key starts with valid SSH key type
        let valid_prefixes = ["ssh-", "ecdsa-sha2-"];
        if !valid_prefixes.iter().any(|prefix| key.trim().starts_with(prefix)) {
            key_validation_error.set(Some(
                "Invalid SSH key format. keys should begin with ssh-* or ecdsa-sha2-*".to_string(),
            ));
            return;
        }

        // Basic structure check: should have at least 2 parts (type and key data)
        let parts: Vec<&str> = key.split_whitespace().collect();
        if parts.len() < 2 {
            key_validation_error.set(Some(
                "Invalid SSH key format. Key should contain the key type and key data".to_string(),
            ));
            return;
        }

        spawn(async move {
            match add_my_ssh_key(key, if comment.is_empty() { None } else { Some(comment) }).await {
                Ok(_) => {
                    is_add_key_modal_open.set(false);
                    toast.success("SSH key added successfully");
                    ssh_keys.restart();
                }
                Err(e) => {
                    toast.error(&format!("Failed to add SSH key: {}", e));
                }
            }
        });
    };

    let handle_delete_key = move |_| {
        if let Some((id, _)) = delete_key_target() {
            spawn(async move {
                match delete_my_ssh_key(id).await {
                    Ok(_) => {
                        delete_key_target.set(None);
                        toast.success("SSH key deleted successfully");
                        ssh_keys.restart();
                    }
                    Err(e) => {
                        toast.error(&format!("Failed to delete SSH key: {}", e));
                    }
                }
            });
        }
    };

    let handle_oidc_link = move |_| {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = web_sys::window()
                .unwrap()
                .location()
                .set_href("/api/auth/oidc/link?return_to=/profile");
        }
    };

    let handle_oidc_unlink = move |_| {
        oidc_unlink_confirm_open.set(true);
    };

    let confirm_oidc_unlink = move |_| {
        spawn(async move {
            use crate::app::auth::oidc::unlink_oidc;
            match unlink_oidc().await {
                Ok(_) => {
                    oidc_unlink_confirm_open.set(false);
                    toast.success("OIDC account unlinked successfully");
                    oidc_status.restart();
                }
                Err(e) => {
                    oidc_unlink_confirm_open.set(false);
                    toast.error(&format!("Failed to unlink OIDC account: {}", e));
                }
            }
        });
    };

    rsx! {
        RequireAuth {
            Layout {

                div { class: "flex flex-col gap-6",
                    // OIDC Section
                    div { class: "card bg-base-200 shadow-xl self-start w-full",
                        div { class: "card-body",
                            h2 { class: "card-title", "Identity Provider" }
                            p { "Link your account to an external identity provider for single sign-on." }

                            match oidc_status() {
                                Some(Some(status)) => rsx! {
                                    div { class: "flex items-center justify-between mt-4",
                                        div { class: "flex items-center gap-4",
                                            if status.is_linked {
                                                div { class: "badge badge-success gap-2 p-3",
                                                    svg { xmlns: "http://www.w3.org/2000/svg", fill: "none", view_box: "0 0 24 24", stroke_width: "1.5", stroke: "currentColor", class: "w-4 h-4",
                                                        path { stroke_linecap: "round", stroke_linejoin: "round", d: "M9 12.75 11.25 15 15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" }
                                                    }
                                                    "Linked"
                                                }
                                                div { class: "text-sm opacity-70",
                                                    if let Some(subject) = status.subject {
                                                        if let Some(provider) = status.provider {
                                                            "Issuer: {provider}, Subject: {subject}"
                                                        } else {
                                                            "Issuer: Unknown, Subject: {subject}"
                                                        }
                                                    } else {
                                                        "Issuer: Unknown, Subject: Unknown"
                                                    }
                                                }
                                            } else {
                                                div { class: "badge badge-ghost gap-2 p-3", "Not Linked" }
                                            }
                                        }

                                        if status.is_linked {
                                            button {
                                                class: "btn btn-outline btn-error btn-sm",
                                                onclick: handle_oidc_unlink,
                                                "Unlink Account"
                                            }
                                        } else {
                                            button {
                                                class: "btn btn-primary btn-sm",
                                                onclick: handle_oidc_link,
                                                "Link Account"
                                            }
                                        }
                                    }
                                },
                                _ => rsx! { span { class: "loading loading-spinner loading-sm" } }
                            }
                        }
                    }

                    // SSH Keys Section
                    div { class: "card bg-base-200 shadow-xl self-start w-full",
                        div { class: "card-body",
                            div { class: "flex justify-between items-center mb-4",
                                div {
                                    h2 { class: "card-title", "SSH Keys" }
                                    p { class: "text-sm opacity-70", "Manage public keys for SSH authentication." }
                                }
                                button { class: "btn btn-primary btn-sm", onclick: open_add_key,
                                    svg { xmlns: "http://www.w3.org/2000/svg", fill: "none", view_box: "0 0 24 24", stroke_width: "1.5", stroke: "currentColor", class: "w-4 h-4 mr-1",
                                        path { stroke_linecap: "round", stroke_linejoin: "round", d: "M12 4.5v15m7.5-7.5h-15" }
                                    }
                                    "Add Key"
                                }
                            }

                            match ssh_keys() {
                                Some(Ok(keys)) => rsx! {
                                    if keys.is_empty() {
                                        div { class: "text-center py-8 opacity-50", "No SSH keys added yet." }
                                    } else {
                                        Table {
                                            class: "table table-zebra table-pin-rows table-fixed",
                                            headers: vec!["Key", "Added", "Actions"],
                                            header_widths: vec![&None, &Some("w-[125px]"), &Some("w-[125px]")],
                                            for key in keys {
                                                tr {
                                                    td {
                                                        div { class: "font-mono text-xs truncate min-w-0 hover:whitespace-normal hover:break-all",
                                                            "{key.public_key}"
                                                        }
                                                        if let Some(comment) = &key.comment {
                                                            div { class: "text-xs opacity-50 mt-1", "{comment}" }
                                                        }
                                                    }
                                                    td { class: "whitespace-nowrap text-sm",
                                                        {
                                                            // Format Unix timestamp to readable date
                                                            #[cfg(target_arch = "wasm32")]
                                                            {
                                                                use web_sys::wasm_bindgen::JsValue;
                                                                let date = js_sys::Date::new(&JsValue::from_f64((key.created_at as f64) * 1000.0));
                                                                date.to_locale_date_string("en-US", &JsValue::UNDEFINED).as_string().unwrap_or_else(|| key.created_at.to_string())
                                                            }
                                                            #[cfg(not(target_arch = "wasm32"))]
                                                            {
                                                                // Server-side: simple date formatting
                                                                // Days since Unix epoch
                                                                let days = key.created_at / 86400;
                                                                // Approximate year calculation (365.25 days per year)
                                                                let year = 1970 + (days as f64 / 365.25) as i64;
                                                                let day_of_year = days - ((year - 1970) as f64 * 365.25) as i64;
                                                                let month = (day_of_year / 30).min(11) + 1;
                                                                let day = (day_of_year % 30) + 1;
                                                                format!("{:04}-{:02}-{:02}", year, month, day)
                                                            }
                                                        }
                                                    }
                                                    td { class: "text-right",
                                                        button {
                                                            class: "btn btn-ghost btn-xs text-error",
                                                            onclick: {
                                                                let id = key.id;
                                                                let preview = key.comment.clone().unwrap_or_else(|| "SSH Key".to_string());
                                                                move |_| delete_key_target.set(Some((id, preview.clone())))
                                                            },
                                                            svg { xmlns: "http://www.w3.org/2000/svg", fill: "none", view_box: "0 0 24 24", stroke_width: "1.5", stroke: "currentColor", class: "w-4 h-4",
                                                                path { stroke_linecap: "round", stroke_linejoin: "round", d: "m14.74 9-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 0 1-2.244 2.077H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 0 0-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 0 0-7.5 0" }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                },
                                Some(Err(e)) => rsx! {
                                    div { class: "alert alert-error", "Error loading SSH keys: {e}" }
                                },
                                None => rsx! {
                                    div { class: "flex justify-center p-4", span { class: "loading loading-spinner" } }
                                }
                            }
                        }
                    }

                    // Web Settings Section
                    div { class: "card bg-base-200 shadow-xl self-start w-full",
                        div { class: "card-body",
                            h2 { class: "card-title", "Web Settings" }
                            p { class: "text-sm opacity-70 mb-4", "Configure browser-specific preferences." }

                            // Snap Behavior Toggle
                            {
                                let session = use_session();
                                let mut snap_to_navbar = session.snap_to_navbar;
                                let is_enabled = snap_to_navbar.read();

                                rsx! {
                                    div { class: "form-control",
                                        label { class: "label cursor-pointer justify-start gap-4",
                                            input {
                                                r#type: "checkbox",
                                                class: "toggle toggle-primary",
                                                checked: *is_enabled,
                                                onchange: move |evt| {
                                                    let new_value = evt.checked();
                                                    snap_to_navbar.set(new_value);
                                                    // Save to localStorage
                                                    let storage = BrowserStorage::new(StorageType::Local);
                                                    let _ = storage.set_json("rb-snap-to-navbar", &new_value);
                                                }
                                            }
                                            div { class: "flex flex-col",
                                                span { class: "label-text font-semibold",
                                                    "Snap Windows Below Navbar"
                                                    span { class: "ml-1 text-primary", "*" }
                                                }
                                                span { class: "label-text-alt opacity-70",
                                                    if *is_enabled {
                                                        "Windows snap below the navigation bar"
                                                    } else {
                                                        "Windows snap to the screen edge"
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    div { class: "text-xs opacity-50 mt-4 pl-1",
                                        span { class: "text-primary", "* " }
                                        "Settings marked with an asterisk are stored locally in your browser and are not synced across devices."
                                    }
                                }
                            }
                        }
                    }

                    // Sessions Section
                    sessions::SessionsSection {}

                    // Session History Section
                    SessionHistorySection {}
                }

                // Add Key Modal
                Modal {
                    open: is_add_key_modal_open(),
                    on_close: move |_| {
                        is_add_key_modal_open.set(false);
                        key_validation_error.set(None);
                    },
                    title: "Add SSH Public Key",
                    actions: rsx! {
                        button {
                            class: "btn btn-primary",
                            onclick: handle_add_key,
                            svg { xmlns: "http://www.w3.org/2000/svg", fill: "none", view_box: "0 0 24 24", stroke_width: "1.5", stroke: "currentColor", class: "w-4 h-4 mr-2",
                                path { stroke_linecap: "round", stroke_linejoin: "round", d: "M12 4.5v15m7.5-7.5h-15" }
                            }
                            "Add Key"
                        }
                    },
                    div { class: "flex flex-col gap-4",
                        if let Some(error) = key_validation_error() {
                            div { class: "alert alert-error",
                                svg { xmlns: "http://www.w3.org/2000/svg", fill: "none", view_box: "0 0 24 24", class: "stroke-current shrink-0 w-6 h-6",
                                    path { stroke_linecap: "round", stroke_linejoin: "round", stroke_width: "2", d: "M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" }
                                }
                                span { "{error}" }
                            }
                        }

                        div { class: "form-control w-full",
                            label { class: "label",
                                span { class: "label-text font-semibold", "Public Key" }
                                span { class: "label-text-alt opacity-70", "Paste your SSH public key" }
                            }
                            textarea {
                                class: if key_validation_error().is_some() {
                                    "textarea textarea-bordered textarea-error h-32 font-mono text-xs w-full"
                                } else {
                                    "textarea textarea-bordered h-32 font-mono text-xs w-full"
                                },
                                placeholder: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...",
                                value: "{new_key_value}",
                                oninput: move |e| {
                                    new_key_value.set(e.value());
                                    key_validation_error.set(None);
                                }
                            }
                            div { class: "label",
                                span { class: "label-text-alt opacity-60", "Supported: RSA, DSA, ECDSA, Ed25519" }
                            }
                        }

                        div { class: "form-control w-full",
                            label { class: "label",
                                span { class: "label-text font-semibold", "Comment " }
                                span { class: "label-text-alt opacity-70", "(Optional)" }
                            }
                            input {
                                r#type: "text",
                                class: "input input-bordered",
                                placeholder: "My Laptop, Work Desktop, etc.",
                                value: "{new_key_comment}",
                                oninput: move |e| new_key_comment.set(e.value())
                            }
                            div { class: "label",
                                span { class: "label-text-alt opacity-60", "Helps you identify this key later" }
                            }
                        }
                    }
                }

                // Delete Confirmation Modal
                Modal {
                    open: delete_key_target().is_some(),
                    on_close: move |_| delete_key_target.set(None),
                    title: "Delete SSH Key",
                    actions: rsx! {
                        button { class: "btn btn-error", onclick: handle_delete_key, "Delete" }
                    },
                    p { "Are you sure you want to delete this SSH key?" }
                    if let Some((_, comment)) = delete_key_target() {
                        p { class: "font-bold mt-2", "{comment}" }
                    }
                }

                // OIDC Unlink Confirmation Modal
                Modal {
                    open: oidc_unlink_confirm_open(),
                    on_close: move |_| oidc_unlink_confirm_open.set(false),
                    title: "Unlink Identity Provider",
                    actions: rsx! {
                        button { class: "btn btn-error", onclick: confirm_oidc_unlink, "Unlink" }
                    },
                    div { class: "flex flex-col gap-4",
                        p { "Are you sure you want to unlink your identity provider?" }
                        div { class: "alert alert-warning",
                            svg { xmlns: "http://www.w3.org/2000/svg", fill: "none", view_box: "0 0 24 24", class: "stroke-current shrink-0 w-6 h-6",
                                path { stroke_linecap: "round", stroke_linejoin: "round", stroke_width: "2", d: "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" }
                            }
                            span { "You will need to use your username and password to log in after unlinking." }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn SessionHistorySection() -> Element {
    let sessions = use_resource(|| async move { list_my_sessions().await });

    rsx! {
        div { class: "card bg-base-200 shadow-xl self-start w-full",
            div { class: "card-body",
                h2 { class: "card-title", "Session History" }
                p { class: "text-sm opacity-70", "View and replay your recorded sessions." }

                match &*sessions.read_unchecked() {
                    Some(Ok(session_list)) => rsx! {
                        if session_list.is_empty() {
                            div { class: "text-center py-8 opacity-50", "No recorded sessions found." }
                        } else {
                            div { class: "overflow-x-auto",
                                table { class: "table table-zebra w-full",
                                    thead {
                                        tr {
                                            th { "Time" }
                                            th { "Relay" }
                                            th { "Session #" }
                                            th { "Duration" }
                                            th { "Status" }
                                            th { "Actions" }
                                        }
                                    }
                                    tbody {
                                        for session in session_list {
                                            SessionHistoryRow { session: session.clone() }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    Some(Err(e)) => rsx! {
                        div { class: "alert alert-error",
                            "Error loading session history: {e}"
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
fn SessionHistoryRow(session: RecordedSession) -> Element {
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
                class: "btn btn-xs btn-ghost",
                "Export ▼"
            }
            ul {
                tabindex: "0",
                class: "dropdown-content menu bg-base-100 rounded-box z-[1] w-52 p-2 shadow",
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
            td {
                span { class: "font-mono text-sm",
                    {session.relay_name.as_deref().unwrap_or("Unknown")}
                }
            }
            td {
                span { class: "badge badge-neutral badge-sm",
                    "#{session.session_number}"
                }
            }
            td { "{duration}" }
            td {
                span {
                    class: if session.end_time.is_some() { "badge badge-success badge-sm" } else { "badge badge-info badge-sm" },
                    "{status}"
                }
            }
            td {
                div { class: "flex gap-2",
                    Link {
                        to: "/admin/sessions/{session.id}/replay",
                        class: "btn btn-xs btn-primary",
                        "Replay"
                    }
                    {export_dropdown}
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
