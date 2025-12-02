use dioxus::prelude::*;

use super::session_window::SessionWindow;
#[cfg(feature = "web")]
use crate::app::components::use_toast;
use crate::app::{
    api::relay_list::list_user_relays, auth::hooks::use_auth, session::provider::use_session, storage::{BrowserStorage, StorageType}
};
#[derive(Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
enum DrawerState {
    Closed,
    SessionsOpen,
    RelaysOpen,
}

#[component]
pub fn SessionGlobalChrome(children: Element) -> Element {
    let mut session = use_session();
    let sessions = session.sessions();
    let auth = use_auth();

    // Initialize drawer state from storage
    let mut drawer_state = use_signal(move || {
        if let Some(user) = auth.read().user.as_ref() {
            let storage = BrowserStorage::new(StorageType::Local);
            let key = format!("rb-drawer-{}", user.id);
            storage.get_json(&key).unwrap_or(DrawerState::Closed)
        } else {
            DrawerState::Closed
        }
    });

    // Toast notification hook - used in web feature for event listener
    #[cfg(feature = "web")]
    let toast = use_toast();

    // Helper to update drawer state and persist it
    let mut set_drawer_state = move |new_state: DrawerState| {
        drawer_state.set(new_state);
        if let Some(user) = auth.read().user.as_ref() {
            let storage = BrowserStorage::new(StorageType::Local);
            let key = format!("rb-drawer-{}", user.id);
            let _ = storage.set_json(&key, &new_state);
        }
    };

    // Setup event listener for toast notifications from SessionContext
    use_effect(move || {
        #[cfg(feature = "web")]
        {
            spawn(async move {
                let mut eval = dioxus::document::eval(
                    r#"
                    console.log('Setting up rb-toast-notification listener');
                    window.addEventListener('rb-toast-notification', (event) => {
                        console.log('Received rb-toast-notification event:', event.detail);
                        const detail = event.detail;
                        dioxus.send({
                            message: detail.message,
                            type: detail.type || 'info'
                        });
                    });
                    "#,
                );

                while let Ok(notification) = eval.recv::<serde_json::Value>().await {
                    if let Some(message) = notification.get("message").and_then(|v| v.as_str()) {
                        let type_str = notification.get("type").and_then(|v| v.as_str()).unwrap_or("info");
                        match type_str {
                            "success" => toast.success(message),
                            "error" => toast.error(message),
                            "warning" => toast.warning(message),
                            _ => toast.info(message),
                        }
                    }
                }
            });
        }
    });

    let relays = use_resource(|| async move { list_user_relays().await.unwrap_or_default() });

    // Auto-load existing SSH sessions is now handled in app_root via SessionContext::restore_sessions_from_backend

    // Setup global mouseup handler to clear drag state
    use_effect(move || {
        #[cfg(feature = "web")]
        {
            let session = session;
            spawn(async move {
                let mut eval = dioxus::document::eval(
                    r#"
                    document.addEventListener('mouseup', () => {
                        dioxus.send(true);
                    });
                "#,
                );

                while let Ok(_) = eval.recv::<bool>().await {
                    session.end_drag();
                    session.end_resize();
                }
            });
        }
    });

    rsx! {
        // Main container with mouse handlers for dragging
        div {
            class: "relative min-h-screen flex",
            onmousemove: move |evt| {
                let coords = evt.data.client_coordinates();
                session.update_drag(coords.x as i32, coords.y as i32);
                session.update_resize(coords.x as i32, coords.y as i32);
            },
            onmouseup: move |_| {
                session.end_drag();
                session.end_resize();
            },
            // Close drawers when clicking outside them
            onclick: move |_evt| {
                // Check if click is outside drawer areas
                // The drawers and their buttons will stop propagation via their own onclick handlers
                #[cfg(feature = "web")]
                {
                    use web_sys::wasm_bindgen::JsCast;

                    // Get the event target from the web_sys event
                    if let Some(event) = _evt.data.downcast::<web_sys::MouseEvent>() {
                        if let Some(target) = event.target() {
                            if let Some(element) = target.dyn_ref::<web_sys::Element>() {
                                // Check if click is inside a drawer or drawer button
                                let in_drawer = element.closest(".drawer-container").ok().flatten().is_some()
                                    || element.closest(".drawer-tab-button").ok().flatten().is_some();

                                if !in_drawer && drawer_state() != DrawerState::Closed {
                                    set_drawer_state(DrawerState::Closed);
                                }
                            }
                        }
                    }
                }
            },

            // Left Drawer - Sessions
            div {
                class: if drawer_state() == DrawerState::SessionsOpen {
                    "fixed left-0 top-0 h-full w-80 bg-base-200 shadow-xl z-[201] transition-transform duration-300 transform translate-x-0 drawer-container"
                } else {
                    "fixed left-0 top-0 h-full w-80 bg-base-200 shadow-xl z-[201] transition-transform duration-300 transform -translate-x-full drawer-container"
                },
                onclick: move |evt| {
                    // Stop propagation so clicks inside drawer don't close it
                    evt.stop_propagation();
                },

                div { class: "h-full overflow-y-auto p-4",
                    h2 { class: "text-2xl font-bold mb-4", "Open Sessions" }

                    // Session count indicator
                    div { class: "mb-4 text-sm",
                        span {
                            class: if session.at_capacity() { "text-warning font-semibold" } else { "text-base-content/70" },
                            "{session.session_count()} / 4 sessions"
                        }
                    }

                    if sessions.read().is_empty() {
                        div { class: "text-center text-gray-500 py-8",
                            "No open sessions"
                        }
                    } else {
                        div { class: "space-y-2",
                            {
                                let sessions_read = sessions.read();
                                rsx! {
                                    for s in sessions_read.iter() {
                                        {
                                            let id = s.id.clone();
                                            let relay_name = s.relay_name.clone();
                                            let minimized = s.minimized;
                                            let active_viewers = s.active_viewers;
                                            let attachable = s.attachable;

                                            // Use a stable label based on relay and backend session number
                                            let title = if let Some(num) = s.session_number {
                                                format!("{} #{}", relay_name, num)
                                            } else {
                                                s.title.clone()
                                            };
                                            rsx! {
                                                button {
                                                    class: format!(
                                                        "btn btn-ghost w-full justify-start text-left relative {} {}",
                                                        if minimized { "" } else { "btn-active" },
                                                        if attachable { "" } else { "cursor-not-allowed opacity-60" }
                                                    ),
                                                    disabled: !attachable,
                                                    onclick: move |_| {
                                                        if !attachable {
                                                            #[cfg(feature = "web")]
                                                            web_sys::console::log_1(&"OpenSessions: SSH-origin session is view-only in web".into());
                                                            return;
                                                        }
                                                        if minimized {
                                                            session.restore(&id);
                                                            // Close the drawer when restoring
                                                            drawer_state.set(DrawerState::Closed);

                                                            #[cfg(feature = "web")]
                                                            {
                                                                let term_id = format!("term-{}", id);
                                                                spawn(async move {
                                                                    gloo_timers::future::TimeoutFuture::new(50).await;
                                                                    let _ = dioxus::document::eval(&format!("if (window.fitTerminal) window.fitTerminal('{}')", term_id)).await;
                                                                    let _ = dioxus::document::eval(&format!("if (window.focusTerminal) window.focusTerminal('{}')", term_id)).await;
                                                                });
                                                            }
                                                        } else {
                                                            session.focus(&id);
                                                        }
                                                    },
                                                    span { class: "font-semibold", "{title}" }
                                                    if !attachable {
                                                        span {
                                                            class: "ml-2 badge badge-xs badge-error align-middle",
                                                            "SSH-only"
                                                        }
                                                    }
                                                    if active_viewers > 1 {
                                                        span {
                                                            class: "absolute right-2 top-1/2 transform -translate-y-1/2 badge badge-warning badge-xs",
                                                            "{active_viewers}"
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

            // Left Tab Button
            button {
                class: "fixed left-0 top-1/2 bg-base-200 hover:cursor-pointer shadow-lg z-[200] transition-all duration-300 rounded-r-lg border-r border-t border-b border-base-300 drawer-tab-button",
                style: if drawer_state() == DrawerState::SessionsOpen {
                    "transform: translateX(20rem) translateY(-50%);"
                } else {
                    "transform: translateX(0) translateY(-50%);"
                },
                onclick: move |_| {
                    set_drawer_state(if drawer_state() == DrawerState::SessionsOpen {
                        DrawerState::Closed
                    } else {
                        DrawerState::SessionsOpen
                    });
                },
                div { class: "py-6 px-2 flex items-center justify-center",
                    // Vertical text
                    span {
                        class: "text-xs font-bold tracking-wider",
                        style: "writing-mode: vertical-rl; text-orientation: mixed;",
                        "OPEN SESSIONS"
                    }
                }
            }

            // Right Drawer - Relays
            div {
                class: if drawer_state() == DrawerState::RelaysOpen {
                    "fixed right-0 top-0 h-full w-80 bg-base-200 shadow-xl z-[201] transition-transform duration-300 transform translate-x-0 drawer-container"
                } else {
                    "fixed right-0 top-0 h-full w-80 bg-base-200 shadow-xl z-[201] transition-transform duration-300 transform translate-x-full drawer-container"
                },
                onclick: move |evt| {
                    // Stop propagation so clicks inside drawer don't close it
                    evt.stop_propagation();
                },

                div { class: "h-full overflow-y-auto p-4",
                    h2 { class: "text-2xl font-bold mb-4", "Select Relay" }

                    // Session cap warning banner
                    if session.at_capacity() {
                        div { class: "alert alert-warning mb-4",
                            svg {
                                xmlns: "http://www.w3.org/2000/svg",
                                class: "stroke-current shrink-0 h-6 w-6",
                                fill: "none",
                                view_box: "0 0 24 24",
                                path {
                                    stroke_linecap: "round",
                                    stroke_linejoin: "round",
                                    stroke_width: "2",
                                    d: "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                                }
                            }
                            span { class: "text-sm",
                                "Session limit reached (4/4). Close a session to connect to a new relay."
                            }
                        }
                    }

                    {
                        let relay_data = relays.read();
                        let at_capacity = session.at_capacity();
                        match relay_data.as_ref() {
                            Some(relay_list) => rsx! {
                                if relay_list.is_empty() {
                                    div { class: "text-center text-gray-500 py-8",
                                        "No relay hosts available"
                                    }
                                } else {
                                    ul { class: "space-y-2",
                                        for relay in relay_list {
                                            {
                                                let relay_name = relay.name.clone();
                                                let disabled = at_capacity;
                                                rsx! {
                                                    li {
                                                        key: "{relay.id}",
                                                        button {
                                                            class: if disabled {
                                                                "btn btn-ghost w-full justify-start text-left opacity-50 cursor-not-allowed"
                                                            } else {
                                                                "btn btn-ghost w-full justify-start text-left"
                                                            },
                                                            disabled: disabled,
                                                            onclick: move |_| {
                                                                if !disabled {
                                                                    session.open(relay_name.clone());
                                                                    set_drawer_state(DrawerState::Closed);
                                                                }
                                                            },
                                                            div { class: "flex flex-col items-start",
                                                                span { class: "font-semibold", "{relay.name}" }
                                                                span { class: "text-sm text-gray-500", "{relay.ip}:{relay.port}" }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            None => rsx! {
                                div { class: "flex justify-center py-8",
                                    span { class: "loading loading-spinner loading-lg" }
                                }
                            }
                        }
                    }
                }
            }

            // Right Tab Button
            button {
                class: "fixed right-0 top-1/2 bg-base-200 hover:cursor-pointer shadow-lg z-[200] transition-all duration-300 rounded-l-lg border-l border-t border-b border-base-300 drawer-tab-button",
                style: if drawer_state() == DrawerState::RelaysOpen {
                    "transform: translateX(-20rem) translateY(-50%);"
                } else {
                    "transform: translateX(0) translateY(-50%);"
                },
                onclick: move |_| {
                    set_drawer_state(if drawer_state() == DrawerState::RelaysOpen {
                        DrawerState::Closed
                    } else {
                        DrawerState::RelaysOpen
                    });
                },
                div { class: "py-6 px-2 flex items-center justify-center",
                    // Vertical text
                    span {
                        class: "text-xs font-bold tracking-wider",
                        style: "writing-mode: vertical-rl; text-orientation: mixed;",
                        "RELAYS"
                    }
                }
            }

            // Main content area
            div {
                class: "flex-1 flex flex-col min-h-screen",
                {children}
            }

            // Session Windows - rendered with high z-index
            // Snap Preview
            if let Some(preview) = session.snap_preview.read().as_ref() {
                div {
                    class: "absolute z-[100] bg-blue-500/20 border-2 border-blue-500 rounded-lg pointer-events-none transition-all duration-100",
                    style: format!("left: {}px; top: {}px; width: {}px; height: {}px;", preview.x, preview.y, preview.width, preview.height)
                }
            }

            // Session Windows - rendered with high z-index
            for s in sessions.read().iter() {
                SessionWindow {
                    key: "{s.id}",
                    session_id: s.id.clone()
                }
            }

            // Toast notifications are now handled globally by the provider
        }
    }
}
