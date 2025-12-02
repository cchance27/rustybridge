use dioxus::prelude::*;

use crate::app::{
    components::Terminal, session::provider::{ResizeDirection, use_session}
};

#[component]
pub fn SessionWindow(session_id: String) -> Element {
    let session = use_session();
    let sessions = session.sessions();

    // Read the session data reactively - this will cause re-renders when the signal changes
    let current_session = sessions.read().iter().find(|s| s.id == session_id).cloned();

    if let Some(s) = current_session {
        // SSH-origin relay sessions are not attachable from web; don't render a window
        if !s.attachable {
            return rsx! {};
        }

        let active_viewers = s.viewers.web + s.viewers.ssh;
        let web_viewers = s.viewers.web;
        let ssh_viewers = s.viewers.ssh;
        // Use pre-calculated z-index from session state
        let z_index = if s.fullscreen {
            // When fullscreen, add 40 to ensure it's always on top of windowed sessions
            s.z_index + 40
        } else {
            s.z_index
        };

        // Position and Size - compute style based on fullscreen state
        let container_style = if s.fullscreen {
            // When fullscreen, use fixed positioning
            format!(
                "top: 0px; left: 0px; right: 0px; bottom: 0px; width: auto; height: auto; z-index: {};",
                z_index
            )
        } else {
            // When windowed, use explicit positioning with cached z-index
            format!(
                "top: {}px; left: {}px; width: {}px; height: {}px; z-index: {};",
                s.geometry.y, s.geometry.x, s.geometry.width, s.geometry.height, z_index
            )
        };

        let container_class = if s.minimized {
            "hidden"
        } else if s.fullscreen {
            "fixed inset-0 bg-[#1e1e1e] flex flex-col"
        } else {
            "fixed bg-[#1e1e1e] shadow-xl rounded-lg border border-gray-700 flex flex-col overflow-hidden"
        };

        // Clone session_id multiple times for different closures
        let session_id = s.id.clone();
        let session_id_header = s.id.clone();
        let session_id_minimize = s.id.clone();
        let session_id_fullscreen = s.id.clone();
        let session_id_close = s.id.clone();
        let session_id_terminal = s.id.clone();

        // Confirmation modal state
        let mut show_close_confirm = use_signal(|| false);
        let minimize_session_id = s.id.clone();
        let close_session_id = s.id.clone();

        rsx! {
            // Close Confirmation Modal
            if show_close_confirm() {
                div {
                    class: "modal modal-open z-[100]",
                    div { class: "modal-box bg-[#1e1e1e] border border-gray-700 text-gray-200",
                        h3 { class: "font-bold text-lg text-warning", "Close Shared Session?" }
                        p { class: "py-4",
                            "This session has "
                            span { class: "font-bold text-white", "{active_viewers}" }
                            " active viewers. Closing it will disconnect everyone."
                        }
                        div { class: "modal-action flex-wrap",
                            button {
                                class: "btn btn-sm btn-ghost",
                                onclick: move |_| show_close_confirm.set(false),
                                "Cancel"
                            }
                            button {
                                class: "btn btn-sm btn-primary",
                                onclick: move |_| {
                                    show_close_confirm.set(false);
                                    session.minimize(&minimize_session_id);
                                },
                                "Minimize (Just Me)"
                            }
                            button {
                                class: "btn btn-sm btn-error",
                                onclick: move |_| {
                                    show_close_confirm.set(false);
                                    session.close_with_command(&close_session_id);
                                },
                                "Close (For Everyone)"
                            }
                        }
                    }
                    // Backdrop click to cancel
                    div { class: "modal-backdrop", onclick: move |_| show_close_confirm.set(false) }
                }
            }

            div {
                class: "{container_class}",
                style: "{container_style}",
                tabindex: "0",
                // Focus the window when clicking anywhere in it or tabbing to it
                onfocus: {
                    let session_id = session_id.clone();
                    move |_| {
                        session.focus(&session_id);
                        // Also focus the terminal for immediate typing
                        #[cfg(feature = "web")]
                        {
                            let term_id = format!("term-{}", session_id);
                            spawn(async move {
                                let _ = dioxus::document::eval(&format!("if (window.focusTerminal) window.focusTerminal('{}')", term_id)).await;
                            });
                        }
                    }
                },
                onmousedown: {
                    let session_id = session_id.clone();
                    move |_| {
                        session.focus(&session_id);
                        // Also focus the terminal for immediate typing
                        #[cfg(feature = "web")]
                        {
                            let term_id = format!("term-{}", session_id);
                            spawn(async move {
                                let _ = dioxus::document::eval(&format!("if (window.focusTerminal) window.focusTerminal('{}')", term_id)).await;
                            });
                        }
                    }
                },

                // Resize Handles
                if !s.fullscreen && !s.minimized {
                    {
                        let id_top = s.id.clone();
                        let id_bottom = s.id.clone();
                        let id_left = s.id.clone();
                        let id_right = s.id.clone();
                        let id_tl = s.id.clone();
                        let id_tr = s.id.clone();
                        let id_bl = s.id.clone();
                        let id_br = s.id.clone();

                        rsx! {
                            // Top
                            div {
                                class: "absolute top-0 left-2 right-2 h-1 cursor-ns-resize z-10",
                                onmousedown: move |evt| {
                                    evt.stop_propagation();
                                    let coords = evt.data.client_coordinates();
                                    session.start_resize(id_top.clone(), coords.x as i32, coords.y as i32, ResizeDirection::Top);
                                }
                            }
                            // Bottom
                            div {
                                class: "absolute bottom-0 left-2 right-2 h-1 cursor-ns-resize z-10",
                                onmousedown: move |evt| {
                                    evt.stop_propagation();
                                    let coords = evt.data.client_coordinates();
                                    session.start_resize(id_bottom.clone(), coords.x as i32, coords.y as i32, ResizeDirection::Bottom);
                                }
                            }
                            // Left
                            div {
                                class: "absolute top-2 bottom-2 left-0 w-1 cursor-ew-resize z-10",
                                onmousedown: move |evt| {
                                    evt.stop_propagation();
                                    let coords = evt.data.client_coordinates();
                                    session.start_resize(id_left.clone(), coords.x as i32, coords.y as i32, ResizeDirection::Left);
                                }
                            }
                            // Right
                            div {
                                class: "absolute top-2 bottom-2 right-0 w-1 cursor-ew-resize z-10",
                                onmousedown: move |evt| {
                                    evt.stop_propagation();
                                    let coords = evt.data.client_coordinates();
                                    session.start_resize(id_right.clone(), coords.x as i32, coords.y as i32, ResizeDirection::Right);
                                }
                            }
                            // Top-Left
                            div {
                                class: "absolute top-0 left-0 w-3 h-3 cursor-nwse-resize z-20",
                                onmousedown: move |evt| {
                                    evt.stop_propagation();
                                    let coords = evt.data.client_coordinates();
                                    session.start_resize(id_tl.clone(), coords.x as i32, coords.y as i32, ResizeDirection::TopLeft);
                                }
                            }
                            // Top-Right
                            div {
                                class: "absolute top-0 right-0 w-3 h-3 cursor-nesw-resize z-20",
                                onmousedown: move |evt| {
                                    evt.stop_propagation();
                                    let coords = evt.data.client_coordinates();
                                    session.start_resize(id_tr.clone(), coords.x as i32, coords.y as i32, ResizeDirection::TopRight);
                                }
                            }
                            // Bottom-Left
                            div {
                                class: "absolute bottom-0 left-0 w-3 h-3 cursor-nesw-resize z-20",
                                onmousedown: move |evt| {
                                    evt.stop_propagation();
                                    let coords = evt.data.client_coordinates();
                                    session.start_resize(id_bl.clone(), coords.x as i32, coords.y as i32, ResizeDirection::BottomLeft);
                                }
                            }
                            // Bottom-Right
                            div {
                                class: "absolute bottom-0 right-0 w-3 h-3 cursor-nwse-resize z-20",
                                onmousedown: move |evt| {
                                    evt.stop_propagation();
                                    let coords = evt.data.client_coordinates();
                                    session.start_resize(id_br.clone(), coords.x as i32, coords.y as i32, ResizeDirection::BottomRight);
                                }
                            }
                        }
                    }
                }

                // Header
                div {
                    class: if s.fullscreen {
                        "h-8 bg-gray-800 flex items-center justify-between px-2 select-none border-b border-gray-700"
                    } else {
                        "h-8 bg-gray-800 flex items-center justify-between px-2 cursor-move select-none border-b border-gray-700"
                    },
                    onmousedown: move |evt| {
                        session.focus(&session_id_header);

                        // Only start dragging if not fullscreen
                        if !s.fullscreen {
                            let coords = evt.data.client_coordinates();
                            session.start_drag(session_id_header.to_owned(), coords.x as i32, coords.y as i32);
                        }

                        // Also trigger focus on the terminal window itself
                        #[cfg(feature = "web")]
                        {
                            let term_id = format!("term-{}", session_id_header);
                            spawn(async move {
                                let _ = dioxus::document::eval(&format!("window.focusTerminal('{}')", term_id)).await;
                            });
                        }
                    },

                    div { class: "flex items-center gap-2",
                        {
                            let sessions_read = sessions.read();
                            let relay_name = s.relay_name.clone();
                            let same_relay_count = sessions_read.iter().filter(|sess| sess.relay_name == relay_name).count();

                            let title = if s.is_admin_attached {
                                if let Some(target_user) = &s.attached_to_username {
                                    format!("[{}] {} #{}", target_user, s.relay_name, s.session_number.unwrap_or(0))
                                } else {
                                    format!("[Unknown] {} #{}", s.relay_name, s.session_number.unwrap_or(0))
                                }
                            } else if same_relay_count > 1 {
                                // Find our index among sessions with same relay name
                                let index = sessions_read.iter()
                                    .filter(|sess| sess.relay_name == relay_name)
                                    .position(|sess| sess.id == s.id)
                                    .map(|i| i + 1)
                                    .unwrap_or(1);
                                format!("{} #{}", s.title, index)
                            } else {
                                s.title.clone()
                            };

                            rsx! {
                                span { class: "text-xs font-bold text-gray-300", "{title}" }
                            }
                        }
                    }

                    div { class: "flex gap-1",
                        button {
                            class: "btn btn-xs btn-ghost text-gray-400 hover:text-white",
                            onclick: move |_| session.minimize(&session_id_minimize),
                            "_"
                        }
                        button {
                            class: "btn btn-xs btn-ghost text-gray-400 hover:text-white",
                            onclick: move |_| {
                                // If toggling fullscreen, trigger fit
                                session.toggle_fullscreen(&session_id_fullscreen);

                                #[cfg(feature = "web")]
                                {
                                    let term_id = format!("term-{}", session_id_fullscreen);
                                    spawn(async move {
                                        // Wait for transition/render
                                        gloo_timers::future::TimeoutFuture::new(50).await;
                                        let _ = dioxus::document::eval(&format!("if (window.fitTerminal) window.fitTerminal('{}')", term_id)).await;
                                        let _ = dioxus::document::eval(&format!("if (window.focusTerminal) window.focusTerminal('{}')", term_id)).await;
                                    });
                                }
                            },
                            "[]"
                        }
                        if s.is_admin_attached {
                            button {
                                class: "btn btn-xs btn-ghost text-error hover:bg-red-900 py-2",
                                title: "Detach from session",
                                onclick: move |evt| {
                                    evt.stop_propagation();
                                    // Admin just detaches locally
                                    session.close(&session_id_close);
                                },
                                span { class: "w-4 h-4",
                                    crate::app::components::icons::DisconnectIcon {}
                                }
                            }
                        } else {
                            button {
                                class: "btn btn-xs btn-ghost text-error hover:bg-red-900",
                                onclick: move |evt| {
                                    evt.stop_propagation();

                                    // If multiple viewers (active windows), confirm before closing
                                    if active_viewers > 1 {
                                        show_close_confirm.set(true);
                                    } else {
                                        session.close_with_command(&session_id_close);
                                    }
                                },
                                "X"
                            }
                        }
                    }
                }
                // Terminal Content
                div { class: "flex-1 min-h-0 relative bg-black",
                    // Multi-session warning bar - only show if multiple viewers have window open OR if admin is viewing
                    if active_viewers > 1 || !s.admin_viewers.is_empty() {
                        div {
                            class: if !s.admin_viewers.is_empty() {
                                "bg-red-900/90 text-white items-center text-xs px-3 py-1.5 flex justify-between gap-2 border-b border-red-700"
                            } else {
                                "bg-yellow-600 items-center text-black text-xs px-3 py-1.5 flex justify-between gap-2 border-b border-yellow-700"
                            },
                            div {
                                class: "flex flex-row items-center gap-2",
                                if !s.admin_viewers.is_empty() {
                                    svg {
                                        class: "w-4 h-4 flex-shrink-0 text-white animate-pulse",
                                        view_box: "0 0 24 24",
                                        fill: "none",
                                        stroke: "currentColor",
                                        stroke_width: "2",
                                        path {
                                            stroke_linecap: "round",
                                            stroke_linejoin: "round",
                                            d: "M15 12a3 3 0 11-6 0 3 3 0 016 0z"
                                        }
                                        path {
                                            stroke_linecap: "round",
                                            stroke_linejoin: "round",
                                            d: "M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"
                                        }
                                    }
                                    span {
                                        class: "font-bold uppercase tracking-wider",
                                        "ADMIN VIEWING"
                                    }
                                } else {
                                    svg {
                                        class: "w-4 h-4 flex-shrink-0",
                                        view_box: "0 0 20 20",
                                        fill: "currentColor",
                                        path {
                                            fill_rule: "evenodd",
                                            d: "M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z",
                                            clip_rule: "evenodd"
                                        }
                                    }
                                    span {
                                        class: "font-semibold",
                                        "{active_viewers} viewers connected to this shell"
                                    }
                                }
                            }
                            div {
                                div { class: "flex items-center gap-1 font-semibold",
                                    div { class: "w-5 h-5 inline-flex", crate::app::components::icons::TerminalIcon {} }
                                    span { "{ssh_viewers}" }
                                    div { class: "ml-2 w-5 h-5 mt-1inline-flex", crate::app::components::icons::BrowserIcon {} }
                                    span { "{web_viewers}" }
                                }
                            }
                        }
                    }
                    Terminal {
                        id: format!("term-{}", s.id),
                        relay_name: Some(s.relay_name.clone()),
                        session_number: s.session_number,
                        target_user_id: s.target_user_id,
                        minimized: s.minimized,
                        on_close: move |_| {
                            // When the SSH session ends, close the window
                            session.close(&session_id_terminal);
                        },
                        on_window_close: move |_| {
                            // User clicked X - Terminal will send close command
                        },
                    }
                }
            }
        }
    } else {
        rsx! {}
    }
}
