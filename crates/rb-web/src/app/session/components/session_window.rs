use dioxus::prelude::*;

use crate::app::{components::Terminal, session::provider::use_session};

#[component]
pub fn SessionWindow(session_id: String) -> Element {
    let session = use_session();
    let sessions = session.sessions();
    let current_session = sessions.read().iter().find(|s| s.id == session_id).cloned();

    if let Some(s) = current_session {
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

        rsx! {
            div {
                class: "{container_class}",
                style: "{container_style}",
                // Focus the window when clicking anywhere in it
                onmousedown: move |_| {
                    session.focus(&session_id);
                },
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
                        span { class: "text-xs font-bold text-gray-300", "{s.title}" }
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
                        button {
                            class: "btn btn-xs btn-ghost text-error hover:bg-red-900",
                            onclick: move |_| {
                                session.close_with_command(&session_id_close);
                            },
                            "X"
                        }
                    }
                }
                // Terminal Content
                div { class: "flex-1 min-h-0 relative bg-black",
                    Terminal {
                        id: format!("term-{}", s.id),
                        relay_name: Some(s.relay_name.clone()),
                        session_number: s.session_number,
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
