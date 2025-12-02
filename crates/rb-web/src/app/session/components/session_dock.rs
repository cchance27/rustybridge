use dioxus::prelude::*;

use crate::app::session::provider::use_session;

#[component]
pub fn SessionDock() -> Element {
    let session = use_session();
    let sessions = session.sessions();

    if sessions.read().is_empty() {
        return rsx! {};
    }

    rsx! {
        div {
            class: "fixed left-0 top-1/4 z-[60] flex flex-col gap-2 p-2",
            for s in sessions.read().iter() {
                {
                    let id = s.id.clone();
                    let title = s.title.clone();
                    let relay_name = s.relay_name.clone();
                    let minimized = s.minimized;
                    let active_viewers = s.active_viewers;
                    let attachable = s.attachable;

                    rsx! {
                        div {
                            class: "tooltip tooltip-right",
                            "data-tip": "{title}",
                            div { class: "indicator",
                                if active_viewers > 1 {
                                    span {
                                        class: "indicator-item badge badge-warning badge-xs text-[9px] border-none",
                                        style: "right: 4px; top: 4px;",
                                        "{active_viewers}"
                                    }
                                }
                                button {
                                    class: format!(
                                        "btn btn-circle shadow-lg border border-gray-600 {} {}",
                                        if minimized { "btn-ghost bg-base-200 opacity-75" } else { "btn-primary" },
                                        if attachable { "" } else { "cursor-not-allowed opacity-60" }
                                    ),
                                    disabled: !attachable,
                                    onclick: move |_| {
                                        if !attachable {
                                            #[cfg(feature = "web")]
                                            web_sys::console::log_1(&"SessionDock: SSH-origin session is view-only in web".into());
                                            return;
                                        }
                                        if minimized {
                                            session.restore(&id);

                                            #[cfg(feature = "web")]
                                            {
                                                let term_id = format!("term-{}", id);
                                                spawn(async move {
                                                    // Wait for visibility transition
                                                    gloo_timers::future::TimeoutFuture::new(50).await;
                                                    let _ = dioxus::document::eval(&format!("if (window.fitTerminal) window.fitTerminal('{}')", term_id)).await;
                                                    let _ = dioxus::document::eval(&format!("if (window.focusTerminal) window.focusTerminal('{}')", term_id)).await;
                                                });
                                            }
                                        } else {
                                            session.focus(&id);
                                        }
                                    },
                                    // Use first letter of relay name or title
                                    span { class: "text-xs font-bold", "{relay_name.chars().next().unwrap_or('?')}" }
                                }
                                if !attachable {
                                    span {
                                        class: "badge badge-xs badge-error ml-[-6px] mt-[-6px]",
                                        "SSH"
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
