use dioxus::prelude::*;

use crate::app::components::{Layout, RelayDrawer, Terminal};

#[component]
pub fn DashboardPage() -> Element {
    let mut active_relay = use_signal(|| None::<String>);

    // Listen for connection close events from JavaScript
    #[cfg(feature = "web")]
    {
        let mut listener_started = use_signal(|| false);
        use_effect(move || {
            if !listener_started() {
                listener_started.set(true);
                spawn(async move {
                    let mut eval = dioxus::document::eval(
                        r#"
                        console.log("Dashboard: Adding ssh-connection-closed listener");
                        window.addEventListener('ssh-connection-closed', (event) => {
                            dioxus.send(event.detail);
                        });
                        "#,
                    );

                    while let Ok(_) = eval.recv::<serde_json::Value>().await {
                        web_sys::console::log_1(&"Dashboard: Received ssh-connection-closed event".into());
                        active_relay.set(None);
                    }
                });
            }
        });
    }

    rsx! {
        Layout {
            div { class: "flex flex-col h-full p-4 gap-4",
                // Header with relay selection button
                div { class: "flex justify-between items-center",
                    h1 { class: "text-3xl font-bold", "SSH Terminal" }

                    if active_relay().is_none() {
                        label {
                            r#for: "relay-drawer",
                            class: "btn btn-primary",
                            "Select Relay"
                        }
                    } else {
                        div { class: "flex gap-2 items-center",
                            span { class: "text-sm text-gray-600",
                                "Connected to: "
                                span { class: "font-semibold", "{active_relay().as_ref().unwrap()}" }
                            }
                            button {
                                class: "btn btn-sm btn-ghost",
                                onclick: move |_| active_relay.set(None),
                                "Disconnect"
                            }
                        }
                    }
                }

                // Terminal
                div { class: "flex-1 min-h-0",
                    Terminal {
                        id: "main-terminal",
                        fit: true,
                        web_links: true,
                        webgl: true,
                        relay_name: active_relay(),
                    }
                }

                // Relay Drawer
                RelayDrawer {
                    on_select: move |relay_name: String| {
                        #[cfg(feature = "web")]
                        web_sys::console::log_1(&format!("Dashboard: Selected relay: {}", relay_name).into());
                        active_relay.set(Some(relay_name));
                    }
                }
            }
        }
    }
}
