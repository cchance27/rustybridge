use crate::app::api::relay_list::list_user_relays;
use dioxus::prelude::*;
#[cfg(feature = "web")]
use wasm_bindgen::JsCast;

// Server function is available on both client and server through Dioxus RPC

#[component]
pub fn RelayDrawer(on_select: EventHandler<String>, children: Element) -> Element {
    let relays = use_resource(|| async move { list_user_relays().await.unwrap_or_default() });

    rsx! {
        div {
            class: "drawer drawer-end",
            input {
                id: "relay-drawer",
                r#type: "checkbox",
                class: "drawer-toggle",
            }
            div { class: "drawer-content", {children} }
            div {
                class: "drawer-side z-50",
                label {
                    r#for: "relay-drawer",
                    "aria-label": "close sidebar",
                    class: "drawer-overlay",
                }
                div {
                    class: "menu bg-base-200 text-base-content min-h-full w-80 p-4",
                    h2 { class: "text-2xl font-bold mb-4", "Select Relay" }

                    {
                        let relay_data = relays.read();
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
                                                rsx! {
                                                    li {
                                                        key: "{relay.id}",
                                                        button {
                                                            class: "btn btn-ghost w-full justify-start text-left",
                                                            onclick: move |_| {
                                                                on_select.call(relay_name.clone());
                                                                // Close the drawer using JavaScript
                                                                #[cfg(feature = "web")]
                                                                {
                                                                    spawn(async move {
                                                                        if let Some(window) = web_sys::window() {
                                                                            if let Some(document) = window.document() {
                                                                                if let Some(element) = document.get_element_by_id("relay-drawer") {
                                                                                    if let Ok(input) = element.dyn_into::<web_sys::HtmlInputElement>() {
                                                                                        input.set_checked(false);
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    });
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
        }
    }
}
