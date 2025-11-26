use dioxus::prelude::*;

use crate::app::components::Layout;

#[component]
pub fn SshSuccessPage() -> Element {
    rsx! {
        Layout {
            div { class: "flex items-center justify-center p-4",
                div { class: "card bg-base-100 shadow-xl max-w-2xl w-full",
                    div { class: "card-body",
                        // Success icon
                        div { class: "flex justify-center mb-4",
                            div { class: "rounded-full bg-success/10 p-4",
                                svg {
                                    xmlns: "http://www.w3.org/2000/svg",
                                    class: "h-16 w-16 text-success",
                                    fill: "none",
                                    view_box: "0 0 24 24",
                                    stroke: "currentColor",
                                    path {
                                        stroke_linecap: "round",
                                        stroke_linejoin: "round",
                                        stroke_width: "2",
                                        d: "M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                                    }
                                }
                            }
                        }

                        // Title
                        h2 { class: "card-title text-2xl justify-center mb-2",
                            "SSH Authentication Successful"
                        }

                        // Message
                        p { class: "text-center text-lg mb-4",
                            "You have successfully authenticated via OIDC for your SSH session."
                        }

                        // Instructions
                        div { class: "alert alert-info mb-4",
                            svg {
                                xmlns: "http://www.w3.org/2000/svg",
                                class: "stroke-current shrink-0 h-6 w-6",
                                fill: "none",
                                view_box: "0 0 24 24",
                                path {
                                    stroke_linecap: "round",
                                    stroke_linejoin: "round",
                                    stroke_width: "2",
                                    d: "M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                                }
                            }
                            span {
                                "You can now close this window and return to your SSH terminal. ",
                                "Your connection will proceed automatically."
                            }
                        }

                        // Actions
                        div { class: "card-actions justify-center gap-2 mt-4",
                            button {
                                class: "btn btn-primary",
                                onclick: move |_| {
                                    #[cfg(target_arch = "wasm32")]
                                    {
                                        use web_sys::window;
                                        if let Some(window) = window() {
                                            let _ = window.close();
                                        }
                                    }
                                },
                                "Close Window"
                            }
                            Link {
                                to: "/",
                                class: "btn btn-ghost",
                                "Go to Dashboard"
                            }
                        }
                    }
                }
            }
        }
    }
}
