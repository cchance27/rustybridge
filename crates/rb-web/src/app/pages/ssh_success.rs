use dioxus::prelude::*;

#[component]
pub fn SshSuccessPage() -> Element {
    rsx! {
        div { class: "min-h-screen flex items-center justify-center bg-base-200 p-4",
            div { class: "card bg-base-100 shadow-xl max-w-lg w-full",
                div { class: "card-body text-center",
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
                    p { class: "text-lg mb-6",
                        "You have successfully authenticated via OIDC for your SSH session."
                    }

                    // Instructions
                    div { class: "alert alert-success bg-success/10 text-success-content border-success/20 mb-6",
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
                            "You can now close this window and return to your terminal."
                        }
                    }

                    // Actions
                    div { class: "flex flex-col gap-3",
                        button {
                            class: "btn btn-primary w-full",
                            onclick: move |_| {
                                #[cfg(feature = "web")]
                                {
                                    use web_sys::window;
                                    if let Some(window) = window() {
                                        let _ = window.close();
                                    }
                                }
                            },
                            "Close Window"
                        }

                        div { class: "divider text-xs text-base-content/50", "OR" }

                        Link {
                            to: "/",
                            class: "btn btn-outline btn-ghost w-full gap-2",
                            svg {
                                xmlns: "http://www.w3.org/2000/svg",
                                class: "h-5 w-5",
                                fill: "none",
                                view_box: "0 0 24 24",
                                stroke: "currentColor",
                                path {
                                    stroke_linecap: "round",
                                    stroke_linejoin: "round",
                                    stroke_width: "2",
                                    d: "M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"
                                }
                            }
                            "Continue to Dashboard"
                        }
                    }
                }
            }
        }
    }
}
