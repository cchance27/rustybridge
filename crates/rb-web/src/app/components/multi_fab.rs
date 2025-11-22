use dioxus::prelude::*;

#[component]
pub fn MultiFab(on_add_user: EventHandler<()>, on_add_group: EventHandler<()>) -> Element {
    let mut is_open = use_signal(|| false);

    let toggle = move |_| {
        is_open.set(!is_open());
    };

    rsx! {
        div { class: "fixed bottom-8 right-8 flex flex-col-reverse items-center",
            // Main FAB button
            button {
                class: "btn btn-circle btn-primary shadow-lg z-50",
                onclick: toggle,
                svg {
                    xmlns: "http://www.w3.org/2000/svg",
                    class: if is_open() { "h-6 w-6 transform rotate-45 transition-transform" } else { "h-6 w-6 transition-transform" },
                    fill: "none",
                    view_box: "0 0 24 24",
                    stroke: "currentColor",
                    path {
                        stroke_linecap: "round",
                        stroke_linejoin: "round",
                        stroke_width: "2",
                        d: "M12 4v16m8-8H4"
                    }
                }
            }

            // Secondary action buttons (appear when open)
            if is_open() {
                div { class: "flex flex-col-reverse gap-3 animate-fade-in",
                    // Add User button
                    div { class: "tooltip tooltip-left", "data-tip": "Add User",
                        button {
                            class: "btn btn-circle btn-secondary shadow-lg",
                            onclick: move |_| {
                                is_open.set(false);
                                on_add_user.call(());
                            },
                            // User icon (👤)
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
                                    d: "M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"
                                }
                            }
                        }
                    }

                    // Add Group button
                    div { class: "tooltip tooltip-left", "data-tip": "Add Group",
                        button {
                            class: "btn btn-circle btn-accent shadow-lg",
                            onclick: move |_| {
                                is_open.set(false);
                                on_add_group.call(());
                            },
                            // Group icon (👥)
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
                                    d: "M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
