use crate::components::Protected;
use dioxus::prelude::*;
use rb_types::auth::{ClaimLevel, ClaimType};

/// A multi-action floating action button (FAB) that expands to show additional actions.
/// Supports "Add User", "Add Group", and "Add Role" actions with role-based access control.
#[component]
pub fn MultiFab(on_add_user: EventHandler<()>, on_add_group: EventHandler<()>, on_add_role: EventHandler<()>) -> Element {
    rsx! {
        div { class: "fab fab-flower",
            // Main FAB button
            div {
                class: "btn btn-circle btn-primary shadow-lg",
                role: "button",
                tabindex: "0",
                svg {
                    xmlns: "http://www.w3.org/2000/svg",
                    class: "h-6 w-6 transition-transform" ,
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

            // Main FAB Close Button
            button {
                class: "btn btn-circle btn-primary shadow-lg fab-main-action",
                svg {
                    xmlns: "http://www.w3.org/2000/svg",
                    class: "h-6 w-6 transform rotate-45 transition-transform",
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
                Protected {
                    claim: Some(ClaimType::Users(ClaimLevel::Create)),
                    // Add User button
                    div { class: "tooltip tooltip-left", "data-tip": "Add User",
                        button {
                            class: "btn btn-circle btn-secondary shadow-lg",
                            onclick: move |_| {
                                //is_open.set(false);
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
                    Protected {
                        claim: Some(ClaimType::Groups(ClaimLevel::Create)),
                        div { class: "tooltip tooltip-left", "data-tip": "Add Group",
                            button {
                                class: "btn btn-circle btn-accent shadow-lg",
                                onclick: move |_| {
                                    //is_open.set(false);
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

                    // Add Role button
                    Protected {
                        claim: Some(ClaimType::Roles(ClaimLevel::Create)),
                        div { class: "tooltip tooltip-left", "data-tip": "Add Role",
                            button {
                                class: "btn btn-circle btn-info shadow-lg",
                                onclick: move |_| {
                                    on_add_role.call(());
                                },
                                // Shield icon (🛡️)
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
                                        d: "M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                                    }
                                }
                            }
                        }
                    }
                }
        }
    }
}
