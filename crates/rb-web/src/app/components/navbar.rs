use dioxus::prelude::*;

use crate::components::{AvatarDropDown, ThemeToggle};

#[component]
pub fn NavBar() -> Element {
    rsx! {
        div { class: "navbar bg-base-200 shadow-sm",
            div { class: "flex-1",
                a { class: "btn btn-ghost text-xl", href: "/", "RustyBridge" }
                ul { class: "menu menu-horizontal px-1",
                    li { Link { to: crate::routes::Routes::DashboardPage {}, "Dashboard" } }
                    li { Link { to: crate::routes::Routes::RelaysPage {}, "Relays" } }
                    li { Link { to: crate::routes::Routes::CredentialsPage {}, "Credentials" } }
                    li { Link { to: crate::routes::Routes::AccessPage {}, "Access" } }
                }
            }

            div { class: "flex-none",

                // CART DROPDOWN
                div { class: "dropdown dropdown-end",
                    div {
                        tabindex: "0",
                        role: "button",
                        class: "btn btn-ghost btn-circle",
                        div { class: "indicator",
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
                                    d: "M3 3h2l.4 2M7 13h10l4-8H5.4M7 13L5.4 5M7 13l-2.293
                                    2.293c-.63.63-.184 1.707.707 1.707H17m0
                                    0a2 2 0 100 4 2 2 0 000-4zm-8
                                    2a2 2 0 11-4 0 2 2 0 014 0z"
                                }
                            }
                        }
                    }
                }

                ThemeToggle {}

                AvatarDropDown {}
            }
        }
    }
}
