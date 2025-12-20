use crate::{
    app::{auth::hooks::use_auth, session::provider::use_session},
    components::{AvatarDropDown, Protected, ThemeToggle},
};
use dioxus::prelude::*;
use rb_types::auth::{ClaimLevel, ClaimType};

#[component]
pub fn NavBar() -> Element {
    let auth = use_auth();
    let logged_in = auth.read().user.is_some();
    let session = use_session();
    let active_web_sessions = session.active_web_sessions.read();
    let current_client_id = session.current_client_id.read();
    let time_fmt = "%H:%M:%S %Y-%m-%d";

    // Count sessions with multiple viewers (for tooltip context)
    let shared_ssh_count = session
        .sessions()
        .read()
        .iter()
        .filter(|s| (s.viewers.web + s.viewers.ssh) > 1)
        .count();

    rsx! {
        div { class: "navbar bg-base-200 shadow-sm",
            div { class: "flex-1",
                a { class: "btn btn-ghost text-xl", href: "/", "RustyBridge" }
                ul { class: "menu menu-horizontal px-1",
                    if logged_in {
                        li { Link { to: crate::Routes::DashboardPage {}, "Dashboard" } }

                        Protected {
                            any_claims: vec![ClaimType::Relays(ClaimLevel::View)],
                            li { Link { to: crate::Routes::RelaysPage {}, "Relays" } }
                        }
                        Protected {
                            any_claims: vec![ClaimType::Credentials(ClaimLevel::View)],
                            li { Link { to: crate::Routes::CredentialsPage {}, "Credentials" } }
                        }

                        // Admin Dropdown
                        Protected {
                            any_claims: vec![
                                ClaimType::Server(ClaimLevel::View),
                                ClaimType::Users(ClaimLevel::View),
                                ClaimType::Groups(ClaimLevel::View)
                            ],
                            li {
                                details {
                                    summary { "Admin" }
                                    ul { class: "p-2 bg-base-200 rounded-t-none z-[50]",
                                        Protected {
                                            any_claims: vec![ClaimType::Users(ClaimLevel::View), ClaimType::Groups(ClaimLevel::View)],
                                            li { Link { to: crate::Routes::AccessPage {}, "Access" } }
                                        }
                                        Protected {
                                            any_claims: vec![ClaimType::Server(ClaimLevel::View)],
                                            li { Link { to: crate::Routes::SessionHistory {}, "Sessions" } }
                                        }
                                        Protected {
                                            any_claims: vec![ClaimType::Server(ClaimLevel::View)],
                                            li { Link { to: crate::Routes::AuditEvents {}, "Events" } }
                                        }
                                    }
                                }
                            }
                        }

                        // System Dropdown
                        Protected {
                            any_claims: vec![ClaimType::Server(ClaimLevel::View)],
                            li {
                                details {
                                    summary { "System" }
                                    ul { class: "p-2 bg-base-200 rounded-t-none z-[50]",
                                        li { Link { to: crate::Routes::SystemStatusPage {}, "Status" } }
                                        li { Link { to: crate::Routes::SystemSettingsPage {}, "Settings" } }
                                        li { Link { to: crate::Routes::SystemTasksPage {}, "Tasks" } }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            div { class: "flex-none gap-2",
                if active_web_sessions.len() > 1 {
                    div {
                        class: "dropdown dropdown-end",
                        div {
                            tabindex: "0",
                            role: "button",
                            class: "badge badge-info gap-1 cursor-default mr-2",
                            svg {
                                class: "w-3 h-3",
                                view_box: "0 0 20 20",
                                fill: "currentColor",
                                path {
                                    d: "M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z"
                                }
                            }
                            "{active_web_sessions.len()} Active"
                        }
                        div {
                            tabindex: "0",
                            class: "dropdown-content z-[202] card card-compact w-80 p-2 shadow bg-base-300 text-base-content",
                            div { class: "card-body",
                                h3 { class: "card-title text-sm", "Active Web Sessions" }
                                ul { class: "space-y-2 overflow-x-scroll max-h-[300px]",
                                    for ws in active_web_sessions.iter() {
                                        li { class: "text-xs flex flex-col p-2 bg-base-200 rounded",
                                            div { class: "flex justify-between font-bold",
                                                span { "{ws.ip}" }
                                                if ws.id == *current_client_id {
                                                    span { class: "text-success", "(This Session)" }
                                                }
                                            }
                                            div { class: "text-gray-500 truncate", "{ws.user_agent.as_deref().unwrap_or(\"Unknown\")}" }
                                            div { class: "text-gray-500",
                                                "Connected: {ws.connected_at.format(time_fmt)}"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else if shared_ssh_count > 0 {
                     div {
                        class: "badge badge-warning gap-1 animate-pulse cursor-default mr-2",
                        title: format!("{} sessions are being viewed by multiple people", shared_ssh_count),
                        svg {
                            class: "w-3 h-3",
                            view_box: "0 0 20 20",
                            fill: "currentColor",
                            path {
                                fill_rule: "evenodd",
                                d: "M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z",
                                clip_rule: "evenodd"
                            }
                        }
                        "{shared_ssh_count} Shared"
                    }
                }

                ThemeToggle {}
                if logged_in {
                    AvatarDropDown {}
                }
            }
        }
    }
}
