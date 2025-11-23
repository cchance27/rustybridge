use dioxus::prelude::*;
use rb_types::auth::{ClaimLevel, ClaimType};

use crate::{
    app::auth::hooks::use_auth, components::{AvatarDropDown, Protected, ThemeToggle}
};

#[component]
pub fn NavBar() -> Element {
    let auth = use_auth();
    let logged_in = auth.read().user.is_some();

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
                        Protected {
                            any_claims: vec![ClaimType::Users(ClaimLevel::View), ClaimType::Groups(ClaimLevel::View)],
                            li { Link { to: crate::Routes::AccessPage {}, "Access" } }
                        }
                    }
                }
            }

            div { class: "flex-none",
                ThemeToggle {}
                if logged_in {
                    AvatarDropDown {}
                }
            }
        }
    }
}
