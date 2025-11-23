use dioxus::prelude::*;

use crate::app::auth::hooks::use_auth;

#[component]
pub fn AvatarDropDown() -> Element {
    let auth = use_auth();
    let navigator = use_navigator();

    let username = auth
        .read()
        .user
        .as_ref()
        .map(|u| u.username.clone())
        .unwrap_or_else(|| "User".to_string());
    let initial = username.chars().next().unwrap_or('?').to_uppercase();

    let on_logout = move |_| {
        navigator.push("/logout");
    };

    rsx! {
        div { class: "dropdown dropdown-end pl-2",
            div {
                tabindex: "0",
                role: "button",
                class: "btn btn-ghost btn-circle avatar placeholder",
                div { class: "bg-neutral text-neutral-content rounded-full w-10",
                    span { class: "text-xl", "{initial}" }
                }
            }
            ul {
                tabindex: "-1",
                class: "menu menu-sm dropdown-content bg-base-100 rounded-box z-1 mt-3 w-52 p-2 shadow",
                li {
                    a { class: "pointer-events-none font-bold", "{username}" }
                }
                div { class: "divider my-0" }
                li {
                    a { onclick: on_logout, "Logout" }
                }
            }
        }
    }
}
