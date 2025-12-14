use dioxus::prelude::*;

use crate::app::auth::hooks::use_auth;

#[component]
pub fn AvatarDropDown() -> Element {
    let auth = use_auth();
    let navigator = use_navigator();
    let return_to = use_route::<crate::Routes>().to_string();
    let oidc_link_href = format!("/api/auth/oidc/link?return_to={return_to}");
    let oidc_link_href_onclick = oidc_link_href.clone();

    let user = auth.read().user.clone();
    let username = user.as_ref().map(|u| u.username.clone()).unwrap_or_else(|| "User".to_string());
    let name = user.as_ref().and_then(|u| u.name.clone());
    let picture = user.as_ref().and_then(|u| u.picture.clone());

    // Determine display name (Name > Username)
    let display_name = name.clone().unwrap_or_else(|| username.clone());

    // Determine initial (Name > Username)
    let initial_source = name.clone().unwrap_or_else(|| username.clone());
    let initial = initial_source.chars().next().unwrap_or('?').to_uppercase();

    // Check if user has OIDC linked
    let oidc_status = use_resource(|| async move {
        use crate::app::auth::oidc::get_oidc_link_status;
        get_oidc_link_status().await.ok()
    });

    let on_logout = move |_| {
        navigator.push("/logout");
    };

    rsx! {
        div { class: "dropdown dropdown-end pl-2",
            div {
                tabindex: "0",
                role: "button",
                class: "btn btn-ghost btn-circle avatar placeholder",
                if let Some(pic_url) = picture {
                    div { class: "w-10 rounded-full",
                        img { src: "{pic_url}", alt: "{display_name}" }
                    }
                } else {
                    div { class: "bg-neutral text-neutral-content rounded-full w-10",
                        span { class: "text-xl", "{initial}" }
                    }
                }
            }
            ul {
                tabindex: "-1",
                class: "menu menu-sm dropdown-content bg-base-300 rounded-box mt-2 w-52 p-2 shadow-xl",
                li {
                    class: "menu-title text-base-content opacity-60 px-4",
                    "{display_name}"
                }
                if name.is_some() {
                    li {
                        class: "text-xs opacity-50 text-right",
                        "@{username}"
                    }
                }
                div { class: "divider my-0" }

                // Only show "Link OIDC Account" if not already linked
                {
                    match oidc_status.read().as_ref() {
	                        Some(Some(status)) if !status.is_linked => rsx! {
	                            li {
	                                a {
	                                    onclick: move |evt| {
	                                        // Force a full page navigation to server function routes.
	                                        // Our `/:..route` catch-all means `/api/*` will otherwise be treated
	                                        // as an internal route and end up on NotFound until a hard refresh.
	                                        evt.prevent_default();
	                                        let _ = navigator.push(NavigationTarget::<String>::External(oidc_link_href_onclick.clone()));
	                                    },
	                                    href: "{oidc_link_href}",
	                                    "Link OIDC Account"
	                                }
	                            }
	                        },
	                        _ => rsx! {}
                    }
                }

                li {
                    Link { to: "/profile", "Profile" }
                }

                li {
                    a { onclick: on_logout, "Logout" }
                }
            }
        }
    }
}
