use crate::app::auth::hooks::{use_auth, use_has_all_claims, use_has_any_claim, use_has_claim};
use dioxus::prelude::*;
use rb_types::auth::ClaimType;

/// Route guard component that requires authentication and optional claims
///
/// Redirects to /login if not authenticated, shows 403 if missing required claims.
///
/// # Examples
///
/// ```text
/// // Require authentication only
/// Route { to: "/dashboard", RequireAuth { DashboardPage {} } }
///
/// // Require specific claim
/// Route { to: "/relays", RequireAuth { claim: "relays:view", RelaysPage {} } }
///
/// // Require any of multiple claims
/// Route {
///     to: "/admin",
///     RequireAuth {
///         any_claims: vec!["users:view".into(), "groups:view".into()],
///         AdminPage {}
///     }
/// }
/// ```
#[component]
pub fn RequireAuth(
    /// Single claim required (mutually exclusive with any_claims/all_claims)
    claim: Option<ClaimType<'static>>,

    /// Any of these claims required (mutually exclusive with claim/all_claims)
    any_claims: Option<Vec<ClaimType<'static>>>,

    /// All of these claims required (mutually exclusive with claim/any_claims)
    all_claims: Option<Vec<ClaimType<'static>>>,

    /// Page content to show when authorized
    children: Element,
) -> Element {
    let auth = use_auth();
    let nav = navigator();

    // Redirect to login if not authenticated
    use_effect(move || {
        let auth_state = auth.read();
        if !auth_state.loading && auth_state.user.is_none() {
            nav.push("/login");
        }
    });

    // Show loading while checking auth
    if auth.read().loading {
        return rsx! {
            div { class: "flex items-center justify-center min-h-screen",
                span { class: "loading loading-spinner loading-lg" }
            }
        };
    }

    // User not authenticated
    if auth.read().user.is_none() {
        return rsx! { div {} }; // Will redirect via effect
    }

    // Check claims if specified
    let has_permission = if let Some(c) = claim {
        use_has_claim(&c)
    } else if let Some(claims) = any_claims {
        use_has_any_claim(claims)
    } else if let Some(claims) = all_claims {
        use_has_all_claims(claims)
    } else {
        true // No specific claim required, just authentication
    };

    if !has_permission {
        return rsx! {
            div { class: "hero min-h-screen bg-base-200",
                div { class: "hero-content text-center",
                    div {
                        h1 { class: "text-5xl font-bold", "403" }
                        p { class: "py-6", "You don't have permission to access this page." }
                        Link { to: "/", class: "btn btn-primary", "Go Home" }
                    }
                }
            }
        };
    }

    rsx! { {children} }
}
