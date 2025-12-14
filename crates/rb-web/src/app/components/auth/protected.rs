use crate::app::auth::hooks::{use_auth, use_has_all_claims, use_has_any_claim, use_has_claim};
use dioxus::prelude::*;
use rb_types::auth::ClaimType;

/// Protected component for claim-based conditional rendering
///
/// Shows children only if user has required claims, otherwise shows fallback (or nothing).
///
/// # Examples
///
/// ```text
/// // Hide button for users without create permission
/// rsx! {
///     Protected {
///         claim: "users:create",
///         button { class: "btn btn-primary", "Add User" }
///     }
/// }
///
/// // Show fallback for unauthorized users
/// rsx! {
///     Protected {
///         claim: "relays:view",
///         fallback: rsx! { p { "You don't have permission to view relays" } },
///         RelayList {}
///     }
/// }
///
/// // Require any of multiple claims
/// rsx! {
///     Protected {
///         any_claims: vec!["users:view".to_string(), "groups:view".to_string()],
///         Link { to: "/admin", "Admin Panel" }
///     }
/// }
/// ```
#[component]
pub fn Protected(
    /// Single claim required (mutually exclusive with any_claims/all_claims)
    claim: Option<ClaimType<'static>>,

    /// Any of these claims required (mutually exclusive with claim/all_claims)
    any_claims: Option<Vec<ClaimType<'static>>>,

    /// All of these claims required (mutually exclusive with claim/any_claims)
    all_claims: Option<Vec<ClaimType<'static>>>,

    /// Content to show when user doesn't have required claims
    fallback: Option<Element>,

    /// Content to show when user has required claims
    children: Element,
) -> Element {
    let auth = use_auth();

    // Determine if user is authorized
    let is_authorized = if let Some(c) = claim {
        use_has_claim(&c)
    } else if let Some(claims) = any_claims {
        use_has_any_claim(claims)
    } else if let Some(claims) = all_claims {
        use_has_all_claims(claims)
    } else {
        // No claim specified, just check if authenticated
        auth.read().user.is_some()
    };

    rsx! {
        if is_authorized {
            {children}
        } else if let Some(fallback_element) = fallback {
            {fallback_element}
        }
    }
}
