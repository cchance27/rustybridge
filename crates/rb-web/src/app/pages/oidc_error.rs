use dioxus::prelude::*;

use crate::app::{auth::hooks::use_auth, components::Layout};

#[derive(Clone, PartialEq)]
pub struct OidcError {
    pub title: String,
    pub message: String,
    pub details: Option<String>,
}

#[component]
pub fn OidcErrorPage() -> Element {
    let auth = use_auth();
    let is_authenticated = auth.read().user.is_some();

    // Parse error from query params
    #[allow(unused_mut)] // web_sys usage requires target_arch, which is where we use the mut, compiler doesn't see it.
    let mut error_type = use_signal(|| None::<String>);

    // Parse query params after mount (client-side only)
    use_effect(move || {
        #[cfg(target_arch = "wasm32")]
        {
            use web_sys::window;
            if let Some(window) = window() {
                if let Ok(search) = window.location().search() {
                    if !search.is_empty() {
                        // Parse ?error=type
                        let params: std::collections::HashMap<String, String> = search
                            .trim_start_matches('?')
                            .split('&')
                            .filter_map(|pair| {
                                let mut parts = pair.split('=');
                                Some((parts.next()?.to_string(), parts.next()?.to_string()))
                            })
                            .collect();

                        if let Some(error) = params.get("error") {
                            error_type.set(Some(error.clone()));
                        }
                    }
                }
            }
        }
    });

    let error = use_memo(move || {
        let error_code: Option<String> = error_type();
        match error_code.as_deref() {
            Some("not_authenticated") => OidcError {
                title: "Authentication Required".to_string(),
                message: "You must be logged in to link an OIDC account.".to_string(),
                details: Some("Please log in with your username and password first.".to_string()),
            },
            Some("oidc_not_configured") => OidcError {
                title: "OIDC Not Configured".to_string(),
                message: "OIDC authentication is not configured on this server.".to_string(),
                details: Some("Please contact your administrator to set up OIDC.".to_string()),
            },
            Some("oidc_setup_failed") | Some("oidc_client_failed") => OidcError {
                title: "OIDC Setup Failed".to_string(),
                message: "Failed to initialize OIDC client.".to_string(),
                details: Some("The OIDC provider configuration may be invalid. Please contact your administrator.".to_string()),
            },
            Some("csrf_mismatch") | Some("no_csrf_token") => OidcError {
                title: "Security Error".to_string(),
                message: "CSRF token validation failed.".to_string(),
                details: Some("This may be due to an expired session or a security issue. Please try again.".to_string()),
            },
            Some("no_nonce") => OidcError {
                title: "Session Error".to_string(),
                message: "Authentication session expired.".to_string(),
                details: Some("Please try logging in again.".to_string()),
            },
            Some("token_exchange_failed") => OidcError {
                title: "Token Exchange Failed".to_string(),
                message: "Failed to exchange authorization code for tokens.".to_string(),
                details: Some("The OIDC provider rejected the request. Please try again.".to_string()),
            },
            Some("no_id_token") => OidcError {
                title: "Invalid Response".to_string(),
                message: "No ID token received from OIDC provider.".to_string(),
                details: Some("The provider response was incomplete. Please try again.".to_string()),
            },
            Some("invalid_token") => OidcError {
                title: "Invalid Token".to_string(),
                message: "Failed to validate ID token.".to_string(),
                details: Some("The token signature or claims were invalid. Please try again.".to_string()),
            },
            Some("already_linked") => OidcError {
                title: "Account Already Linked".to_string(),
                message: "This OIDC account is already linked to another user.".to_string(),
                details: Some(
                    "Each OIDC account can only be linked to one user. Please use a different OIDC account or contact your administrator."
                        .to_string(),
                ),
            },
            Some("database_error") | Some("link_failed") | Some("unlink_failed") => OidcError {
                title: "Database Error".to_string(),
                message: "Failed to save OIDC link.".to_string(),
                details: Some("A database error occurred. Please try again or contact your administrator.".to_string()),
            },
            Some("account_not_linked") | Some("no_link_found") => OidcError {
                title: "Account Not Linked".to_string(),
                message: "No user account is linked to this OIDC identity.".to_string(),
                details: Some(
                    "Please log in with your username and password first, then link your OIDC account from your profile.".to_string(),
                ),
            },
            _ => OidcError {
                title: "OIDC Error".to_string(),
                message: "An unknown error occurred during OIDC authentication.".to_string(),
                details: Some("Please try again or contact your administrator.".to_string()),
            },
        }
    });

    rsx! {
        Layout {
            div { class: "flex items-center justify-center p-4",
                div { class: "card bg-base-100 shadow-xl max-w-2xl w-full",
                    div { class: "card-body",
                        // Error icon
                        div { class: "flex justify-center mb-4",
                            div { class: "rounded-full bg-error/10 p-4",
                                svg {
                                    xmlns: "http://www.w3.org/2000/svg",
                                    class: "h-16 w-16 text-error",
                                    fill: "none",
                                    view_box: "0 0 24 24",
                                    stroke: "currentColor",
                                    path {
                                        stroke_linecap: "round",
                                        stroke_linejoin: "round",
                                        stroke_width: "2",
                                        d: "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                                    }
                                }
                            }
                        }

                        // Title
                        h2 { class: "card-title text-2xl justify-center mb-2",
                            {error().title}
                        }

                        // Message
                        p { class: "text-center justify-center text-lg mb-4",
                            {error().message}
                        }

                        // Details
                        if let Some(details) = error().details {
                            div { class: "alert alert-warning mb-4",
                                svg {
                                    xmlns: "http://www.w3.org/2000/svg",
                                    class: "stroke-current shrink-0 h-6 w-6",
                                    fill: "none",
                                    view_box: "0 0 24 24",
                                    path {
                                        stroke_linecap: "round",
                                        stroke_linejoin: "round",
                                        stroke_width: "2",
                                        d: "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                                    }
                                }
                                span { {details} }
                            }
                        }

                        // Actions
                        div { class: "card-actions justify-center gap-2 mt-4",
                            if !is_authenticated {
                                Link {
                                    to: "/login",
                                    class: "btn btn-primary",
                                    "Login"
                                }
                            }
                            if is_authenticated {
                                Link {
                                    to: "/",
                                    class: "btn btn-primary",
                                    "Home"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
