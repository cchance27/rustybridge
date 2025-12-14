use crate::{
    app::{
        api::auth::login,
        auth::{context::AuthState, hooks::use_auth},
    },
    components::Layout,
};
use dioxus::prelude::*;
use rb_types::auth::LoginRequest;

#[component]
pub fn LoginPage() -> Element {
    let auth = use_auth();
    let navigator = use_navigator();
    let oidc_login_href_onclick = "/api/auth/oidc/login".to_string();

    let mut username = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut submitting = use_signal(|| false);
    let mut error_message = use_signal(|| None::<String>);

    // Redirect away from login if already authenticated
    use_effect(move || {
        let state = auth.read();
        if !state.loading && state.user.is_some() {
            navigator.push("/");
        }
    });

    let on_submit = move |evt: Event<FormData>| {
        evt.stop_propagation();
        evt.prevent_default();

        if submitting() {
            return;
        }

        error_message.set(None);

        let username_val = username();
        let password_val = password();

        if username_val.trim().is_empty() {
            error_message.set(Some("Username is required".to_string()));
            return;
        }

        if password_val.is_empty() {
            error_message.set(Some("Password is required".to_string()));
            return;
        }

        submitting.set(true);

        let mut auth = auth;

        spawn(async move {
            let request = LoginRequest {
                username: username_val.clone(),
                password: password_val.clone(),
            };

            let result = login(request).await;

            match result {
                Ok(response) => {
                    if response.success {
                        if let Some(user) = response.user {
                            auth.set(AuthState {
                                user: Some(user),
                                loading: false,
                            });
                        } else {
                            auth.set(AuthState {
                                user: None,
                                loading: false,
                            });
                        }
                        navigator.push("/");
                    } else {
                        error_message.set(Some(response.message));
                    }
                }
                Err(err) => {
                    error_message.set(Some(format!("Login failed: {}", err)));
                }
            }

            submitting.set(false);
        });
    };

    rsx! {
        Layout {
            div { class: "flex items-center justify-center min-h-[calc(100vh-16rem)]",
                div { class: "card w-96 bg-base-100 shadow-xl",
                    div { class: "card-body",
                        h2 { class: "card-title justify-center mb-4", "Login to RustyBridge" }

                        form { onsubmit: on_submit,
                            class: "flex flex-col gap-4",
                            div { class: "form-control w-full max-w-xs flex flex-col gap-2",
                                label { class: "label",
                                    span { class: "label-text", "Username" }
                                }
                                input {
                                    r#type: "text",
                                    placeholder: "username",
                                    class: "input input-bordered w-full max-w-xs",
                                    value: "{username}",
                                    oninput: move |evt| username.set(evt.value()),
                                    autocomplete: "username",
                                }
                            }

                            div { class: "form-control w-full max-w-xs flex flex-col gap-2",
                                label { class: "label",
                                    span { class: "label-text", "Password" }
                                }
                                input {
                                    r#type: "password",
                                    placeholder: "password",
                                    class: "input input-bordered w-full max-w-xs",
                                    value: "{password}",
                                    oninput: move |evt| password.set(evt.value()),
                                    autocomplete: "current-password",
                                }
                            }

                            if let Some(error) = error_message() {
                                div { class: "alert alert-error mt-4",
                                    span { "{error}" }
                                }
                            }

                            div { class: "card-actions justify-end mt-6",
                                button {
                                    r#type: "submit",
                                    class: "btn btn-primary w-full",
                                    disabled: submitting(),
                                    if submitting() {
                                        span { class: "loading loading-spinner" }
                                        span { "Logging in" }
                                    } else {
                                        span { "Login" }
                                    }
                                }
                            }

                            div { class: "divider", "OR" }

                            div { class: "flex flex-col gap-2",
                                a {
                                    href: "/api/auth/oidc/login",
                                    class: "btn btn-outline btn-primary w-full gap-2",
                                    onclick: move |evt| {
                                        evt.prevent_default();
                                        let _ = navigator.push(NavigationTarget::<String>::External(oidc_login_href_onclick.clone()));
                                    },
                                    // Simple OIDC icon (user-circle)
                                    // TODO: Replace with provider icon if available in database or name if available
                                    // TODO: Multiple provider support with logo and icons.
                                    svg {
                                        class: "w-5 h-5",
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
                                    "Login with SSO"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
