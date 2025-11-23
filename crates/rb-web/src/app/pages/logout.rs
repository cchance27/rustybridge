use dioxus::prelude::*;

use crate::{
    app::{
        api::auth::logout, auth::{context::AuthState, hooks::use_auth}
    }, components::Layout
};

#[component]
pub fn LogoutPage() -> Element {
    let auth = use_auth();
    let navigator = use_navigator();
    let started = use_signal(|| false);
    let error_message = use_signal(|| None::<String>);

    {
        let mut auth = auth;
        let mut started_signal = started;
        let mut error_signal = error_message;
        use_effect(move || {
            if started_signal() {
                return;
            }
            started_signal.set(true);

            spawn(async move {
                match logout().await {
                    Ok(_) => {
                        auth.set(AuthState {
                            user: None,
                            loading: false,
                        });
                        navigator.push("/login");
                    }
                    Err(err) => {
                        error_signal.set(Some(format!("Logout failed: {}", err)));
                    }
                }
            });
        });
    }

    rsx! {
        Layout {
            div { class: "flex items-center justify-center min-h-[calc(100vh-16rem)]",
                div { class: "card w-96 bg-base-100 shadow-xl",
                    div { class: "card-body text-center space-y-4",
                        h2 { class: "card-title justify-center", "Logging out" }
                        match error_message() {
                            None => rsx! {
                                span { class: "loading loading-spinner loading-lg mx-auto" }
                                p { "Signing you out..." }
                            },
                            Some(error) => rsx! {
                                div { class: "alert alert-error",
                                    span { "{error}" }
                                }
                                button {
                                    class: "btn btn-primary",
                                    onclick: move |_| {
                                        navigator.push("/login");
                                    },
                                    "Return to login"
                                }
                            },
                        }
                    }
                }
            }
        }
    }
}
