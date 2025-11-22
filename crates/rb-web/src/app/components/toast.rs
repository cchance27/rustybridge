use std::time::Duration;

use dioxus::prelude::*;
use gloo_timers::future::sleep;

#[derive(Clone, PartialEq)]
pub enum ToastType {
    Success,
    Error,
    Warning,
    Info,
}

#[derive(Clone, PartialEq)]
pub struct ToastMessage {
    pub message: String,
    pub toast_type: ToastType,
}

#[component]
pub fn Toast(mut message: Signal<Option<ToastMessage>>) -> Element {
    // Auto-dismiss after 5 seconds when a message is shown
    use_effect(move || {
        if message().is_some() {
            spawn(async move {
                sleep(Duration::from_secs(5)).await;
                message.set(None);
            });
        }
    });

    if let Some(toast) = message() {
        let alert_class = match toast.toast_type {
            ToastType::Success => "alert-success",
            ToastType::Error => "alert-error",
            ToastType::Warning => "alert-warning",
            ToastType::Info => "alert-info",
        };

        rsx! {
            div { class: "toast toast-bottom toast-end z-50",
                div {
                    class: "alert {alert_class}",
                    style: "max-width: 30vw; word-wrap: break-word; white-space: normal;",
                    span { "{toast.message}" }
                    button {
                        class: "btn btn-sm btn-circle btn-ghost ml-2",
                        onclick: move |_| message.set(None),
                        "✕"
                    }
                }
            }
        }
    } else {
        rsx! {}
    }
}
