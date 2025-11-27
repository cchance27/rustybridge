use dioxus::prelude::*;

use crate::{
    app::{
        api::relays::{clear_relay_auth, clear_relay_credential}, pages::relays::state::RelayState
    }, components::{Modal, ToastMessage, ToastType}
};

/// Modal for clearing authentication from a relay
#[component]
pub fn ClearCredentialModal(state: RelayState) -> Element {
    let on_clear = move |_| {
        let target_id = (state.clear_target_id)();
        let target_name = (state.clear_target_name)();
        let is_inline = (state.clear_is_inline)();
        spawn(async move {
            let res = if is_inline {
                clear_relay_auth(target_id).await
            } else {
                clear_relay_credential(target_id).await
            };
            match res {
                Ok(_) => {
                    state.clear_modal_open.set(false);
                    state.toast.set(Some(ToastMessage {
                        message: format!("Authentication cleared from '{}' successfully", target_name),
                        toast_type: ToastType::Success,
                    }));
                    state.relays.restart();
                }
                Err(e) => {
                    state.clear_modal_open.set(false);
                    state.toast.set(Some(ToastMessage {
                        message: format!("Failed to clear credential: {}", e),
                        toast_type: ToastType::Error,
                    }));
                }
            }
        });
    };

    rsx! {
        Modal {
            open: (state.clear_modal_open)(),
            on_close: move |_| state.clear_modal_open.set(false),
            title: "Clear Authentication",
            actions: rsx! {
                button { class: "btn btn-error", onclick: on_clear, "Clear" }
            },
            div { class: "flex flex-col gap-4",
                p { "Are you sure you want to clear authentication for "{state.clear_target_name}"?" }
                p { class: "text-sm text-gray-500",
                    "This will remove the assigned credential or inline authentication for this relay host."
                }
            }
        }
    }
}
