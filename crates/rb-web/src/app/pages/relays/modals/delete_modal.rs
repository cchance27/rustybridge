use dioxus::prelude::*;

use crate::{
    app::{api::relays::delete_relay_host, pages::relays::state::RelayState}, components::{Modal, ToastMessage, ToastType}
};

/// Modal for confirming relay deletion
#[component]
pub fn DeleteRelayModal(state: RelayState) -> Element {
    let on_delete = move |_| {
        let target_id = (state.delete_target_id)();
        let target_name = (state.delete_target_name)();
        spawn(async move {
            match delete_relay_host(target_id).await {
                Ok(_) => {
                    state.delete_confirm_open.set(false);
                    state.toast.set(Some(ToastMessage {
                        message: format!("Relay '{}' deleted successfully", target_name),
                        toast_type: ToastType::Success,
                    }));
                    state.relays.restart();
                }
                Err(e) => {
                    state.delete_confirm_open.set(false);
                    state.toast.set(Some(ToastMessage {
                        message: format!("Failed to delete relay: {}", e),
                        toast_type: ToastType::Error,
                    }));
                }
            }
        });
    };

    rsx! {
        Modal {
            open: (state.delete_confirm_open)(),
            on_close: move |_| state.delete_confirm_open.set(false),
            title: "Delete Relay Host",
            actions: rsx! {
                button { class: "btn btn-error", onclick: on_delete, "Delete" }
            },
            div { class: "flex flex-col gap-4",
                p { "Are you sure you want to delete relay host "{state.delete_target_name}"?" }
                p { class: "text-sm text-gray-500",
                    "This action cannot be undone."
                }
            }
        }
    }
}
