use crate::{
    app::{api::relays::delete_relay_host, pages::relays::state::RelayState},
    components::{Modal, use_toast},
};
use dioxus::prelude::*;

/// Modal for confirming relay deletion
#[component]
pub fn DeleteRelayModal(state: RelayState) -> Element {
    let toast = use_toast();
    let on_delete = move |_| {
        let target_id = (state.delete_target_id)();
        let target_name = (state.delete_target_name)();
        spawn(async move {
            match delete_relay_host(target_id).await {
                Ok(_) => {
                    state.delete_confirm_open.set(false);
                    toast.success(&format!("Relay '{}' deleted successfully", target_name));
                    state.relays.restart();
                }
                Err(e) => {
                    state.delete_confirm_open.set(false);
                    toast.error(&format!("Failed to delete relay: {}", e));
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
