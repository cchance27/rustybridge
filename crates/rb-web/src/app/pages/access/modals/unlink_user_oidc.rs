use dioxus::prelude::*;

use crate::components::Modal;

/// Unlink Modal
#[component]
pub fn UnlinkUserModal(username: String, unlink_modal_open: Signal<bool>, on_unlink: EventHandler<MouseEvent>) -> Element {
    rsx!(
        Modal {
            open: unlink_modal_open(),
            on_close: move |_| unlink_modal_open.set(false),
            title: "Unlink OIDC Account",
            actions: rsx! {
                button {
                    class: "btn btn-error",
                    onclick: move |event| on_unlink.call(event),
                    "Unlink"
                }
            },
            div { class: "flex flex-col gap-4",
                p {
                    "Are you sure you want to unlink the OIDC account for user "
                    strong { "'{username}'" }
                    "?"
                }
                p { class: "text-sm text-warning",
                    "⚠️ This user will no longer be able to log in via OIDC."
                }
            }
        }
    )
}
