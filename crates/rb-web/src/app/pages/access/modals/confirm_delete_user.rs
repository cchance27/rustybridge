use dioxus::prelude::*;

use crate::components::Modal;

// TODO: Confirmation dialogs should really be a component itself, they're all the same, a type field and a name field is all that differs.

/// Delete Confirmation Modal for Users
#[component]
pub fn ConfirmDeleteUserModal(
    username: Signal<String>,
    delete_confirm_open: Signal<bool>,
    handle_delete: EventHandler<MouseEvent>,
) -> Element {
    rsx! {
        Modal {
            open: delete_confirm_open(),
            on_close: move |_| delete_confirm_open.set(false),
            title: "Delete User",
            actions: rsx! {
                button { class: "btn btn-error", onclick: handle_delete, "Delete" }
            },
            div { class: "flex flex-col gap-4",
                p { "Are you sure you want to delete user \"{username()}\"?" }
                p { class: "text-sm text-gray-500",
                    "This action cannot be undone. This will also revoke all relay access for this user."
                }
            }
        }
    }
}
