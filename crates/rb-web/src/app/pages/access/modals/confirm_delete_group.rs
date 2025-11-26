use dioxus::prelude::*;

use crate::components::Modal;

// TODO: Confirmation dialogs should really be a component itself, they're all the same, a type field and a name field is all that differs.

/// Delete Confirmation Modal for Groups
#[component]
pub fn ConfirmDeleteGroupModal(
    group_name: Signal<String>,
    delete_confirm_open: Signal<bool>,
    handle_delete: EventHandler<MouseEvent>,
) -> Element {
    rsx! {
        Modal {
            open: delete_confirm_open(),
            on_close: move |_| delete_confirm_open.set(false),
            title: "Delete Group",
            actions: rsx! {
                button { class: "btn btn-error", onclick: handle_delete, "Delete" }
            },
            div { class: "flex flex-col gap-4",
                p { "Are you sure you want to delete group "{group_name()}"?" }
                p { class: "text-sm text-gray-500",
                    "This action cannot be undone. This will also revoke relay access for all members of this group."
                }
            }
        }
    }
}
