use crate::components::Modal;
use dioxus::prelude::*;

/// Delete Confirmation Modal for Roles
#[component]
pub fn ConfirmDeleteRoleModal(
    role_id: Signal<i64>,
    role_name: Signal<String>,
    delete_confirm_open: Signal<bool>,
    handle_delete: EventHandler<MouseEvent>,
) -> Element {
    let is_super_admin = role_name() == "Super Admin";
    let _ = role_id; // Not displayed

    rsx! {
        Modal {
            open: delete_confirm_open(),
            on_close: move |_| delete_confirm_open.set(false),
            title: "Delete Role",
            actions: rsx! {
                button {
                    class: "btn btn-error",
                    disabled: is_super_admin,
                    onclick: handle_delete,
                    "Delete"
                }
            },
            div { class: "flex flex-col gap-4",
                if is_super_admin {
                    div { class: "alert alert-warning",
                        p { "⚠️ The Super Admin role cannot be deleted." }
                    }
                } else {
                    p { "Are you sure you want to delete role \"{role_name()}\"?" }
                    p { class: "text-sm text-gray-500",
                        "This action cannot be undone. Users and groups assigned to this role will lose the associated claims."
                    }
                }
            }
        }
    }
}
