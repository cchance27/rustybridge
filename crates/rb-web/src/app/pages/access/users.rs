//! Users section with table and modals
//! Self-contained components for managing users

use dioxus::prelude::*;
use rb_types::{
    access::RelayAccessSource, auth::{ClaimLevel, ClaimType}
};

use crate::{
    app::{
        api::users::*, auth::oidc::{OidcLinkStatus, get_user_oidc_status, unlink_user_oidc}
    }, components::{
        Protected, StructuredTooltip, Table, TableActions, ToastMessage, ToastType, TooltipSection, buttons::HoverSwapButton, icons
    }, pages::access::modals::{ConfirmDeleteUserModal, EditUserModal, UnlinkUserModal}
};

/// Main Users Section component
#[component]
pub fn UsersSection(
    users: Resource<Result<Vec<rb_types::users::UserGroupInfo>, ServerFnError>>,
    toast: Signal<Option<ToastMessage>>,
) -> Element {
    // Delete confirmation state
    let mut delete_confirm_open = use_signal(|| false);
    let mut delete_target_name = use_signal(String::new);

    let mut edit_modal_open = use_signal(|| false);
    let mut editing_username = use_signal(|| None::<String>);
    let oidc_refresh_trigger = use_signal(|| 0u32);

    let mut open_edit = move |username: String| {
        editing_username.set(Some(username));
        edit_modal_open.set(true);
    };

    let mut open_delete_confirm = move |target_name: String| {
        delete_target_name.set(target_name);
        delete_confirm_open.set(true);
    };

    let handle_delete = move |_| {
        let target_name = delete_target_name();

        spawn(async move {
            match delete_user(target_name.clone()).await {
                Ok(_) => {
                    delete_confirm_open.set(false);
                    toast.set(Some(ToastMessage {
                        message: format!("User '{}' deleted successfully", target_name),
                        toast_type: ToastType::Success,
                    }));
                    users.restart();
                }
                Err(e) => {
                    delete_confirm_open.set(false);
                    toast.set(Some(ToastMessage {
                        message: format!("Failed to delete user: {}", e),
                        toast_type: ToastType::Error,
                    }));
                }
            }
        });
    };

    rsx! {
        Protected {
            claim: Some(ClaimType::Users(ClaimLevel::View)),
            div { class: "card bg-base-200 shadow-xl self-start w-full",
                div { class: "card-body",
                    h2 { class: "card-title", "Users" }
                    p { "Manage system users and their group memberships." }
                    match users() {
                        Some(Ok(user_list)) => rsx! {
                            Table {
                                headers: vec!["Username", "Groups", "Relays", "SSH Keys", "OIDC", "Actions"],
                                for user in user_list {
                                    tr {
                                        td { "{user.username}" }
                                        td {
                                            if user.groups.is_empty() {
                                                span { class: "text-gray-500 italic", "No groups" }
                                            } else {
                                                StructuredTooltip {
                                                    sections: vec![TooltipSection::new("Groups").with_items(user.groups.clone())],
                                                    span { class: "badge badge-primary whitespace-nowrap",
                                                        "{user.groups.len()} "
                                                        {if user.groups.len() == 1 { "group" } else { "groups" }}
                                                    }
                                                }
                                            }
                                        }
                                        td {
                                            if user.relays.is_empty() {
                                                span { class: "badge badge-ghost whitespace-nowrap", "No access" }
                                            } else {
                                                StructuredTooltip {
                                                    sections: {
                                                        let items = user.relays.iter().map(|r| {
                                                            let source_str = match &r.access_source {
                                                                RelayAccessSource::Direct => "",
                                                                RelayAccessSource::ViaGroup(g) => &format!(" (via {})", g),
                                                                RelayAccessSource::Both(g) => &format!(" (direct + {})", g),
                                                            };
                                                            format!("{} ({}){}", r.relay_name, r.relay_endpoint, source_str)
                                                        }).collect();
                                                        vec![TooltipSection::new("Relays").with_items(items)]
                                                    },
                                                    span { class: "badge badge-success whitespace-nowrap",
                                                        "{user.relays.len()} "
                                                        {if user.relays.len() == 1 { "relay" } else { "relays" }}
                                                    }
                                                }
                                            }
                                        }
                                        td {
                                            if user.ssh_key_count > 0 {
                                                span { class: "badge badge-neutral whitespace-nowrap", "{user.ssh_key_count} keys" }
                                            } else {
                                                span { class: "badge badge-ghost text-xs text-center whitespace-nowrap", "None" }
                                            }
                                        }
                                        td {
                                            OidcStatusCell {
                                                user_id: user.id,
                                                username: user.username.clone(),
                                                oidc_refresh_trigger,
                                                toast,
                                                users,
                                            }
                                        }
                                        td { class: "text-right",
                                            Protected {
                                                any_claims: vec![ClaimType::Users(ClaimLevel::Edit), ClaimType::Users(ClaimLevel::Delete)],
                                                TableActions {
                                                    on_edit: {
                                                        let u = user.username.clone();
                                                        move |_| open_edit(u.clone())
                                                    },
                                                    on_delete: {
                                                        let u = user.username.clone();
                                                        move |_| open_delete_confirm(u.clone())
                                                    }
                                                },
                                            }
                                        }
                                    }
                                }
                            }
                            Protected {
                                any_claims: vec![ClaimType::Users(ClaimLevel::Delete)],
                                ConfirmDeleteUserModal {
                                    username: delete_target_name,
                                    delete_confirm_open,
                                    handle_delete,
                                }
                            }
                        },
                        Some(Err(e)) => rsx! {
                            div { class: "alert alert-error",
                                span { "Error loading users: {e}" }
                            }
                        },
                        None => rsx! {
                            div { class: "flex justify-center p-8",
                                span { class: "loading loading-spinner loading-lg" }
                            }
                        }
                    }
                }
            }
        }

        if editing_username().is_some() {
            EditUserModal {
                open: edit_modal_open,
                username: editing_username,
                users,
                toast,
            }
        }
    }
}

/// OIDC Status Cell with unlink functionality
#[component]
fn OidcStatusCell(
    user_id: i64,
    username: String,
    oidc_refresh_trigger: Signal<u32>,
    toast: Signal<Option<ToastMessage>>,
    users: Resource<Result<Vec<rb_types::users::UserGroupInfo>, ServerFnError>>,
) -> Element {
    // Track per-user OIDC status; kept inside its own component to satisfy Dioxus hook ordering rules.
    let mut oidc_status = use_signal(|| None::<OidcLinkStatus>);
    let mut unlink_modal_open = use_signal(|| false);

    // Refresh when the shared trigger bumps (e.g., after unlink) or on initial mount.
    use_effect(move || {
        let trigger = oidc_refresh_trigger();
        spawn(async move {
            let _ = trigger;
            match get_user_oidc_status(user_id).await {
                Ok(status) => oidc_status.set(Some(status)),
                Err(_) => oidc_status.set(None),
            }
        });
    });

    let handle_unlink = {
        let username_for_unlink = username.clone();
        move |_| {
            let username_clone = username_for_unlink.clone();
            spawn(async move {
                match unlink_user_oidc(user_id).await {
                    Ok(_) => {
                        unlink_modal_open.set(false);
                        toast.set(Some(ToastMessage {
                            message: format!("OIDC account unlinked for user '{}'", username_clone),
                            toast_type: ToastType::Success,
                        }));
                        oidc_refresh_trigger.set(oidc_refresh_trigger() + 1);
                        users.restart();
                    }
                    Err(e) => {
                        unlink_modal_open.set(false);
                        toast.set(Some(ToastMessage {
                            message: format!("Failed to unlink OIDC: {}", e),
                            toast_type: ToastType::Error,
                        }));
                    }
                }
            });
        }
    };

    if let Some(status) = oidc_status()
        && status.is_linked
    {
        return rsx! {
            HoverSwapButton {
                on_click: move |_| unlink_modal_open.set(true),
                regular: rsx! {
                    "Linked"
                    icons::LockIcon {}
                },
                hover: rsx! {
                    "Unlink"
                    icons::XIcon {}
                }
            },
            UnlinkUserModal {
                username,
                unlink_modal_open,
                on_unlink: handle_unlink
            }
        };
    }

    rsx! {
        span { class: "badge badge-ghost whitespace-nowrap", "Not linked" }
    }
}
