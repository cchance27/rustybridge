use dioxus::prelude::*;
use rb_types::access::{GrantAccessRequest, PrincipalKind};

use crate::app::api::{access::*, groups::list_groups, users::list_users};

#[component]
pub fn RelayAccessForm(relay_id: i64, on_change: Option<EventHandler<()>>) -> Element {
    // Load current access principals
    let mut access_principals = use_resource(move || async move { list_relay_access(relay_id).await });

    // Load available users and groups
    let users = use_resource(|| async move { list_users().await });
    let groups = use_resource(|| async move { list_groups().await });

    // State for adding new principals
    let mut selected_user = use_signal(String::new);
    let mut selected_group = use_signal(String::new);

    // Add user to access list
    let add_user = move |_| {
        let user = selected_user();
        if user.is_empty() {
            return;
        }

        spawn(async move {
            let req = GrantAccessRequest {
                principal_kind: "user".to_string(),
                principal_name: user.clone(),
            };

            if grant_relay_access(relay_id, req).await.is_ok() {
                selected_user.set(String::new());
                access_principals.restart();
                if let Some(handler) = on_change {
                    handler.call(());
                }
            }
        });
    };

    // Add group to access list
    let add_group = move |_| {
        let group = selected_group();
        if group.is_empty() {
            return;
        }

        spawn(async move {
            let req = GrantAccessRequest {
                principal_kind: "group".to_string(),
                principal_name: group.clone(),
            };

            if grant_relay_access(relay_id, req).await.is_ok() {
                selected_group.set(String::new());
                access_principals.restart();
                if let Some(handler) = on_change {
                    handler.call(());
                }
            }
        });
    };

    // Remove principal from access list
    let remove_principal = move |kind: PrincipalKind, name: String| {
        spawn(async move {
            if revoke_relay_access(relay_id, kind, name).await.is_ok() {
                access_principals.restart();
                if let Some(handler) = on_change {
                    handler.call(());
                }
            }
        });
    };

    rsx! {
        div { class: "space-y-4",
            // Current access principals
            match access_principals() {
                Some(Ok(principals)) => {
                    let user_principals: Vec<_> = principals.iter().filter(|p| p.kind == PrincipalKind::User).cloned().collect();
                    let group_principals: Vec<_> = principals.iter().filter(|p| p.kind == PrincipalKind::Group).cloned().collect();

                    rsx! {
                        div { class: "grid grid-cols-2 gap-4",
                            // Users column
                            div { class: "space-y-2",
                                h3 { class: "font-semibold text-sm", "Users" }
                                div { class: "space-y-1",
                                    if user_principals.is_empty() {
                                        p { class: "text-sm text-gray-500 italic", "No users have access" }
                                    } else {
                                        for principal in &user_principals {
                                            div { class: "flex items-center justify-between p-2 bg-base-200 rounded",
                                                span { class: "text-sm", "{principal.name}" }
                                                button {
                                                    class: "btn btn-xs btn-ghost",
                                                    onclick: {
                                                        let kind = principal.kind;
                                                        let name = principal.name.clone();
                                                        move |_| remove_principal(kind, name.clone())
                                                    },
                                                    "✕"
                                                }
                                            }
                                        }
                                    }
                                }

                                // Add user dropdown
                                match users() {
                                    Some(Ok(user_list)) => {
                                        let available_users: Vec<_> = user_list
                                            .iter()
                                            .filter(|u| !user_principals.iter().any(|p| p.name == u.username))
                                            .collect();

                                        rsx! {
                                            div { class: "flex gap-2 mt-2",
                                                select {
                                                    class: "select select-sm select-bordered flex-1",
                                                    value: "{selected_user}",
                                                    onchange: move |e| selected_user.set(e.value()),
                                                    option { value: "", "Select user..." }
                                                    for user in available_users {
                                                        option { value: "{user.username}", "{user.username}" }
                                                    }
                                                }
                                                button {
                                                    class: "btn btn-sm btn-primary",
                                                    disabled: selected_user().is_empty(),
                                                    onclick: add_user,
                                                    "Add"
                                                }
                                            }
                                        }
                                    }
                                    _ => rsx! { div { class: "loading loading-spinner loading-sm" } }
                                }
                            }

                            // Groups column
                            div { class: "space-y-2",
                                h3 { class: "font-semibold text-sm", "Groups" }
                                div { class: "space-y-1",
                                    if group_principals.is_empty() {
                                        p { class: "text-sm text-gray-500 italic", "No groups have access" }
                                    } else {
                                        for principal in &group_principals {
                                            div { class: "flex items-center justify-between p-2 bg-base-200 rounded",
                                                span { class: "text-sm", "{principal.name}" }
                                                button {
                                                    class: "btn btn-xs btn-ghost",
                                                    onclick: {
                                                        let kind = principal.kind;
                                                        let name = principal.name.clone();
                                                        move |_| remove_principal(kind, name.clone())
                                                    },
                                                    "✕"
                                                }
                                            }
                                        }
                                    }
                                }

                                // Add group dropdown
                                match groups() {
                                    Some(Ok(group_list)) => {
                                        let available_groups: Vec<_> = group_list
                                            .iter()
                                            .filter(|g| !group_principals.iter().any(|p| p.name == g.name))
                                            .collect();

                                        rsx! {
                                            div { class: "flex gap-2 mt-2",
                                                select {
                                                    class: "select select-sm select-bordered flex-1",
                                                    value: "{selected_group}",
                                                    onchange: move |e| selected_group.set(e.value()),
                                                    option { value: "", "Select group..." }
                                                    for group in available_groups {
                                                        option { value: "{group.name}", "{group.name}" }
                                                    }
                                                }
                                                button {
                                                    class: "btn btn-sm btn-primary",
                                                    disabled: selected_group().is_empty(),
                                                    onclick: add_group,
                                                    "Add"
                                                }
                                            }
                                        }
                                    }
                                    _ => rsx! { div { class: "loading loading-spinner loading-sm" } }
                                }
                            }
                        }
                    }
                }
                Some(Err(e)) => rsx! {
                    div { class: "alert alert-error",
                        span { "Error loading access list: {e}" }
                    }
                },
                None => rsx! {
                    div { class: "flex justify-center p-4",
                        span { class: "loading loading-spinner loading-lg" }
                    }
                }
            }
        }
    }
}
