use dioxus::prelude::*;
use rb_types::{
    access::PrincipalKind, auth::{ClaimLevel, ClaimType}, relay::RelayHostInfo
};

use crate::components::{CredentialBadge, Protected, StructuredTooltip, Table, TableActions, TooltipSection, icons::EditIcon};

/// Render the credential cell for a relay host
pub fn render_credential_cell(
    host: &RelayHostInfo,
    open_clear_modal: impl Fn(i64, String, bool) + Copy + 'static,
    open_assign_modal: impl Fn(i64, String) + Copy + 'static,
) -> Element {
    let badge = if let Some(cred) = &host.credential {
        Some((
            cred.clone(),
            host.credential_kind.clone().unwrap_or_else(|| "password".to_string()),
            host.credential_username_mode.clone(),
            host.credential_password_required,
            "saved".to_string(),
            matches!(host.auth_config.as_ref().map(|c| c.mode.as_str()), Some("custom")),
        ))
    } else if let Some(config) = &host.auth_config {
        if config.mode == "custom" {
            Some((
                "Custom".to_string(),
                config.custom_type.clone().unwrap_or_else(|| "password".to_string()),
                config.username_mode.clone(),
                config.password_required,
                "custom".to_string(),
                true,
            ))
        } else {
            None
        }
    } else {
        None
    };

    rsx! {
        td {
            if let Some((badge_name, badge_kind, badge_username_mode, badge_pw_required, badge_mode, is_inline)) = badge {
                div { class: "flex items-center gap-2 flex-wrap",
                    Protected {
                        claim: Some(ClaimType::Relays(ClaimLevel::Edit)),
                        fallback: Some(rsx! {
                            CredentialBadge {
                                name: Some(badge_name.clone()),
                                kind: badge_kind.clone(),
                                username_mode: badge_username_mode.clone(),
                                password_required: badge_pw_required,
                                kind_prefix: false,
                                custom_prefix: false,
                                compound: true,
                                mode: Some(badge_mode.clone()),
                                on_clear: None,
                            }
                        }),
                        CredentialBadge {
                            name: Some(badge_name),
                            kind: badge_kind,
                            username_mode: badge_username_mode,
                            password_required: badge_pw_required,
                            kind_prefix: false,
                            custom_prefix: false,
                            compound: true,
                            mode: Some(badge_mode.clone()),
                            on_clear: Some(EventHandler::new({
                                let id = host.id;
                                let name = host.name.clone();
                                move |_| open_clear_modal(id, name.clone(), is_inline)
                            })),
                        }
                    }
                }
            } else {
                Protected {
                    claim: Some(ClaimType::Relays(ClaimLevel::Edit)),
                    button {
                        class: "badge badge-secondary cursor-pointer text-[11px] hover:badge-accent",
                        onclick: {
                            let id = host.id;
                            let name = host.name.clone();
                            move |_| open_assign_modal(id, name.clone())
                        },
                        "Assign"
                    }
                }
            }
        }
    }
}

/// Render the relays table
#[component]
pub fn RelaysTable(
    hosts: Vec<RelayHostInfo>,
    open_edit: EventHandler<(i64, String, String, Option<rb_types::credentials::AuthWebConfig>)>,
    open_delete_confirm: EventHandler<(i64, String)>,
    open_access_modal: EventHandler<(i64, String)>,
    show_hostkey_modal: EventHandler<(i64, String)>,
    open_clear_modal: EventHandler<(i64, String, bool)>,
    open_assign_modal: EventHandler<(i64, String)>,
) -> Element {
    rsx! {
        Table {
            headers: vec!["ID", "Name", "Endpoint", "Credential", "Hostkey", "Access", "Actions"],
            for host in hosts {
                tr {
                    th { "{host.id}" }
                    td { "{host.name}" }
                    td { "{host.ip}:{host.port}" }
                    { render_credential_cell(&host, move |id, name, is_inline| open_clear_modal.call((id, name, is_inline)), move |id, name| open_assign_modal.call((id, name))) }
                    td {
                        div { class: "flex items-center gap-2",
                            if host.has_hostkey {
                                span { class: "badge badge-success", "✓" }
                            } else {
                                span { class: "badge badge-ghost", "✗" }
                            }
                            Protected {
                                claim: Some(ClaimType::Relays(ClaimLevel::Edit)),
                                button {
                                    class: "btn btn-xs btn-secondary",
                                    onclick: {
                                        let id = host.id;
                                        let name = host.name.clone();
                                        move |_| show_hostkey_modal.call((id, name.clone()))
                                    },
                                    "Refresh"
                                }
                            }
                        }
                    }
                    td {
                        // Access column - show count with structured tooltip and edit icon
                        StructuredTooltip {
                            sections: {
                                let users: Vec<_> = host.access_principals.iter()
                                    .filter(|p| p.kind == PrincipalKind::User)
                                    .map(|p| p.name.clone())
                                    .collect();
                                let groups: Vec<_> = host.access_principals.iter()
                                    .filter(|p| p.kind == PrincipalKind::Group)
                                    .map(|p| p.name.clone())
                                    .collect();

                                let mut sections = Vec::new();
                                if !users.is_empty() {
                                    sections.push(TooltipSection::new("Users").with_items(users));
                                }
                                if !groups.is_empty() {
                                    sections.push(TooltipSection::new("Groups").with_items(groups));
                                }
                                if sections.is_empty() {
                                    sections.push(TooltipSection::without_header().with_empty_message("No access configured"));
                                }
                                sections
                            },
                            Protected {
                                claim: Some(ClaimType::Relays(ClaimLevel::Edit)),
                                fallback: rsx! {
                                     span {
                                        class: if host.access_principals.is_empty() {
                                            "badge badge-error"
                                        } else {
                                            "badge badge-primary"
                                        },
                                        "{host.access_principals.len()} "
                                        {if host.access_principals.len() == 1 { "principal" } else { "principals" }}
                                     }
                                },
                                button {
                                    class: if host.access_principals.is_empty() {
                                        "badge badge-error cursor-pointer hover:badge-accent"
                                    } else {
                                        "badge badge-primary cursor-pointer hover:badge-accent"
                                    },
                                    onclick: {
                                        let id = host.id;
                                        let name = host.name.clone();
                                        move |_| open_access_modal.call((id, name.clone()))
                                    },
                                    "{host.access_principals.len()} "
                                    {if host.access_principals.len() == 1 { "principal" } else { "principals" }}
                                    // Edit icon
                                    EditIcon {}
                                }
                            }
                        }
                    }
                    td { class: "text-right",
                        Protected {
                            any_claims: vec![ClaimType::Relays(ClaimLevel::Edit), ClaimType::Relays(ClaimLevel::Delete)],
                            TableActions {
                                on_edit: {
                                    let host_name = host.name.clone();
                                    let host_endpoint = format!("{}:{}", host.ip, host.port);
                                    let auth_config = host.auth_config.clone();
                                    move |_| open_edit.call((host.id, host_name.clone(), host_endpoint.clone(), auth_config.clone()))
                                },
                                on_delete: {
                                    let host_id = host.id;
                                    let host_name = host.name.clone();
                                    move |_| open_delete_confirm.call((host_id, host_name.clone()))
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
