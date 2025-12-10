//! TUI app management functionality
//!
//! This module handles creating TUI apps and processing management actions.

use rb_types::relay::HostkeyReview;
use secrecy::ExposeSecret;
use tracing::info;
use tui_core::{
    AppAction, apps::{
        ManagementApp, RelayItem, RelaySelectorApp, management::{CredentialItem, CredentialSpec}, relay_selector
    }
};

use crate::{
    error::{ServerError, ServerResult}, secrets::{SecretBoxedString, decrypt_string_if_encrypted, is_encrypted_marker}
};

/// Create a ManagementApp with all relay hosts loaded from the database (admin view)
pub async fn create_management_app(review: Option<HostkeyReview>) -> ServerResult<ManagementApp> {
    create_management_app_with_tab(0, review).await
}

/// Create a ManagementApp with a specific tab selected
pub async fn create_management_app_with_tab(selected_tab: usize, review: Option<HostkeyReview>) -> ServerResult<ManagementApp> {
    // Admin sees all relay hosts (no filtering)
    use relay_selector::RelayItem;
    let hosts = crate::relay_host::list_hosts().await?;
    let relay_items: Vec<RelayItem> = hosts
        .into_iter()
        .map(|h| RelayItem {
            name: h.name,
            description: format!("{}:{}", h.ip, h.port),
            id: h.id,
        })
        .collect();

    // Credentials with counts
    let creds_rows = crate::credential::list_credentials_with_assignments().await?;
    let credentials: Vec<CredentialItem> = creds_rows
        .into_iter()
        .map(
            |(id, name, kind, _meta, _username_mode, _password_required, assigned_relays)| CredentialItem {
                id,
                name,
                kind,
                assigned: assigned_relays.len() as i64,
            },
        )
        .collect();

    // Build host->credential label mapping
    let (host_creds, hostkeys) = crate::relay_host::summarize_relay_auth().await?;

    // Pending hostkey review (if any)
    let review_opt = review;
    let review_host = review_opt.as_ref().map(|r| r.host.clone());

    let mut app = ManagementApp::new(relay_items, host_creds, hostkeys, credentials, None, review_opt).with_selected_tab(selected_tab);

    // If a hostkey review is being shown, ensure the background table selects that host
    if let Some(name) = review_host.as_deref() {
        app = app.with_selected_host_name(name);
    }

    Ok(app)
}

/// Build a TUI app by name for the given user context.
///
/// - name: "Management" or any other value (treated as relay selector)
/// - tab: optional tab index for Management
/// - user: optional username; when None or Some("admin"), full admin relay list is shown
pub async fn create_app_by_name(user: Option<&str>, name: &str, tab: Option<usize>) -> ServerResult<Box<dyn tui_core::TuiApp>> {
    match name {
        "Management" => {
            let app = if let Some(t) = tab {
                create_management_app_with_tab(t, None).await?
            } else {
                create_management_app(None).await?
            };
            Ok(Box::new(app))
        }
        _ => {
            let app = create_relay_selector_app(user).await?;
            Ok(Box::new(app))
        }
    }
}

/// Apply side effects for management-related AppActions (add/update/delete relay hosts).
/// Centralizing this logic avoids divergence between local and SSH TUI paths.
pub async fn handle_management_action(
    ctx: &rb_types::audit::AuditContext,
    action: tui_core::AppAction,
) -> ServerResult<Option<tui_core::AppAction>> {
    match action {
        AppAction::AddRelay(item) => {
            let (ip, port) = super::relay_host::parse_endpoint(&item.description)?;
            // TUI uses non-interactive add; fetch hostkey separately
            super::relay_host::add_relay_host_without_hostkey(ctx, &format!("{}:{}", ip, port), &item.name).await?;
        }
        AppAction::UpdateRelay(item) => {
            let (ip, port) = super::relay_host::parse_endpoint(&item.description)?;
            super::relay_host::update_relay_host_by_id(ctx, item.id, &item.name, &ip, port).await?;
        }
        AppAction::DeleteRelay(id) => {
            super::relay_host::delete_relay_host_by_id(ctx, id).await?;
        }
        AppAction::AddCredential(spec) => {
            match spec {
                CredentialSpec::Password {
                    name,
                    username,
                    username_mode,
                    password_required,
                    password,
                } => {
                    let _ = super::credential::create_password_credential(
                        ctx,
                        &name,
                        username.as_deref(),
                        &password,
                        &username_mode,
                        password_required,
                    )
                    .await?;
                }
                CredentialSpec::SshKey {
                    name,
                    username,
                    username_mode,
                    key_file: _,
                    value,
                    cert_file,
                    passphrase,
                } => {
                    // TUI provides inline key value; file path not used here
                    let key_data = if let Some(val) = value {
                        val
                    } else {
                        return Err(ServerError::Other("ssh_key requires key content".into()));
                    };
                    let cert_data = cert_file; // may be None
                    let _ = super::credential::create_ssh_key_credential(
                        ctx,
                        &name,
                        username.as_deref(),
                        &key_data,
                        cert_data.as_deref(),
                        passphrase.as_deref(),
                        &username_mode,
                    )
                    .await?;
                }
                CredentialSpec::Agent {
                    name,
                    username,
                    username_mode,
                    public_key,
                } => {
                    let _ =
                        super::credential::create_agent_credential(ctx, &name, username.as_deref(), &public_key, &username_mode).await?;
                }
            }
        }
        AppAction::DeleteCredential(id) => super::credential::delete_credential_by_id(ctx, id).await?,
        AppAction::UnassignCredential(host_id) => super::credential::unassign_credential_by_id(ctx, host_id).await?,
        AppAction::AssignCredential { host_id, cred_id } => super::credential::assign_credential_by_ids(ctx, host_id, cred_id).await?,
        AppAction::FetchHostkey { id, name } => {
            info!(relay = %name, relay_id = id, "refreshing relay host key");
            // Fetch and stage hostkey for review
            let db = state_store::server_db().await?;

            let pool = db.into_pool();

            // Resolve host by id first to avoid stale name collisions
            let host = state_store::fetch_relay_host_by_id(&pool, id)
                .await?
                .ok_or_else(|| ServerError::not_found("relay host", id.to_string()))?;
            if host.name != name {
                tracing::warn!(
                    requested_name = %name,
                    actual_name = %host.name,
                    relay_id = id,
                    "relay name changed during hostkey fetch; using id match"
                );
            }

            use std::sync::{Arc, Mutex};

            use russh::{
                client, keys::{HashAlg, PublicKey}
            };

            struct CaptureHandler {
                key: Arc<Mutex<Option<PublicKey>>>,
            }
            impl russh::client::Handler for CaptureHandler {
                type Error = crate::error::ServerError;
                fn check_server_key(&mut self, key: &PublicKey) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
                    let captured = self.key.clone();
                    let key = key.clone();
                    async move {
                        *captured.lock().unwrap() = Some(key);
                        Ok(true)
                    }
                }
            }

            let captured = Arc::new(Mutex::new(None));
            let handler = CaptureHandler { key: captured.clone() };
            let cfg = std::sync::Arc::new(russh::client::Config {
                preferred: ssh_core::crypto::default_preferred(),
                ..Default::default()
            });
            let connect_timeout = super::relay_host::hostkey_fetch_timeout()?;
            let session = tokio::time::timeout(connect_timeout, client::connect(cfg, (host.ip.as_str(), host.port as u16), handler))
                .await
                .map_err(|_| {
                    ServerError::Other(format!(
                        "timed out fetching host key from {}:{} after {:?}",
                        host.ip, host.port, connect_timeout
                    ))
                })??;
            let _ = session.disconnect(russh::Disconnect::ByApplication, "", "").await;
            let Some(new_key) = captured.lock().unwrap().clone() else {
                return Ok(None);
            };
            let new_fp = new_key.fingerprint(HashAlg::Sha256).to_string();
            let new_pem = new_key.to_openssh().map_err(|e| ServerError::Crypto(e.to_string()))?.to_string();
            let new_type = new_pem.split_whitespace().next().unwrap_or("").to_string();

            // Existing (optional)
            let mut old_fp: Option<String> = None;
            let mut old_type: Option<String> = None;
            let opts = state_store::fetch_relay_host_options(&pool, host.id).await?;
            if let Some((raw, _secure)) = opts.get("hostkey.openssh") {
                let dec = if is_encrypted_marker(raw) {
                    decrypt_string_if_encrypted(raw)
                        .map(|(s, _)| s)
                        .unwrap_or_else(|_| SecretBoxedString::new(Box::new(String::new())))
                } else {
                    SecretBoxedString::new(Box::new(raw.clone()))
                };
                if !dec.expose_secret().is_empty()
                    && let Ok(pk) = PublicKey::from_openssh(dec.expose_secret())
                {
                    old_fp = Some(pk.fingerprint(HashAlg::Sha256).to_string());
                    old_type = Some(dec.expose_secret().split_whitespace().next().unwrap_or("").to_string());
                }
            }

            let review = HostkeyReview {
                host_id: host.id,
                host: host.name,
                new_fingerprint: new_fp,
                new_key_type: new_type,
                old_fingerprint: old_fp,
                old_key_type: old_type,
                new_key_pem: new_pem,
            };

            // Log capture event with context
            crate::audit!(
                ctx,
                RelayHostKeyCaptured {
                    name: review.host.clone(),
                    relay_id: review.host_id,
                    key_type: review.new_key_type.clone(),
                    fingerprint: review.new_fingerprint.clone(),
                }
            );

            return Ok(Some(AppAction::ReviewHostkey(review)));
        }
        AppAction::StoreHostkey { id, name: _name, key } => {
            super::relay_host::store_relay_hostkey_by_id(ctx, id, key).await?;
        }
        AppAction::CancelHostkey { .. } => {
            // No global state to clear
        }
        _ => {}
    }
    Ok(None)
}

/// Convenience wrapper for TUI callers: runs the management action and, on error,
/// sets a one-shot flash message so the Management UI can surface feedback.
// Format an error message suitable for display in the ManagementApp status area
pub fn format_action_error(action: &tui_core::AppAction, e: &ServerError) -> String {
    match action {
        AppAction::AddRelay(item) => format!("Cannot add relay host '{}': {}", item.name, e),
        AppAction::UpdateRelay(item) => format!("Cannot update relay host '{}': {}", item.name, e),
        AppAction::DeleteRelay(id) => format!("Cannot delete relay host id {}: {}", id, e),
        AppAction::AddCredential(spec) => match spec {
            CredentialSpec::Password { name, .. } => {
                format!("Cannot create password credential '{}': {}", name, e)
            }
            CredentialSpec::SshKey { name, .. } => {
                format!("Cannot create ssh_key credential '{}': {}", name, e)
            }
            CredentialSpec::Agent { name, .. } => format!("Cannot create agent credential '{}': {}", name, e),
        },
        AppAction::DeleteCredential(id) => {
            format!("Cannot delete credential (id: {}): {}", id, e)
        }
        AppAction::AssignCredential { host_id, cred_id } => {
            format!("Cannot set credential (id: {}) for host (id: {}): {}", cred_id, host_id, e)
        }
        AppAction::UnassignCredential(host_id) => {
            format!("Cannot clear credential for host (id: {}): {}", host_id, e)
        }
        _ => format!("Operation failed: {}", e),
    }
}

/// Create a RelaySelectorApp with relay hosts loaded from the database
/// If username is Some, filters by access. If None (or "admin"), shows all relays with admin privileges.
pub async fn create_relay_selector_app(username: Option<&str>) -> ServerResult<RelaySelectorApp> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    // TODO THIS SHOULD USE THE SAME LOGIC WE USE IN WEBUI BASED ON AT LEAST VIEW CLAIMS WE SHOULD RELOCATE ENSURE_CLAIMS
    let is_admin = username == Some("admin") || username.is_none();

    // Fetch relays. Admin view must bypass ACL filtering.
    let hosts = if is_admin {
        state_store::list_relay_hosts(&pool, Option::<i64>::None).await?
    } else {
        // username is Some(uname) and not "admin"
        let uname = username.unwrap();
        if let Some(uid) = state_store::fetch_user_id_by_name(&pool, uname).await? {
            state_store::list_relay_hosts(&pool, Some(uid)).await?
        } else {
            Vec::new()
        }
    };

    let relays: Vec<RelayItem> = hosts
        .into_iter()
        .map(|h| RelayItem {
            name: h.name,
            description: format!("{}:{}", h.ip, h.port),
            id: h.id,
        })
        .collect();

    Ok(if is_admin {
        RelaySelectorApp::new_for_admin(relays)
    } else {
        RelaySelectorApp::new(relays)
    })
}

/// Fetch relay hostkey for web UI review (returns tuple to avoid tui_core dependency)
/// Returns: (host_id, host_name, old_fp, old_type, new_fp, new_type, new_pem)
pub async fn fetch_relay_hostkey_for_web(
    ctx: &rb_types::audit::AuditContext,
    id: i64,
) -> ServerResult<(i64, String, Option<String>, Option<String>, String, String, String)> {
    // Get host name first
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_id(&pool, id)
        .await?
        .ok_or_else(|| ServerError::not_found("relay host", id.to_string()))?;

    let action = AppAction::FetchHostkey { id, name: host.name };
    let result = handle_management_action(ctx, action).await?;

    match result {
        Some(AppAction::ReviewHostkey(review)) => Ok((
            review.host_id,
            review.host,
            review.old_fingerprint,
            review.old_key_type,
            review.new_fingerprint,
            review.new_key_type,
            review.new_key_pem,
        )),
        _ => Err(ServerError::Other("Failed to fetch hostkey".to_string())),
    }
}

/// Store relay hostkey from web UI (avoids tui_core dependency)
pub async fn store_relay_hostkey_from_web(ctx: &rb_types::audit::AuditContext, id: i64, key_pem: String) -> ServerResult<()> {
    let action = AppAction::StoreHostkey {
        id,
        name: String::new(), // name is not used in StoreHostkey handler
        key: key_pem,
    };
    handle_management_action(ctx, action).await?;
    Ok(())
}
