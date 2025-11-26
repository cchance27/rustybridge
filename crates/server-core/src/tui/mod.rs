//! TUI app management functionality
//!
//! This module handles creating TUI apps and processing management actions.

use std::collections::HashMap;

use rb_types::relay::HostkeyReview;
use secrecy::ExposeSecret;
use sqlx::Row;
use tracing::info;
use tui_core::{
    AppAction, apps::{
        ManagementApp, RelayItem, RelaySelectorApp, management::{CredentialItem, CredentialSpec}, relay_selector
    }
};

use crate::{
    error::{ServerError, ServerResult}, secrets::{SecretBoxedString, decrypt_string_if_encrypted, encrypt_string, is_encrypted_marker}, set_relay_option
};

/// Create a ManagementApp with all relay hosts loaded from the database (admin view)
pub async fn create_management_app(review: Option<HostkeyReview>) -> ServerResult<ManagementApp> {
    create_management_app_with_tab(0, review).await
}

/// Create a ManagementApp with a specific tab selected
pub async fn create_management_app_with_tab(selected_tab: usize, review: Option<HostkeyReview>) -> ServerResult<ManagementApp> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();

    // Admin sees all relay hosts (no filtering)
    use relay_selector::RelayItem;
    let hosts = state_store::list_relay_hosts(&pool, None).await?;
    let relay_items: Vec<RelayItem> = hosts
        .into_iter()
        .map(|h| RelayItem {
            name: h.name,
            description: format!("{}:{}", h.ip, h.port),
            id: h.id,
        })
        .collect();

    // Credentials with counts
    let creds_rows = state_store::list_relay_credentials(&pool).await?;
    // Build assigned counts by scanning relay_host_options auth.id
    use secrecy::ExposeSecret as _;
    let mut counts: HashMap<i64, i64> = HashMap::new();
    let rows = sqlx::query("SELECT relay_host_id, value FROM relay_host_options WHERE key = 'auth.id'")
        .fetch_all(&pool)
        .await?;
    for row in rows {
        let value: String = row.get("value");
        let (id_str, is_legacy) = if is_encrypted_marker(&value) {
            match decrypt_string_if_encrypted(&value) {
                Ok((s, legacy)) => (s, legacy),
                Err(_) => continue,
            }
        } else {
            (SecretBoxedString::new(Box::new(value)), false)
        };

        if is_legacy {
            tracing::warn!("Upgrading legacy v1 secret for relay option 'auth.id' (management app)");
            if let Ok(new_enc) = encrypt_string(SecretBoxedString::new(Box::new(id_str.expose_secret().to_string()))) {
                let _ = sqlx::query("UPDATE relay_host_options SET value = ? WHERE relay_host_id = ? AND key = 'auth.id'")
                    .bind(new_enc)
                    .bind(row.get::<i64, _>("relay_host_id"))
                    .execute(&pool)
                    .await;
            }
        }
        if let Ok(id) = id_str.expose_secret().parse::<i64>() {
            *counts.entry(id).or_insert(0) += 1;
        }
    }
    let credentials: Vec<CredentialItem> = creds_rows
        .into_iter()
        .map(|(id, name, kind, _meta, _username_mode, _password_required)| CredentialItem {
            id,
            name,
            kind,
            assigned: *counts.get(&id).unwrap_or(&0),
        })
        .collect();

    // Build host->credential label mapping
    let mut host_creds: std::collections::HashMap<i64, String> = std::collections::HashMap::new();
    // Gather relevant options in one query
    let opt_rows = sqlx::query(
        "SELECT relay_host_id, key, value FROM relay_host_options WHERE key IN ('auth.source','auth.id','auth.identity','auth.password')",
    )
    .fetch_all(&pool)
    .await?;
    // Map host_id -> key -> resolved value
    let mut host_opts: std::collections::HashMap<i64, std::collections::HashMap<String, SecretBoxedString>> =
        std::collections::HashMap::new();
    for row in opt_rows {
        let host_id: i64 = row.get("relay_host_id");
        let key: String = row.get("key");
        let raw: String = row.get("value");
        let resolved = if is_encrypted_marker(&raw) {
            match decrypt_string_if_encrypted(&raw) {
                Ok((s, _)) => s, // Skip upgrade - complex context without direct ID access
                Err(_) => continue,
            }
        } else {
            SecretBoxedString::new(Box::new(raw))
        };
        host_opts.entry(host_id).or_default().insert(key, resolved);
    }
    // id -> name
    let mut cred_name_by_id: std::collections::HashMap<i64, String> = std::collections::HashMap::new();
    // rebuild from list (we had moved creds_rows)
    let creds_rows2 = state_store::list_relay_credentials(&pool).await?;
    for (id, name, _kind, _meta, _username_mode, _password_required) in creds_rows2 {
        cred_name_by_id.insert(id, name);
    }
    // Compute label
    for (hid, opts) in host_opts.iter() {
        let label = if let Some(src) = opts.get("auth.source") {
            if src.expose_secret() == "credential" {
                if let Some(id_str) = opts.get("auth.id") {
                    if let Ok(cid) = id_str.expose_secret().parse::<i64>() {
                        cred_name_by_id.get(&cid).cloned().unwrap_or_else(|| "<credential>".to_string())
                    } else {
                        "<credential>".to_string()
                    }
                } else {
                    "<credential>".to_string()
                }
            } else {
                "<custom>".to_string()
            }
        } else if opts.contains_key("auth.identity") || opts.contains_key("auth.password") {
            "<custom>".to_string()
        } else {
            "<none>".to_string()
        };
        host_creds.insert(*hid, label);
    }

    // Hostkey presence mapping
    let mut hostkeys: std::collections::HashMap<i64, bool> = std::collections::HashMap::new();
    let hk_rows = sqlx::query("SELECT relay_host_id FROM relay_host_options WHERE key = 'hostkey.openssh'")
        .fetch_all(&pool)
        .await?;
    for row in hk_rows {
        let hid: i64 = row.get("relay_host_id");
        hostkeys.insert(hid, true);
    }
    // Ensure entries exist for all hosts
    for item in &relay_items {
        hostkeys.entry(item.id).or_insert(false);
    }

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
pub async fn handle_management_action(action: tui_core::AppAction) -> ServerResult<Option<tui_core::AppAction>> {
    match action {
        AppAction::AddRelay(item) => {
            let (ip, port) = super::relay_host::parse_endpoint(&item.description)?;
            let db = state_store::server_db().await?;

            let pool = db.into_pool();
            state_store::insert_relay_host(&pool, &item.name, &ip, port).await?;
        }
        AppAction::UpdateRelay(item) => {
            let (ip, port) = super::relay_host::parse_endpoint(&item.description)?;
            let db = state_store::server_db().await?;

            let pool = db.into_pool();
            state_store::update_relay_host(&pool, item.id, &item.name, &ip, port).await?;
        }
        AppAction::DeleteRelay(id) => {
            let db = state_store::server_db().await?;

            let pool = db.into_pool();
            state_store::delete_relay_host_by_id(&pool, id).await?;
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
                    let _ = super::credential::create_agent_credential(&name, username.as_deref(), &public_key, &username_mode).await?;
                }
            }
        }
        AppAction::DeleteCredential(name) => super::credential::delete_credential(&name).await?,
        AppAction::UnassignCredential(hostname) => super::credential::unassign_credential(&hostname).await?,
        AppAction::AssignCredential { host, cred_name } => super::credential::assign_credential(&host, &cred_name).await?,
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
            if let Some(row) = sqlx::query("SELECT value FROM relay_host_options WHERE relay_host_id = ? AND key = 'hostkey.openssh'")
                .bind(host.id)
                .fetch_optional(&pool)
                .await?
            {
                let raw: String = row.get("value");
                let dec = if is_encrypted_marker(&raw) {
                    match decrypt_string_if_encrypted(&raw) {
                        Ok((s, _)) => s,
                        Err(_) => SecretBoxedString::new(Box::new("".to_string())),
                    }
                } else {
                    SecretBoxedString::new(Box::new(raw))
                };
                if !dec.expose_secret().is_empty()
                    && let Ok(pk) = PublicKey::from_openssh(dec.expose_secret())
                {
                    old_fp = Some(pk.fingerprint(HashAlg::Sha256).to_string());
                    // Extract type from stored content (prefix token)
                    old_type = Some(dec.expose_secret().split_whitespace().next().unwrap_or("").to_string());
                }
            }

            return Ok(Some(AppAction::ReviewHostkey(HostkeyReview {
                host_id: host.id,
                host: host.name,
                new_fingerprint: new_fp,
                new_key_type: new_type,
                old_fingerprint: old_fp,
                old_key_type: old_type,
                new_key_pem: new_pem,
            })));
        }
        AppAction::StoreHostkey { id, name: _name, key } => {
            let db = state_store::server_db().await?;

            let pool = db.into_pool();

            // Resolve host strictly by id to avoid races when names change mid-review
            let host = state_store::fetch_relay_host_by_id(&pool, id)
                .await?
                .ok_or_else(|| ServerError::not_found("relay host", id.to_string()))?;
            let stored = encrypt_string(SecretBoxedString::new(Box::new(key)))?;
            sqlx::query(
                "INSERT INTO relay_host_options (relay_host_id, key, value) VALUES (?, ?, ?) \
                 ON CONFLICT(relay_host_id, key) DO UPDATE SET value = excluded.value",
            )
            .bind(host.id)
            .bind("hostkey.openssh")
            .bind(stored)
            .execute(&pool)
            .await?;
            info!(relay = %host.name, relay_id = host.id, "relay host key accepted and stored");
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
        AppAction::DeleteCredential(name) => {
            format!("Cannot delete credential '{}': {}", name, e)
        }
        AppAction::AssignCredential { host, cred_name } => {
            format!("Cannot set credential '{}' for '{}': {}", cred_name, host, e)
        }
        AppAction::UnassignCredential(host) => {
            format!("Cannot clear credential for '{}': {}", host, e)
        }
        _ => format!("Operation failed: {}", e),
    }
}

/// Create a RelaySelectorApp with relay hosts loaded from the database
/// If username is Some, filters by access. If None (or "admin"), shows all relays with admin privileges.
pub async fn create_relay_selector_app(username: Option<&str>) -> ServerResult<RelaySelectorApp> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    let is_admin = username == Some("admin") || username.is_none();

    // Fetch relays. Admin view must bypass ACL filtering.
    let filter_username = if is_admin { None } else { username };
    let hosts = state_store::list_relay_hosts(&pool, filter_username).await?;
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
pub async fn fetch_relay_hostkey_for_web(id: i64) -> ServerResult<(i64, String, Option<String>, Option<String>, String, String, String)> {
    // Get host name first
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_id(&pool, id)
        .await?
        .ok_or_else(|| ServerError::not_found("relay host", id.to_string()))?;

    let action = AppAction::FetchHostkey { id, name: host.name };
    let result = handle_management_action(action).await?;

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
pub async fn store_relay_hostkey_from_web(id: i64, key_pem: String) -> ServerResult<()> {
    let action = AppAction::StoreHostkey {
        id,
        name: String::new(), // name is not used in StoreHostkey handler
        key: key_pem,
    };
    handle_management_action(action).await?;
    Ok(())
}

/// Set custom password authentication for a relay (inline, not using a saved credential)
pub async fn set_custom_password_auth(
    hostname: &str,
    username: Option<&str>,
    password: &str,
    username_mode: &str,
    password_required: bool,
) -> ServerResult<()> {
    // Clear any existing auth first
    let db = state_store::server_db().await?;
    let pool = db.into_pool();
    if let Some(host) = state_store::fetch_relay_host_by_name(&pool, hostname).await? {
        sqlx::query("DELETE FROM relay_host_options WHERE relay_host_id = ? AND key LIKE 'auth.%'")
            .bind(host.id)
            .execute(&pool)
            .await?;
    }

    set_relay_option(hostname, "auth.source", "inline", true).await?;
    if let Some(user) = username {
        set_relay_option(hostname, "auth.username", user, true).await?;
    }
    set_relay_option(hostname, "auth.password", password, true).await?;
    set_relay_option(hostname, "auth.username_mode", username_mode, true).await?;
    set_relay_option(
        hostname,
        "auth.password_required",
        if password_required { "true" } else { "false" },
        true,
    )
    .await?;
    info!(relay_host = hostname, "custom password auth configured");
    Ok(())
}

/// Set custom SSH key authentication for a relay (inline, not using a saved credential)
pub async fn set_custom_ssh_key_auth(
    hostname: &str,
    username: Option<&str>,
    private_key: &str,
    passphrase: Option<&str>,
    username_mode: &str,
) -> ServerResult<()> {
    // Clear any existing auth first
    let db = state_store::server_db().await?;
    let pool = db.into_pool();
    if let Some(host) = state_store::fetch_relay_host_by_name(&pool, hostname).await? {
        sqlx::query("DELETE FROM relay_host_options WHERE relay_host_id = ? AND key LIKE 'auth.%'")
            .bind(host.id)
            .execute(&pool)
            .await?;
    }

    set_relay_option(hostname, "auth.source", "inline", true).await?;
    set_relay_option(hostname, "auth.method", "publickey", true).await?;
    if let Some(user) = username {
        set_relay_option(hostname, "auth.username", user, true).await?;
    }
    set_relay_option(hostname, "auth.identity", private_key, true).await?;
    if let Some(pass) = passphrase {
        set_relay_option(hostname, "auth.passphrase", pass, true).await?;
    }
    set_relay_option(hostname, "auth.username_mode", username_mode, true).await?;
    info!(relay_host = hostname, "custom SSH key auth configured");
    Ok(())
}

/// Set custom SSH agent authentication for a relay (inline, not using a saved credential)
pub async fn set_custom_agent_auth(hostname: &str, username: Option<&str>, public_key: &str, username_mode: &str) -> ServerResult<()> {
    // Clear any existing auth first
    let db = state_store::server_db().await?;
    let pool = db.into_pool();
    if let Some(host) = state_store::fetch_relay_host_by_name(&pool, hostname).await? {
        sqlx::query("DELETE FROM relay_host_options WHERE relay_host_id = ? AND key LIKE 'auth.%'")
            .bind(host.id)
            .execute(&pool)
            .await?;
    }

    set_relay_option(hostname, "auth.source", "inline", true).await?;
    set_relay_option(hostname, "auth.method", "agent", true).await?;
    if let Some(user) = username {
        set_relay_option(hostname, "auth.username", user, true).await?;
    }
    set_relay_option(hostname, "auth.agent_pubkey", public_key, true).await?;
    set_relay_option(hostname, "auth.username_mode", username_mode, true).await?;
    info!(relay_host = hostname, "custom agent auth configured");
    Ok(())
}

/// Clear all authentication settings from a relay
pub async fn clear_all_auth(hostname: &str) -> ServerResult<()> {
    let db = state_store::server_db().await?;

    let pool = db.into_pool();
    let host = state_store::fetch_relay_host_by_name(&pool, hostname)
        .await?
        .ok_or_else(|| ServerError::not_found("relay host", hostname))?;
    sqlx::query("DELETE FROM relay_host_options WHERE relay_host_id = ? AND key LIKE 'auth.%'")
        .bind(host.id)
        .execute(&pool)
        .await?;
    info!(relay_host = hostname, "all auth settings cleared");
    Ok(())
}
