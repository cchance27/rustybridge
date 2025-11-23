use std::sync::Arc;

// Internal Result type alias
type Result<T> = crate::ServerResult<T>;
use rb_types::RelayInfo;
use russh::{ChannelMsg, CryptoVec, client, keys, keys::HashAlg};
use secrecy::ExposeSecret;
use serde_json::Value as JsonValue;
use ssh_core::crypto::default_preferred;
use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

#[derive(Clone)]
pub struct RelayHandle {
    input_tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl RelayHandle {
    pub fn send(&self, bytes: Vec<u8>) {
        let _ = self.input_tx.send(bytes);
    }
}

/// Start an outbound SSH session to the relay host and bridge IO between the remote channel and the inbound client channel.
///
/// - `server_handle` is used to send data back to the inbound client channel.
/// - `client_channel` is the inbound channel id on the embedded server.
/// - `pty_size_rx` emits window-size updates to propagate to the relay session.
/// - `options` is a key-value map from `relay_host_options`.
#[allow(clippy::too_many_arguments)]
pub async fn start_bridge(
    server_handle: russh::server::Handle,
    client_channel: russh::ChannelId,
    relay: &RelayInfo,
    base_username: &str,
    initial_size: (u16, u16),
    mut pty_size_rx: watch::Receiver<(u16, u16)>,
    options: &std::collections::HashMap<String, crate::secrets::SecretString>,
    peer_addr: Option<std::net::SocketAddr>,
) -> Result<RelayHandle> {
    // Build client config with secure defaults.
    let cfg = build_client_config(options);

    // Client handler that enforces host-key policy.
    let handler = SharedRelayHandler {
        expected_key: options.get("hostkey.openssh").map(|v| v.expose_secret().clone()),
        relay_name: relay.name.clone(),
        warning_callback: Box::new({
            let server_handle = server_handle.clone();
            let relay_name = relay.name.clone();
            move |msg| {
                let server_handle = server_handle.clone();
                let relay_name = relay_name.clone();
                async move {
                    warn!(relay = %relay_name, "{}", msg);
                    let mut payload = CryptoVec::new();
                    payload.extend(format!("[rustybridge] {}\r\n", msg).as_bytes());
                    let _ = server_handle.data(client_channel, payload).await;
                }
            }
        }),
    };

    let target = format!("{}:{}", relay.ip, relay.port);
    let peer = peer_addr.map(|a| a.to_string()).unwrap_or_else(|| "unknown".to_string());
    info!(relay = %relay.name, target, peer, "connecting to relay host");

    let mut remote = client::connect(cfg, (relay.ip.as_str(), relay.port as u16), handler).await?;

    // Authenticate according to options.
    authenticate_relay_session(&mut remote, options, base_username).await?;

    // Open channel + PTY + shell
    let rchan = remote.channel_open_session().await?;
    let (cols, rows) = initial_size;
    rchan.request_pty(true, "xterm", cols as u32, rows as u32, 0, 0, &[]).await?;
    rchan.request_shell(true).await?;

    // Set up input channel for client->relay traffic.
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let server_handle_in = server_handle.clone();
    let client_channel_in = client_channel;

    // Single task handling relay->client, client->relay, and window resizes.
    tokio::spawn(async move {
        let mut rchan = rchan; // move into task
        loop {
            tokio::select! {
                msg = rchan.wait() => {
                    match msg {
                        Some(ChannelMsg::Data { data }) => {
                            let mut payload = CryptoVec::new();
                            payload.extend(&data);
                            if server_handle_in.data(client_channel_in, payload).await.is_err() {
                                break;
                            }
                        }
                        Some(ChannelMsg::ExtendedData { data, .. }) => {
                            let mut payload = CryptoVec::new();
                            payload.extend(&data);
                            if server_handle_in.data(client_channel_in, payload).await.is_err() {
                                break;
                            }
                        }
                        Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                            let _ = server_handle_in.close(client_channel_in).await;
                            break;
                        }
                        _ => {}
                    }
                }
                maybe_bytes = rx.recv() => {
                    match maybe_bytes {
                        Some(bytes) => {
                            if !bytes.is_empty() {
                                let mut cursor = std::io::Cursor::new(bytes);
                                if rchan.data(&mut cursor).await.is_err() {
                                    break;
                                }
                            }
                        }
                        None => {
                            let _ = rchan.eof().await;
                            let _ = rchan.close().await;
                            break;
                        }
                    }
                }
                changed = pty_size_rx.changed() => {
                    if changed.is_err() { break; }
                    let size = *pty_size_rx.borrow();
                    let cols = size.0.max(1) as u32;
                    let rows = size.1.max(1) as u32;
                    if rchan.window_change(cols, rows, 0, 0).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    Ok(RelayHandle { input_tx: tx })
}

async fn resolve_auth_username(options: &std::collections::HashMap<String, crate::secrets::SecretString>, fallback: &str) -> String {
    if let Some(u) = options.get("auth.username") {
        return u.expose_secret().clone();
    }
    if let Some(id_str) = options.get("auth.id")
        && let Ok(id) = id_str.expose_secret().parse::<i64>()
    {
        let db = match state_store::server_db().await {
            Ok(h) => h,
            Err(_) => return fallback.to_string(),
        };
        if state_store::migrate_server(&db).await.is_err() {
            return fallback.to_string();
        }
        let pool = db.into_pool();
        if let Ok(Some(row)) = state_store::get_relay_credential_by_id(&pool, id).await
            && let Some(meta) = row.meta
            && let Ok(json) = serde_json::from_str::<JsonValue>(&meta)
            && let Some(u) = json.get("username").and_then(|v| v.as_str())
        {
            return u.to_string();
        }
    }
    fallback.to_string()
}

fn ensure_success(res: client::AuthResult, method: &str) -> Result<()> {
    match res {
        client::AuthResult::Success => Ok(()),
        client::AuthResult::Failure { .. } => Err(crate::ServerError::Other(format!("relay authentication failed via {method}"))),
    }
}

async fn authenticate_relay_session<H: client::Handler>(
    remote: &mut client::Handle<H>,
    options: &std::collections::HashMap<String, crate::secrets::SecretString>,
    base_username: &str,
) -> Result<()> {
    let method = options.get("auth.method").map(|s| s.expose_secret().as_str()).unwrap_or("password");
    let username = resolve_auth_username(options, base_username).await;
    let cred_id = options.get("auth.id").and_then(|s| s.expose_secret().parse::<i64>().ok());
    match method {
        "password" => {
            let password = if let Some(id) = cred_id {
                let db = state_store::server_db().await?;
                state_store::migrate_server(&db).await?;
                let pool = db.into_pool();
                let cred = state_store::get_relay_credential_by_id(&pool, id)
                    .await?
                    .ok_or_else(|| crate::ServerError::not_found("credential", id.to_string()))?;
                if cred.kind != "password" {
                    return Err(crate::ServerError::Other("credential is not of kind password".to_string()));
                }
                let (pt, is_legacy) = crate::secrets::decrypt_secret(&cred.salt, &cred.nonce, &cred.secret)?;
                if is_legacy {
                    warn!("Upgrading legacy v1 credential '{}' (password)", id);
                    if let Ok(blob) = crate::secrets::encrypt_secret(pt.expose_secret()) {
                        let _ = sqlx::query("UPDATE relay_credentials SET salt = ?, nonce = ?, secret = ? WHERE id = ?")
                            .bind(blob.salt)
                            .bind(blob.nonce)
                            .bind(blob.ciphertext)
                            .bind(id)
                            .execute(&pool)
                            .await;
                    }
                }
                String::from_utf8(pt.expose_secret().clone())
                    .map_err(|_| crate::ServerError::Crypto("credential secret is not valid UTF-8".to_string()))?
            } else {
                options
                    .get("auth.password")
                    .ok_or_else(|| crate::ServerError::Other("relay host requires 'auth.password' for password auth".to_string()))?
                    .expose_secret()
                    .to_string()
            };
            let res = remote.authenticate_password(username.to_string(), password).await?;
            ensure_success(res, "password")?;
        }
        "publickey" | "ssh_key" => {
            if let Some(id) = cred_id {
                let db = state_store::server_db().await?;
                state_store::migrate_server(&db).await?;
                let pool = db.into_pool();
                let cred = state_store::get_relay_credential_by_id(&pool, id)
                    .await?
                    .ok_or_else(|| crate::ServerError::not_found("credential", id.to_string()))?;
                if cred.kind != "ssh_key" {
                    return Err(crate::ServerError::Other("credential is not of kind ssh_key".to_string()));
                }
                let (pt, is_legacy) = crate::secrets::decrypt_secret(&cred.salt, &cred.nonce, &cred.secret)?;
                if is_legacy {
                    warn!("Upgrading legacy v1 credential '{}' (ssh_key)", id);
                    if let Ok(blob) = crate::secrets::encrypt_secret(pt.expose_secret()) {
                        let _ = sqlx::query("UPDATE relay_credentials SET salt = ?, nonce = ?, secret = ? WHERE id = ?")
                            .bind(blob.salt)
                            .bind(blob.nonce)
                            .bind(blob.ciphertext)
                            .bind(id)
                            .execute(&pool)
                            .await;
                    }
                }
                let json: serde_json::Value = serde_json::from_slice(pt.expose_secret()).map_err(crate::ServerError::Json)?;
                let pk_str = json
                    .get("private_key")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| crate::ServerError::Crypto("ssh_key payload missing private_key".to_string()))?;
                let passphrase = json.get("passphrase").and_then(|v| v.as_str());
                let priv_key =
                    ssh_core::keys::load_private_key_from_str(pk_str, passphrase).map_err(|e| crate::ServerError::Crypto(e.to_string()))?;
                let cert = json.get("certificate").and_then(|v| v.as_str());
                let auth_res = if let Some(cert_str) = cert {
                    let cert = keys::Certificate::from_openssh(cert_str).map_err(|e| crate::ServerError::Crypto(e.to_string()))?;
                    remote
                        .authenticate_openssh_cert(username.to_string(), Arc::new(priv_key), cert)
                        .await?
                } else {
                    // Pick best RSA hash if applicable (rsa-sha2-256/512 vs legacy ssh-rsa)
                    let rsa_hint = remote.best_supported_rsa_hash().await.unwrap_or(None).flatten();
                    let hash_alg = if priv_key.algorithm().is_rsa() { rsa_hint } else { None };
                    let key = Arc::new(priv_key);
                    let key = keys::PrivateKeyWithHashAlg::new(key, hash_alg);
                    remote.authenticate_publickey(username.to_string(), key).await?
                };
                ensure_success(auth_res, "publickey")?;
            } else {
                let key_data = options.get("auth.identity").map(|s| s.expose_secret()).ok_or_else(|| {
                    crate::ServerError::Other("relay host requires 'auth.identity' or 'auth.id' for publickey/ssh_key auth".to_string())
                })?;
                let passphrase = options.get("auth.passphrase").map(|s| s.expose_secret().as_str());

                // Parse inline key material only; path-based keys are intentionally unsupported on the server.
                let r#priv = ssh_core::keys::load_private_key_from_str(key_data, passphrase)
                    .map_err(|e| crate::ServerError::Crypto(format!("failed to parse inline private key: {e}")))?;

                // Pick best RSA hash if applicable (rsa-sha2-256/512 vs legacy ssh-rsa)
                let rsa_hint = remote.best_supported_rsa_hash().await.unwrap_or(None).flatten();
                let hash_alg = if r#priv.algorithm().is_rsa() { rsa_hint } else { None };
                let key = Arc::new(r#priv);
                let key = keys::PrivateKeyWithHashAlg::new(key, hash_alg);
                let res = remote.authenticate_publickey(username.to_string(), key).await?;
                ensure_success(res, "publickey")?;
            }
        }
        "agent" => {
            #[cfg(unix)]
            {
                use russh::keys::agent::client::AgentClient;
                use tokio::net::UnixStream;
                let socket = options
                    .get("auth.agent_socket")
                    .map(|s| s.expose_secret().clone())
                    .or_else(|| std::env::var("RB_SERVER_SSH_AUTH_SOCK").ok())
                    .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
                    .ok_or_else(|| crate::ServerError::Other("agent auth requested but no agent socket configured".to_string()))?;
                let stream = UnixStream::connect(&socket).await.map_err(crate::ServerError::Io)?;
                let mut agent = AgentClient::connect(stream);
                let mut identities = agent
                    .request_identities()
                    .await
                    .map_err(|e| crate::ServerError::Other(format!("failed to list identities from SSH agent: {e}")))?;
                if let Some(id) = cred_id {
                    let db = state_store::server_db().await?;
                    state_store::migrate_server(&db).await?;
                    let pool = db.into_pool();
                    if let Some(cred) = state_store::get_relay_credential_by_id(&pool, id).await?
                        && cred.kind == "agent"
                    {
                        let (pt, is_legacy) = crate::secrets::decrypt_secret(&cred.salt, &cred.nonce, &cred.secret)?;
                        if is_legacy {
                            warn!("Upgrading legacy v1 credential '{}' (agent)", id);
                            if let Ok(blob) = crate::secrets::encrypt_secret(pt.expose_secret()) {
                                let _ = sqlx::query("UPDATE relay_credentials SET salt = ?, nonce = ?, secret = ? WHERE id = ?")
                                    .bind(blob.salt)
                                    .bind(blob.nonce)
                                    .bind(blob.ciphertext)
                                    .bind(id)
                                    .execute(&pool)
                                    .await;
                            }
                        }
                        let json: serde_json::Value = serde_json::from_slice(pt.expose_secret())?;
                        let target_fp = json.get("fingerprint").and_then(|v| v.as_str()).map(|s| s.to_string());
                        let target_pk = json.get("public_key").and_then(|v| v.as_str()).map(|s| s.to_string());
                        let mut filtered = Vec::new();
                        for k in identities.into_iter() {
                            let fp = k.fingerprint(russh::keys::HashAlg::Sha256).to_string();
                            let matches_fp = target_fp.as_ref().map(|t| t == &fp).unwrap_or(false);
                            let matches_pk = if let Some(ref pk) = target_pk {
                                k.to_openssh().ok().map(|s| s.to_string()) == Some(pk.clone())
                            } else {
                                false
                            };
                            if matches_fp || matches_pk {
                                filtered.push(k);
                            }
                        }
                        identities = filtered;
                        if identities.is_empty() {
                            return Err(crate::ServerError::Other(
                                "SSH agent does not hold the required key for this host".to_string(),
                            ));
                        }
                    }
                }
                if identities.is_empty() {
                    return Err(crate::ServerError::Other("SSH agent has no loaded keys".to_string()));
                }
                let rsa_hint = remote.best_supported_rsa_hash().await.unwrap_or(None).flatten();
                let mut last = None;
                for key in identities.drain(..) {
                    let hash_alg = match key.algorithm() {
                        keys::Algorithm::Rsa { .. } => rsa_hint,
                        _ => None,
                    };
                    match remote
                        .authenticate_publickey_with(username.to_string(), key.clone(), hash_alg, &mut agent)
                        .await
                    {
                        Ok(result) if result.success() => {
                            last = Some(result);
                            break;
                        }
                        Ok(result) => {
                            last = Some(result);
                        }
                        Err(_err) => {
                            warn!("agent authentication attempt failed");
                        }
                    }
                }
                let res = last.ok_or_else(|| crate::ServerError::Other("agent authentication failed for all identities".to_string()))?;
                ensure_success(res, "agent")?;
            }
            #[cfg(not(unix))]
            {
                return Err(crate::ServerError::Other(
                    "agent authentication is not supported on this platform".to_string(),
                ));
            }
        }
        other => return Err(crate::ServerError::Other(format!("unsupported relay auth.method: {other}"))),
    }
    Ok(())
}

/// Connect to a relay host and return an open channel for external I/O handling.
/// This is used for WebSocket bridging where the caller manages the channel I/O.
pub async fn connect_to_relay_channel(
    relay_name: &str,
    base_username: &str,
    term_size: (u32, u32),
) -> Result<russh::Channel<russh::client::Msg>> {
    let db = state_store::server_db().await?;
    state_store::migrate_server(&db).await?;
    let pool = db.into_pool();

    let relay = state_store::fetch_relay_host_by_name(&pool, relay_name)
        .await?
        .ok_or_else(|| crate::ServerError::not_found("relay host", relay_name))?;

    let options_map = state_store::fetch_relay_host_options(&pool, relay.id).await?;
    let mut options = std::collections::HashMap::new();
    for (k, (v, is_secure)) in options_map {
        if is_secure {
            if let Ok((decrypted, is_legacy)) = crate::secrets::decrypt_string_if_encrypted(&v) {
                if is_legacy {
                    warn!("Upgrading legacy v1 secret for relay option '{}'", k);
                    if let Ok(new_enc) =
                        crate::secrets::encrypt_string(secrecy::SecretBox::<String>::new(Box::new(decrypted.expose_secret().to_string())))
                    {
                        let _ = sqlx::query("UPDATE relay_host_options SET value = ? WHERE relay_host_id = ? AND key = ?")
                            .bind(new_enc)
                            .bind(relay.id)
                            .bind(&k)
                            .execute(&pool)
                            .await;
                    }
                }
                options.insert(k, decrypted);
            } else {
                options.insert(k, crate::secrets::SecretString::new(Box::new(v)));
            }
        } else {
            options.insert(k, crate::secrets::SecretString::new(Box::new(v)));
        }
    }

    let cfg = build_client_config(&options);

    let handler = SharedRelayHandler {
        expected_key: options.get("hostkey.openssh").map(|v| v.expose_secret().clone()),
        relay_name: relay.name.clone(),
        warning_callback: Box::new(|msg| async move {
            eprintln!("Warning: {}", msg);
        }),
    };

    let mut session = client::connect(cfg, (relay.ip.as_str(), relay.port as u16), handler).await?;

    authenticate_relay_session(&mut session, &options, base_username).await?;

    let channel = session.channel_open_session().await?;
    channel.request_pty(true, "xterm", term_size.0, term_size.1, 0, 0, &[]).await?;
    channel.request_shell(true).await?;

    Ok(channel)
}

/// Connect to a relay host from the local machine (CLI) and bridge to stdio.
pub async fn connect_to_relay_local(relay_name: &str, base_username: &str) -> Result<()> {
    let db = state_store::server_db().await?;
    state_store::migrate_server(&db).await?;
    let pool = db.into_pool();

    let relay = state_store::fetch_relay_host_by_name(&pool, relay_name)
        .await?
        .ok_or_else(|| crate::ServerError::not_found("relay host", relay_name))?;

    let options_map = state_store::fetch_relay_host_options(&pool, relay.id).await?;
    let mut options = std::collections::HashMap::new();
    for (k, (v, is_secure)) in options_map {
        if is_secure {
            if let Ok((decrypted, is_legacy)) = crate::secrets::decrypt_string_if_encrypted(&v) {
                if is_legacy {
                    warn!("Upgrading legacy v1 secret for relay option '{}'", k);
                    if let Ok(new_enc) =
                        crate::secrets::encrypt_string(secrecy::SecretBox::<String>::new(Box::new(decrypted.expose_secret().to_string())))
                    {
                        let _ = sqlx::query("UPDATE relay_host_options SET value = ? WHERE relay_host_id = ? AND key = ?")
                            .bind(new_enc)
                            .bind(relay.id)
                            .bind(&k)
                            .execute(&pool)
                            .await;
                    }
                }
                options.insert(k, decrypted);
            } else {
                // Fallback if decryption fails or it wasn't encrypted but marked secure
                options.insert(k, crate::secrets::SecretString::new(Box::new(v)));
            }
        } else {
            // Plain text
            options.insert(k, crate::secrets::SecretString::new(Box::new(v)));
        }
    }

    // Build client config
    let cfg = build_client_config(&options);

    let handler = SharedRelayHandler {
        expected_key: options.get("hostkey.openssh").map(|v| v.expose_secret().clone()),
        relay_name: relay.name.clone(),
        warning_callback: Box::new(|msg| async move {
            eprintln!("Warning: {}", msg);
        }),
    };

    let mut session = client::connect(cfg, (relay.ip.as_str(), relay.port as u16), handler).await?;

    authenticate_relay_session(&mut session, &options, base_username).await?;

    // Run interactive shell bridging to stdio
    let shell_opts = ssh_core::session::ShellOptions {
        newline_mode: ssh_core::terminal::NewlineMode::default(),
        local_echo: false,
        forward_agent: false, // TODO: support forwarding agent if requested
        forwarding: ssh_core::forwarding::ForwardingManager::new(ssh_core::forwarding::ForwardingConfig::default()),
    };

    let session = Arc::new(session);
    ssh_core::session::run_shell(&session, shell_opts)
        .await
        .map_err(|e| crate::ServerError::Other(e.to_string()))?;

    Ok(())
}

fn build_client_config(options: &std::collections::HashMap<String, crate::secrets::SecretString>) -> Arc<client::Config> {
    let mut cfg = client::Config {
        preferred: default_preferred(),
        nodelay: true,
        keepalive_interval: Some(std::time::Duration::from_secs(30)),
        keepalive_max: 3,
        ..Default::default()
    };
    let insecure = options.get("insecure").map(|v| v.expose_secret() == "true").unwrap_or(false);
    if insecure {
        // Fallback to legacy crypto suite if requested
        cfg.preferred = ssh_core::crypto::legacy_preferred();
    }
    let prefer_compression = options.get("compression").map(|v| v.expose_secret() == "true").unwrap_or(false);
    cfg.preferred.compression = if prefer_compression {
        std::borrow::Cow::Owned(vec![
            russh::compression::ZLIB,
            russh::compression::ZLIB_LEGACY,
            russh::compression::NONE,
        ])
    } else {
        std::borrow::Cow::Owned(vec![
            russh::compression::NONE,
            russh::compression::ZLIB,
            russh::compression::ZLIB_LEGACY,
        ])
    };
    Arc::new(cfg)
}

#[derive(Clone)]
pub struct SharedRelayHandler<F> {
    pub expected_key: Option<String>,
    pub relay_name: String,
    pub warning_callback: Box<F>,
}

impl<F, Fut> client::Handler for SharedRelayHandler<F>
where
    F: Fn(String) -> Fut + Send + Sync + Clone + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    type Error = crate::ServerError;
    fn check_server_key(
        &mut self,
        key: &keys::PublicKey,
    ) -> impl std::future::Future<Output = std::result::Result<bool, Self::Error>> + Send {
        let expected = self.expected_key.clone().map(|s| s.trim().to_string());
        let relay_name = self.relay_name.clone();
        let presented = key.to_openssh().map(|s| s.to_string()).unwrap_or_default();
        let presented_norm = presented.trim().to_string();
        let algo = key.algorithm().to_string();
        let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
        let callback = self.warning_callback.clone();

        async move {
            if let Some(exp) = expected {
                if exp == presented_norm {
                    return Ok(true);
                }
                callback(format!(
                    "Relay host key mismatch for '{}'! Expected: {}, Presented: {}",
                    relay_name, exp, presented_norm
                ))
                .await;
                return Ok(false);
            }
            callback(format!(
                "No stored host key for relay '{}'. Key type: {}, Fingerprint: {}. Accepted this session only.",
                relay_name, algo, fingerprint
            ))
            .await;
            Ok(true)
        }
    }
}
