use std::{path::PathBuf, sync::Arc};

// Internal Result type alias
type Result<T> = crate::ServerResult<T>;
use russh::{ChannelMsg, CryptoVec, client, keys, keys::HashAlg};
use serde_json::Value as JsonValue;
use ssh_core::crypto::default_preferred;
use state_store::RelayHost;
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
pub async fn start_bridge(
    server_handle: russh::server::Handle,
    client_channel: russh::ChannelId,
    relay: &RelayHost,
    base_username: &str,
    initial_size: (u16, u16),
    mut pty_size_rx: watch::Receiver<(u16, u16)>,
    options: &std::collections::HashMap<String, String>,
) -> Result<RelayHandle> {
    // Build client config with secure defaults.
    let mut cfg = client::Config {
        preferred: default_preferred(),
        nodelay: true,
        keepalive_interval: Some(std::time::Duration::from_secs(30)),
        keepalive_max: 3,
        ..Default::default()
    };
    let insecure = options.get("insecure").map(|v| v == "true").unwrap_or(false);
    if insecure {
        // Fallback to legacy crypto suite if requested; this is a placeholder and can be extended later.
        cfg.preferred = ssh_core::crypto::legacy_preferred();
    }
    let prefer_compression = options.get("compression").map(|v| v == "true").unwrap_or(false);
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

    let cfg = Arc::new(cfg);

    // Client handler that enforces host-key policy.
    #[derive(Clone)]
    struct RelayClientHandler {
        expected_key: Option<String>,
        server_handle: russh::server::Handle,
        client_channel: russh::ChannelId,
        relay_name: String,
    }
    impl client::Handler for RelayClientHandler {
        type Error = crate::ServerError;
        fn check_server_key(
            &mut self,
            key: &keys::PublicKey,
        ) -> impl std::future::Future<Output = std::result::Result<bool, Self::Error>> + Send {
            let expected = self.expected_key.clone().map(|s| s.trim().to_string());
            let relay_name = self.relay_name.clone();
            let handle = self.server_handle.clone();
            let channel = self.client_channel;
            let presented = key.to_openssh().map(|s| s.to_string()).unwrap_or_default();
            let presented_norm = presented.trim().to_string();
            let algo = key.algorithm().to_string();
            let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
            async move {
                if let Some(exp) = expected {
                    if exp == presented_norm {
                        return Ok(true);
                    }
                    warn!(relay = %relay_name, algo, fp = %fingerprint, "relay host key mismatch; rejecting connection");
                    return Ok(false);
                }
                warn!(relay = %relay_name, algo, fp = %fingerprint, "no stored relay host key; accepting this session only");
                let msg = format!(
                    "[rustybridge] Warning: no stored host key for relay '{relay_name}'.\r\nKey type: {algo}, Fingerprint (SHA256): {fingerprint}.\r\nAccepted this session only. Please store the host key to avoid this warning.\r\n"
                );
                let mut payload = CryptoVec::new();
                payload.extend(msg.as_bytes());
                let _ = handle.data(channel, payload).await;
                Ok(true)
            }
        }
    }

    let target = format!("{}:{}", relay.ip, relay.port);
    info!(relay = %relay.name, target, "connecting to relay host");
    let handler = RelayClientHandler {
        expected_key: options.get("hostkey.openssh").cloned(),
        server_handle: server_handle.clone(),
        client_channel,
        relay_name: relay.name.clone(),
    };
    let mut remote = client::connect(cfg, (relay.ip.as_str(), relay.port as u16), handler)
        .await?;

    // Authenticate according to options.
    let method = options.get("auth.method").map(|s| s.as_str()).unwrap_or("password");
    let username = resolve_auth_username(options, base_username).await;
    let cred_id = options.get("auth.id").and_then(|s| s.parse::<i64>().ok());
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
                let pt = crate::secrets::decrypt_secret(&cred.salt, &cred.nonce, &cred.secret)?;
                String::from_utf8(pt).map_err(|_| crate::ServerError::Crypto("credential secret is not valid UTF-8".to_string()))?
            } else {
                options
                    .get("auth.password")
                    .ok_or_else(|| crate::ServerError::Other("relay host requires 'auth.password' for password auth".to_string()))?
                    .to_string()
            };
            let res = remote.authenticate_password(username.to_string(), password).await?;
            ensure_success(res, "password")?;
        }
        "publickey" | "ssh_key" => {
            use russh::keys::HashAlg;
            // Prefer credential if provided; else require auth.identity path
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
                // Decrypt secret JSON and parse key + optional certificate
                let pt = crate::secrets::decrypt_secret(&cred.salt, &cred.nonce, &cred.secret)?;
                let json: serde_json::Value = serde_json::from_slice(&pt).map_err(crate::ServerError::Json)?;
                let pk_str = json
                    .get("private_key")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| crate::ServerError::Crypto("ssh_key payload missing private_key".to_string()))?;
                let passphrase = json.get("passphrase").and_then(|v| v.as_str());
                let priv_key = match keys::PrivateKey::from_openssh(pk_str) {
                    Ok(k) => k,
                    Err(_) => {
                        if let Some(pw) = passphrase {
                            keys::decode_secret_key(pk_str, Some(pw))
                                .map_err(|e| crate::ServerError::Crypto(format!("failed to decode encrypted private key: {e}")))?
                        } else {
                            return Err(crate::ServerError::Crypto(
                                "encrypted private key requires a passphrase in credential".to_string(),
                            ));
                        }
                    }
                };
                let cert = json.get("certificate").and_then(|v| v.as_str());
                let auth_res = if let Some(cert_str) = cert {
                    let cert = keys::Certificate::from_openssh(cert_str).map_err(|e| crate::ServerError::Crypto(e.to_string()))?;
                    remote
                        .authenticate_openssh_cert(username.to_string(), Arc::new(priv_key), cert)
                        .await?
                } else {
                    let key = Arc::new(priv_key);
                    let key = keys::PrivateKeyWithHashAlg::new(key, None::<HashAlg>);
                    remote.authenticate_publickey(username.to_string(), key).await?
                };
                ensure_success(auth_res, "publickey")?;
            } else {
                let key_path = options.get("auth.identity").ok_or_else(|| {
                    crate::ServerError::Other("relay host requires 'auth.identity' or 'auth.id' for publickey/ssh_key auth".to_string())
                })?;
                let r#priv = load_private_key(PathBuf::from(key_path)).await?;
                let key = Arc::new(r#priv);
                let key = keys::PrivateKeyWithHashAlg::new(key, None::<HashAlg>);
                let res = remote.authenticate_publickey(username.to_string(), key).await?;
                ensure_success(res, "publickey")?;
            }
        }
        "agent" => {
            #[cfg(unix)]
            {
                use russh::keys::agent::client::AgentClient;
                use tokio::net::UnixStream;
                // Resolve agent socket path
                let socket = options
                    .get("auth.agent_socket")
                    .cloned()
                    .or_else(|| std::env::var("RB_SERVER_SSH_AUTH_SOCK").ok())
                    .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
                    .ok_or_else(|| crate::ServerError::Other("agent auth requested but no agent socket configured (set auth.agent_socket or RB_SERVER_SSH_AUTH_SOCK/SSH_AUTH_SOCK)".to_string()))?;
                let stream = UnixStream::connect(&socket).await.map_err(crate::ServerError::Io)?;
                let mut agent = AgentClient::connect(stream);
                let mut identities = agent
                    .request_identities()
                    .await
                    .map_err(|e| crate::ServerError::Other(format!("failed to list identities from SSH agent: {e}")))?;
                // If a specific agent credential is assigned, filter identities to match
                if let Some(id) = cred_id {
                    let db = state_store::server_db().await?;
                    state_store::migrate_server(&db).await?;
                    let pool = db.into_pool();
                    if let Some(cred) = state_store::get_relay_credential_by_id(&pool, id).await? && cred.kind == "agent" {
                        let pt = crate::secrets::decrypt_secret(&cred.salt, &cred.nonce, &cred.secret)?;
                        let json: serde_json::Value = serde_json::from_slice(&pt)?;
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
                // RSA hash hint
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

async fn resolve_auth_username(options: &std::collections::HashMap<String, String>, fallback: &str) -> String {
    if let Some(u) = options.get("auth.username") {
        return u.clone();
    }
    if let Some(id_str) = options.get("auth.id") && let Ok(id) = id_str.parse::<i64>() {
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
            && let Some(u) = json.get("username").and_then(|v| v.as_str()) {
            return u.to_string();
        }
    }
    fallback.to_string()
}

async fn load_private_key(path: PathBuf) -> Result<keys::PrivateKey> {
    let data = tokio::fs::read_to_string(&path).await?;
    match keys::PrivateKey::from_openssh(&data) {
        Ok(key) => Ok(key),
        Err(_openssh_err) => match keys::decode_secret_key(&data, None) {
            Ok(key) => Ok(key),
            Err(keys::Error::KeyIsEncrypted) => Err(crate::ServerError::Crypto(
                "encrypted private keys are not supported for server-side relay yet".to_string(),
            )),
            Err(_) => Err(crate::ServerError::Crypto(format!(
                "{} is not a valid OpenSSH or PEM private key",
                path.display()
            ))),
        },
    }
}

fn ensure_success(res: client::AuthResult, method: &str) -> Result<()> {
    match res {
        client::AuthResult::Success => Ok(()),
        client::AuthResult::Failure { .. } => Err(crate::ServerError::Other(format!("relay authentication failed via {method}"))),
    }
}
