use std::sync::Arc;

// Internal Result type alias
type Result<T> = crate::ServerResult<T>;
use rb_types::RelayInfo;
use russh::{ChannelMsg, CryptoVec, client, keys};
use secrecy::ExposeSecret;
use serde_json::Value as JsonValue;
use ssh_core::crypto::default_preferred;
use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

pub struct RelayHandle {
    pub session: russh::client::Handle<SharedRelayHandler>,
    pub channel_id: russh::ChannelId,
    pub input_tx: mpsc::UnboundedSender<Vec<u8>>,
}

/// Minimal prompt event used by non-TUI frontends (e.g., Web UI) to drive interactive auth.
#[derive(Debug, Clone)]
pub struct AuthPromptEvent {
    pub prompt: String,
    pub echo: bool,
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
    action_tx: Option<tokio::sync::mpsc::UnboundedSender<tui_core::AppAction>>,
    auth_rx: Option<tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<String>>>,
    prompt_sink: Option<(russh::server::Handle, russh::ChannelId)>,
) -> Result<RelayHandle> {
    let auth_rx = auth_rx.map(Arc::new);

    // Build client config with secure defaults.
    let cfg = build_client_config(options);

    // Client handler that enforces host-key policy.
    let handler = SharedRelayHandler {
        expected_key: options.get("hostkey.openssh").map(|v| v.expose_secret().clone()),
        relay_name: relay.name.clone(),
        warning_callback: Arc::new({
            let server_handle = server_handle.clone();
            let relay_name = relay.name.clone();
            move |msg| {
                let server_handle = server_handle.clone();
                let relay_name = relay_name.clone();
                Box::pin(async move {
                    warn!(relay = %relay_name, "{}", msg);
                    let mut payload = CryptoVec::new();
                    payload.extend(format!("[rustybridge] {}\r\n", msg).as_bytes());
                    let _ = server_handle.data(client_channel, payload).await;
                })
            }
        }),
        action_tx: action_tx.clone(),
        auth_rx: auth_rx.clone(),
    };

    let target = format!("{}:{}", relay.ip, relay.port);
    let peer = peer_addr.map(|a| a.to_string()).unwrap_or_else(|| "unknown".to_string());
    info!(relay = %relay.name, target, peer, "connecting to relay host");

    let mut remote = client::connect(cfg, (relay.ip.as_str(), relay.port as u16), handler).await?;

    // Authenticate according to options.
    let prompt_sink = prompt_sink.clone();
    authenticate_relay_session(&mut remote, options, base_username, &action_tx, &auth_rx, prompt_sink).await?;

    // Open channel + PTY + shell
    let rchan = remote.channel_open_session().await?;
    let (cols, rows) = initial_size;
    rchan.request_pty(true, "xterm", cols as u32, rows as u32, 0, 0, &[]).await?;
    rchan.request_shell(true).await?;

    // Set up input channel for client->relay traffic.
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let server_handle_in = server_handle.clone();
    let client_channel_in = client_channel;
    let channel_id = rchan.id();

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

    Ok(RelayHandle {
        session: remote,
        channel_id,
        input_tx: tx,
    })
}

/// Resolve the username for relay authentication based on credential configuration.
/// Returns None if username should be prompted interactively (username_mode="blank").
async fn resolve_auth_username(
    options: &std::collections::HashMap<String, crate::secrets::SecretString>,
    fallback: &str,
) -> Option<String> {
    // Explicit auth.username always takes precedence (for inline auth)
    if let Some(u) = options.get("auth.username") {
        return Some(u.expose_secret().clone());
    }

    // If relay options declare username_mode explicitly, honor it
    if let Some(mode) = options.get("auth.username_mode").map(|s| s.expose_secret().as_str()) {
        match mode {
            "passthrough" => return Some(fallback.to_string()),
            "blank" => return None,
            "fixed" => {
                // fall through to credential/meta or inline username
            }
            _ => {}
        }
    }

    // Check credential configuration
    if let Some(id_str) = options.get("auth.id")
        && let Ok(id) = id_str.expose_secret().parse::<i64>()
    {
        let db = match state_store::server_db().await {
            Ok(h) => h,
            Err(_) => return Some(fallback.to_string()),
        };
        let pool = db.into_pool();
        if let Ok(Some(row)) = state_store::get_relay_credential_by_id(&pool, id).await {
            // Check username_mode
            match row.username_mode.as_str() {
                "passthrough" => {
                    // Use the relay user's username (base_username)
                    return Some(fallback.to_string());
                }
                "blank" => {
                    // Signal that username should be prompted interactively
                    return None;
                }
                "fixed" | _ => {
                    // Use stored username from meta, or fallback
                    if let Some(meta) = row.meta
                        && let Ok(json) = serde_json::from_str::<JsonValue>(&meta)
                        && let Some(u) = json.get("username").and_then(|v| v.as_str())
                    {
                        return Some(u.to_string());
                    } else {
                        // No stored username; fallback to base user
                        return Some(fallback.to_string());
                    }
                }
            }
        }
    }

    // No credential; default to manual login
    // TODO: Perhaps this should be a failure, or perhaps we should allow our server to configure in
    // settings if we should fallback to manual, passthrough, or deny when no username mode is specified.
    None
}

fn ensure_success(res: client::AuthResult, method: &str) -> Result<()> {
    match res {
        client::AuthResult::Success => Ok(()),
        client::AuthResult::Failure { .. } => Err(crate::ServerError::Other(format!("relay authentication failed via {method}"))),
    }
}

/// Send an interactive prompt to the user (if channels are present) and await the response.
async fn prompt_for_input(
    prompt: &str,
    echo: bool,
    action_tx: &Option<tokio::sync::mpsc::UnboundedSender<tui_core::AppAction>>,
    auth_rx: &Option<std::sync::Arc<tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<String>>>>,
    prompt_sink: Option<(russh::server::Handle, russh::ChannelId)>,
) -> Result<String> {
    let tx = action_tx
        .as_ref()
        .ok_or_else(|| crate::ServerError::Other("interactive auth prompt channel unavailable".to_string()))?;
    let rx_arc = auth_rx
        .as_ref()
        .ok_or_else(|| crate::ServerError::Other("interactive auth response channel unavailable".to_string()))?;

    // Fire the prompt to the UI; ignore send errors because the receiver might have gone away.
    tracing::warn!("sending interactive prompt: '{}', echo={}", prompt, echo);
    let prompt_str = if echo { prompt.to_string() } else { format!("\r\n{}", prompt) };
    let _ = tx.send(tui_core::AppAction::AuthPrompt { prompt: prompt_str, echo });

    if let Some((handle, chan)) = prompt_sink {
        let mut payload = CryptoVec::new();
        payload.extend(prompt.as_bytes());
        // Do not append trailing spaces/newlines here; just the prompt text.
        let _ = handle.data(chan, payload).await;
    }

    let mut rx = rx_arc.lock().await;
    let response = rx
        .recv()
        .await
        .ok_or_else(|| crate::ServerError::Other("authentication prompt was cancelled".to_string()))?;

    let trimmed = response.trim_end_matches(|c| c == '\r' || c == '\n').to_string();
    tracing::warn!(
        "received interactive response (len={}, echo={} prompt='{}')",
        trimmed.len(),
        echo,
        prompt
    );
    Ok(trimmed)
}

async fn authenticate_relay_session<H: client::Handler>(
    remote: &mut client::Handle<H>,
    options: &std::collections::HashMap<String, crate::secrets::SecretString>,
    base_username: &str,
    action_tx: &Option<tokio::sync::mpsc::UnboundedSender<tui_core::AppAction>>,
    auth_rx: &Option<std::sync::Arc<tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<String>>>>,
    prompt_sink: Option<(russh::server::Handle, russh::ChannelId)>,
) -> Result<()> {
    let method = options.get("auth.method").map(|s| s.expose_secret().as_str()).unwrap_or("password");
    let username_opt = resolve_auth_username(options, base_username).await;
    let cred_id = options.get("auth.id").and_then(|s| s.expose_secret().parse::<i64>().ok());
    let interactive_available = action_tx.is_some() && auth_rx.is_some();
    let mut username_mode = String::from("inline");
    let mut password_required_flag: Option<bool> = None;
    // Capture explicit username_mode override from options (e.g., relay settings)
    if let Some(mode) = options.get("auth.username_mode") {
        username_mode = mode.expose_secret().clone();
    }

    match method {
        "password" => {
            // Resolve username, prompting if configured as blank
            let username = match username_opt {
                Some(u) => u,
                None if interactive_available => {
                    tracing::warn!(
                        "relay auth prompting for username (base_user={}, cred_id={:?})",
                        base_username,
                        cred_id
                    );
                    prompt_for_input("Username: ", true, action_tx, auth_rx, prompt_sink.clone()).await?
                }
                None => {
                    return Err(crate::ServerError::Other(
                        "relay host requires a username but no interactive prompt channel is available".to_string(),
                    ));
                }
            };

            // Resolve password depending on credential configuration
            let mut password_required = true;
            let mut password: Option<String> = None;

            if let Some(id) = cred_id {
                let db = state_store::server_db().await?;
                let pool = db.into_pool();
                let cred = state_store::get_relay_credential_by_id(&pool, id)
                    .await?
                    .ok_or_else(|| crate::ServerError::not_found("credential", id.to_string()))?;
                if cred.kind != "password" {
                    return Err(crate::ServerError::Other("credential is not of kind password".to_string()));
                }
                username_mode = cred.username_mode.clone();
                password_required = cred.password_required;
                password_required_flag = Some(cred.password_required);

                let has_secret = !cred.secret.is_empty();
                if has_secret {
                    match crate::secrets::decrypt_secret(&cred.salt, &cred.nonce, &cred.secret) {
                        Ok((pt, is_legacy)) => {
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
                            password = Some(
                                String::from_utf8(pt.expose_secret().clone())
                                    .map_err(|_| crate::ServerError::Crypto("credential secret is not valid UTF-8".to_string()))?,
                            );
                            // If the stored password is empty, treat it as None so we prompt interactively
                            if let Some(ref p) = password {
                                if p.is_empty() {
                                    password = None;
                                }
                            }
                        }
                        Err(e) => {
                            warn!("failed to decrypt password credential {id}: {e}");
                            // Fall through to prompt/empty handling below
                            password = None;
                        }
                    }
                }
            } else if let Some(pw) = options.get("auth.password") {
                let val = pw.expose_secret().to_string();
                if val.is_empty() {
                    // Treat empty inline password as "absent" so we will prompt
                    password = None;
                } else {
                    password = Some(val);
                }
            }
            tracing::info!(
                "relay auth password path pre-prompt (cred_id={:?}, inline_pw_present={}, password_required={}, interactive_available={})",
                cred_id,
                password.is_some(),
                password_required,
                interactive_available
            );

            let password = match password {
                Some(pw) => pw,
                None if interactive_available => {
                    tracing::warn!(
                        "relay auth prompting for password (user={}, cred_id={:?}, password_required={:?}, username_mode={})",
                        username,
                        cred_id,
                        password_required_flag.unwrap_or(password_required),
                        username_mode
                    );
                    prompt_for_input("Password: ", false, action_tx, auth_rx, prompt_sink.clone()).await?
                }
                None if !password_required => {
                    warn!("password not stored for relay credential; using empty password");
                    String::new()
                }
                None => {
                    return Err(crate::ServerError::Other(
                        "relay host requires a password but no interactive prompt channel is available".to_string(),
                    ));
                }
            };

            tracing::info!(
                "relay auth attempting password method (user={}, cred_id={:?}, username_mode={}, password_required={}, interactive_available={})",
                username,
                cred_id,
                username_mode,
                password_required_flag.unwrap_or(password_required),
                interactive_available
            );

            tracing::info!(
                "relay auth attempting password method (user={}, cred_id={:?}, username_mode={}, password_required={}, interactive_available={}, options_username_mode={})",
                username,
                cred_id,
                username_mode,
                password_required_flag.unwrap_or(password_required),
                interactive_available,
                options
                    .get("auth.username_mode")
                    .map(|s| s.expose_secret().as_str())
                    .unwrap_or("unset"),
            );
            let res = remote.authenticate_password(username, password).await?;
            ensure_success(res, "password")?;
        }
        "publickey" | "ssh_key" => {
            // Resolve username (publickey doesn't support blank/interactive username)
            let username =
                username_opt.ok_or_else(|| crate::ServerError::Other("Username required for publickey authentication".to_string()))?;

            if let Some(id) = cred_id {
                let db = state_store::server_db().await?;
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
            // Resolve username (agent doesn't support blank/interactive username)
            let username =
                username_opt.ok_or_else(|| crate::ServerError::Other("Username required for agent authentication".to_string()))?;

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
    prompt_tx: Option<tokio::sync::mpsc::UnboundedSender<AuthPromptEvent>>,
    auth_rx: Option<tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<String>>>,
) -> Result<russh::Channel<russh::client::Msg>> {
    let db = state_store::server_db().await?;
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

    let auth_rx = auth_rx.map(Arc::new);

    // Bridge simple prompt events (for web) to AppAction channel expected by auth flow
    let (action_tx, mut action_rx_forward) = if prompt_tx.is_some() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<tui_core::AppAction>();
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    let handler = SharedRelayHandler {
        expected_key: options.get("hostkey.openssh").map(|v| v.expose_secret().clone()),
        relay_name: relay.name.clone(),
        warning_callback: std::sync::Arc::new(|msg| {
            Box::pin(async move {
                eprintln!("Warning: {}", msg);
            })
        }),
        action_tx: action_tx.clone(),
        auth_rx: auth_rx.clone(),
    };

    let mut session = client::connect(cfg, (relay.ip.as_str(), relay.port as u16), handler).await?;

    // If we're bridging prompts, forward AuthPrompt actions to the caller's channel.
    if let (Some(mut rx), Some(ptx)) = (action_rx_forward.take(), prompt_tx) {
        tokio::spawn(async move {
            while let Some(action) = rx.recv().await {
                if let tui_core::AppAction::AuthPrompt { prompt, echo } = action {
                    let _ = ptx.send(AuthPromptEvent { prompt, echo });
                }
            }
        });
    }

    authenticate_relay_session(&mut session, &options, base_username, &action_tx, &auth_rx, None).await?;

    let channel = session.channel_open_session().await?;
    channel.request_pty(true, "xterm", term_size.0, term_size.1, 0, 0, &[]).await?;
    channel.request_shell(true).await?;

    Ok(channel)
}

/// Connect to a relay host from the local machine (CLI) and bridge to stdio.
pub async fn connect_to_relay_local(relay_name: &str, base_username: &str) -> Result<()> {
    let db = state_store::server_db().await?;
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
        warning_callback: std::sync::Arc::new(|msg| {
            Box::pin(async move {
                eprintln!("Warning: {}", msg);
            })
        }),
        action_tx: None,
        auth_rx: None,
    };

    let mut session = client::connect(cfg, (relay.ip.as_str(), relay.port as u16), handler).await?;

    let no_action_tx: Option<tokio::sync::mpsc::UnboundedSender<tui_core::AppAction>> = None;
    let no_auth_rx: Option<std::sync::Arc<tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<String>>>> = None;
    authenticate_relay_session(&mut session, &options, base_username, &no_action_tx, &no_auth_rx, None).await?;

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

pub struct SharedRelayHandler {
    pub expected_key: Option<String>,
    pub relay_name: String,
    pub warning_callback: std::sync::Arc<dyn Fn(String) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync>,
    pub action_tx: Option<tokio::sync::mpsc::UnboundedSender<tui_core::AppAction>>,
    pub auth_rx: Option<std::sync::Arc<tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<String>>>>,
}

impl client::Handler for SharedRelayHandler {
    type Error = russh::Error;

    fn check_server_key(
        &mut self,
        server_public_key: &keys::PublicKey,
    ) -> impl std::future::Future<Output = std::result::Result<bool, Self::Error>> + Send {
        let expected = self.expected_key.clone();
        let callback = self.warning_callback.clone();
        let key_str_res = server_public_key.to_openssh().map(|k| k.to_string());

        async move {
            let key_str = match key_str_res {
                Ok(k) => k,
                Err(_) => return Ok(false),
            };

            if let Some(ref exp) = expected {
                if key_str != *exp {
                    callback(format!("HOST KEY MISMATCH: expected '{}', got '{}'", exp, key_str)).await;
                    return Ok(false);
                }
            }
            Ok(true)
        }
    }
}
