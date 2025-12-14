//! Authentication logic for relay connections.
//!
//! This module handles the various authentication methods for connecting to relay hosts.

use super::credential::ResolvedCredential;
use crate::{
    error::{ServerError, ServerResult},
    secrets::SecretBoxedString,
};
use russh::{CryptoVec, client, keys};
use secrecy::ExposeSecret;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tracing::{trace, warn};

// Internal Result type alias
type Result<T> = ServerResult<T>;

pub fn ensure_success(res: client::AuthResult, method: &str) -> Result<()> {
    match res {
        client::AuthResult::Success => Ok(()),
        client::AuthResult::Failure { .. } => Err(ServerError::Other(format!("relay authentication failed via {method}"))),
    }
}

/// Send an interactive prompt to the user (if channels are present) and await the response.
pub async fn prompt_for_input(
    prompt: &str,
    echo: bool,
    action_tx: &Option<UnboundedSender<tui_core::AppAction>>,
    auth_rx: &Option<std::sync::Arc<tokio::sync::Mutex<UnboundedReceiver<String>>>>,
    prompt_sink: Option<(russh::server::Handle, russh::ChannelId)>,
) -> Result<String> {
    let tx = action_tx
        .as_ref()
        .ok_or_else(|| ServerError::Other("interactive auth prompt channel unavailable".to_string()))?;
    let rx_arc = auth_rx
        .as_ref()
        .ok_or_else(|| ServerError::Other("interactive auth response channel unavailable".to_string()))?;

    // Fire the prompt to the UI; ignore send errors because the receiver might have gone away.
    trace!(prompt = %prompt, echo, "sending interactive prompt");
    let prompt_str = if echo { prompt.to_string() } else { format!("\r\n{}", prompt) };
    let _ = tx.send(tui_core::AppAction::AuthPrompt { prompt: prompt_str, echo });

    if let Some((handle, chan)) = prompt_sink {
        let mut payload = CryptoVec::new();
        payload.extend(prompt.as_bytes());
        // Do not append trailing spaces/newlines here; just the prompt text.
        let _ = handle.data(chan, payload).await;
    }

    const MAX_PROMPT_RESPONSE: usize = 1024; // Reasonable username/password size

    let mut rx = rx_arc.lock().await;
    let response = rx
        .recv()
        .await
        .ok_or_else(|| ServerError::Other("authentication prompt was cancelled".to_string()))?;

    if response.len() > MAX_PROMPT_RESPONSE {
        return Err(ServerError::Other("interactive response too large".to_string()));
    }

    let trimmed = response.trim_end_matches(['\r', '\n']).to_string();
    trace!(
        len = trimmed.len(),
        echo,
        prompt = %prompt,
        "received interactive response"
    );
    Ok(trimmed)
}

pub async fn authenticate_relay_session<H: client::Handler>(
    remote: &mut client::Handle<H>,
    options: &HashMap<String, SecretBoxedString>,
    base_username: &str,
    resolved_cred: Option<&ResolvedCredential>,
    action_tx: &Option<UnboundedSender<tui_core::AppAction>>,
    auth_rx: &Option<std::sync::Arc<tokio::sync::Mutex<UnboundedReceiver<String>>>>,
    prompt_sink: Option<(russh::server::Handle, russh::ChannelId)>,
) -> Result<()> {
    let method = options.get("auth.method").map(|s| s.expose_secret().as_str()).unwrap_or("password");
    let interactive_available = action_tx.is_some() && auth_rx.is_some();

    // Get username and metadata from resolved credential or options
    let (username_opt, username_mode, password_required) = if let Some(cred) = resolved_cred {
        (cred.username.clone(), cred.username_mode.clone(), cred.password_required)
    } else {
        // Inline auth: resolve username from options
        let username = if let Some(u) = options.get("auth.username") {
            Some(u.expose_secret().clone())
        } else if let Some(mode) = options.get("auth.username_mode").map(|s| s.expose_secret().as_str()) {
            match mode {
                "passthrough" => Some(base_username.to_string()),
                "blank" => None,
                _ => Some(base_username.to_string()),
            }
        } else {
            Some(base_username.to_string())
        };
        (username, String::from("inline"), true)
    };

    match method {
        "password" => {
            // Resolve username, prompting if configured as blank
            let username = match username_opt {
                Some(u) => u,
                None if interactive_available => {
                    trace!(
                        base_user = %base_username,
                        cred_id = ?resolved_cred.map(|c| c.id),
                        "relay auth prompting for username"
                    );
                    prompt_for_input("Username: ", true, action_tx, auth_rx, prompt_sink.clone()).await?
                }
                None => {
                    return Err(ServerError::Other(
                        "relay host requires a username but no interactive prompt channel is available".to_string(),
                    ));
                }
            };

            // Resolve password from credential or inline options
            let mut password: Option<String> = None;

            if let Some(cred) = resolved_cred {
                // Use pre-decrypted secret from resolved credential
                if cred.kind != "password" {
                    return Err(ServerError::Other("credential is not of kind password".to_string()));
                }

                if !cred.secret.expose_secret().is_empty() {
                    password = Some(
                        String::from_utf8(cred.secret.expose_secret().clone())
                            .map_err(|_| ServerError::Crypto("credential secret is not valid UTF-8".to_string()))?,
                    );
                    // If the stored password is empty, treat it as None so we prompt interactively
                    if let Some(ref p) = password
                        && p.is_empty()
                    {
                        password = None;
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

            trace!(
                cred_id = ?resolved_cred.map(|c| c.id),
                inline_pw_present = password.is_some(),
                password_required,
                interactive_available,
                "relay auth password path pre-prompt"
            );

            let password = match password {
                Some(pw) => pw,
                None if interactive_available => {
                    trace!(
                        user = %username,
                        cred_id = ?resolved_cred.map(|c| c.id),
                        password_required,
                        username_mode = %username_mode,
                        "relay auth prompting for password"
                    );
                    prompt_for_input("Password: ", false, action_tx, auth_rx, prompt_sink.clone()).await?
                }
                None if !password_required => {
                    warn!("password not stored for relay credential; using empty password");
                    String::new()
                }
                None => {
                    return Err(ServerError::Other(
                        "relay host requires a password but no interactive prompt channel is available".to_string(),
                    ));
                }
            };

            trace!(
                user = %username,
                cred_id = ?resolved_cred.map(|c| c.id),
                username_mode = %username_mode,
                password_required,
                interactive_available,
                "relay auth attempting password method"
            );

            let res = remote.authenticate_password(username, password).await?;
            ensure_success(res, "password")?;
        }
        "publickey" | "ssh_key" => {
            // Resolve username (publickey doesn't support blank/interactive username)
            let username = username_opt.ok_or_else(|| ServerError::Other("Username required for publickey authentication".to_string()))?;

            if let Some(cred) = resolved_cred {
                // Use pre-decrypted secret from resolved credential
                if cred.kind != "ssh_key" {
                    return Err(ServerError::Other("credential is not of kind ssh_key".to_string()));
                }

                let json: serde_json::Value = serde_json::from_slice(cred.secret.expose_secret()).map_err(ServerError::Json)?;
                let pk_str = json
                    .get("private_key")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| ServerError::Crypto("ssh_key payload missing private_key".to_string()))?;
                let passphrase = json.get("passphrase").and_then(|v| v.as_str());
                let priv_key =
                    ssh_core::keys::load_private_key_from_str(pk_str, passphrase).map_err(|e| ServerError::Crypto(e.to_string()))?;
                let cert = json.get("certificate").and_then(|v| v.as_str());
                let auth_res = if let Some(cert_str) = cert {
                    let cert = keys::Certificate::from_openssh(cert_str).map_err(|e| ServerError::Crypto(e.to_string()))?;
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
                    ServerError::Other("relay host requires 'auth.identity' or 'auth.id' for publickey/ssh_key auth".to_string())
                })?;
                let passphrase = options.get("auth.passphrase").map(|s| s.expose_secret().as_str());

                // Parse inline key material only; path-based keys are intentionally unsupported on the server.
                let r#priv = ssh_core::keys::load_private_key_from_str(key_data, passphrase)
                    .map_err(|e| ServerError::Crypto(format!("failed to parse inline private key: {e}")))?;

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
            let username = username_opt.ok_or_else(|| ServerError::Other("Username required for agent authentication".to_string()))?;

            #[cfg(unix)]
            {
                use russh::keys::agent::client::AgentClient;
                use tokio::net::UnixStream;
                let socket = options
                    .get("auth.agent_socket")
                    .map(|s| s.expose_secret().clone())
                    .or_else(|| std::env::var("RB_SERVER_SSH_AUTH_SOCK").ok())
                    .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
                    .ok_or_else(|| ServerError::Other("agent auth requested but no agent socket configured".to_string()))?;
                let stream = UnixStream::connect(&socket).await.map_err(ServerError::Io)?;
                let mut agent = AgentClient::connect(stream);
                let mut identities = agent
                    .request_identities()
                    .await
                    .map_err(|e| ServerError::Other(format!("failed to list identities from SSH agent: {e}")))?;

                if let Some(cred) = resolved_cred {
                    // Use pre-decrypted secret from resolved credential
                    if cred.kind != "agent" {
                        return Err(ServerError::Other("credential is not of kind agent".to_string()));
                    }

                    let json: serde_json::Value = serde_json::from_slice(cred.secret.expose_secret())?;
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
                        return Err(ServerError::Other(
                            "SSH agent does not hold the required key for this host".to_string(),
                        ));
                    }
                }

                if identities.is_empty() {
                    return Err(ServerError::Other("no identities available for agent authentication".to_string()));
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
                let res = last.ok_or_else(|| ServerError::Other("agent authentication failed for all identities".to_string()))?;
                ensure_success(res, "agent")?;
            }
            #[cfg(not(unix))]
            {
                return Err(ServerError::Other(
                    "agent authentication is not supported on this platform".to_string(),
                ));
            }
        }
        other => return Err(ServerError::Other(format!("unsupported relay auth.method: {other}"))),
    }
    Ok(())
}
