use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result, anyhow};
use russh::{ChannelMsg, CryptoVec, client, keys};
use tokio::sync::{mpsc, watch};
use tracing::{info, warn};
use russh::keys::HashAlg;

use ssh_core::crypto::default_preferred;
use state_store::RelayHost;

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
        std::borrow::Cow::Owned(vec![russh::compression::ZLIB, russh::compression::ZLIB_LEGACY, russh::compression::NONE])
    } else {
        std::borrow::Cow::Owned(vec![russh::compression::NONE, russh::compression::ZLIB, russh::compression::ZLIB_LEGACY])
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
        type Error = anyhow::Error;
        fn check_server_key(&mut self, key: &keys::PublicKey) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
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
        .await
        .with_context(|| format!("failed to connect to relay host {}", target))?;

    // Authenticate according to options.
    let username = options
        .get("auth.username")
        .map(|s| s.as_str())
        .unwrap_or(base_username);
    let method = options.get("auth.method").map(|s| s.as_str()).unwrap_or("password");
    match method {
        "password" => {
            let password = options
                .get("auth.password")
                .ok_or_else(|| anyhow!("relay host requires 'auth.password' for password auth"))?;
            let res = remote
                .authenticate_password(username.to_string(), password.clone())
                .await?;
            ensure_success(res, "password")?;
        }
        "publickey" => {
            let key_path = options
                .get("auth.identity")
                .ok_or_else(|| anyhow!("relay host requires 'auth.identity' for publickey auth"))?;
            use russh::keys::HashAlg;
            let key = load_private_key(PathBuf::from(key_path))
                .await
                .with_context(|| format!("failed to load identity from {}", key_path))?;
            let key = Arc::new(key);
            let key = keys::PrivateKeyWithHashAlg::new(key, None::<HashAlg>);
            let res = remote
                .authenticate_publickey(username.to_string(), key)
                .await?;
            ensure_success(res, "publickey")?;
        }
        other => return Err(anyhow!("unsupported relay auth.method: {other}")),
    }

    // Open channel + PTY + shell
    let rchan = remote.channel_open_session().await?;
    let (cols, rows) = initial_size;
    rchan
        .request_pty(true, "xterm", cols as u32, rows as u32, 0, 0, &[])
        .await?;
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

async fn load_private_key(path: PathBuf) -> Result<keys::PrivateKey> {
    let data = tokio::fs::read_to_string(&path).await?;
    match keys::PrivateKey::from_openssh(&data) {
        Ok(key) => Ok(key),
        Err(openssh_err) => {
            match keys::decode_secret_key(&data, None) {
                Ok(key) => Ok(key),
                Err(keys::Error::KeyIsEncrypted) => Err(anyhow!(
                    "encrypted private keys are not supported for server-side relay yet"
                )),
                Err(err) => Err(anyhow!(
                    "{} is not a valid OpenSSH or PEM private key ({openssh_err})",
                    path.display()
                )
                .context(err)),
            }
        }
    }
}

fn ensure_success(res: client::AuthResult, method: &str) -> Result<()> {
    match res {
        client::AuthResult::Success => Ok(()),
        client::AuthResult::Failure { .. } => Err(anyhow!("relay authentication failed via {method}")),
    }
}
