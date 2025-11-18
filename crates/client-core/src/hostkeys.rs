use std::{
    io::{self, Write}, path::{Path, PathBuf}, sync::Arc
};

// Internal Result type alias
type Result<T> = crate::ClientResult<T>;
use russh::{
    Channel, client::{Msg, Session}, keys::{self, HashAlg, PublicKey}
};
use sqlx::{Row, SqlitePool};
use ssh_core::forwarding::ForwardingManager;
use state_store::{client_db, migrate_client};
#[cfg(unix)]
use tokio::io::{AsyncWriteExt, copy_bidirectional};
use tokio::task;
use tracing::{info, warn};

#[derive(Clone, Copy)]
pub enum HostKeyPolicy {
    Prompt,
    AcceptOnce,
    AcceptAndStore,
}

pub struct HostKeyVerifier {
    pool: SqlitePool,
    authority: String,
    policy: HostKeyPolicy,
}

impl HostKeyVerifier {
    pub async fn new(authority: String, policy: HostKeyPolicy) -> Result<Self> {
        let handle = client_db().await.map_err(crate::ClientError::Database)?;
        migrate_client(&handle).await?;

        Ok(Self {
            pool: handle.into_pool(),
            authority,
            policy,
        })
    }

    pub async fn clear(&self) -> Result<()> {
        sqlx::query("DELETE FROM client_hostkeys WHERE authority = ?")
            .bind(&self.authority)
            .execute(&self.pool)
            .await?;
        info!("cleared cached host key for {}", self.authority);
        Ok(())
    }

    pub async fn check(&self, server_key: &PublicKey) -> Result<bool> {
        let presented = server_key
            .to_openssh()
            .map_err(|e| crate::ClientError::Crypto(e.to_string()))?
            .to_string();
        if let Some(row) = sqlx::query("SELECT key FROM client_hostkeys WHERE authority = ?")
            .bind(&self.authority)
            .fetch_optional(&self.pool)
            .await?
        {
            let key: String = row.try_get("key")?;
            if key == presented {
                info!("host key for {} verified against stored fingerprint", self.authority);
                return Ok(true);
            }
            let cached_fp = fingerprint_for_string(&key).unwrap_or_else(|| "<invalid cache>".into());
            let presented_fp = server_key.fingerprint(HashAlg::Sha256).to_string();
            return Err(crate::ClientError::HostKeyFailed(format!(
                "host key mismatch for {} (cached SHA256 {} vs received {})",
                self.authority, cached_fp, presented_fp
            )));
        }

        match self.policy {
            HostKeyPolicy::Prompt => {
                let algo = server_key.algorithm().to_string();
                let fingerprint = server_key.fingerprint(HashAlg::Sha256).to_string();
                match prompt_for_hostkey(&self.authority, &algo, &fingerprint).await? {
                    PromptDecision::AcceptSession => {
                        info!("user accepted host key for {} (session only)", self.authority);
                        Ok(true)
                    }
                    PromptDecision::AcceptAndStore => {
                        sqlx::query("INSERT INTO client_hostkeys (authority, key) VALUES (?, ?) ON CONFLICT(authority) DO UPDATE SET key = excluded.key")
                            .bind(&self.authority)
                            .bind(&presented)
                            .execute(&self.pool)
                            .await?;
                        info!("stored host key for {} after user confirmation", self.authority);
                        Ok(true)
                    }
                    PromptDecision::Reject => Err(crate::ClientError::HostKeyFailed("host key rejected by user".to_string())),
                }
            }
            HostKeyPolicy::AcceptOnce => {
                info!("accepting host key for {} (session only)", self.authority);
                Ok(true)
            }
            HostKeyPolicy::AcceptAndStore => {
                sqlx::query(
                    "INSERT INTO client_hostkeys (authority, key) VALUES (?, ?) ON CONFLICT(authority) DO UPDATE SET key = excluded.key",
                )
                .bind(&self.authority)
                .bind(&presented)
                .execute(&self.pool)
                .await?;
                info!("stored host key for {}", self.authority);
                Ok(true)
            }
        }
    }
}

#[derive(Clone)]
pub struct ClientHandler {
    verifier: Arc<HostKeyVerifier>,
    agent_socket: Option<Arc<PathBuf>>,
    forward_agent: bool,
    forwarding: ForwardingManager,
}

impl ClientHandler {
    pub fn new(verifier: HostKeyVerifier, agent_socket: Option<PathBuf>, forward_agent: bool, forwarding: ForwardingManager) -> Self {
        Self {
            verifier: Arc::new(verifier),
            agent_socket: agent_socket.map(Arc::new),
            forward_agent,
            forwarding,
        }
    }
}

impl russh::client::Handler for ClientHandler {
    type Error = crate::ClientError;

    fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> impl std::future::Future<Output = std::result::Result<bool, Self::Error>> + Send {
        let verifier = Arc::clone(&self.verifier);
        let key = server_public_key.clone();
        async move { verifier.check(&key).await }
    }

    fn server_channel_open_agent_forward(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> impl std::future::Future<Output = std::result::Result<(), Self::Error>> + Send {
        let allow = self.forward_agent;
        let socket = self.agent_socket.clone();
        async move {
            if !allow {
                return Ok(());
            }
            let Some(path) = socket else {
                warn!("server requested agent forwarding but no SSH_AUTH_SOCK is configured");
                return Ok(());
            };
            #[cfg(unix)]
            {
                if let Err(err) = proxy_agent_channel(channel, path.as_ref()).await {
                    warn!(error = ?err, "agent forwarding channel closed with error");
                }
            }
            #[cfg(not(unix))]
            {
                warn!("agent forwarding is not supported on this platform");
            }
            Ok(())
        }
    }

    fn server_channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut Session,
    ) -> impl std::future::Future<Output = std::result::Result<(), Self::Error>> + Send {
        let forwarding = self.forwarding.clone();
        async move {
            if let Err(err) = forwarding
                .handle_remote_forward_channel(channel, host_to_connect, port_to_connect, originator_address, originator_port)
                .await
            {
                warn!(?err, "remote forwarded connection failed");
            }
            Ok(())
        }
    }

    fn server_channel_open_direct_streamlocal(
        &mut self,
        channel: Channel<Msg>,
        socket_path: &str,
        _session: &mut Session,
    ) -> impl std::future::Future<Output = std::result::Result<(), Self::Error>> + Send {
        let forwarding = self.forwarding.clone();
        async move {
            if let Err(err) = forwarding.handle_remote_streamlocal_channel(channel, socket_path).await {
                warn!(?err, socket = socket_path, "remote unix forwarded connection failed");
            }
            Ok(())
        }
    }
}

enum PromptDecision {
    AcceptSession,
    AcceptAndStore,
    Reject,
}

async fn prompt_for_hostkey(authority: &str, algo: &str, fingerprint: &str) -> Result<PromptDecision> {
    let authority = authority.to_string();
    let algo = algo.to_string();
    let fingerprint = fingerprint.to_string();
    task::spawn_blocking(move || -> Result<PromptDecision> {
        println!("The authenticity of host '{authority}' can't be established.");
        println!("Key type: {algo}");
        println!("Fingerprint (SHA256): {fingerprint}");
        print!("Accept host key? [y]es/[s]tore/[N]o: ");
        io::stdout().flush().ok();
        let mut input = String::new();
        io::stdin().read_line(&mut input).map_err(crate::ClientError::Io)?;
        match input.trim().to_lowercase().as_str() {
            "y" | "yes" => Ok(PromptDecision::AcceptSession),
            "s" | "store" => Ok(PromptDecision::AcceptAndStore),
            _ => Ok(PromptDecision::Reject),
        }
    })
    .await
    .map_err(|e| crate::ClientError::Other(format!("task join error: {e}")))?
}

fn fingerprint_for_string(blob: &str) -> Option<String> {
    let mut parts = blob.split_whitespace();
    let maybe_key = match (parts.next(), parts.next()) {
        (Some(_algo), Some(key)) => Some(key),
        (Some(key), None) => Some(key),
        _ => None,
    }?;
    let parsed = keys::parse_public_key_base64(maybe_key).ok()?;
    Some(parsed.fingerprint(HashAlg::Sha256).to_string())
}

#[cfg(unix)]
async fn proxy_agent_channel(channel: Channel<Msg>, socket: &Path) -> Result<()> {
    use tokio::net::UnixStream;

    let mut agent = UnixStream::connect(socket).await.map_err(crate::ClientError::Io)?;

    let mut stream = channel.into_stream();
    let _ = copy_bidirectional(&mut stream, &mut agent).await?;
    let _ = stream.shutdown().await;
    let _ = agent.shutdown().await;
    Ok(())
}
