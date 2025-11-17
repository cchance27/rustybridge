use std::{
    env,
    io::{self, Write},
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use russh::keys::{self, HashAlg, PublicKey};
use sqlx::{Row, SqlitePool, migrate::Migrator, sqlite::SqlitePoolOptions};
use tokio::task;
use tracing::info;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

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
        let pool = SqlitePoolOptions::new()
            .max_connections(20)
            .connect(&client_db_url())
            .await
            .context("failed to open client state database")?;
        
        MIGRATOR.run(&pool).await?;

        Ok(Self { pool, authority, policy })
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
        let presented = server_key.to_openssh()?.to_string();
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
            bail!(
                "host key mismatch for {} (cached SHA256 {} vs received {})",
                self.authority,
                cached_fp,
                presented_fp
            );
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
                    PromptDecision::Reject => bail!("host key rejected by user"),
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

fn client_db_url() -> String {
    match env::var("DATABASE_URL") {
        Ok(value) if value.starts_with("sqlite:") => value,
        Ok(value) => format!("sqlite://{value}"),
        Err(_) => "sqlite://rustybridge.db".to_string(),
    }
}

#[derive(Clone)]
pub struct HostKeyHandler {
    verifier: Arc<HostKeyVerifier>,
}

impl HostKeyHandler {
    pub fn new(verifier: HostKeyVerifier) -> Self {
        Self {
            verifier: Arc::new(verifier),
        }
    }
}

impl russh::client::Handler for HostKeyHandler {
    type Error = anyhow::Error;

    fn check_server_key(&mut self, server_public_key: &PublicKey) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        let verifier = Arc::clone(&self.verifier);
        let key = server_public_key.clone();
        async move { verifier.check(&key).await }
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
        print!("Accept host key? [y]es/[s]tore/[n]o: ");
        io::stdout().flush().ok();
        let mut input = String::new();
        io::stdin().read_line(&mut input).context("failed to read host-key confirmation")?;
        match input.trim().to_lowercase().as_str() {
            "y" | "yes" => Ok(PromptDecision::AcceptSession),
            "s" | "store" => Ok(PromptDecision::AcceptAndStore),
            _ => Ok(PromptDecision::Reject),
        }
    })
    .await?
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
