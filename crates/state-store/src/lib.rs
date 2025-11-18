use std::{
    env, fs::OpenOptions, path::{Path, PathBuf}
};

use sqlx::{Row, SqlitePool, migrate::Migrator, prelude::FromRow, sqlite::SqlitePoolOptions};
use tracing::warn;
use url::Url;

mod error;
pub use error::{DbError, DbResult};

static CLIENT_MIGRATOR: Migrator = sqlx::migrate!("./migrations/client");
static SERVER_MIGRATOR: Migrator = sqlx::migrate!("./migrations/server");

const CLIENT_DB_ENV: &str = "RB_CLIENT_DB_URL";
const SERVER_DB_ENV: &str = "RB_SERVER_DB_URL";

pub struct DbHandle {
    pub pool: SqlitePool,
    pub url: String,
    pub path: Option<PathBuf>,
    pub freshly_created: bool,
}

impl DbHandle {
    pub fn into_pool(self) -> SqlitePool {
        self.pool
    }
}

// -----------------------------
// Server-side relay host access
// -----------------------------

#[derive(Debug, Clone, FromRow)]
pub struct RelayHost {
    pub id: i64,
    pub name: String,
    pub ip: String,
    pub port: i64,
}

pub async fn fetch_relay_host_by_name(pool: &SqlitePool, name: &str) -> DbResult<Option<RelayHost>> {
    if let Some(row) = sqlx::query_as::<_, RelayHost>("SELECT id, name, ip, port FROM relay_hosts WHERE name = ?")
        .bind(name)
        .fetch_optional(pool)
        .await?
    {
        Ok(Some(RelayHost {
            id: row.id,
            name: row.name,
            ip: row.ip,
            port: row.port,
        }))
    } else {
        Ok(None)
    }
}

pub async fn fetch_relay_host_options(pool: &SqlitePool, relay_host_id: i64) -> DbResult<std::collections::HashMap<String, String>> {
    let mut map = std::collections::HashMap::new();
    let rows = sqlx::query_as::<_, (String, String)>("SELECT key, value FROM relay_host_options WHERE relay_host_id = ?")
        .bind(relay_host_id)
        .fetch_all(pool)
        .await?;
    for row in rows {
        map.insert(row.0, row.1);
    }
    Ok(map)
}

pub async fn user_has_relay_access(pool: &SqlitePool, username: &str, relay_host_id: i64) -> DbResult<bool> {
    let row = sqlx::query("SELECT id FROM relay_host_acl WHERE username = ? AND relay_host_id = ?")
        .bind(username)
        .bind(relay_host_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.is_some())
}

pub async fn list_relay_hosts(pool: &SqlitePool) -> DbResult<Vec<RelayHost>> {
    let rows = sqlx::query_as::<_, RelayHost>("SELECT id, name, ip, port FROM relay_hosts ORDER BY name")
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|row| RelayHost {
            id: row.id,
            name: row.name,
            ip: row.ip,
            port: row.port,
        })
        .collect())
}

pub async fn fetch_relay_access_usernames(pool: &SqlitePool, relay_host_id: i64) -> DbResult<Vec<String>> {
    let rows = sqlx::query("SELECT username FROM relay_host_acl WHERE relay_host_id = ? ORDER BY username")
        .bind(relay_host_id)
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("username")).collect())
}

pub async fn fetch_user_id_by_name(pool: &SqlitePool, username: &str) -> DbResult<Option<i64>> {
    let row = sqlx::query("SELECT id FROM users WHERE username = ?")
        .bind(username)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.get::<i64, _>("id")))
}

pub async fn fetch_user_password_hash(pool: &SqlitePool, username: &str) -> DbResult<Option<String>> {
    let row = sqlx::query("SELECT password_hash FROM users WHERE username = ?")
        .bind(username)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.get::<String, _>("password_hash")))
}

pub async fn count_users(pool: &SqlitePool) -> DbResult<i64> {
    let row = sqlx::query("SELECT COUNT(*) as cnt FROM users").fetch_one(pool).await?;
    Ok(row.get::<i64, _>("cnt"))
}

pub async fn list_usernames(pool: &SqlitePool) -> DbResult<Vec<String>> {
    let rows = sqlx::query("SELECT username FROM users ORDER BY username").fetch_all(pool).await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("username")).collect())
}

#[derive(Debug, Clone)]
pub struct RelayCredentialRow {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub secret: Vec<u8>,
    pub meta: Option<String>,
}

pub async fn insert_relay_credential(
    pool: &SqlitePool,
    name: &str,
    kind: &str,
    salt: &[u8],
    nonce: &[u8],
    secret: &[u8],
    meta: Option<&str>,
) -> DbResult<i64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    sqlx::query(
        "INSERT INTO relay_credentials (name, kind, salt, nonce, secret, meta, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(name)
    .bind(kind)
    .bind(salt)
    .bind(nonce)
    .bind(secret)
    .bind(meta)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    let row = sqlx::query("SELECT id FROM relay_credentials WHERE name = ?")
        .bind(name)
        .fetch_one(pool)
        .await?;
    Ok(row.get::<i64, _>("id"))
}

pub async fn delete_relay_credential_by_name(pool: &SqlitePool, name: &str) -> DbResult<()> {
    sqlx::query("DELETE FROM relay_credentials WHERE name = ?")
        .bind(name)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn get_relay_credential_by_name(pool: &SqlitePool, name: &str) -> DbResult<Option<RelayCredentialRow>> {
    let row = sqlx::query("SELECT id, name, kind, salt, nonce, secret, meta FROM relay_credentials WHERE name = ?")
        .bind(name)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(map_cred_row))
}

pub async fn get_relay_credential_by_id(pool: &SqlitePool, id: i64) -> DbResult<Option<RelayCredentialRow>> {
    let row = sqlx::query("SELECT id, name, kind, salt, nonce, secret, meta FROM relay_credentials WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(map_cred_row))
}

pub async fn list_relay_credentials(pool: &SqlitePool) -> DbResult<Vec<(i64, String, String)>> {
    let rows = sqlx::query("SELECT id, name, kind FROM relay_credentials ORDER BY name")
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| (r.get::<i64, _>("id"), r.get::<String, _>("name"), r.get::<String, _>("kind")))
        .collect())
}

fn map_cred_row(r: sqlx::sqlite::SqliteRow) -> RelayCredentialRow {
    RelayCredentialRow {
        id: r.get("id"),
        name: r.get("name"),
        kind: r.get("kind"),
        salt: r.get("salt"),
        nonce: r.get("nonce"),
        secret: r.get("secret"),
        meta: r.get("meta"),
    }
}

/// Establish a pooled SQLite connection for client-side state (host keys, etc.).
pub async fn client_db() -> DbResult<DbHandle> {
    let location = resolve_client_location().await?;
    init_pool(location).await
}

/// Establish a pooled SQLite connection for server-side state (relay hosts, server options, etc.).
pub async fn server_db() -> DbResult<DbHandle> {
    let location = resolve_server_location().await?;
    init_pool(location).await
}

/// Apply the client migrations to the provided pool.
pub async fn migrate_client(handle: &DbHandle) -> DbResult<()> {
    CLIENT_MIGRATOR.run(&handle.pool).await?;
    if handle.freshly_created {
        warn!(db = %display_path(handle), "initialized client database and applied migrations");
    }
    Ok(())
}

/// Apply the server migrations to the provided pool.
pub async fn migrate_server(handle: &DbHandle) -> DbResult<()> {
    SERVER_MIGRATOR.run(&handle.pool).await?;
    if handle.freshly_created {
        warn!(db = %display_path(handle), "initialized server database and applied migrations");
    }
    Ok(())
}

async fn resolve_client_location() -> DbResult<DbLocation> {
    if let Ok(value) = env::var(CLIENT_DB_ENV) {
        return build_location_from_env(value).await;
    }

    build_location_from_path(default_client_path()).await
}

async fn resolve_server_location() -> DbResult<DbLocation> {
    if let Ok(value) = env::var(SERVER_DB_ENV) {
        return build_location_from_env(value).await;
    }

    build_location_from_path(default_server_path()).await
}

async fn build_location_from_env(value: String) -> DbResult<DbLocation> {
    if value.starts_with("sqlite:") {
        Ok(DbLocation {
            url: value,
            path: None,
            freshly_created: false,
        })
    } else {
        build_location_from_path(PathBuf::from(value)).await
    }
}

async fn build_location_from_path(path: PathBuf) -> DbResult<DbLocation> {
    let existed = tokio::fs::try_exists(&path).await.unwrap_or(false);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| DbError::DirectoryCreationFailed {
                path: parent.to_path_buf(),
                source: e,
            })?;
    }
    if !existed {
        let path_clone = path.clone();
        tokio::task::spawn_blocking(move || {
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(&path_clone)
                    .map_err(|e| DbError::FileCreationFailed {
                        path: path_clone.clone(),
                        source: e,
                    })
            }
            #[cfg(not(unix))]
            {
                // Best-effort fallback on non-Unix platforms.
                OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&path_clone)
                    .map_err(|e| DbError::FileCreationFailed {
                        path: path_clone.clone(),
                        source: e,
                    })
            }
        })
        .await
        .map_err(|e| DbError::TaskPanicked(e.to_string()))??;
    }
    let url = sqlite_url_from_path(&path)?;
    Ok(DbLocation {
        url,
        path: Some(path),
        freshly_created: !existed,
    })
}

fn sqlite_url_from_path(path: &Path) -> DbResult<String> {
    let url = Url::from_file_path(path).map_err(|_| DbError::InvalidPath(path.to_path_buf()))?;
    let mut url_string: String = url.into();
    url_string.replace_range(..4, "sqlite");
    Ok(url_string)
}

async fn init_pool(location: DbLocation) -> DbResult<DbHandle> {
    let max_connections = env::var("RB_DB_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(20);

    let pool = SqlitePoolOptions::new()
        .max_connections(max_connections)
        .connect(&location.url)
        .await
        .map_err(|e| DbError::ConnectionFailed {
            path: location.url.clone(),
            source: e,
        })?;

    Ok(DbHandle {
        pool,
        url: location.url,
        path: location.path,
        freshly_created: location.freshly_created,
    })
}

fn default_client_path() -> PathBuf {
    preferred_data_dir().join("rustybridge").join("client.db")
}

fn default_server_path() -> PathBuf {
    preferred_state_dir().join("rustybridge").join("server.db")
}

fn preferred_data_dir() -> PathBuf {
    dirs::data_dir().unwrap_or_else(|| fallback_home().join(".local/share"))
}

fn preferred_state_dir() -> PathBuf {
    dirs::state_dir()
        .or_else(dirs::data_dir)
        .unwrap_or_else(|| fallback_home().join(".local/state"))
}

fn fallback_home() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("."))
}

fn display_path(handle: &DbHandle) -> String {
    handle
        .path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| handle.url.clone())
}

struct DbLocation {
    url: String,
    path: Option<PathBuf>,
    freshly_created: bool,
}
