use std::{
    env,
    fs::{self, File},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use sqlx::{SqlitePool, migrate::Migrator, sqlite::SqlitePoolOptions};
use tracing::warn;
use url::Url;

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

/// Establish a pooled SQLite connection for client-side state (host keys, etc.).
pub async fn client_db() -> Result<DbHandle> {
    let location = resolve_client_location()?;
    init_pool(location).await
}

/// Establish a pooled SQLite connection for server-side state (relay hosts, server options, etc.).
pub async fn server_db() -> Result<DbHandle> {
    let location = resolve_server_location()?;
    init_pool(location).await
}

/// Apply the client migrations to the provided pool.
pub async fn migrate_client(handle: &DbHandle) -> Result<()> {
    CLIENT_MIGRATOR.run(&handle.pool).await.context("failed to run client migrations")?;
    if handle.freshly_created {
        warn!(db = %display_path(handle), "initialized client database and applied migrations");
    }
    Ok(())
}

/// Apply the server migrations to the provided pool.
pub async fn migrate_server(handle: &DbHandle) -> Result<()> {
    SERVER_MIGRATOR.run(&handle.pool).await.context("failed to run server migrations")?;
    if handle.freshly_created {
        warn!(db = %display_path(handle), "initialized server database and applied migrations");
    }
    Ok(())
}

fn resolve_client_location() -> Result<DbLocation> {
    if let Ok(value) = env::var(CLIENT_DB_ENV) {
        return build_location_from_env(value);
    }

    build_location_from_path(default_client_path())
}

fn resolve_server_location() -> Result<DbLocation> {
    if let Ok(value) = env::var(SERVER_DB_ENV) {
        return build_location_from_env(value);
    }

    build_location_from_path(default_server_path())
}

fn build_location_from_env(value: String) -> Result<DbLocation> {
    if value.starts_with("sqlite:") {
        Ok(DbLocation {
            url: value,
            path: None,
            freshly_created: false,
        })
    } else {
        build_location_from_path(PathBuf::from(value))
    }
}

fn build_location_from_path(path: PathBuf) -> Result<DbLocation> {
    let existed = path.exists();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    }
    if !existed {
        File::create(&path).with_context(|| format!("failed to create {}", path.display()))?;
    }
    let url = sqlite_url_from_path(&path)?;
    Ok(DbLocation {
        url,
        path: Some(path),
        freshly_created: !existed,
    })
}

fn sqlite_url_from_path(path: &Path) -> Result<String> {
    let url = Url::from_file_path(path).map_err(|_| anyhow!("invalid sqlite path: {}", path.display()))?;
    let mut url_string: String = url.into();
    url_string.replace_range(..4, "sqlite");
    Ok(url_string)
}

async fn init_pool(location: DbLocation) -> Result<DbHandle> {
    let pool = SqlitePoolOptions::new()
        .max_connections(20)
        .connect(&location.url)
        .await
        .with_context(|| format!("failed to open sqlite database at {}", location.url))?;

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
