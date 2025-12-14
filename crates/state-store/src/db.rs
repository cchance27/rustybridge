//! Database initialization, migration, and connection management.

use crate::DbResult;
#[cfg(feature = "client")]
use rb_types::state::DbLocation;
use sqlx::{migrate::Migrator, sqlite::SqlitePoolOptions};
use std::{
    env,
    fs::OpenOptions,
    io::ErrorKind,
    path::{Path, PathBuf},
};
use tokio::sync::OnceCell;
use tracing::warn;
use url::Url;

#[cfg(feature = "client")]
static CLIENT_MIGRATOR: Migrator = sqlx::migrate!("./migrations/client");
#[cfg(feature = "server")]
static SERVER_MIGRATOR: Migrator = sqlx::migrate!("./migrations/server");

#[cfg(feature = "client")]
const CLIENT_DB_ENV: &str = "RB_CLIENT_DB_URL";
#[cfg(feature = "server")]
const SERVER_DB_ENV: &str = "RB_SERVER_DB_URL";

#[cfg(feature = "client")]
static CLIENT_DB: OnceCell<rb_types::state::DbHandle> = OnceCell::const_new();
#[cfg(feature = "server")]
static SERVER_DB: OnceCell<rb_types::state::DbHandle> = OnceCell::const_new();

/// Return a human-friendly string describing where the client DB will live.
/// Prefers a filesystem path when available, otherwise returns the configured URL.
#[cfg(feature = "client")]
pub fn display_client_db_path() -> String {
    if let Ok(val) = std::env::var(CLIENT_DB_ENV) {
        return val;
    }
    default_client_path().display().to_string()
}

/// Return a human-friendly string describing where the server DB will live.
/// Prefers a filesystem path when available, otherwise returns the configured URL.
#[cfg(feature = "server")]
pub fn display_server_db_path() -> String {
    if let Ok(val) = std::env::var(SERVER_DB_ENV) {
        return val;
    }
    default_server_path().display().to_string()
}

/// Return the directory where the server database is stored
#[cfg(feature = "server")]
pub fn server_db_dir() -> PathBuf {
    default_server_path().parent().unwrap_or(Path::new(".")).to_path_buf()
}

/// Return the full path to the server database file
#[cfg(feature = "server")]
pub fn server_db_path() -> PathBuf {
    default_server_path()
}

/// Establish a pooled SQLite connection for client-side state (host keys, etc.).
#[cfg(feature = "client")]
pub async fn client_db() -> DbResult<rb_types::state::DbHandle> {
    let handle = CLIENT_DB
        .get_or_try_init(|| async {
            let location = resolve_client_location().await?;
            init_pool(location).await
        })
        .await?;
    Ok(handle.clone())
}

/// Establish a pooled SQLite connection for server-side state (relay hosts, server options, etc.).
#[cfg(feature = "server")]
pub async fn server_db() -> DbResult<rb_types::state::DbHandle> {
    let handle = SERVER_DB
        .get_or_try_init(|| async {
            let location = resolve_server_location().await?;
            init_pool(location).await
        })
        .await?;
    Ok(handle.clone())
}

/// Apply the client migrations to the provided pool.
#[cfg(feature = "client")]
pub async fn migrate_client(handle: &rb_types::state::DbHandle) -> DbResult<()> {
    CLIENT_MIGRATOR.run(&handle.pool).await?;
    if handle.freshly_created {
        warn!(db = %display_path(handle), "initialized client database and applied migrations");
    }
    Ok(())
}

/// Apply the server migrations to the provided pool.
#[cfg(feature = "server")]
pub async fn migrate_server(handle: &rb_types::state::DbHandle) -> DbResult<()> {
    SERVER_MIGRATOR.run(&handle.pool).await?;
    if handle.freshly_created {
        warn!(db = %display_path(handle), "initialized server database and applied migrations");
    }
    Ok(())
}

#[cfg(feature = "client")]
async fn resolve_client_location() -> DbResult<DbLocation> {
    if let Ok(value) = env::var(CLIENT_DB_ENV) {
        return build_location_from_env(value).await;
    }

    build_location_from_path(default_client_path()).await
}

#[cfg(feature = "server")]
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
            .map_err(|e| crate::DbError::DirectoryCreationFailed {
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
                let mut options = OpenOptions::new();
                options.create_new(true).write(true).mode(0o600);
                match options.open(&path_clone) {
                    Ok(_) => {
                        warn!(path = %path_clone.display(), "creating file with 600 permissions");
                        Ok(())
                    }
                    Err(err) if err.kind() == ErrorKind::AlreadyExists => Ok(()),
                    Err(err) => Err(crate::DbError::FileCreationFailed {
                        path: path_clone.clone(),
                        source: err,
                    }),
                }
            }
            #[cfg(not(unix))]
            {
                // Best-effort fallback on non-Unix platforms.
                let mut options = OpenOptions::new();
                options.create_new(true).write(true);
                match options.open(&path_clone) {
                    Ok(_) => {
                        warn!(path = %path_clone.display(), "creating file with 600 permissions");
                        Ok(())
                    }
                    Err(err) if err.kind() == ErrorKind::AlreadyExists => Ok(()),
                    Err(err) => Err(crate::DbError::FileCreationFailed {
                        path: path_clone.clone(),
                        source: err,
                    }),
                }
            }
        })
        .await
        .map_err(|e| crate::DbError::TaskPanicked(e.to_string()))??;
    }
    let url = sqlite_url_from_path(&path)?;
    Ok(DbLocation {
        url,
        path: Some(path),
        freshly_created: !existed,
    })
}

fn sqlite_url_from_path(path: &Path) -> DbResult<String> {
    let url = Url::from_file_path(path).map_err(|_| crate::DbError::InvalidPath(path.to_path_buf()))?;
    let mut url_string: String = url.into();
    url_string.replace_range(..4, "sqlite");
    Ok(url_string)
}

async fn init_pool(location: DbLocation) -> DbResult<rb_types::state::DbHandle> {
    let max_connections = env::var("RB_DB_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(20);

    let pool = SqlitePoolOptions::new()
        .max_connections(max_connections)
        .connect(&location.url)
        .await
        .map_err(|e| crate::DbError::ConnectionFailed {
            path: location.url.clone(),
            source: e,
        })?;

    // Check and fix permissions on existing database files
    if let Some(ref path) = location.path
        && !location.freshly_created
        && let Ok(changed) = ensure_secure_permissions(path)
        && changed
    {
        warn!(
            db = %path.display(),
            "fixed insecure database file permissions to 0600"
        );
    }

    Ok(rb_types::state::DbHandle {
        pool,
        url: location.url,
        path: location.path.clone(),
        freshly_created: location.freshly_created,
    })
}

/// Ensure a file has secure permissions (0600 on Unix)
/// Returns true if permissions were changed
fn ensure_secure_permissions(path: &Path) -> DbResult<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let metadata = std::fs::metadata(path).map_err(crate::DbError::Io)?;
        let current_mode = metadata.permissions().mode() & 0o777;

        if current_mode != 0o600 {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms).map_err(crate::DbError::Io)?;
            return Ok(true);
        }
        Ok(false)
    }

    #[cfg(not(unix))]
    {
        // On non-Unix platforms, we can't check/set permissions
        Ok(false)
    }
}

#[cfg(feature = "client")]
fn default_client_path() -> PathBuf {
    preferred_data_dir().join("rustybridge").join("client.db")
}

#[cfg(feature = "server")]
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

pub fn display_path(handle: &rb_types::state::DbHandle) -> String {
    handle
        .path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| handle.url.clone())
}
