//! Audit database management.
//!
//! This module handles the connection to the separate `audit.db` SQLite database,
//! which stores session recordings and system event logs.

use std::{
    env, fs::OpenOptions, io::ErrorKind, path::{Path, PathBuf}
};

use rb_types::state::DbLocation;
use sqlx::{migrate::Migrator, sqlite::SqlitePoolOptions};
use tokio::sync::OnceCell;
use tracing::warn;
use url::Url;

use crate::DbResult;

pub mod connections;
pub mod events;
pub mod retention;

#[cfg(test)]
mod tests;

static AUDIT_MIGRATOR: Migrator = sqlx::migrate!("./migrations/audit");

const AUDIT_DB_ENV: &str = "RB_AUDIT_DB_URL";

static AUDIT_DB: OnceCell<rb_types::state::DbHandle> = OnceCell::const_new();

/// Return a human-friendly string describing where the audit DB will live.
pub fn display_audit_db_path() -> String {
    if let Ok(val) = std::env::var(AUDIT_DB_ENV) {
        return val;
    }
    default_audit_path().display().to_string()
}

/// Establish a pooled SQLite connection for audit logs.
pub async fn audit_db() -> DbResult<rb_types::state::DbHandle> {
    let handle = AUDIT_DB
        .get_or_try_init(|| async {
            let location = resolve_audit_location().await?;
            let handle = init_pool(location).await?;
            migrate_audit(&handle).await?;
            Ok::<_, crate::DbError>(handle)
        })
        .await?;
    Ok(handle.clone())
}

/// Apply migrations to the audit database.
pub async fn migrate_audit(handle: &rb_types::state::DbHandle) -> DbResult<()> {
    AUDIT_MIGRATOR.run(&handle.pool).await?;
    if handle.freshly_created {
        warn!(db = %crate::db::display_path(handle), "initialized audit database and applied migrations");
    }
    Ok(())
}

async fn resolve_audit_location() -> DbResult<DbLocation> {
    if let Ok(value) = env::var(AUDIT_DB_ENV) {
        return build_location_from_env(value).await;
    }

    build_location_from_path(default_audit_path()).await
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
                        warn!("Creating audit DB file with 600 permissions: {}", path_clone.display());
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
                        warn!("Creating audit DB file with 600 permissions: {}", path_clone.display());
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
    let max_connections = env::var("RB_AUDIT_DB_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(10); // Lower default than main DB

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
            "Fixed insecure audit database file permissions to 0600"
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
        Ok(false)
    }
}

fn default_audit_path() -> PathBuf {
    crate::db::server_db_dir().join("audit.db")
}

/// Return the full path to the audit database file
pub fn audit_db_path() -> PathBuf {
    default_audit_path()
}
