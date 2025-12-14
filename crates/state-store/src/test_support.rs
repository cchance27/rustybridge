//! Test utilities for fast, isolated SQLite databases.
//!
//! Goal: allow nextest-friendly parallel tests without global env vars, while
//! keeping SQLx setup fast by creating a migrated "template" DB once and
//! cloning it for each test.
//!
//! By default, this uses a temporary directory that is deleted when the factory
//! is dropped. To persist test DB files for debugging, set `RB_TEST_DB_PERSIST=1`.

use crate::{DbResult, migrate_audit, migrate_server};
use rb_types::state::DbHandle;
use sqlx::sqlite::SqlitePoolOptions;
use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use tempfile::TempDir;
use tokio::sync::OnceCell;

fn unique_suffix() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    // Per-process uniqueness + timestamp is enough; collisions are astronomically unlikely.
    format!("{}-{}-{}", std::process::id(), now, uuid::Uuid::now_v7())
}

fn sqlite_url_from_path(path: &Path) -> DbResult<String> {
    let url = url::Url::from_file_path(path).map_err(|_| crate::DbError::InvalidPath(path.to_path_buf()))?;
    let mut url_string: String = url.into();
    url_string.replace_range(..4, "sqlite");
    Ok(url_string)
}

async fn connect_file_db(path: &Path, max_connections: u32) -> DbResult<DbHandle> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| crate::DbError::DirectoryCreationFailed {
                path: parent.to_path_buf(),
                source: e,
            })?;
    }
    // SQLx/SQLite can fail to create the file on some platforms unless it exists already.
    // Create it explicitly with secure permissions (0600) when possible.
    let existed = tokio::fs::try_exists(path).await.unwrap_or(false);
    if !existed {
        let path = path.to_path_buf();
        tokio::task::spawn_blocking(move || {
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                let mut options = std::fs::OpenOptions::new();
                options.create_new(true).write(true).mode(0o600);
                let _ = options.open(&path);
            }
            #[cfg(not(unix))]
            {
                let _ = std::fs::OpenOptions::new().create(true).write(true).open(&path);
            }
        })
        .await
        .map_err(|e| crate::DbError::TaskPanicked(e.to_string()))?;
    }

    let url = sqlite_url_from_path(path)?;
    let pool = SqlitePoolOptions::new()
        .max_connections(max_connections)
        .connect(&url)
        .await
        .map_err(|e| crate::DbError::ConnectionFailed {
            path: url.clone(),
            source: e,
        })?;

    // Pragmas optimized for tests: we prefer speed over durability.
    // If a pragma isn't supported by the underlying SQLite build, ignore errors.
    let _ = sqlx::query("PRAGMA journal_mode = MEMORY").execute(&pool).await;
    let _ = sqlx::query("PRAGMA synchronous = OFF").execute(&pool).await;
    let _ = sqlx::query("PRAGMA temp_store = MEMORY").execute(&pool).await;

    Ok(DbHandle {
        pool,
        url,
        path: Some(path.to_path_buf()),
        freshly_created: true,
    })
}

/// Creates migrated template DB files once and clones them per test.
///
/// Intended usage:
/// - Create one factory per test module/binary (cheap).
/// - For each test, call `server_db()` / `audit_db()` / `server_and_audit()`.
#[derive(Debug)]
pub struct SqliteTestDbFactory {
    root: PathBuf,
    _tempdir: Option<TempDir>,
    server_template: OnceCell<PathBuf>,
    audit_template: OnceCell<PathBuf>,
}

impl SqliteTestDbFactory {
    /// Create a new factory rooted in the process temp directory.
    pub fn new() -> Self {
        let persist = std::env::var_os("RB_TEST_DB_PERSIST").is_some_and(|v| v != "0");

        let tempdir = tempfile::Builder::new()
            .prefix("rustybridge-testdb-")
            .tempdir()
            .expect("failed to create temporary directory for test DBs");

        let (root, tempdir) = if persist {
            (tempdir.keep(), None)
        } else {
            (tempdir.path().to_path_buf(), Some(tempdir))
        };
        Self {
            root,
            _tempdir: tempdir,
            server_template: OnceCell::const_new(),
            audit_template: OnceCell::const_new(),
        }
    }

    async fn ensure_root(&self) -> DbResult<()> {
        tokio::fs::create_dir_all(&self.root)
            .await
            .map_err(|e| crate::DbError::DirectoryCreationFailed {
                path: self.root.clone(),
                source: e,
            })?;
        Ok(())
    }

    async fn template_server_path(&self) -> DbResult<PathBuf> {
        self.ensure_root().await?;
        let path = self
            .server_template
            .get_or_try_init(|| async {
                let template_path = self.root.join("template_server.db");
                let handle = connect_file_db(&template_path, 1).await?;
                migrate_server(&handle).await?;
                handle.pool.close().await;
                Ok::<_, crate::DbError>(template_path)
            })
            .await?;
        Ok(path.clone())
    }

    async fn template_audit_path(&self) -> DbResult<PathBuf> {
        self.ensure_root().await?;
        let path = self
            .audit_template
            .get_or_try_init(|| async {
                let template_path = self.root.join("template_audit.db");
                let handle = connect_file_db(&template_path, 1).await?;
                migrate_audit(&handle).await?;
                handle.pool.close().await;
                Ok::<_, crate::DbError>(template_path)
            })
            .await?;
        Ok(path.clone())
    }

    /// Create a migrated server DB for a single test case.
    pub async fn server_db(&self) -> DbResult<DbHandle> {
        let template = self.template_server_path().await?;
        let target = self.root.join(format!("server_{}.db", unique_suffix()));
        tokio::fs::copy(&template, &target).await.map_err(crate::DbError::Io)?;
        connect_file_db(&target, 1).await
    }

    /// Create a migrated audit DB for a single test case.
    pub async fn audit_db(&self) -> DbResult<DbHandle> {
        let template = self.template_audit_path().await?;
        let target = self.root.join(format!("audit_{}.db", unique_suffix()));
        tokio::fs::copy(&template, &target).await.map_err(crate::DbError::Io)?;
        connect_file_db(&target, 1).await
    }

    /// Create both migrated DBs for a single test case.
    pub async fn server_and_audit(&self) -> DbResult<(DbHandle, DbHandle)> {
        let server = self.server_db().await?;
        let audit = self.audit_db().await?;
        Ok((server, audit))
    }
}

impl Default for SqliteTestDbFactory {
    fn default() -> Self {
        Self::new()
    }
}
