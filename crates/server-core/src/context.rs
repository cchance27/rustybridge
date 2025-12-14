use crate::{
    error::{ServerError, ServerResult},
    secrets,
};
use rb_types::state::DbHandle;
use sqlx::SqlitePool;

/// Runtime dependencies for server-core operations.
///
/// This replaces env/global lookups so tests can run in parallel (nextest-friendly)
/// and callers can control DB/secrets wiring explicitly.
#[derive(Clone, Debug)]
pub struct ServerContext {
    pub server_db: DbHandle,
    pub audit_db: DbHandle,
    /// Master key bytes used for encrypting/decrypting secrets at rest.
    pub master_key: [u8; 32],
}

impl ServerContext {
    pub fn server_pool(&self) -> &SqlitePool {
        &self.server_db.pool
    }

    pub fn audit_pool(&self) -> &SqlitePool {
        &self.audit_db.pool
    }

    pub fn new(server_db: DbHandle, audit_db: DbHandle, master_key: [u8; 32]) -> Self {
        Self {
            server_db,
            audit_db,
            master_key,
        }
    }

    /// Build a context using existing env-based secrets configuration.
    ///
    /// Callers should prefer `new(...)` in tests to avoid env coupling.
    pub async fn from_env(server_db: DbHandle, audit_db: DbHandle) -> ServerResult<Self> {
        let master_key = secrets::master_key_from_env()?;
        Ok(Self::new(server_db, audit_db, master_key))
    }
}

/// Load a fully-initialized context using the default state-store wiring.
///
/// This is intended for runtime paths that haven't been refactored to pass
/// `ServerContext` explicitly yet.
pub async fn server_context_from_env() -> ServerResult<ServerContext> {
    let server_db = state_store::server_db().await.map_err(ServerError::StateStore)?;
    let audit_db = state_store::audit::audit_db().await.map_err(ServerError::StateStore)?;
    ServerContext::from_env(server_db, audit_db).await
}
