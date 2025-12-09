//! Server-core external façade.
//!
//! This module curates high-level, ready-to-use operations for other crates (rb-web,
//! CLI, TUI). Callers should prefer these helpers instead of reaching into
//! internal modules or `state_store` directly.

use std::collections::{HashMap, HashSet};

use base64::Engine;
use rb_types::{
    access::{PrincipalKind, RelayAccessPrincipal, RelayAccessSource, UserRelayAccess}, audit::{AuditContext, RecordedSessionChunk}, auth::{OidcLinkInfo, OidcProfile, UserAuthRecord, oidc::OidcConfig}, credentials::AuthWebConfig, relay::{RelayHostInfo, RelayInfo}, state::DbHandle, users::{GroupInfo, UserGroupInfo}
};
use secrecy::ExposeSecret;
use sqlx::{Row, SqlitePool};
use state_store::ClaimType;

use crate::{
    error::{ServerError, ServerResult}, secrets, sessions::SessionRegistry
};

/// Shared accessor for the audit database so wrappers accept either a raw handle
/// or the live [`SessionRegistry`].
pub trait AuditDbSource {
    fn audit_db(&self) -> &DbHandle;
}

impl AuditDbSource for &DbHandle {
    fn audit_db(&self) -> &DbHandle {
        self
    }
}

impl AuditDbSource for &SessionRegistry {
    fn audit_db(&self) -> &DbHandle {
        &self.audit_db
    }
}

impl AuditDbSource for std::sync::Arc<SessionRegistry> {
    fn audit_db(&self) -> &DbHandle {
        &self.audit_db
    }
}

impl AuditDbSource for &std::sync::Arc<SessionRegistry> {
    fn audit_db(&self) -> &DbHandle {
        &self.audit_db
    }
}

// --- DB handles & migrations ---

/// Get the primary server database handle.
pub async fn server_db_handle() -> ServerResult<DbHandle> {
    state_store::server_db().await.map_err(ServerError::StateStore)
}

/// Get the audit database handle.
pub async fn audit_db_handle() -> ServerResult<DbHandle> {
    state_store::audit::audit_db().await.map_err(ServerError::StateStore)
}

/// Display path to the server database (for help/diagnostics).
pub fn display_server_db_path() -> String {
    state_store::display_server_db_path()
}

/// Run pending migrations on the server database.
pub async fn migrate_server_db() -> ServerResult<()> {
    let handle = server_db_handle().await?;
    state_store::migrate_server(&handle).await.map_err(ServerError::StateStore)
}

// --- Generic lookups ---

pub async fn get_user_id_by_name(username: &str) -> ServerResult<Option<i64>> {
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    state_store::fetch_user_id_by_name(&pool, username)
        .await
        .map_err(ServerError::StateStore)
}

pub async fn get_group_id_by_name(group: &str) -> ServerResult<Option<i64>> {
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    state_store::fetch_group_id_by_name(&pool, group)
        .await
        .map_err(ServerError::StateStore)
}

pub async fn get_role_id_by_name(role: &str) -> ServerResult<Option<i64>> {
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    state_store::fetch_role_id_by_name(&pool, role)
        .await
        .map_err(ServerError::StateStore)
}

pub async fn list_usernames() -> ServerResult<Vec<String>> {
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    state_store::list_usernames(&pool).await.map_err(ServerError::StateStore)
}

pub async fn list_roles() -> ServerResult<Vec<String>> {
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    let roles = state_store::list_roles(&pool).await.map_err(ServerError::StateStore)?;
    Ok(roles.into_iter().map(|r| r.name).collect())
}

pub async fn fetch_user_auth_record_by_id(user_id: i64) -> ServerResult<Option<UserAuthRecord>> {
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    state_store::fetch_user_auth_record(&pool, user_id)
        .await
        .map_err(ServerError::StateStore)
}

pub async fn get_server_option(key: &str) -> ServerResult<Option<String>> {
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    state_store::get_server_option(&pool, key).await.map_err(ServerError::StateStore)
}

pub async fn get_oidc_config() -> ServerResult<Option<OidcConfig>> {
    let issuer_url = get_server_option("oidc_issuer_url").await?;
    let client_id = get_server_option("oidc_client_id").await?;
    let client_secret = get_server_option("oidc_client_secret").await?;
    let redirect_url = get_server_option("oidc_redirect_url").await?;

    match (issuer_url, client_id, client_secret, redirect_url) {
        (Some(issuer_url), Some(client_id), Some(client_secret), Some(redirect_url)) => Ok(Some(OidcConfig {
            issuer_url,
            client_id,
            client_secret,
            redirect_url,
        })),
        _ => Ok(None),
    }
}

pub async fn find_user_id_by_oidc_subject(issuer: &str, subject: &str) -> ServerResult<Option<i64>> {
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    state_store::find_user_id_by_oidc_subject(&pool, issuer, subject)
        .await
        .map_err(ServerError::StateStore)
}

pub async fn upsert_oidc_link(
    user_id: i64,
    issuer: &str,
    subject: &str,
    email: &Option<String>,
    name: &Option<String>,
    picture: &Option<String>,
) -> ServerResult<()> {
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    state_store::upsert_oidc_link(&pool, user_id, issuer, subject, email, name, picture)
        .await
        .map(|_| ())
        .map_err(ServerError::StateStore)
}

pub async fn update_oidc_profile_by_subject(
    issuer: &str,
    subject: &str,
    email: &Option<String>,
    name: &Option<String>,
    picture: &Option<String>,
) -> ServerResult<()> {
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    state_store::update_oidc_profile_by_subject(&pool, issuer, subject, email, name, picture)
        .await
        .map(|_| ())
        .map_err(ServerError::StateStore)
}

pub async fn delete_oidc_link_for_user(user_id: i64) -> ServerResult<u64> {
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    state_store::delete_oidc_link_for_user(&pool, user_id)
        .await
        .map_err(ServerError::StateStore)
}

pub async fn get_oidc_link_for_user(user_id: i64) -> ServerResult<Option<OidcLinkInfo>> {
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    state_store::get_oidc_link_for_user(&pool, user_id)
        .await
        .map_err(ServerError::StateStore)
}

pub async fn get_latest_oidc_profile(user_id: i64) -> ServerResult<Option<OidcProfile>> {
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    state_store::get_latest_oidc_profile(&pool, user_id)
        .await
        .map_err(ServerError::StateStore)
}

/// Fetch roles with members/claims for UI listings.
pub async fn list_roles_with_details() -> ServerResult<Vec<rb_types::users::RoleInfo<'static>>> {
    let db = server_db_handle().await?;
    let pool = db.into_pool();

    let roles = state_store::list_roles(&pool).await.map_err(ServerError::StateStore)?;

    let mut result = Vec::with_capacity(roles.len());
    for role in roles {
        let users = state_store::list_role_users_by_id(&pool, role.id)
            .await
            .map_err(ServerError::StateStore)?;
        let groups = state_store::list_role_groups_by_id(&pool, role.id)
            .await
            .map_err(ServerError::StateStore)?;
        let claims = state_store::get_role_claims_by_id(&pool, role.id)
            .await
            .map_err(ServerError::StateStore)?;

        result.push(rb_types::users::RoleInfo {
            id: role.id,
            name: role.name,
            description: role.description,
            user_count: users.len() as i64,
            group_count: groups.len() as i64,
            users,
            groups,
            claims,
        });
    }

    Ok(result)
}

// --- Relay + credential helpers ---

pub async fn fetch_relay_by_name(name: &str) -> ServerResult<Option<RelayInfo>> {
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    state_store::fetch_relay_host_by_name(&pool, name)
        .await
        .map_err(ServerError::StateStore)
}

pub async fn fetch_relay_by_id(id: i64) -> ServerResult<Option<RelayInfo>> {
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    state_store::fetch_relay_host_by_id(&pool, id)
        .await
        .map_err(ServerError::StateStore)
}

pub async fn get_relay_credential_by_name(name: &str) -> ServerResult<Option<rb_types::state::RelayCredentialRow>> {
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    state_store::get_relay_credential_by_name(&pool, name)
        .await
        .map_err(ServerError::StateStore)
}

pub async fn get_relay_credential_by_id(id: i64) -> ServerResult<Option<rb_types::state::RelayCredentialRow>> {
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    state_store::get_relay_credential_by_id(&pool, id)
        .await
        .map_err(ServerError::StateStore)
}

pub async fn update_relay_host_by_id(ctx: &AuditContext, id: i64, name: &str, ip: &str, port: i64) -> ServerResult<()> {
    crate::relay_host::update_relay_host_by_id(ctx, id, name, ip, port).await
}

pub async fn list_relay_options_by_id(id: i64) -> ServerResult<Vec<(String, String)>> {
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    let map = state_store::fetch_relay_host_options(&pool, id)
        .await
        .map_err(ServerError::StateStore)?;
    Ok(map.into_iter().map(|(k, (v, _))| (k, v)).collect())
}

pub async fn user_has_relay_access(user_id: i64, relay_id: i64) -> ServerResult<bool> {
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    state_store::user_has_relay_access(&pool, user_id, relay_id)
        .await
        .map_err(ServerError::StateStore)
}

// --- Role helpers (ID-based) ---

pub async fn assign_role_to_user(ctx: &AuditContext, user_id: i64, role_id: i64) -> ServerResult<()> {
    let _ = ctx;
    let db = server_db_handle().await?;
    let mut conn = db.into_pool().acquire().await.map_err(ServerError::Database)?;
    state_store::assign_role_to_user_by_ids(&mut *conn, user_id, role_id)
        .await
        .map_err(ServerError::StateStore)?;
    Ok(())
}

pub async fn revoke_role_from_user(ctx: &AuditContext, user_id: i64, role_id: i64) -> ServerResult<()> {
    let _ = ctx;
    let db = server_db_handle().await?;
    let mut conn = db.into_pool().acquire().await.map_err(ServerError::Database)?;
    state_store::revoke_role_from_user_by_ids(&mut conn, user_id, role_id)
        .await
        .map_err(ServerError::StateStore)?;
    Ok(())
}

pub async fn create_role(ctx: &AuditContext, name: &str, description: Option<&str>) -> ServerResult<()> {
    let _ = ctx;
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    state_store::create_role(&pool, name, description)
        .await
        .map_err(ServerError::StateStore)?;
    Ok(())
}

pub async fn delete_role(ctx: &AuditContext, role_id: i64, _role_name: &str) -> ServerResult<()> {
    let _ = ctx;
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    state_store::delete_role_by_id(&pool, role_id)
        .await
        .map_err(ServerError::StateStore)?;
    Ok(())
}

pub async fn add_claim_to_role(ctx: &AuditContext, role_id: i64, claim: &ClaimType<'_>) -> ServerResult<()> {
    let _ = ctx;
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    state_store::add_claim_to_role_by_id(&pool, role_id, claim)
        .await
        .map_err(ServerError::StateStore)?;
    Ok(())
}

pub async fn remove_claim_from_role(ctx: &AuditContext, role_id: i64, claim: &ClaimType<'_>) -> ServerResult<()> {
    let _ = ctx;
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    state_store::remove_claim_from_role_by_id(&pool, role_id, claim)
        .await
        .map_err(ServerError::StateStore)?;
    Ok(())
}

// --- Role detail queries ---

pub async fn list_role_users_by_id(role_id: i64) -> ServerResult<Vec<String>> {
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    state_store::list_role_users_by_id(&pool, role_id)
        .await
        .map_err(ServerError::StateStore)
}

pub async fn list_role_groups_by_id(role_id: i64) -> ServerResult<Vec<String>> {
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    state_store::list_role_groups_by_id(&pool, role_id)
        .await
        .map_err(ServerError::StateStore)
}

pub async fn assign_role_to_group_by_ids(ctx: &AuditContext, group_id: i64, role_id: i64) -> ServerResult<()> {
    let _ = ctx;
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    state_store::assign_role_to_group_by_ids(&pool, group_id, role_id)
        .await
        .map_err(ServerError::StateStore)
}

pub async fn revoke_role_from_group_by_ids(ctx: &AuditContext, group_id: i64, role_id: i64) -> ServerResult<()> {
    let _ = ctx;
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    state_store::revoke_role_from_group_by_ids(&pool, group_id, role_id)
        .await
        .map_err(ServerError::StateStore)
}

// --- Claims and keys ---

pub async fn get_user_claims_by_id(user_id: i64) -> ServerResult<Vec<ClaimType<'static>>> {
    let db = server_db_handle().await?;
    let mut conn = db.into_pool().acquire().await.map_err(ServerError::Database)?;
    state_store::get_user_claims_by_id(&mut conn, user_id)
        .await
        .map_err(ServerError::StateStore)
}

pub async fn list_user_public_keys_by_id(user_id: i64) -> ServerResult<Vec<(i64, String, Option<String>, i64)>> {
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    state_store::list_user_public_keys_by_id(&pool, user_id)
        .await
        .map_err(ServerError::StateStore)
}

pub async fn add_user_public_key_by_id(ctx: &AuditContext, user_id: i64, public_key: &str, comment: Option<&str>) -> ServerResult<i64> {
    let _ = ctx;
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    state_store::add_user_public_key_by_id(&pool, user_id, public_key, comment)
        .await
        .map_err(ServerError::StateStore)
}

pub async fn delete_user_public_key_by_id(ctx: &AuditContext, key_id: i64) -> ServerResult<()> {
    let _ = ctx;
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    state_store::delete_user_public_key(&pool, key_id)
        .await
        .map_err(ServerError::StateStore)
}

// --- Group helpers ---

pub async fn list_group_members_by_id(group_id: i64) -> ServerResult<Vec<String>> {
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    state_store::list_group_members_by_id(&pool, group_id)
        .await
        .map_err(ServerError::StateStore)
}

pub async fn get_group_claims_by_id(group_id: i64) -> ServerResult<Vec<ClaimType<'static>>> {
    let db = server_db_handle().await?;
    let pool = db.into_pool();
    state_store::get_group_claims_by_id(&pool, group_id)
        .await
        .map_err(ServerError::StateStore)
}

// --- Audit helpers ---

pub async fn query_audit_events(filter: rb_types::audit::EventFilter) -> ServerResult<Vec<rb_types::audit::AuditEvent>> {
    crate::audit::query_events(filter).await
}

pub async fn query_recent_audit_events(limit: i64) -> ServerResult<Vec<rb_types::audit::AuditEvent>> {
    crate::audit::query_recent_events(limit).await
}

/// Paginated recorded session listing for UI.
pub struct SessionQueryResult {
    pub total: i64,
    pub records: Vec<SessionSummary>,
}

#[derive(Clone, Debug)]
pub struct SessionSummary {
    pub id: String,
    pub user_id: i64,
    pub relay_id: i64,
    pub session_number: i64,
    pub start_time: i64,
    pub end_time: Option<i64>,
    pub metadata: serde_json::Value,
    pub username: Option<String>,
    pub relay_name: Option<String>,
    pub original_size_bytes: Option<i64>,
    pub compressed_size_bytes: Option<i64>,
    pub encrypted_size_bytes: Option<i64>,
    pub chunk_count: Option<i64>,
    pub first_chunk_ts: Option<i64>,
    pub last_chunk_ts: Option<i64>,
}

impl SessionSummary {
    pub fn to_recorded(&self) -> rb_types::audit::RecordedSessionSummary {
        rb_types::audit::RecordedSessionSummary {
            id: self.id.clone(),
            user_id: self.user_id,
            relay_id: self.relay_id,
            session_number: self.session_number,
            start_time: self.start_time,
            end_time: self.end_time,
            metadata: self.metadata.clone(),
            username: self.username.clone(),
            relay_name: self.relay_name.clone(),
            original_size_bytes: self.original_size_bytes,
            compressed_size_bytes: self.compressed_size_bytes,
            encrypted_size_bytes: self.encrypted_size_bytes,
            chunk_count: self.chunk_count,
            first_chunk_ts: self.first_chunk_ts,
            last_chunk_ts: self.last_chunk_ts,
        }
    }
}

#[derive(Default)]
pub struct SessionQuery {
    pub page: i64,
    pub limit: i64,
    pub user_id: Option<i64>,
    pub relay_id: Option<i64>,
    pub start: Option<i64>,
    pub end: Option<i64>,
    pub username_contains: Option<String>,
    pub relay_name_contains: Option<String>,
    pub sort_by: Option<String>,
    pub sort_dir: Option<String>,
}

pub async fn query_sessions(query: SessionQuery, include_sizes: bool) -> ServerResult<SessionQueryResult> {
    let audit_db = state_store::audit::audit_db().await.map_err(ServerError::StateStore)?;
    let pool = &audit_db.pool;

    let page = query.page.max(1);
    let limit = query.limit.clamp(1, 100);
    let offset = (page - 1) * limit;

    let mut builder = sqlx::QueryBuilder::new(
        "SELECT rs.*, \
            (SELECT COUNT(*) FROM session_chunks sc WHERE sc.relay_session_id = rs.id) as chunk_count, \
            (SELECT MIN(timestamp) FROM session_chunks sc WHERE sc.relay_session_id = rs.id) as first_chunk_ts, \
            (SELECT MAX(timestamp) FROM session_chunks sc WHERE sc.relay_session_id = rs.id) as last_chunk_ts \
         FROM relay_sessions rs WHERE 1=1",
    );
    let mut count_builder = sqlx::QueryBuilder::new("SELECT COUNT(*) FROM relay_sessions rs WHERE 1=1");

    if let Some(uid) = query.user_id {
        builder.push(" AND user_id = ").push_bind(uid);
        count_builder.push(" AND user_id = ").push_bind(uid);
    }
    if let Some(rid) = query.relay_id {
        builder.push(" AND relay_host_id = ").push_bind(rid);
        count_builder.push(" AND relay_host_id = ").push_bind(rid);
    }
    if let Some(start) = query.start {
        builder.push(" AND start_time >= ").push_bind(start);
        count_builder.push(" AND start_time >= ").push_bind(start);
    }
    if let Some(end) = query.end {
        builder.push(" AND start_time <= ").push_bind(end);
        count_builder.push(" AND start_time <= ").push_bind(end);
    }
    if let Some(uname) = query.username_contains {
        builder
            .push(" AND json_extract(metadata, '$.username') LIKE ")
            .push_bind(format!("%{}%", uname));
        count_builder
            .push(" AND json_extract(metadata, '$.username') LIKE ")
            .push_bind(format!("%{}%", uname));
    }
    if let Some(rname) = query.relay_name_contains {
        builder
            .push(" AND json_extract(metadata, '$.relay_name') LIKE ")
            .push_bind(format!("%{}%", rname));
        count_builder
            .push(" AND json_extract(metadata, '$.relay_name') LIKE ")
            .push_bind(format!("%{}%", rname));
    }

    let sort_col = match query.sort_by.as_deref() {
        Some("start_time") => "start_time",
        Some("user_id") => "user_id",
        Some("relay_id") => "relay_host_id",
        Some("session_number") => "session_number",
        Some("original_size_bytes") => "original_size",
        Some("compressed_size_bytes") => "compressed_size",
        _ => "start_time",
    };
    let sort_dir = match query.sort_dir.as_deref() {
        Some("asc") => "ASC",
        _ => "DESC",
    };

    builder.push(format!(" ORDER BY {} {} LIMIT ", sort_col, sort_dir));
    builder.push_bind(limit);
    builder.push(" OFFSET ");
    builder.push_bind(offset);

    let total: i64 = count_builder
        .build_query_scalar()
        .fetch_one(pool)
        .await
        .map_err(ServerError::Database)?;

    let rows: Vec<sqlx::sqlite::SqliteRow> = builder.build().fetch_all(pool).await.map_err(ServerError::Database)?;

    let mut records = Vec::with_capacity(rows.len());
    for row in rows {
        let metadata: serde_json::Value = serde_json::from_str(row.get("metadata")).unwrap_or(serde_json::json!({}));
        let relay_name = metadata.get("relay_name").and_then(|v| v.as_str()).map(|s| s.to_string());
        let username = metadata.get("username").and_then(|v| v.as_str()).map(|s| s.to_string());

        let chunk_count = if include_sizes { row.try_get("chunk_count").ok() } else { None };
        let first_chunk_ts = if include_sizes { row.try_get("first_chunk_ts").ok() } else { None };
        let last_chunk_ts = if include_sizes { row.try_get("last_chunk_ts").ok() } else { None };

        records.push(SessionSummary {
            id: row.get("id"),
            user_id: row.get("user_id"),
            relay_id: row.get("relay_host_id"),
            session_number: row.get("session_number"),
            start_time: row.get("start_time"),
            end_time: row.try_get("end_time").ok().flatten().filter(|t| *t > 0),
            metadata,
            username,
            relay_name,
            original_size_bytes: if include_sizes { row.try_get("original_size").ok() } else { None },
            compressed_size_bytes: if include_sizes { row.try_get("compressed_size").ok() } else { None },
            encrypted_size_bytes: if include_sizes { row.try_get("encrypted_size").ok() } else { None },
            chunk_count,
            first_chunk_ts,
            last_chunk_ts,
        });
    }

    Ok(SessionQueryResult { total, records })
}

/// Fetch a single session by id with aggregated chunk metadata.
pub async fn get_session_summary(session_id: &str) -> ServerResult<Option<SessionSummary>> {
    let audit_db = state_store::audit::audit_db().await.map_err(ServerError::StateStore)?;
    let pool = &audit_db.pool;

    let row = sqlx::query(
        r#"SELECT rs.*, 
                (SELECT COUNT(*) FROM session_chunks sc WHERE sc.relay_session_id = rs.id) as chunk_count,
                (SELECT MIN(timestamp) FROM session_chunks sc WHERE sc.relay_session_id = rs.id) as first_chunk_ts,
                (SELECT MAX(timestamp) FROM session_chunks sc WHERE sc.relay_session_id = rs.id) as last_chunk_ts
            FROM relay_sessions rs
            WHERE rs.id = ?"#,
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await
    .map_err(ServerError::Database)?;

    if let Some(row) = row {
        let metadata: serde_json::Value = serde_json::from_str(row.get("metadata")).unwrap_or(serde_json::json!({}));
        let relay_name = metadata.get("relay_name").and_then(|v| v.as_str()).map(|s| s.to_string());
        let username = metadata.get("username").and_then(|v| v.as_str()).map(|s| s.to_string());

        let record = SessionSummary {
            id: row.get("id"),
            user_id: row.get("user_id"),
            relay_id: row.get("relay_host_id"),
            session_number: row.get("session_number"),
            start_time: row.get("start_time"),
            end_time: row.try_get("end_time").ok().flatten().filter(|t| *t > 0),
            metadata,
            username,
            relay_name,
            original_size_bytes: row.try_get("original_size").ok(),
            compressed_size_bytes: row.try_get("compressed_size").ok(),
            encrypted_size_bytes: row.try_get("encrypted_size").ok(),
            chunk_count: row.try_get("chunk_count").ok(),
            first_chunk_ts: row.try_get("first_chunk_ts").ok(),
            last_chunk_ts: row.try_get("last_chunk_ts").ok(),
        };

        Ok(Some(record))
    } else {
        Ok(None)
    }
}

/// Get all client connection IDs that participated in a relay session.
/// These IDs correspond to the session_id field in audit events.
/// Includes both:
/// - The initiator connection ID from the relay_sessions table
/// - Any additional participant connection IDs from relay_session_participants
pub async fn get_session_participant_connection_ids(relay_session_id: &str) -> ServerResult<Vec<String>> {
    let audit_db = state_store::audit::audit_db().await.map_err(ServerError::StateStore)?;
    let pool = &audit_db.pool;

    // First, get the initiator connection ID from the relay_sessions table itself
    let initiator: Option<String> = sqlx::query_scalar("SELECT initiator_client_session_id FROM relay_sessions WHERE id = ?")
        .bind(relay_session_id)
        .fetch_optional(pool)
        .await
        .map_err(ServerError::Database)?
        .flatten();

    // Then get all participant connection IDs
    let participant_ids: Vec<String> =
        sqlx::query_scalar("SELECT DISTINCT client_session_id FROM relay_session_participants WHERE relay_session_id = ?")
            .bind(relay_session_id)
            .fetch_all(pool)
            .await
            .map_err(ServerError::Database)?;

    // Combine and deduplicate (initiator may also be in participants table)
    let mut connection_ids: Vec<String> = Vec::with_capacity(participant_ids.len() + 1);
    if let Some(init_id) = initiator {
        connection_ids.push(init_id);
    }
    for id in participant_ids {
        if !connection_ids.contains(&id) {
            connection_ids.push(id);
        }
    }

    Ok(connection_ids)
}

// --- Session chunks retrieval for replay ---

#[derive(Clone, Debug)]
pub struct SessionChunk {
    pub timestamp: i64,
    pub direction: u8,
    /// Base64-encoded plaintext chunk data
    pub data: String,
    pub connection_id: Option<String>,
    pub user_id: Option<i64>,
    pub username: Option<String>,
    pub connection_type: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub ssh_client: Option<String>,
    pub timing_markers: Option<Vec<(usize, i64)>>,
    pub is_admin_input: bool,
    pub db_chunk_index: Option<usize>,
}

impl From<SessionChunk> for RecordedSessionChunk {
    fn from(value: SessionChunk) -> Self {
        RecordedSessionChunk {
            timestamp: value.timestamp,
            direction: value.direction,
            data: value.data,
            connection_id: value.connection_id,
            user_id: value.user_id,
            username: value.username,
            connection_type: value.connection_type,
            ip_address: value.ip_address,
            user_agent: value.user_agent,
            ssh_client: value.ssh_client,
            is_admin_input: value.is_admin_input,
            timing_markers: value.timing_markers,
            db_chunk_index: value.db_chunk_index,
        }
    }
}

fn decrypt_chunk(encrypted: &[u8]) -> ServerResult<Vec<u8>> {
    if encrypted.len() < 40 {
        return Err(ServerError::Other("invalid chunk data".into()));
    }
    let (salt, rest) = encrypted.split_at(16);
    let (nonce, ciphertext) = rest.split_at(24);
    let (compressed, _) = secrets::decrypt_secret(salt, nonce, ciphertext)?;
    let plaintext =
        zstd::decode_all(compressed.expose_secret().as_slice()).map_err(|e| ServerError::Other(format!("decompress failed: {e}")))?;
    Ok(plaintext)
}

pub async fn fetch_session_chunks(session_id: &str) -> ServerResult<Vec<SessionChunk>> {
    let audit_db = state_store::audit::audit_db().await.map_err(ServerError::StateStore)?;
    let pool = &audit_db.pool;

    // Get owner id for admin detection and username lookup
    let session_row = sqlx::query("SELECT user_id FROM relay_sessions WHERE id = ?")
        .bind(session_id)
        .fetch_optional(pool)
        .await
        .map_err(ServerError::Database)?
        .ok_or_else(|| ServerError::not_found("session", session_id))?;

    let session_owner: i64 = session_row.get("user_id");

    let rows = sqlx::query(
        r#"
        SELECT sc.*, c.user_id as conn_user_id, c.connection_type, c.ip_address, c.user_agent, c.ssh_client
        FROM session_chunks sc
        LEFT JOIN client_sessions c ON sc.client_session_id = c.id
        WHERE sc.relay_session_id = ?
        ORDER BY sc.chunk_index ASC
        "#,
    )
    .bind(session_id)
    .fetch_all(pool)
    .await
    .map_err(ServerError::Database)?;

    // Collect user ids for username mapping
    let mut user_ids: HashSet<i64> = HashSet::new();
    user_ids.insert(session_owner);
    for row in &rows {
        if let Some(uid) = row.get::<Option<i64>, _>("conn_user_id") {
            user_ids.insert(uid);
        }
    }

    let mut username_map = HashMap::new();
    if !user_ids.is_empty()
        && let Ok(server_db) = state_store::server_db().await
    {
        let pool = server_db.into_pool();
        for uid in user_ids {
            if let Ok(Some(user)) = state_store::fetch_user_auth_record(&pool, uid).await {
                username_map.insert(uid, user.username);
            }
        }
    }

    let mut chunks = Vec::with_capacity(rows.len());
    for row in rows {
        let encrypted: Vec<u8> = row.get("data");
        let plaintext = decrypt_chunk(&encrypted).map_err(|e| {
            tracing::warn!("chunk decrypt failed: {}", e);
            e
        })?;

        let timing_markers = row
            .try_get::<Option<String>, _>("timing_markers")
            .ok()
            .and_then(|s| s.and_then(|json| serde_json::from_str(&json).ok()));

        let chunk_user_id: Option<i64> = row.get("conn_user_id");
        let direction: i32 = row.get("direction");
        let username = if direction == 0 {
            username_map.get(&session_owner).cloned()
        } else {
            chunk_user_id.and_then(|uid| username_map.get(&uid).cloned())
        };

        use base64::engine::general_purpose::STANDARD;
        let data_b64 = STANDARD.encode(plaintext);

        chunks.push(SessionChunk {
            timestamp: row.get("timestamp"),
            direction: direction as u8,
            data: data_b64,
            connection_id: row.get("client_session_id"),
            user_id: chunk_user_id,
            username,
            connection_type: row.get("connection_type"),
            ip_address: row.get("ip_address"),
            user_agent: row.get("user_agent"),
            ssh_client: row.get("ssh_client"),
            timing_markers,
            is_admin_input: chunk_user_id.map(|uid| uid != session_owner).unwrap_or(false),
            db_chunk_index: Some(row.get::<i64, _>("chunk_index") as usize),
        });
    }

    Ok(chunks)
}

pub async fn fetch_session_snapshot(session_id: &str, chunk_index: usize) -> ServerResult<Option<rb_types::ssh::TerminalSnapshot>> {
    let audit_db = state_store::audit::audit_db().await.map_err(ServerError::StateStore)?;
    let pool = &audit_db.pool;

    let row = sqlx::query(
        r#"SELECT snapshot_buffer, snapshot_cursor_row, snapshot_cursor_col, terminal_rows, terminal_cols, chunk_index, timestamp
            FROM session_snapshots
            WHERE relay_session_id = ? AND chunk_index = ?"#,
    )
    .bind(session_id)
    .bind(chunk_index as i64)
    .fetch_optional(pool)
    .await
    .map_err(ServerError::Database)?;

    if let Some(row) = row {
        let screen_buffer: String = row.get("snapshot_buffer");
        let cursor_row: i64 = row.get("snapshot_cursor_row");
        let cursor_col: i64 = row.get("snapshot_cursor_col");
        let rows: i64 = row.get("terminal_rows");
        let cols: i64 = row.get("terminal_cols");
        let ts: i64 = row.get("timestamp");
        let idx: i64 = row.get("chunk_index");

        return Ok(Some(rb_types::ssh::TerminalSnapshot {
            screen_buffer,
            cursor_row: cursor_row as usize,
            cursor_col: cursor_col as usize,
            chunk_index: idx as usize,
            timestamp: ts,
            terminal_size: (rows as usize, cols as usize),
        }));
    }

    Ok(None)
}
fn decode_value(raw: &str, is_secure: bool) -> String {
    if !is_secure {
        return raw.to_string();
    }

    secrets::decrypt_string_if_encrypted(raw)
        .map(|s| s.0.expose_secret().to_string())
        .unwrap_or_else(|_| raw.to_string())
}

fn decode_option(entry: Option<&(String, bool)>) -> Option<String> {
    entry.map(|(v, secure)| decode_value(v, *secure))
}

async fn load_relay_principals(pool: &SqlitePool, relays: &[RelayInfo]) -> ServerResult<HashMap<i64, Vec<state_store::RelayAclPrincipal>>> {
    let mut map = HashMap::with_capacity(relays.len());
    for relay in relays {
        let principals = state_store::fetch_relay_access_principals(pool, relay.id).await?;
        map.insert(relay.id, principals);
    }
    Ok(map)
}

/// Provide full relay host details (credentials, auth config, ACL principals) for web views.
pub async fn list_relay_hosts_with_details() -> ServerResult<Vec<RelayHostInfo>> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    let hosts = state_store::list_relay_hosts(&pool, None).await?;
    let mut result = Vec::with_capacity(hosts.len());

    for host in hosts {
        let opts = state_store::fetch_relay_host_options(&pool, host.id).await?;
        let auth_source = decode_option(opts.get("auth.source"));

        let credential_id = opts
            .get("auth.id")
            .and_then(|(raw, is_secure)| decode_value(raw, *is_secure).parse::<i64>().ok());

        let (credential, credential_kind, credential_username_mode, credential_password_required) = match auth_source.as_deref() {
            Some("credential") => {
                if let Some(cred_id) = credential_id {
                    match state_store::get_relay_credential_by_id(&pool, cred_id).await {
                        Ok(Some(cred)) => (
                            Some(cred.name),
                            Some(cred.kind),
                            Some(cred.username_mode),
                            Some(cred.password_required),
                        ),
                        Ok(None) => (Some("<unknown>".to_string()), None, None, None),
                        Err(_) => (None, None, None, None),
                    }
                } else {
                    (None, None, None, None)
                }
            }
            Some("inline") => (None, None, None, None),
            _ => (None, None, None, None),
        };

        let has_hostkey = opts.contains_key("hostkey.openssh");

        let auth_config = match auth_source.as_deref() {
            Some("credential") => Some(AuthWebConfig {
                mode: "saved".to_string(),
                saved_credential_id: credential_id,
                custom_type: None,
                username: None,
                username_mode: None,
                has_password: false,
                has_private_key: false,
                has_passphrase: false,
                has_public_key: false,
                password_required: None,
            }),
            Some("inline") => Some(AuthWebConfig {
                mode: "custom".to_string(),
                saved_credential_id: None,
                custom_type: decode_option(opts.get("auth.method")),
                username: decode_option(opts.get("auth.username")),
                username_mode: decode_option(opts.get("auth.username_mode")),
                has_password: opts.contains_key("auth.password"),
                has_private_key: opts.contains_key("auth.identity"),
                has_passphrase: opts.contains_key("auth.passphrase"),
                has_public_key: opts.contains_key("auth.agent_pubkey"),
                password_required: decode_option(opts.get("auth.password_required")).and_then(|v| v.parse::<bool>().ok()),
            }),
            _ => Some(AuthWebConfig {
                mode: "none".to_string(),
                saved_credential_id: None,
                custom_type: None,
                username: None,
                username_mode: None,
                has_password: false,
                has_private_key: false,
                has_passphrase: false,
                has_public_key: false,
                password_required: None,
            }),
        };

        let access_principals = state_store::fetch_relay_access_principals(&pool, host.id)
            .await?
            .into_iter()
            .map(|p| RelayAccessPrincipal {
                kind: p.kind,
                id: p.id,
                name: p.name,
            })
            .collect();

        result.push(RelayHostInfo {
            id: host.id,
            name: host.name,
            ip: host.ip,
            port: host.port,
            credential,
            credential_kind,
            credential_username_mode,
            credential_password_required,
            has_hostkey,
            auth_config,
            access_principals,
        });
    }

    Ok(result)
}

/// Summaries for group listing view (members, relays, claims, roles).
pub async fn list_groups_overview() -> ServerResult<Vec<GroupInfo<'static>>> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    let group_names = state_store::list_groups(&pool).await?;
    let relays = state_store::list_relay_hosts(&pool, None).await?;
    let relay_principals = load_relay_principals(&pool, &relays).await?;

    let mut result = Vec::with_capacity(group_names.len());
    for name in group_names {
        let group_id = state_store::fetch_group_id_by_name(&pool, &name)
            .await?
            .ok_or_else(|| ServerError::not_found("group", &name))?;

        let members = state_store::list_group_members_by_id(&pool, group_id).await?;
        let claims = state_store::get_group_claims_by_id(&pool, group_id).await?;
        let roles = state_store::list_group_roles_by_id(&pool, group_id).await?;

        let mut relay_count = 0i64;
        let mut relay_names = Vec::new();
        for relay in &relays {
            if relay_principals
                .get(&relay.id)
                .map(|principals| principals.iter().any(|p| p.kind == PrincipalKind::Group && p.name == name))
                .unwrap_or(false)
            {
                relay_count += 1;
                relay_names.push(format!("{} ({}:{})", relay.name, relay.ip, relay.port));
            }
        }

        result.push(GroupInfo {
            id: group_id,
            name,
            member_count: members.len() as i64,
            relay_count,
            members,
            relays: relay_names,
            claims,
            roles,
        });
    }

    Ok(result)
}

/// Summaries for user listing view (groups, relay access, claims, ssh key counts, roles).
pub async fn list_users_overview() -> ServerResult<Vec<UserGroupInfo<'static>>> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    let usernames = state_store::list_usernames(&pool).await?;
    let relays = state_store::list_relay_hosts(&pool, None).await?;
    let relay_principals = load_relay_principals(&pool, &relays).await?;

    let mut result = Vec::with_capacity(usernames.len());
    for username in usernames {
        let user_id = state_store::fetch_user_id_by_name(&pool, &username)
            .await?
            .ok_or_else(|| ServerError::not_found("user", &username))?;

        let groups = state_store::list_user_groups_by_id(&pool, user_id).await?;
        let claims = state_store::get_user_direct_claims_by_id(&pool, user_id).await?;
        let ssh_key_count = state_store::list_user_public_keys_by_id(&pool, user_id).await?.len() as i64;
        let roles = state_store::list_user_roles_by_id(&pool, user_id).await?;

        let relays_access: Vec<UserRelayAccess> = relays
            .iter()
            .filter_map(|relay| {
                relay_principals.get(&relay.id).map(|principals| {
                    let has_direct = principals.iter().any(|p| p.kind == PrincipalKind::User && p.name == username);
                    let via_groups: Vec<String> = principals
                        .iter()
                        .filter(|p| p.kind == PrincipalKind::Group && groups.contains(&p.name))
                        .map(|p| p.name.clone())
                        .collect();

                    let access_source = match (has_direct, via_groups.is_empty()) {
                        (true, true) => Some(RelayAccessSource::Direct),
                        (false, false) => Some(RelayAccessSource::ViaGroup(via_groups.join(", "))),
                        (true, false) => Some(RelayAccessSource::Both(via_groups.join(", "))),
                        _ => None,
                    };

                    access_source.map(|source| UserRelayAccess {
                        relay_name: relay.name.clone(),
                        relay_endpoint: format!("{}:{}", relay.ip, relay.port),
                        access_source: source,
                    })
                })
            })
            .flatten()
            .collect();

        result.push(UserGroupInfo {
            id: user_id,
            username,
            groups,
            relays: relays_access,
            claims,
            ssh_key_count,
            roles,
        });
    }

    Ok(result)
}

/// Lightweight credential metadata used by the web update flow.
pub async fn get_credential_meta(id: i64) -> ServerResult<(String, bool, String, bool)> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    let cred = state_store::get_relay_credential_by_id(&pool, id)
        .await?
        .ok_or_else(|| ServerError::not_found("credential", id.to_string()))?;

    let has_secret = !cred.secret.is_empty();

    Ok((cred.kind, has_secret, cred.username_mode, cred.password_required))
}

/// Record a new SSH connection in the audit database.
pub async fn record_ssh_connection<T: AuditDbSource>(
    audit: T,
    user_id: i64,
    ip_address: impl Into<String>,
    ssh_client: Option<String>,
    connection_id: Option<String>,
) -> ServerResult<String> {
    state_store::audit::connections::record_ssh_connection(audit.audit_db(), user_id, ip_address.into(), ssh_client, connection_id)
        .await
        .map_err(ServerError::Database)
}

/// Record a new web connection using an audit context to supply identifiers.
pub async fn record_web_connection_with_context<T: AuditDbSource>(
    audit: T,
    ctx: &AuditContext,
    user_agent: Option<String>,
    parent_session_id: Option<String>,
) -> ServerResult<()> {
    let AuditContext::Web {
        user_id,
        ip_address,
        session_id,
        ..
    } = ctx
    else {
        return Err(ServerError::Other(
            "record_web_connection_with_context expects web audit context".to_string(),
        ));
    };

    state_store::audit::connections::record_web_connection(
        audit.audit_db(),
        session_id.clone(),
        *user_id,
        Some(ip_address.clone()),
        user_agent,
        parent_session_id,
    )
    .await
    .map_err(ServerError::Database)
}

/// Record a web connection when only raw identifiers are available.
pub async fn record_web_connection<T: AuditDbSource>(
    audit: T,
    connection_id: impl Into<String>,
    user_id: i64,
    ip_address: Option<String>,
    user_agent: Option<String>,
    parent_session_id: Option<String>,
) -> ServerResult<()> {
    state_store::audit::connections::record_web_connection(
        audit.audit_db(),
        connection_id.into(),
        user_id,
        ip_address,
        user_agent,
        parent_session_id,
    )
    .await
    .map_err(ServerError::Database)
}

/// Mark a connection as disconnected in the audit database.
pub async fn record_connection_disconnection<T: AuditDbSource>(audit: T, connection_id: &str) -> ServerResult<()> {
    state_store::audit::connections::record_disconnection(audit.audit_db(), connection_id)
        .await
        .map_err(ServerError::Database)
}
