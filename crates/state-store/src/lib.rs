use std::{
    env, fs::OpenOptions, io::ErrorKind, path::{Path, PathBuf}, str::FromStr as _
};

use rb_types::{
    RelayInfo, web::{PrincipalKind, RelayAclPrincipal}
};
use sqlx::{Row, SqlitePool, migrate::Migrator, prelude::FromRow, sqlite::SqlitePoolOptions};
use tracing::warn;
use url::Url;

mod error;
pub use error::{DbError, DbResult};
// Re-export claim types from rb-types
use rb_types::auth::ClaimType;

#[cfg(test)]
mod tests_rbac;

static CLIENT_MIGRATOR: Migrator = sqlx::migrate!("./migrations/client");
static SERVER_MIGRATOR: Migrator = sqlx::migrate!("./migrations/server");

const CLIENT_DB_ENV: &str = "RB_CLIENT_DB_URL";
const SERVER_DB_ENV: &str = "RB_SERVER_DB_URL";

/// Return a human-friendly string describing where the client DB will live.
/// Prefers a filesystem path when available, otherwise returns the configured URL.
pub fn display_client_db_path() -> String {
    if let Ok(val) = std::env::var(CLIENT_DB_ENV) {
        return val;
    }
    default_client_path().display().to_string()
}

/// Return a human-friendly string describing where the server DB will live.
/// Prefers a filesystem path when available, otherwise returns the configured URL.
pub fn display_server_db_path() -> String {
    if let Ok(val) = std::env::var(SERVER_DB_ENV) {
        return val;
    }
    default_server_path().display().to_string()
}

/// Return the directory where the server database is stored
pub fn server_db_dir() -> PathBuf {
    default_server_path().parent().unwrap_or(Path::new(".")).to_path_buf()
}

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

pub async fn fetch_relay_host_by_name(pool: &SqlitePool, name: &str) -> DbResult<Option<RelayInfo>> {
    if let Some(row) = sqlx::query_as::<_, RelayInfo>("SELECT id, name, ip, port FROM relay_hosts WHERE name = ?")
        .bind(name)
        .fetch_optional(pool)
        .await?
    {
        Ok(Some(RelayInfo {
            id: row.id,
            name: row.name,
            ip: row.ip,
            port: row.port,
        }))
    } else {
        Ok(None)
    }
}

pub async fn fetch_relay_host_by_id(pool: &SqlitePool, id: i64) -> DbResult<Option<RelayInfo>> {
    if let Some(row) = sqlx::query_as::<_, RelayInfo>("SELECT id, name, ip, port FROM relay_hosts WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await?
    {
        Ok(Some(RelayInfo {
            id: row.id,
            name: row.name,
            ip: row.ip,
            port: row.port,
        }))
    } else {
        Ok(None)
    }
}

pub async fn fetch_relay_host_options(
    pool: &SqlitePool,
    relay_host_id: i64,
) -> DbResult<std::collections::HashMap<String, (String, bool)>> {
    let mut map = std::collections::HashMap::new();
    let rows = sqlx::query_as::<_, (String, String, bool)>("SELECT key, value, is_secure FROM relay_host_options WHERE relay_host_id = ?")
        .bind(relay_host_id)
        .fetch_all(pool)
        .await?;
    for row in rows {
        map.insert(row.0, (row.1, row.2));
    }
    Ok(map)
}

/// Return true if the user has access to the relay host either directly or via any group membership.
pub async fn user_has_relay_access(pool: &SqlitePool, username: &str, relay_host_id: i64) -> DbResult<bool> {
    // Direct user ACL
    let direct = sqlx::query_scalar::<_, i64>(
        "SELECT id FROM relay_host_acl WHERE relay_host_id = ? AND principal_kind = 'user' AND principal_name = ? LIMIT 1",
    )
    .bind(relay_host_id)
    .bind(username)
    .fetch_optional(pool)
    .await?;
    if direct.is_some() {
        return Ok(true);
    }

    // Group-based ACL
    let via_group = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT a.id
        FROM relay_host_acl a
        JOIN groups g ON a.principal_kind = 'group' AND a.principal_name = g.name
        JOIN user_groups ug ON ug.group_id = g.id
        JOIN users u ON u.id = ug.user_id
        WHERE a.relay_host_id = ? AND u.username = ?
        LIMIT 1
        "#,
    )
    .bind(relay_host_id)
    .bind(username)
    .fetch_optional(pool)
    .await?;

    Ok(via_group.is_some())
}

/// List all relay hosts, optionally filtered by username access
pub async fn list_relay_hosts(pool: &SqlitePool, username: Option<&str>) -> DbResult<Vec<RelayInfo>> {
    let rows = match username {
        Some(user) => {
            sqlx::query_as::<_, RelayInfo>(
                r#"
                SELECT DISTINCT h.id, h.name, h.ip, h.port
                FROM relay_hosts h
                JOIN relay_host_acl a ON h.id = a.relay_host_id
                LEFT JOIN groups g ON a.principal_kind = 'group' AND a.principal_name = g.name
                LEFT JOIN user_groups ug ON g.id = ug.group_id
                LEFT JOIN users u ON u.id = ug.user_id
                WHERE (a.principal_kind = 'user' AND a.principal_name = ?)
                   OR (a.principal_kind = 'group' AND u.username = ?)
                ORDER BY h.name
                "#,
            )
            .bind(user)
            .bind(user)
            .fetch_all(pool)
            .await?
        }
        None => {
            sqlx::query_as::<_, RelayInfo>("SELECT id, name, ip, port FROM relay_hosts ORDER BY name")
                .fetch_all(pool)
                .await?
        }
    };

    Ok(rows
        .into_iter()
        .map(|row| RelayInfo {
            id: row.id,
            name: row.name,
            ip: row.ip,
            port: row.port,
        })
        .collect())
}

pub async fn insert_relay_host(pool: &SqlitePool, name: &str, ip: &str, port: i64) -> DbResult<i64> {
    sqlx::query("INSERT INTO relay_hosts (name, ip, port) VALUES (?, ?, ?)")
        .bind(name)
        .bind(ip)
        .bind(port)
        .execute(pool)
        .await?;
    let row = sqlx::query("SELECT id FROM relay_hosts WHERE name = ?")
        .bind(name)
        .fetch_one(pool)
        .await?;
    Ok(row.get::<i64, _>("id"))
}

pub async fn update_relay_host(pool: &SqlitePool, id: i64, name: &str, ip: &str, port: i64) -> DbResult<()> {
    sqlx::query("UPDATE relay_hosts SET name = ?, ip = ?, port = ? WHERE id = ?")
        .bind(name)
        .bind(ip)
        .bind(port)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_relay_host_by_id(pool: &SqlitePool, id: i64) -> DbResult<()> {
    sqlx::query("DELETE FROM relay_hosts WHERE id = ?").bind(id).execute(pool).await?;
    Ok(())
}

pub async fn fetch_relay_access_principals(pool: &SqlitePool, relay_host_id: i64) -> DbResult<Vec<RelayAclPrincipal>> {
    let rows = sqlx::query(
        "SELECT principal_kind, principal_name FROM relay_host_acl WHERE relay_host_id = ? ORDER BY principal_kind, principal_name",
    )
    .bind(relay_host_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| RelayAclPrincipal {
            kind: r.get::<String, _>("principal_kind").parse::<PrincipalKind>().unwrap(),
            name: r.get::<String, _>("principal_name"),
        })
        .collect())
}

pub async fn fetch_user_id_by_name(pool: &SqlitePool, username: &str) -> DbResult<Option<i64>> {
    let row = sqlx::query("SELECT id FROM users WHERE username = ?")
        .bind(username)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.get::<i64, _>("id")))
}

pub async fn fetch_group_id_by_name(pool: &SqlitePool, name: &str) -> DbResult<Option<i64>> {
    let row = sqlx::query("SELECT id FROM groups WHERE name = ?")
        .bind(name)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.get::<i64, _>("id")))
}

pub async fn create_group(pool: &SqlitePool, name: &str) -> DbResult<i64> {
    sqlx::query("INSERT INTO groups (name, created_at) VALUES (?, ?)")
        .bind(name)
        .bind(current_ts())
        .execute(pool)
        .await?;
    let row = sqlx::query("SELECT id FROM groups WHERE name = ?")
        .bind(name)
        .fetch_one(pool)
        .await?;
    Ok(row.get::<i64, _>("id"))
}

pub async fn delete_group_by_name(pool: &SqlitePool, name: &str) -> DbResult<()> {
    sqlx::query("DELETE FROM groups WHERE name = ?").bind(name).execute(pool).await?;
    Ok(())
}

pub async fn list_groups(pool: &SqlitePool) -> DbResult<Vec<String>> {
    let rows = sqlx::query("SELECT name FROM groups ORDER BY name").fetch_all(pool).await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("name")).collect())
}

pub async fn add_user_to_group(pool: &SqlitePool, username: &str, group_name: &str) -> DbResult<()> {
    let user_id = fetch_user_id_by_name(pool, username).await?.ok_or(DbError::UserNotFound {
        username: username.to_string(),
    })?;
    let group_id = fetch_group_id_by_name(pool, group_name).await?.ok_or(DbError::GroupNotFound {
        group: group_name.to_string(),
    })?;
    sqlx::query("INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES (?, ?)")
        .bind(user_id)
        .bind(group_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn remove_user_from_group(pool: &SqlitePool, username: &str, group_name: &str) -> DbResult<()> {
    let user_id = fetch_user_id_by_name(pool, username).await?.ok_or(DbError::UserNotFound {
        username: username.to_string(),
    })?;
    let group_id = fetch_group_id_by_name(pool, group_name).await?.ok_or(DbError::GroupNotFound {
        group: group_name.to_string(),
    })?;
    sqlx::query("DELETE FROM user_groups WHERE user_id = ? AND group_id = ?")
        .bind(user_id)
        .bind(group_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_user_groups(pool: &SqlitePool, username: &str) -> DbResult<Vec<String>> {
    let rows = sqlx::query(
        "SELECT g.name FROM groups g JOIN user_groups ug ON g.id = ug.group_id JOIN users u ON u.id = ug.user_id WHERE u.username = ? ORDER BY g.name",
    )
    .bind(username)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("name")).collect())
}

pub async fn list_group_members(pool: &SqlitePool, group_name: &str) -> DbResult<Vec<String>> {
    let rows = sqlx::query(
        "SELECT u.username FROM users u JOIN user_groups ug ON u.id = ug.user_id JOIN groups g ON g.id = ug.group_id WHERE g.name = ? ORDER BY u.username",
    )
    .bind(group_name)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("username")).collect())
}

pub async fn grant_relay_access_principal(
    pool: &SqlitePool,
    relay_host_id: i64,
    principal_kind: &str,
    principal_name: &str,
) -> DbResult<()> {
    match principal_kind {
        "user" => {
            fetch_user_id_by_name(pool, principal_name).await?.ok_or(DbError::UserNotFound {
                username: principal_name.to_string(),
            })?;
        }
        "group" => {
            fetch_group_id_by_name(pool, principal_name).await?.ok_or(DbError::GroupNotFound {
                group: principal_name.to_string(),
            })?;
        }
        other => {
            return Err(DbError::InvalidPrincipalKind { kind: other.to_string() });
        }
    }

    sqlx::query("INSERT OR IGNORE INTO relay_host_acl (relay_host_id, principal_kind, principal_name) VALUES (?, ?, ?)")
        .bind(relay_host_id)
        .bind(principal_kind)
        .bind(principal_name)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn revoke_relay_access_principal(
    pool: &SqlitePool,
    relay_host_id: i64,
    principal_kind: &PrincipalKind,
    principal_name: &str,
) -> DbResult<()> {
    sqlx::query("DELETE FROM relay_host_acl WHERE relay_host_id = ? AND principal_kind = ? AND principal_name = ?")
        .bind(relay_host_id)
        .bind(principal_kind.to_string())
        .bind(principal_name)
        .execute(pool)
        .await?;
    Ok(())
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

pub async fn list_relay_credentials(pool: &SqlitePool) -> DbResult<Vec<(i64, String, String, Option<String>)>> {
    let rows = sqlx::query("SELECT id, name, kind, meta FROM relay_credentials ORDER BY name")
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            (
                r.get::<i64, _>("id"),
                r.get::<String, _>("name"),
                r.get::<String, _>("kind"),
                r.get::<Option<String>, _>("meta"),
            )
        })
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

fn current_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub async fn update_relay_credential(
    pool: &SqlitePool,
    id: i64,
    kind: &str,
    salt: &[u8],
    nonce: &[u8],
    secret: &[u8],
    meta: Option<&str>,
) -> DbResult<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    sqlx::query("UPDATE relay_credentials SET kind = ?, salt = ?, nonce = ?, secret = ?, meta = ?, updated_at = ? WHERE id = ?")
        .bind(kind)
        .bind(salt)
        .bind(nonce)
        .bind(secret)
        .bind(meta)
        .bind(now)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_relay_credential_by_id(pool: &SqlitePool, id: i64) -> DbResult<()> {
    sqlx::query("DELETE FROM relay_credentials WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

// -----------------------------
// RBAC: Roles & Claims
// -----------------------------

#[derive(Debug, Clone, FromRow)]
pub struct Role {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub created_at: i64,
}

pub async fn create_role(pool: &SqlitePool, name: &str, description: Option<&str>) -> DbResult<i64> {
    let now = current_ts();
    sqlx::query("INSERT INTO roles (name, description, created_at) VALUES (?, ?, ?)")
        .bind(name)
        .bind(description)
        .bind(now)
        .execute(pool)
        .await?;
    let row = sqlx::query("SELECT id FROM roles WHERE name = ?")
        .bind(name)
        .fetch_one(pool)
        .await?;
    Ok(row.get::<i64, _>("id"))
}

pub async fn delete_role(pool: &SqlitePool, name: &str) -> DbResult<()> {
    sqlx::query("DELETE FROM roles WHERE name = ?").bind(name).execute(pool).await?;
    Ok(())
}

pub async fn list_roles(pool: &SqlitePool) -> DbResult<Vec<Role>> {
    let rows = sqlx::query_as::<_, Role>("SELECT id, name, description, created_at FROM roles ORDER BY name")
        .fetch_all(pool)
        .await?;
    Ok(rows)
}

pub async fn assign_role_to_user(pool: &SqlitePool, username: &str, role_name: &str) -> DbResult<()> {
    let user_id = fetch_user_id_by_name(pool, username).await?.ok_or(DbError::UserNotFound {
        username: username.to_string(),
    })?;
    let role_id = fetch_role_id_by_name(pool, role_name).await?.ok_or(DbError::GroupNotFound {
        group: role_name.to_string(), // Reusing GroupNotFound for generic "not found" or add RoleNotFound
    })?;
    sqlx::query("INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)")
        .bind(user_id)
        .bind(role_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn revoke_role_from_user(pool: &SqlitePool, username: &str, role_name: &str) -> DbResult<()> {
    let user_id = fetch_user_id_by_name(pool, username).await?.ok_or(DbError::UserNotFound {
        username: username.to_string(),
    })?;
    let role_id = fetch_role_id_by_name(pool, role_name).await?.ok_or(DbError::GroupNotFound {
        group: role_name.to_string(),
    })?;
    sqlx::query("DELETE FROM user_roles WHERE user_id = ? AND role_id = ?")
        .bind(user_id)
        .bind(role_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn add_claim_to_role(pool: &SqlitePool, role_name: &str, claim: &ClaimType) -> DbResult<()> {
    let role_id = fetch_role_id_by_name(pool, role_name).await?.ok_or(DbError::GroupNotFound {
        group: role_name.to_string(),
    })?;
    sqlx::query("INSERT OR IGNORE INTO role_claims (role_id, claim_key) VALUES (?, ?)")
        .bind(role_id)
        .bind(claim.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn remove_claim_from_role(pool: &SqlitePool, role_name: &str, claim: &ClaimType) -> DbResult<()> {
    let role_id = fetch_role_id_by_name(pool, role_name).await?.ok_or(DbError::GroupNotFound {
        group: role_name.to_string(),
    })?;
    sqlx::query("DELETE FROM role_claims WHERE role_id = ? AND claim_key = ?")
        .bind(role_id)
        .bind(claim.to_string())
        .execute(pool)
        .await?;
    Ok(())
}
pub async fn get_user_claims(pool: &SqlitePool, username: &str) -> DbResult<Vec<ClaimType>> {
    let user_id = fetch_user_id_by_name(pool, username).await?.ok_or(DbError::UserNotFound {
        username: username.to_string(),
    })?;

    // Fetch direct user claims
    let user_claims = sqlx::query_scalar::<_, String>("SELECT claim_key FROM user_claims WHERE user_id = ?")
        .bind(user_id)
        .fetch_all(pool)
        .await?;

    // Fetch claims via roles
    let role_claims = sqlx::query_scalar::<_, String>(
        r#"
        SELECT rc.claim_key 
        FROM role_claims rc
        JOIN user_roles ur ON rc.role_id = ur.role_id
        WHERE ur.user_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    // Fetch claims via groups
    let group_claims = sqlx::query_scalar::<_, String>(
        r#"
        SELECT gc.claim_key 
        FROM group_claims gc
        JOIN user_groups ug ON gc.group_id = ug.group_id
        WHERE ug.user_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    let mut all_claims = Vec::new();
    all_claims.extend(user_claims);
    all_claims.extend(role_claims);
    all_claims.extend(group_claims);

    // Dedup strings first
    all_claims.sort();
    all_claims.dedup();

    // Convert to ClaimType
    Ok(all_claims.into_iter().filter_map(|s| ClaimType::from_str(&s).ok()).collect())
}

pub async fn add_claim_to_user(pool: &SqlitePool, username: &str, claim: &ClaimType) -> DbResult<()> {
    let user_id = fetch_user_id_by_name(pool, username).await?.ok_or(DbError::UserNotFound {
        username: username.to_string(),
    })?;
    sqlx::query("INSERT OR IGNORE INTO user_claims (user_id, claim_key) VALUES (?, ?)")
        .bind(user_id)
        .bind(claim.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn remove_claim_from_user(pool: &SqlitePool, username: &str, claim: &ClaimType) -> DbResult<()> {
    let user_id = fetch_user_id_by_name(pool, username).await?.ok_or(DbError::UserNotFound {
        username: username.to_string(),
    })?;
    sqlx::query("DELETE FROM user_claims WHERE user_id = ? AND claim_key = ?")
        .bind(user_id)
        .bind(claim.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn add_claim_to_group(pool: &SqlitePool, group_name: &str, claim: &ClaimType) -> DbResult<()> {
    let group_id = fetch_group_id_by_name(pool, group_name).await?.ok_or(DbError::GroupNotFound {
        group: group_name.to_string(),
    })?;
    sqlx::query("INSERT OR IGNORE INTO group_claims (group_id, claim_key) VALUES (?, ?)")
        .bind(group_id)
        .bind(claim.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn remove_claim_from_group(pool: &SqlitePool, group_name: &str, claim: &ClaimType) -> DbResult<()> {
    let group_id = fetch_group_id_by_name(pool, group_name).await?.ok_or(DbError::GroupNotFound {
        group: group_name.to_string(),
    })?;
    sqlx::query("DELETE FROM group_claims WHERE group_id = ? AND claim_key = ?")
        .bind(group_id)
        .bind(claim.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn get_group_claims(pool: &SqlitePool, group_name: &str) -> DbResult<Vec<ClaimType>> {
    let group_id = fetch_group_id_by_name(pool, group_name).await?.ok_or(DbError::GroupNotFound {
        group: group_name.to_string(),
    })?;
    let claims = sqlx::query_scalar::<_, String>("SELECT claim_key FROM group_claims WHERE group_id = ?")
        .bind(group_id)
        .fetch_all(pool)
        .await?;

    Ok(claims.into_iter().filter_map(|s| ClaimType::from_str(&s).ok()).collect())
}

pub async fn fetch_role_id_by_name(pool: &SqlitePool, name: &str) -> DbResult<Option<i64>> {
    let row = sqlx::query("SELECT id FROM roles WHERE name = ?")
        .bind(name)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.get::<i64, _>("id")))
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
                let mut options = OpenOptions::new();
                options.create_new(true).write(true).mode(0o600);
                match options.open(&path_clone) {
                    Ok(_) => {
                        warn!("Creating file with 600 permissions: {}", path_clone.display());
                        Ok(())
                    }
                    Err(err) if err.kind() == ErrorKind::AlreadyExists => Ok(()),
                    Err(err) => Err(DbError::FileCreationFailed {
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
                        warn!("Creating file with 600 permissions: {}", path_clone.display());
                        Ok(())
                    }
                    Err(err) if err.kind() == ErrorKind::AlreadyExists => Ok(()),
                    Err(err) => Err(DbError::FileCreationFailed {
                        path: path_clone.clone(),
                        source: err,
                    }),
                }
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

    // Check and fix permissions on existing database files
    if let Some(ref path) = location.path {
        if !location.freshly_created {
            if let Ok(changed) = ensure_secure_permissions(path) {
                if changed {
                    warn!(
                        db = %path.display(),
                        "Fixed insecure database file permissions to 0600"
                    );
                }
            }
        }
    }

    Ok(DbHandle {
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

        let metadata = std::fs::metadata(path).map_err(|e| DbError::Io(e))?;
        let current_mode = metadata.permissions().mode() & 0o777;

        if current_mode != 0o600 {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms).map_err(|e| DbError::Io(e))?;
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
