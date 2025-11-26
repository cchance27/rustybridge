use std::{
    env, fs::OpenOptions, io::ErrorKind, path::{Path, PathBuf}, str::FromStr as _
};

use rb_types::{
    access::{PrincipalKind, RelayAclPrincipal}, relay::RelayInfo, state::DbLocation
};
use sqlx::{Row, SqlitePool, migrate::Migrator, sqlite::SqlitePoolOptions};
use tokio::sync::OnceCell;
use tracing::warn;
use url::Url;

mod error;
pub use error::{DbError, DbResult};
// Re-export claim types from rb-types
use rb_types::auth::ClaimType;
use rb_types::state::{DbHandle, RelayCredentialRow, Role};

#[cfg(test)]
mod tests_rbac;

#[cfg(feature = "client")]
static CLIENT_MIGRATOR: Migrator = sqlx::migrate!("./migrations/client");
#[cfg(feature = "server")]
static SERVER_MIGRATOR: Migrator = sqlx::migrate!("./migrations/server");

#[cfg(feature = "client")]
const CLIENT_DB_ENV: &str = "RB_CLIENT_DB_URL";
#[cfg(feature = "server")]
const SERVER_DB_ENV: &str = "RB_SERVER_DB_URL";

#[cfg(feature = "client")]
static CLIENT_DB: OnceCell<DbHandle> = OnceCell::const_new();
#[cfg(feature = "server")]
static SERVER_DB: OnceCell<DbHandle> = OnceCell::const_new();

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

// -----------------------------
// Server-side relay host access
// -----------------------------

#[cfg(feature = "server")]
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

#[cfg(feature = "server")]
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

#[cfg(feature = "server")]
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
#[cfg(feature = "server")]
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
#[cfg(feature = "server")]
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

#[cfg(feature = "server")]
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

#[cfg(feature = "server")]
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

#[cfg(feature = "server")]
pub async fn delete_relay_host_by_id(pool: &SqlitePool, id: i64) -> DbResult<()> {
    sqlx::query("DELETE FROM relay_hosts WHERE id = ?").bind(id).execute(pool).await?;
    Ok(())
}

#[cfg(feature = "server")]
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

#[cfg(feature = "server")]
pub async fn fetch_user_id_by_name(pool: &SqlitePool, username: &str) -> DbResult<Option<i64>> {
    let row = sqlx::query("SELECT id FROM users WHERE username = ?")
        .bind(username)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.get::<i64, _>("id")))
}

/// Basic authentication row for a user.
#[cfg(feature = "server")]
#[derive(Debug, Clone)]
pub struct UserAuthRecord {
    pub id: i64,
    pub username: String,
    pub password_hash: Option<String>,
}

/// Fetch a user's auth record by ID (id, username, password hash).
#[cfg(feature = "server")]
pub async fn fetch_user_auth_record(pool: &SqlitePool, user_id: i64) -> DbResult<Option<UserAuthRecord>> {
    let row = sqlx::query("SELECT id, username, password_hash FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(pool)
        .await?;

    Ok(row.map(|r| UserAuthRecord {
        id: r.get("id"),
        username: r.get("username"),
        password_hash: r.get("password_hash"),
    }))
}

#[cfg(feature = "server")]
pub async fn fetch_group_id_by_name(pool: &SqlitePool, name: &str) -> DbResult<Option<i64>> {
    let row = sqlx::query("SELECT id FROM groups WHERE name = ?")
        .bind(name)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.get::<i64, _>("id")))
}

#[cfg(feature = "server")]
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

#[cfg(feature = "server")]
pub async fn delete_group_by_name(pool: &SqlitePool, name: &str) -> DbResult<()> {
    sqlx::query("DELETE FROM groups WHERE name = ?").bind(name).execute(pool).await?;
    Ok(())
}

#[cfg(feature = "server")]
pub async fn list_groups(pool: &SqlitePool) -> DbResult<Vec<String>> {
    let rows = sqlx::query("SELECT name FROM groups ORDER BY name").fetch_all(pool).await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("name")).collect())
}

#[cfg(feature = "server")]
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

#[cfg(feature = "server")]
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

#[cfg(feature = "server")]
pub async fn list_user_groups(pool: &SqlitePool, username: &str) -> DbResult<Vec<String>> {
    let rows = sqlx::query(
        "SELECT g.name FROM groups g JOIN user_groups ug ON g.id = ug.group_id JOIN users u ON u.id = ug.user_id WHERE u.username = ? ORDER BY g.name",
    )
    .bind(username)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("name")).collect())
}

#[cfg(feature = "server")]
pub async fn list_group_members(pool: &SqlitePool, group_name: &str) -> DbResult<Vec<String>> {
    let rows = sqlx::query(
        "SELECT u.username FROM users u JOIN user_groups ug ON u.id = ug.user_id JOIN groups g ON g.id = ug.group_id WHERE g.name = ? ORDER BY u.username",
    )
    .bind(group_name)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("username")).collect())
}

#[cfg(feature = "server")]
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

#[cfg(feature = "server")]
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

#[cfg(feature = "server")]
pub async fn fetch_user_password_hash(pool: &SqlitePool, username: &str) -> DbResult<Option<String>> {
    let row = sqlx::query("SELECT password_hash FROM users WHERE username = ?")
        .bind(username)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.get::<String, _>("password_hash")))
}

#[cfg(feature = "server")]
pub async fn count_users(pool: &SqlitePool) -> DbResult<i64> {
    let row = sqlx::query("SELECT COUNT(*) as cnt FROM users").fetch_one(pool).await?;
    Ok(row.get::<i64, _>("cnt"))
}

#[cfg(feature = "server")]
pub async fn list_usernames(pool: &SqlitePool) -> DbResult<Vec<String>> {
    let rows = sqlx::query("SELECT username FROM users ORDER BY username").fetch_all(pool).await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("username")).collect())
}

#[cfg(feature = "server")]
#[allow(clippy::too_many_arguments)]
pub async fn insert_relay_credential(
    pool: &SqlitePool,
    name: &str,
    kind: &str,
    salt: &[u8],
    nonce: &[u8],
    secret: &[u8],
    meta: Option<&str>,
    username_mode: &str,
    password_required: bool,
) -> DbResult<i64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    sqlx::query(
        "INSERT INTO relay_credentials (name, kind, salt, nonce, secret, meta, username_mode, password_required, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(name)
    .bind(kind)
    .bind(salt)
    .bind(nonce)
    .bind(secret)
    .bind(meta)
    .bind(username_mode)
    .bind(password_required as i64)
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

#[cfg(feature = "server")]
pub async fn delete_relay_credential_by_name(pool: &SqlitePool, name: &str) -> DbResult<()> {
    sqlx::query("DELETE FROM relay_credentials WHERE name = ?")
        .bind(name)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(feature = "server")]
pub async fn get_relay_credential_by_name(pool: &SqlitePool, name: &str) -> DbResult<Option<RelayCredentialRow>> {
    let row = sqlx::query(
        "SELECT id, name, kind, salt, nonce, secret, meta, username_mode, password_required FROM relay_credentials WHERE name = ?",
    )
    .bind(name)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(map_cred_row))
}

#[cfg(feature = "server")]
pub async fn get_relay_credential_by_id(pool: &SqlitePool, id: i64) -> DbResult<Option<RelayCredentialRow>> {
    let row = sqlx::query(
        "SELECT id, name, kind, salt, nonce, secret, meta, username_mode, password_required FROM relay_credentials WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(map_cred_row))
}

#[cfg(feature = "server")]
pub async fn list_relay_credentials(pool: &SqlitePool) -> DbResult<Vec<(i64, String, String, Option<String>, String, bool)>> {
    let rows = sqlx::query("SELECT id, name, kind, meta, username_mode, password_required FROM relay_credentials ORDER BY name")
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
                r.get::<String, _>("username_mode"),
                r.get::<i64, _>("password_required") != 0,
            )
        })
        .collect())
}

#[cfg(feature = "server")]
fn map_cred_row(r: sqlx::sqlite::SqliteRow) -> RelayCredentialRow {
    RelayCredentialRow {
        id: r.get("id"),
        name: r.get("name"),
        kind: r.get("kind"),
        salt: r.get("salt"),
        nonce: r.get("nonce"),
        secret: r.get("secret"),
        meta: r.get("meta"),
        username_mode: r.get("username_mode"),
        password_required: r.get::<i64, _>("password_required") != 0,
    }
}

fn current_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(feature = "server")]
#[allow(clippy::too_many_arguments)]
pub async fn update_relay_credential(
    pool: &SqlitePool,
    id: i64,
    kind: &str,
    salt: &[u8],
    nonce: &[u8],
    secret: &[u8],
    meta: Option<&str>,
    username_mode: &str,
    password_required: bool,
) -> DbResult<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    sqlx::query("UPDATE relay_credentials SET kind = ?, salt = ?, nonce = ?, secret = ?, meta = ?, username_mode = ?, password_required = ?, updated_at = ? WHERE id = ?")
        .bind(kind)
        .bind(salt)
        .bind(nonce)
        .bind(secret)
        .bind(meta)
        .bind(username_mode)
        .bind(password_required as i64)
        .bind(now)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(feature = "server")]
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

#[cfg(feature = "server")]
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

#[cfg(feature = "server")]
pub async fn delete_role(pool: &SqlitePool, name: &str) -> DbResult<()> {
    sqlx::query("DELETE FROM roles WHERE name = ?").bind(name).execute(pool).await?;
    Ok(())
}

#[cfg(feature = "server")]
pub async fn list_roles(pool: &SqlitePool) -> DbResult<Vec<Role>> {
    let rows = sqlx::query_as::<_, Role>("SELECT id, name, description, created_at FROM roles ORDER BY name")
        .fetch_all(pool)
        .await?;
    Ok(rows)
}

#[cfg(feature = "server")]
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

#[cfg(feature = "server")]
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

#[cfg(feature = "server")]
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

#[cfg(feature = "server")]
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

#[cfg(feature = "server")]
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

    // Fetch claims via group roles (NEW: groups → roles → claims)
    let group_role_claims = sqlx::query_scalar::<_, String>(
        r#"
        SELECT rc.claim_key 
        FROM role_claims rc
        JOIN group_roles gr ON rc.role_id = gr.role_id
        JOIN user_groups ug ON gr.group_id = ug.group_id
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
    all_claims.extend(group_role_claims); // NEW: Add group role claims

    // Dedup strings first
    all_claims.sort();
    all_claims.dedup();

    // Convert to ClaimType
    Ok(all_claims.into_iter().filter_map(|s| ClaimType::from_str(&s).ok()).collect())
}

#[cfg(feature = "server")]
pub async fn get_user_direct_claims(pool: &SqlitePool, username: &str) -> DbResult<Vec<ClaimType>> {
    let user_id = fetch_user_id_by_name(pool, username).await?.ok_or(DbError::UserNotFound {
        username: username.to_string(),
    })?;

    // Fetch direct user claims only
    let user_claims = sqlx::query_scalar::<_, String>("SELECT claim_key FROM user_claims WHERE user_id = ?")
        .bind(user_id)
        .fetch_all(pool)
        .await?;

    Ok(user_claims.into_iter().filter_map(|s| ClaimType::from_str(&s).ok()).collect())
}

#[cfg(feature = "server")]
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

#[cfg(feature = "server")]
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

#[cfg(feature = "server")]
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

#[cfg(feature = "server")]
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

#[cfg(feature = "server")]
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

#[cfg(feature = "server")]
pub async fn get_role_claims(pool: &SqlitePool, role_name: &str) -> DbResult<Vec<ClaimType>> {
    let role_id = fetch_role_id_by_name(pool, role_name).await?.ok_or(DbError::GroupNotFound {
        group: role_name.to_string(), // TODO: Add RoleNotFound error
    })?;
    let claims = sqlx::query_scalar::<_, String>("SELECT claim_key FROM role_claims WHERE role_id = ?")
        .bind(role_id)
        .fetch_all(pool)
        .await?;

    Ok(claims.into_iter().filter_map(|s| ClaimType::from_str(&s).ok()).collect())
}

#[cfg(feature = "server")]
pub async fn list_user_roles(pool: &SqlitePool, username: &str) -> DbResult<Vec<String>> {
    let rows = sqlx::query(
        "SELECT r.name FROM roles r JOIN user_roles ur ON r.id = ur.role_id JOIN users u ON u.id = ur.user_id WHERE u.username = ? ORDER BY r.name",
    )
    .bind(username)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("name")).collect())
}

#[cfg(feature = "server")]
pub async fn list_role_users(pool: &SqlitePool, role_name: &str) -> DbResult<Vec<String>> {
    let rows = sqlx::query(
        "SELECT u.username FROM users u JOIN user_roles ur ON u.id = ur.user_id JOIN roles r ON r.id = ur.role_id WHERE r.name = ? ORDER BY u.username",
    )
    .bind(role_name)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("username")).collect())
}

#[cfg(feature = "server")]
pub async fn list_group_roles(pool: &SqlitePool, group_name: &str) -> DbResult<Vec<String>> {
    let rows = sqlx::query(
        "SELECT r.name FROM roles r JOIN group_roles gr ON r.id = gr.role_id JOIN groups g ON g.id = gr.group_id WHERE g.name = ? ORDER BY r.name",
    )
    .bind(group_name)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("name")).collect())
}

#[cfg(feature = "server")]
pub async fn list_role_groups(pool: &SqlitePool, role_name: &str) -> DbResult<Vec<String>> {
    let rows = sqlx::query(
        "SELECT g.name FROM groups g JOIN group_roles gr ON g.id = gr.group_id JOIN roles r ON r.id = gr.role_id WHERE r.name = ? ORDER BY g.name",
    )
    .bind(role_name)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("name")).collect())
}

#[cfg(feature = "server")]
pub async fn assign_role_to_group(pool: &SqlitePool, group_name: &str, role_name: &str) -> DbResult<()> {
    let group_id = fetch_group_id_by_name(pool, group_name).await?.ok_or(DbError::GroupNotFound {
        group: group_name.to_string(),
    })?;
    let role_id = fetch_role_id_by_name(pool, role_name).await?.ok_or(DbError::GroupNotFound {
        group: role_name.to_string(), // TODO: Add RoleNotFound error
    })?;
    sqlx::query("INSERT OR IGNORE INTO group_roles (group_id, role_id) VALUES (?, ?)")
        .bind(group_id)
        .bind(role_id)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(feature = "server")]
pub async fn revoke_role_from_group(pool: &SqlitePool, group_name: &str, role_name: &str) -> DbResult<()> {
    let group_id = fetch_group_id_by_name(pool, group_name).await?.ok_or(DbError::GroupNotFound {
        group: group_name.to_string(),
    })?;
    let role_id = fetch_role_id_by_name(pool, role_name).await?.ok_or(DbError::GroupNotFound {
        group: role_name.to_string(),
    })?;
    sqlx::query("DELETE FROM group_roles WHERE group_id = ? AND role_id = ?")
        .bind(group_id)
        .bind(role_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Latest OIDC profile (name/picture) for a user, if linked.
#[cfg(feature = "server")]
#[derive(Debug, Clone, Default)]
pub struct OidcProfile {
    pub name: Option<String>,
    pub picture: Option<String>,
}

#[cfg(feature = "server")]
pub async fn get_latest_oidc_profile(pool: &SqlitePool, user_id: i64) -> DbResult<Option<OidcProfile>> {
    let profile = sqlx::query("SELECT name, picture FROM user_oidc_links WHERE user_id = ? ORDER BY created_at DESC LIMIT 1")
        .bind(user_id)
        .fetch_optional(pool)
        .await?;

    Ok(profile.map(|row| OidcProfile {
        name: row.get("name"),
        picture: row.get("picture"),
    }))
}

/// OIDC link row for a user (latest entry).
#[cfg(feature = "server")]
#[derive(Debug, Clone)]
pub struct OidcLinkInfo {
    pub user_id: i64,
    pub provider_id: String,
    pub subject_id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub picture: Option<String>,
}

/// Fetch the latest OIDC link (if any) for a given user.
#[cfg(feature = "server")]
pub async fn get_oidc_link_for_user(pool: &SqlitePool, user_id: i64) -> DbResult<Option<OidcLinkInfo>> {
    let row = sqlx::query(
        r#"
        SELECT user_id, provider_id, subject_id, email, name, picture
        FROM user_oidc_links
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| OidcLinkInfo {
        user_id: r.get("user_id"),
        provider_id: r.get("provider_id"),
        subject_id: r.get("subject_id"),
        email: r.get("email"),
        name: r.get("name"),
        picture: r.get("picture"),
    }))
}

/// Locate a user id by OIDC provider + subject.
#[cfg(feature = "server")]
pub async fn find_user_id_by_oidc_subject(pool: &SqlitePool, provider_id: &str, subject_id: &str) -> DbResult<Option<i64>> {
    let result = sqlx::query_scalar::<_, i64>("SELECT user_id FROM user_oidc_links WHERE provider_id = ? AND subject_id = ?")
        .bind(provider_id)
        .bind(subject_id)
        .fetch_optional(pool)
        .await?;

    Ok(result)
}

/// Upsert (link) an OIDC account to a user.
#[cfg(feature = "server")]
#[allow(clippy::too_many_arguments)]
pub async fn upsert_oidc_link(
    pool: &SqlitePool,
    user_id: i64,
    provider_id: &str,
    subject_id: &str,
    email: &Option<String>,
    name: &Option<String>,
    picture: &Option<String>,
) -> DbResult<()> {
    sqlx::query(
        r#"
        INSERT INTO user_oidc_links (user_id, provider_id, subject_id, email, name, picture)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id, provider_id) DO UPDATE SET
            subject_id = excluded.subject_id,
            email = excluded.email,
            name = excluded.name,
            picture = excluded.picture
        "#,
    )
    .bind(user_id)
    .bind(provider_id)
    .bind(subject_id)
    .bind(email)
    .bind(name)
    .bind(picture)
    .execute(pool)
    .await?;

    Ok(())
}

/// Update stored OIDC profile fields by provider/subject (no user_id change).
#[cfg(feature = "server")]
pub async fn update_oidc_profile_by_subject(
    pool: &SqlitePool,
    provider_id: &str,
    subject_id: &str,
    email: &Option<String>,
    name: &Option<String>,
    picture: &Option<String>,
) -> DbResult<()> {
    sqlx::query("UPDATE user_oidc_links SET email = ?, name = ?, picture = ? WHERE provider_id = ? AND subject_id = ?")
        .bind(email)
        .bind(name)
        .bind(picture)
        .bind(provider_id)
        .bind(subject_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Remove OIDC link for the specified user; returns affected rows.
#[cfg(feature = "server")]
pub async fn delete_oidc_link_for_user(pool: &SqlitePool, user_id: i64) -> DbResult<u64> {
    let res = sqlx::query("DELETE FROM user_oidc_links WHERE user_id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

#[cfg(feature = "server")]
pub async fn fetch_role_id_by_name(pool: &SqlitePool, name: &str) -> DbResult<Option<i64>> {
    let row = sqlx::query("SELECT id FROM roles WHERE name = ?")
        .bind(name)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.get::<i64, _>("id")))
}

// -----------------------------
// SSH Authentication Sessions
// -----------------------------

/// Create a new SSH authentication session bound to a specific user
#[cfg(feature = "server")]
pub async fn create_ssh_auth_session(pool: &SqlitePool, code: &str, expires_at: i64, requested_user_id: i64) -> DbResult<()> {
    sqlx::query("INSERT INTO ssh_auth_sessions (id, status, expires_at, requested_user_id) VALUES (?, 'pending', ?, ?)")
        .bind(code)
        .bind(expires_at)
        .bind(requested_user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Get SSH authentication session status, authenticated user, and requested user
#[cfg(feature = "server")]
pub async fn get_ssh_auth_session(pool: &SqlitePool, code: &str) -> DbResult<Option<(String, Option<i64>, Option<i64>)>> {
    sqlx::query_as::<_, (String, Option<i64>, Option<i64>)>("SELECT status, user_id, requested_user_id FROM ssh_auth_sessions WHERE id = ?")
        .bind(code)
        .fetch_optional(pool)
        .await
        .map_err(Into::into)
}

/// Update SSH authentication session status
#[cfg(feature = "server")]
pub async fn update_ssh_auth_session(pool: &SqlitePool, code: &str, status: &str, user_id: Option<i64>) -> DbResult<()> {
    sqlx::query("UPDATE ssh_auth_sessions SET status = ?, user_id = ? WHERE id = ?")
        .bind(status)
        .bind(user_id)
        .bind(code)
        .execute(pool)
        .await?;
    Ok(())
}

/// Cleanup expired and used SSH auth sessions
#[cfg(feature = "server")]
pub async fn cleanup_expired_ssh_auth_sessions(pool: &SqlitePool) -> DbResult<u64> {
    let result =
        sqlx::query("DELETE FROM ssh_auth_sessions WHERE expires_at < strftime('%s', 'now') OR status IN ('used', 'expired', 'rejected')")
            .execute(pool)
            .await?;
    Ok(result.rows_affected())
}

// -----------------------------
// User SSH Public Keys
// -----------------------------

/// Get all public keys for a user by username
#[cfg(feature = "server")]
pub async fn get_user_public_keys(pool: &SqlitePool, username: &str) -> DbResult<Vec<String>> {
    let rows = sqlx::query_scalar::<_, String>(
        "SELECT public_key FROM user_public_keys 
         WHERE user_id = (SELECT id FROM users WHERE username = ?)",
    )
    .bind(username)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Add a public key for a user
#[cfg(feature = "server")]
pub async fn add_user_public_key(pool: &SqlitePool, username: &str, public_key: &str, comment: Option<&str>) -> DbResult<i64> {
    let user_id = fetch_user_id_by_name(pool, username).await?.ok_or(DbError::UserNotFound {
        username: username.to_string(),
    })?;

    let result = sqlx::query("INSERT INTO user_public_keys (user_id, public_key, comment) VALUES (?, ?, ?)")
        .bind(user_id)
        .bind(public_key)
        .bind(comment)
        .execute(pool)
        .await?;

    Ok(result.last_insert_rowid())
}

/// Delete a user's public key by ID
#[cfg(feature = "server")]
pub async fn delete_user_public_key(pool: &SqlitePool, key_id: i64) -> DbResult<()> {
    sqlx::query("DELETE FROM user_public_keys WHERE id = ?")
        .bind(key_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// List all public keys for a user (with full details)
#[cfg(feature = "server")]
pub async fn list_user_public_keys(pool: &SqlitePool, username: &str) -> DbResult<Vec<(i64, String, Option<String>, i64)>> {
    let user_id = fetch_user_id_by_name(pool, username).await?.ok_or(DbError::UserNotFound {
        username: username.to_string(),
    })?;

    // Cast created_at to Unix epoch seconds so callers receive a numeric value (integer).
    let rows = sqlx::query_as::<_, (i64, String, Option<String>, i64)>(
        "SELECT id, public_key, comment, CAST(strftime('%s', created_at) AS INTEGER) as created_at
         FROM user_public_keys WHERE user_id = ? ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

#[cfg(feature = "server")]
pub async fn get_server_option(pool: &SqlitePool, key: &str) -> DbResult<Option<String>> {
    let row = sqlx::query("SELECT value FROM server_options WHERE key = ?")
        .bind(key)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.get("value")))
}

#[cfg(feature = "server")]
pub async fn set_server_option(pool: &SqlitePool, key: &str, value: &str) -> DbResult<()> {
    sqlx::query("INSERT OR REPLACE INTO server_options (key, value) VALUES (?, ?)")
        .bind(key)
        .bind(value)
        .execute(pool)
        .await?;
    Ok(())
}

/// Get user ID by username
#[cfg(feature = "server")]
pub async fn get_user_id(pool: &SqlitePool, username: &str) -> DbResult<Option<i64>> {
    let result = sqlx::query_scalar::<_, i64>("SELECT id FROM users WHERE username = ?")
        .bind(username)
        .fetch_optional(pool)
        .await?;
    Ok(result)
}

/// Establish a pooled SQLite connection for client-side state (host keys, etc.).
#[cfg(feature = "client")]
pub async fn client_db() -> DbResult<DbHandle> {
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
pub async fn server_db() -> DbResult<DbHandle> {
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
pub async fn migrate_client(handle: &DbHandle) -> DbResult<()> {
    CLIENT_MIGRATOR.run(&handle.pool).await?;
    if handle.freshly_created {
        warn!(db = %display_path(handle), "initialized client database and applied migrations");
    }
    Ok(())
}

/// Apply the server migrations to the provided pool.
#[cfg(feature = "server")]
pub async fn migrate_server(handle: &DbHandle) -> DbResult<()> {
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
    if let Some(ref path) = location.path
        && !location.freshly_created
        && let Ok(changed) = ensure_secure_permissions(path)
        && changed
    {
        warn!(
            db = %path.display(),
            "Fixed insecure database file permissions to 0600"
        );
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

        let metadata = std::fs::metadata(path).map_err(DbError::Io)?;
        let current_mode = metadata.permissions().mode() & 0o777;

        if current_mode != 0o600 {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms).map_err(DbError::Io)?;
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

fn display_path(handle: &DbHandle) -> String {
    handle
        .path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| handle.url.clone())
}

// DbLocation now lives in rb-types::state for shared use
