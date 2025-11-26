//! Credential management operations.

use rb_types::state::RelayCredentialRow;
use sqlx::{Row, SqlitePool};

use crate::DbResult;

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

pub async fn delete_relay_credential_by_name(pool: &SqlitePool, name: &str) -> DbResult<()> {
    sqlx::query("DELETE FROM relay_credentials WHERE name = ?")
        .bind(name)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn get_relay_credential_by_name(pool: &SqlitePool, name: &str) -> DbResult<Option<RelayCredentialRow>> {
    let row = sqlx::query(
        "SELECT id, name, kind, salt, nonce, secret, meta, username_mode, password_required FROM relay_credentials WHERE name = ?",
    )
    .bind(name)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(map_cred_row))
}

pub async fn get_relay_credential_by_id(pool: &SqlitePool, id: i64) -> DbResult<Option<RelayCredentialRow>> {
    let row = sqlx::query(
        "SELECT id, name, kind, salt, nonce, secret, meta, username_mode, password_required FROM relay_credentials WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(map_cred_row))
}

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

pub async fn delete_relay_credential_by_id(pool: &SqlitePool, id: i64) -> DbResult<()> {
    sqlx::query("DELETE FROM relay_credentials WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}
