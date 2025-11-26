//! Relay host management operations.

use rb_types::{access::RelayAclPrincipal, relay::RelayInfo};
use sqlx::{Row, SqlitePool};

use crate::DbResult;

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
            kind: r
                .get::<String, _>("principal_kind")
                .parse::<rb_types::access::PrincipalKind>()
                .unwrap(),
            name: r.get::<String, _>("principal_name"),
        })
        .collect())
}

pub async fn grant_relay_access_principal(
    pool: &SqlitePool,
    relay_host_id: i64,
    principal_kind: &str,
    principal_name: &str,
) -> DbResult<()> {
    match principal_kind {
        "user" => {
            // Validate user exists
            let _ = crate::fetch_user_id_by_name(pool, principal_name)
                .await?
                .ok_or(crate::DbError::UserNotFound {
                    username: principal_name.to_string(),
                })?;
        }
        "group" => {
            // Validate group exists
            let _ = crate::fetch_group_id_by_name(pool, principal_name)
                .await?
                .ok_or(crate::DbError::GroupNotFound {
                    group: principal_name.to_string(),
                })?;
        }
        other => {
            return Err(crate::DbError::InvalidPrincipalKind { kind: other.to_string() });
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
    principal_kind: &rb_types::access::PrincipalKind,
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
