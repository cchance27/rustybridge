//! Relay host management operations.

use crate::DbResult;
use rb_types::{access::RelayAclPrincipal, relay::RelayInfo};
use sqlx::{Row, SqliteExecutor};

/// Return true if the user has access to the relay host either directly or via any group membership.
pub async fn user_has_relay_access(executor: impl SqliteExecutor<'_>, user_id: i64, relay_host_id: i64) -> DbResult<bool> {
    let result = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT 1
        FROM relay_host_acl a
        LEFT JOIN user_groups ug ON a.principal_kind = 'group' AND a.principal_id = ug.group_id
        WHERE a.relay_host_id = ?
          AND (
               (a.principal_kind = 'user' AND a.principal_id = ?)
            OR (a.principal_kind = 'group' AND ug.user_id = ?)
          )
        LIMIT 1
        "#,
    )
    .bind(relay_host_id)
    .bind(user_id)
    .bind(user_id)
    .fetch_optional(executor)
    .await?;

    Ok(result.is_some())
}

/// List all relay hosts, optionally filtered by user ID access
pub async fn list_relay_hosts(executor: impl SqliteExecutor<'_>, user_id: Option<i64>) -> DbResult<Vec<RelayInfo>> {
    let rows = match user_id {
        Some(uid) => {
            sqlx::query_as::<_, RelayInfo>(
                r#"
                SELECT DISTINCT h.id, h.name, h.ip, h.port
                FROM relay_hosts h
                JOIN relay_host_acl a ON h.id = a.relay_host_id
                LEFT JOIN user_groups ug ON a.principal_kind = 'group' AND a.principal_id = ug.group_id
                WHERE (a.principal_kind = 'user' AND a.principal_id = ?)
                   OR (a.principal_kind = 'group' AND ug.user_id = ?)
                ORDER BY h.name
                "#,
            )
            .bind(uid)
            .bind(uid)
            .fetch_all(executor)
            .await?
        }
        None => {
            sqlx::query_as::<_, RelayInfo>("SELECT id, name, ip, port FROM relay_hosts ORDER BY name")
                .fetch_all(executor)
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

pub async fn fetch_relay_host_by_name(executor: impl SqliteExecutor<'_>, name: &str) -> DbResult<Option<RelayInfo>> {
    if let Some(row) = sqlx::query_as::<_, RelayInfo>("SELECT id, name, ip, port FROM relay_hosts WHERE name = ?")
        .bind(name)
        .fetch_optional(executor)
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

pub async fn fetch_relay_host_by_id(executor: impl SqliteExecutor<'_>, id: i64) -> DbResult<Option<RelayInfo>> {
    if let Some(row) = sqlx::query_as::<_, RelayInfo>("SELECT id, name, ip, port FROM relay_hosts WHERE id = ?")
        .bind(id)
        .fetch_optional(executor)
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
    executor: impl SqliteExecutor<'_>,
    relay_host_id: i64,
) -> DbResult<std::collections::HashMap<String, (String, bool)>> {
    let mut map = std::collections::HashMap::new();
    let rows = sqlx::query_as::<_, (String, String, bool)>("SELECT key, value, is_secure FROM relay_host_options WHERE relay_host_id = ?")
        .bind(relay_host_id)
        .fetch_all(executor)
        .await?;
    for row in rows {
        map.insert(row.0, (row.1, row.2));
    }
    Ok(map)
}

pub async fn insert_relay_host(executor: impl SqliteExecutor<'_>, name: &str, ip: &str, port: i64) -> DbResult<i64> {
    let result = sqlx::query("INSERT INTO relay_hosts (name, ip, port) VALUES (?, ?, ?)")
        .bind(name)
        .bind(ip)
        .bind(port)
        .execute(executor)
        .await?;
    Ok(result.last_insert_rowid())
}

pub async fn update_relay_host(executor: impl SqliteExecutor<'_>, id: i64, name: &str, ip: &str, port: i64) -> DbResult<()> {
    sqlx::query("UPDATE relay_hosts SET name = ?, ip = ?, port = ? WHERE id = ?")
        .bind(name)
        .bind(ip)
        .bind(port)
        .bind(id)
        .execute(executor)
        .await?;
    Ok(())
}

pub async fn delete_relay_host_by_id(executor: impl SqliteExecutor<'_>, id: i64) -> DbResult<()> {
    sqlx::query("DELETE FROM relay_hosts WHERE id = ?")
        .bind(id)
        .execute(executor)
        .await?;
    Ok(())
}

pub async fn fetch_relay_access_principals(executor: impl SqliteExecutor<'_>, relay_host_id: i64) -> DbResult<Vec<RelayAclPrincipal>> {
    let rows = sqlx::query(
        r#"
        SELECT
            a.principal_kind,
            a.principal_id,
            CASE
                WHEN a.principal_kind = 'user' THEN u.username
                WHEN a.principal_kind = 'group' THEN g.name
                ELSE CAST(a.principal_id AS TEXT)
            END as principal_name
        FROM relay_host_acl a
        LEFT JOIN users u ON a.principal_kind = 'user' AND a.principal_id = u.id
        LEFT JOIN groups g ON a.principal_kind = 'group' AND a.principal_id = g.id
        WHERE a.relay_host_id = ?
        ORDER BY a.principal_kind, principal_name
        "#,
    )
    .bind(relay_host_id)
    .fetch_all(executor)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| RelayAclPrincipal {
            kind: r
                .get::<String, _>("principal_kind")
                .parse::<rb_types::access::PrincipalKind>()
                .unwrap(),
            id: r.get::<i64, _>("principal_id"),
            name: r.get::<String, _>("principal_name"),
        })
        .collect())
}

pub async fn grant_relay_access_principal(
    executor: impl SqliteExecutor<'_>,
    relay_host_id: i64,
    principal_kind: &str,
    principal_id: i64,
) -> DbResult<()> {
    // Validate existence (optional since we have IDs, but good for foreign key integrity check if we don't trust caller)
    // Actually, caller should have resolved ID, so it exists.

    sqlx::query("INSERT OR IGNORE INTO relay_host_acl (relay_host_id, principal_kind, principal_id) VALUES (?, ?, ?)")
        .bind(relay_host_id)
        .bind(principal_kind)
        .bind(principal_id)
        .execute(executor)
        .await?;
    Ok(())
}

pub async fn revoke_relay_access_principal(
    executor: impl SqliteExecutor<'_>,
    relay_host_id: i64,
    principal_kind: &rb_types::access::PrincipalKind,
    principal_id: i64,
) -> DbResult<()> {
    sqlx::query("DELETE FROM relay_host_acl WHERE relay_host_id = ? AND principal_kind = ? AND principal_id = ?")
        .bind(relay_host_id)
        .bind(principal_kind.to_string())
        .bind(principal_id)
        .execute(executor)
        .await?;
    Ok(())
}

/// Revoke all relay accesses for a user by user ID (used when deleting a user).
pub async fn revoke_user_relay_accesses(executor: impl SqliteExecutor<'_>, user_id: i64) -> DbResult<()> {
    sqlx::query("DELETE FROM relay_host_acl WHERE principal_kind = 'user' AND principal_id = ?")
        .bind(user_id)
        .execute(executor)
        .await?;
    Ok(())
}

/// Revoke all relay accesses for a group by group ID (used when deleting a group).
pub async fn revoke_group_relay_accesses(executor: impl SqliteExecutor<'_>, group_id: i64) -> DbResult<()> {
    sqlx::query("DELETE FROM relay_host_acl WHERE principal_kind = 'group' AND principal_id = ?")
        .bind(group_id)
        .execute(executor)
        .await?;
    Ok(())
}
