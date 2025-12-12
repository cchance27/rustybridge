//! Authentication and OIDC operations.

use rb_types::auth::{OidcLinkInfo, OidcProfile};
use sqlx::{Row, SqliteExecutor};

use crate::DbResult;

/// Fetch the latest OIDC link (if any) for a given user.
pub async fn get_latest_oidc_profile(executor: impl SqliteExecutor<'_>, user_id: i64) -> DbResult<Option<OidcProfile>> {
    let profile = sqlx::query("SELECT name, picture FROM user_oidc_links WHERE user_id = ? ORDER BY created_at DESC LIMIT 1")
        .bind(user_id)
        .fetch_optional(executor)
        .await?;

    Ok(profile.map(|row| OidcProfile {
        name: row.get("name"),
        picture: row.get("picture"),
    }))
}

/// Fetch the latest OIDC link (if any) for a given user.
pub async fn get_oidc_link_for_user(executor: impl SqliteExecutor<'_>, user_id: i64) -> DbResult<Option<OidcLinkInfo>> {
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
    .fetch_optional(executor)
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
pub async fn find_user_id_by_oidc_subject(executor: impl SqliteExecutor<'_>, provider_id: &str, subject_id: &str) -> DbResult<Option<i64>> {
    let result = sqlx::query_scalar::<_, i64>("SELECT user_id FROM user_oidc_links WHERE provider_id = ? AND subject_id = ?")
        .bind(provider_id)
        .bind(subject_id)
        .fetch_optional(executor)
        .await?;

    Ok(result)
}

/// Upsert (link) an OIDC account to a user.
#[allow(clippy::too_many_arguments)]
pub async fn upsert_oidc_link(
    executor: impl SqliteExecutor<'_>,
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
    .execute(executor)
    .await?;

    Ok(())
}

/// Update stored OIDC profile fields by provider/subject (no user_id change).
pub async fn update_oidc_profile_by_subject(
    executor: impl SqliteExecutor<'_>,
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
        .execute(executor)
        .await?;

    Ok(())
}

/// Remove OIDC link for the specified user; returns affected rows.
pub async fn delete_oidc_link_for_user(executor: impl SqliteExecutor<'_>, user_id: i64) -> DbResult<u64> {
    let res = sqlx::query("DELETE FROM user_oidc_links WHERE user_id = ?")
        .bind(user_id)
        .execute(executor)
        .await?;
    Ok(res.rows_affected())
}

// -----------------------------
// SSH Authentication Sessions
// -----------------------------

/// Create a new SSH authentication session bound to a specific user
pub async fn create_ssh_auth_session(
    executor: impl SqliteExecutor<'_>,
    code: &str,
    expires_at: i64,
    requested_user_id: i64,
) -> DbResult<()> {
    sqlx::query("INSERT INTO ssh_auth_sessions (id, status, expires_at, requested_user_id) VALUES (?, 'pending', ?, ?)")
        .bind(code)
        .bind(expires_at)
        .bind(requested_user_id)
        .execute(executor)
        .await?;
    Ok(())
}

/// Get SSH authentication session status, authenticated user, and requested user
pub async fn get_ssh_auth_session(executor: impl SqliteExecutor<'_>, code: &str) -> DbResult<Option<(String, Option<i64>, Option<i64>)>> {
    sqlx::query_as::<_, (String, Option<i64>, Option<i64>)>("SELECT status, user_id, requested_user_id FROM ssh_auth_sessions WHERE id = ?")
        .bind(code)
        .fetch_optional(executor)
        .await
        .map_err(Into::into)
}

/// Update SSH authentication session status
pub async fn update_ssh_auth_session(executor: impl SqliteExecutor<'_>, code: &str, status: &str, user_id: Option<i64>) -> DbResult<()> {
    sqlx::query("UPDATE ssh_auth_sessions SET status = ?, user_id = ? WHERE id = ?")
        .bind(status)
        .bind(user_id)
        .bind(code)
        .execute(executor)
        .await?;
    Ok(())
}

/// Cleanup expired and used SSH auth sessions
pub async fn cleanup_expired_ssh_auth_sessions(executor: impl SqliteExecutor<'_>) -> DbResult<u64> {
    let result =
        sqlx::query("DELETE FROM ssh_auth_sessions WHERE expires_at < strftime('%s', 'now') OR status IN ('used', 'expired', 'rejected')")
            .execute(executor)
            .await?;
    Ok(result.rows_affected())
}
