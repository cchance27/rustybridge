use dioxus::prelude::*;
use rb_types::ssh::SshKey;

#[cfg(feature = "server")]
use crate::server::auth::guards::{WebAuthSession, ensure_authenticated};

#[get(
    "/api/my/ssh_keys",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn get_my_ssh_keys() -> Result<Vec<SshKey>, ServerFnError> {
    let user = ensure_authenticated(&auth).map_err(|e| ServerFnError::new(e.to_string()))?;

    let keys = state_store::list_user_public_keys(&pool, &user.username)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(keys
        .into_iter()
        .map(|(id, public_key, comment, created_at)| SshKey {
            id,
            public_key,
            comment,
            created_at,
        })
        .collect())
}

#[post(
    "/api/my/ssh_keys",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn add_my_ssh_key(public_key: String, comment: Option<String>) -> Result<(), ServerFnError> {
    let user = ensure_authenticated(&auth).map_err(|e| ServerFnError::new(e.to_string()))?;

    state_store::add_user_public_key(&pool, &user.username, &public_key, comment.as_deref())
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(())
}

#[delete(
    "/api/my/ssh_keys/{key_id}",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn delete_my_ssh_key(key_id: i64) -> Result<(), ServerFnError> {
    let user = ensure_authenticated(&auth).map_err(|e| ServerFnError::new(e.to_string()))?;

    // Verify ownership
    let keys = state_store::list_user_public_keys(&pool, &user.username)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    if !keys.iter().any(|(id, _, _, _)| *id == key_id) {
        return Err(ServerFnError::new("Key not found or access denied"));
    }

    state_store::delete_user_public_key(&pool, key_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(())
}
