use dioxus::prelude::*;
use rb_types::ssh::SshKey;

#[cfg(feature = "server")]
use crate::server::auth::guards::{WebAuthSession, ensure_authenticated};

#[get(
    "/api/my/ssh_keys",
    auth: WebAuthSession
)]
pub async fn get_my_ssh_keys() -> Result<Vec<SshKey>, ServerFnError> {
    let user = ensure_authenticated(&auth).map_err(|e| ServerFnError::new(e.to_string()))?;

    let keys = server_core::list_user_public_keys_by_id(user.id)
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
    auth: WebAuthSession
)]
pub async fn add_my_ssh_key(public_key: String, comment: Option<String>) -> Result<(), ServerFnError> {
    let user = ensure_authenticated(&auth).map_err(|e| ServerFnError::new(e.to_string()))?;

    server_core::add_user_public_key_by_id(
        &rb_types::audit::AuditContext::system("rb-web"),
        user.id,
        &public_key,
        comment.as_deref(),
    )
    .await
    .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(())
}

#[delete(
    "/api/my/ssh_keys/{key_id}",
    auth: WebAuthSession
)]
pub async fn delete_my_ssh_key(key_id: i64) -> Result<(), ServerFnError> {
    let user = ensure_authenticated(&auth).map_err(|e| ServerFnError::new(e.to_string()))?;

    // Verify ownership
    let keys = server_core::list_user_public_keys_by_id(user.id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    if !keys.iter().any(|(id, _, _, _)| *id == key_id) {
        return Err(ServerFnError::new("Key not found or access denied"));
    }

    server_core::delete_user_public_key_by_id(&rb_types::audit::AuditContext::system("rb-web"), key_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(())
}
