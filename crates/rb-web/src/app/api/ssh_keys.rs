use crate::error::ApiError;
#[cfg(feature = "server")]
use crate::server::{
    audit::WebAuditContext,
    auth::guards::{WebAuthSession, ensure_authenticated},
};
use dioxus::prelude::*;
use rb_types::ssh::SshKey;

#[get(
    "/api/my/ssh_keys",
    auth: WebAuthSession
)]
pub async fn get_my_ssh_keys() -> Result<Vec<SshKey>, ApiError> {
    let user = ensure_authenticated(&auth)?;

    let keys = server_core::list_user_public_keys_by_id(user.id).await?;

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
    audit: WebAuditContext
)]
pub async fn add_my_ssh_key(public_key: String, comment: Option<String>) -> Result<(), ApiError> {
    let user = ensure_authenticated(&auth)?;

    server_core::add_user_public_key_by_id(&audit.0, user.id, &public_key, comment.as_deref()).await?;

    Ok(())
}

#[delete(
    "/api/my/ssh_keys/{key_id}",
    auth: WebAuthSession,
    audit: WebAuditContext
)]
pub async fn delete_my_ssh_key(key_id: i64) -> Result<(), ApiError> {
    let user = ensure_authenticated(&auth)?;

    // Verify ownership
    let keys = server_core::list_user_public_keys_by_id(user.id).await?;

    if !keys.iter().any(|(id, _, _, _)| *id == key_id) {
        return Err(ApiError::Forbidden {
            message: "Key not found or access denied".to_string(),
        });
    }

    server_core::delete_user_public_key_by_id(&audit.0, key_id).await?;

    Ok(())
}
