use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

#[cfg(feature = "server")]
use crate::server::auth::guards::WebAuthSession;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OidcLinkStatus {
    pub is_linked: bool,
    pub provider: Option<String>,
    pub email: Option<String>,
    pub subject: Option<String>,
}

/// Get the current user's OIDC link status
#[get(
    "/api/auth/oidc/link_status",
    auth: WebAuthSession,
)]
pub async fn get_oidc_link_status() -> Result<OidcLinkStatus, ServerFnError> {
    let user_id = match auth.current_user.as_ref() {
        Some(user) => user.id,
        None => return Err(ServerFnError::new("Not authenticated")),
    };

    let result = server_core::api::get_oidc_link_for_user(user_id)
        .await
        .map_err(|e| ServerFnError::new(format!("Database error: {}", e)))?;

    Ok(match result {
        Some(link) => OidcLinkStatus {
            is_linked: true,
            provider: Some(link.provider_id),
            email: link.email,
            subject: Some(link.subject_id),
        },
        None => OidcLinkStatus {
            is_linked: false,
            provider: None,
            email: None,
            subject: None,
        },
    })
}

/// Unlink OIDC from the current user's account
#[post(
    "/api/auth/oidc/unlink",
    auth: WebAuthSession,
    session: axum_session::Session<server_core::sessions::web::WebSessionManager>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>
)]
pub async fn unlink_oidc() -> Result<(), ServerFnError> {
    let user = match auth.current_user.as_ref() {
        Some(user) => user,
        None => return Err(ServerFnError::new("Not authenticated")),
    };

    let session_id = session.get_session_id().to_string();
    let ip_address = connect_info.0.ip().to_string();

    let ctx = rb_types::audit::AuditContext::web(user.id, user.username.clone(), ip_address, session_id, None);
    let result = server_core::api::delete_oidc_link_for_user(&ctx, user.id)
        .await
        .map_err(|e| ServerFnError::new(format!("Database error: {}", e)))?;

    if result > 0 {
        tracing::info!(user_id = %user.id, "OIDC account unlinked via server function");
        // Clear cached user data (including OIDC profile info)
        auth.cache_clear_user(user.id);
        Ok(())
    } else {
        Err(ServerFnError::new("No OIDC link found"))
    }
}

/// Get OIDC link status for a specific user (admin only)
#[get(
    "/api/users/{user_id}/oidc_status",
    auth: WebAuthSession,
)]
pub async fn get_user_oidc_status(user_id: i64) -> Result<OidcLinkStatus, ServerFnError> {
    use rb_types::auth::{ClaimLevel, ClaimType};

    use crate::server::auth::guards::ensure_claim;

    // Require users:view permission
    ensure_claim(&auth, &ClaimType::Users(ClaimLevel::View)).map_err(|e| ServerFnError::new(e.to_string()))?;

    let result = server_core::api::get_oidc_link_for_user(user_id)
        .await
        .map_err(|e| ServerFnError::new(format!("Database error: {}", e)))?;

    Ok(match result {
        Some(link) => OidcLinkStatus {
            is_linked: true,
            provider: Some(link.provider_id),
            email: link.email,
            subject: Some(link.subject_id),
        },
        None => OidcLinkStatus {
            is_linked: false,
            provider: None,
            email: None,
            subject: None,
        },
    })
}

/// Unlink OIDC from a specific user's account (admin only)
#[delete(
    "/api/users/{user_id}/oidc",
    auth: WebAuthSession,
    session: axum_session::Session<server_core::sessions::web::WebSessionManager>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>
)]
pub async fn unlink_user_oidc(user_id: i64) -> Result<(), ServerFnError> {
    use rb_types::auth::{ClaimLevel, ClaimType};

    use crate::server::auth::guards::ensure_claim;

    // Require users:manage permission
    ensure_claim(&auth, &ClaimType::Users(ClaimLevel::Edit)).map_err(|e| ServerFnError::new(e.to_string()))?;

    let admin_user = auth.current_user.as_ref().unwrap();
    let session_id = session.get_session_id().to_string();
    let ip_address = connect_info.0.ip().to_string();

    let ctx = rb_types::audit::AuditContext::web(admin_user.id, admin_user.username.clone(), ip_address, session_id, None);
    let result = server_core::api::delete_oidc_link_for_user(&ctx, user_id)
        .await
        .map_err(|e| ServerFnError::new(format!("Database error: {}", e)))?;

    if result > 0 {
        tracing::info!(
            admin_user = ?admin_user.id,
            target_user = %user_id,
            "OIDC account unlinked by admin"
        );
        // If we unlinked the current user, clear cache.
        // If unlinked another user, we can't easily clear their cache here without a global signal,
        // but `delete_oidc_link_for_user` updates DB which is authoritative.
        if admin_user.id == user_id {
            auth.cache_clear_user(user_id);
        }
        Ok(())
    } else {
        Err(ServerFnError::new("No OIDC link found"))
    }
}
