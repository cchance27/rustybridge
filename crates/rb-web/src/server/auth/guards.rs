use axum_session_auth::AuthSession;
use rb_types::auth::{ATTACH_ANY_CLAIM, ClaimType};
use server_core::sessions::web::WebSessionManager;

use super::claims;
use crate::error::ApiError;

pub type WebAuthSession = AuthSession<super::WebUser, i64, WebSessionManager, ()>;

/// Result type for guard functions using ApiError.
pub type GuardResult<T> = Result<T, ApiError>;

pub fn ensure_authenticated(auth: &WebAuthSession) -> GuardResult<super::WebUser> {
    auth.current_user.clone().ok_or(ApiError::Unauthorized)
}

pub fn ensure_claim(auth: &WebAuthSession, claim: &ClaimType) -> GuardResult<()> {
    let user = ensure_authenticated(auth)?;
    if claims::has_claim(&user, claim) {
        Ok(())
    } else {
        Err(ApiError::forbidden(format!("missing {}", claim)))
    }
}

pub fn ensure_any_claim(auth: &WebAuthSession, needed: &[ClaimType]) -> GuardResult<()> {
    let user = ensure_authenticated(auth)?;
    if claims::has_any_claim(&user, needed) {
        Ok(())
    } else {
        Err(ApiError::forbidden("missing required claims"))
    }
}

pub fn ensure_all_claims(auth: &WebAuthSession, needed: &[ClaimType]) -> GuardResult<()> {
    let user = ensure_authenticated(auth)?;
    if claims::has_all_claims(&user, needed) {
        Ok(())
    } else {
        Err(ApiError::forbidden("missing required claims"))
    }
}

pub fn ensure_management_access(auth: &WebAuthSession) -> GuardResult<()> {
    let user = ensure_authenticated(auth)?;
    if claims::has_management_access(&user) {
        Ok(())
    } else {
        Err(ApiError::forbidden("management access required"))
    }
}

pub async fn check_session_attach_access(auth: &WebAuthSession, target_user_id: i64, relay_id: i64) -> GuardResult<()> {
    let user = ensure_authenticated(auth)?;
    let has_attach_any = ensure_claim(auth, &ATTACH_ANY_CLAIM).is_ok();

    if has_attach_any {
        return Ok(());
    }

    if user.id != target_user_id {
        return Err(ApiError::forbidden("cannot attach to another user's session"));
    }

    let has_access = server_core::api::user_has_relay_access(user.id, relay_id)
        .await
        .map_err(ApiError::internal)?;

    if !has_access {
        return Err(ApiError::forbidden("relay access denied"));
    }

    Ok(())
}
