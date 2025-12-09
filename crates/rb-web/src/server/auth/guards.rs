use anyhow::anyhow;
use axum_session_auth::AuthSession;
use dioxus::prelude::Result;
use rb_types::auth::{ATTACH_ANY_CLAIM, ClaimType};
use server_core::sessions::web::WebSessionManager;

use super::claims;

pub type WebAuthSession = AuthSession<super::WebUser, i64, WebSessionManager, ()>;

pub fn ensure_authenticated(auth: &WebAuthSession) -> Result<super::WebUser> {
    if auth.is_authenticated() {
        if let Some(user) = auth.current_user.clone() {
            Ok(user)
        } else {
            Err(anyhow!("Unauthorized").into())
        }
    } else {
        Err(anyhow!("Unauthorized").into())
    }
}

pub fn ensure_claim(auth: &WebAuthSession, claim: &ClaimType) -> Result<()> {
    let user = ensure_authenticated(auth)?;
    if claims::has_claim(&user, claim) {
        Ok(())
    } else {
        Err(anyhow!("Forbidden: missing {}", claim).into())
    }
}

pub fn ensure_any_claim(auth: &WebAuthSession, needed: &[ClaimType]) -> Result<()> {
    let user = ensure_authenticated(auth)?;
    if claims::has_any_claim(&user, needed) {
        Ok(())
    } else {
        Err(anyhow!("Forbidden: missing required claims").into())
    }
}

pub fn ensure_all_claims(auth: &WebAuthSession, needed: &[ClaimType]) -> Result<()> {
    let user = ensure_authenticated(auth)?;
    if claims::has_all_claims(&user, needed) {
        Ok(())
    } else {
        Err(anyhow!("Forbidden: missing required claims").into())
    }
}

pub fn ensure_management_access(auth: &WebAuthSession) -> Result<()> {
    let user = ensure_authenticated(auth)?;
    if claims::has_management_access(&user) {
        Ok(())
    } else {
        Err(anyhow!("Forbidden: management access required").into())
    }
}

pub async fn check_session_attach_access(auth: &WebAuthSession, target_user_id: i64, relay_id: i64) -> Result<()> {
    let user = ensure_authenticated(auth)?;
    let has_attach_any = ensure_claim(auth, &ATTACH_ANY_CLAIM).is_ok();

    if has_attach_any {
        return Ok(());
    }

    if user.id != target_user_id {
        return Err(anyhow!("Cannot attach to another user's session").into());
    }

    let has_access = server_core::api::user_has_relay_access(user.id, relay_id)
        .await
        .map_err(|e| anyhow!(e.to_string()))?;

    if !has_access {
        return Err(anyhow!("Relay access denied").into());
    }

    Ok(())
}
