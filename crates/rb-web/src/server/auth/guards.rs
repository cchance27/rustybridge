use anyhow::anyhow;
use axum_session_auth::AuthSession;
use axum_session_sqlx::SessionSqlitePool;
use dioxus::prelude::Result;
use rb_types::auth::ClaimType;

use super::{WebUser, claims};

pub type WebAuthSession = AuthSession<WebUser, i64, SessionSqlitePool, sqlx::SqlitePool>;

pub fn ensure_authenticated(auth: &WebAuthSession) -> Result<WebUser> {
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
