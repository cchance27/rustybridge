use std::{future::Future, pin::Pin, sync::Arc};

use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};
use rb_types::auth::ClaimType;

use super::claims;
use crate::server::auth::WebAuthSession;

type MiddlewareFuture = Pin<Box<dyn Future<Output = Result<Response, StatusCode>> + Send>>;
type AuthMiddleware = Arc<dyn Fn(WebAuthSession, Request, Next) -> MiddlewareFuture + Send + Sync>;

/// Middleware that requires authentication
/// Returns 401 if user is not logged in
pub async fn require_auth(auth: WebAuthSession, request: Request, next: Next) -> Result<Response, StatusCode> {
    if auth.is_authenticated() {
        Ok(next.run(request).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

/// Middleware that requires a specific claim
/// Returns 403 if user doesn't have the claim
pub fn require_claim(claim: &'static ClaimType) -> AuthMiddleware {
    Arc::new(move |auth: WebAuthSession, request: Request, next: Next| {
        Box::pin(async move {
            if auth.is_authenticated()
                && let Some(user) = auth.current_user
            {
                if claims::has_claim(&user, claim) {
                    return Ok(next.run(request).await);
                }
                return Err(StatusCode::FORBIDDEN);
            }
            Err(StatusCode::UNAUTHORIZED)
        })
    })
}

/// Middleware that requires any of the specified claims
/// Returns 403 if user doesn't have at least one claim
pub fn require_any_claim(required_claims: &'static [ClaimType]) -> AuthMiddleware {
    Arc::new(move |auth: WebAuthSession, request: Request, next: Next| {
        Box::pin(async move {
            if auth.is_authenticated()
                && let Some(user) = auth.current_user
            {
                if claims::has_any_claim(&user, required_claims) {
                    return Ok(next.run(request).await);
                }
                return Err(StatusCode::FORBIDDEN);
            }
            Err(StatusCode::UNAUTHORIZED)
        })
    })
}

/// Middleware that requires management access (any :view claim)
pub async fn require_management_access(auth: WebAuthSession, request: Request, next: Next) -> Result<Response, StatusCode> {
    if auth.is_authenticated()
        && let Some(user) = auth.current_user
    {
        if claims::has_management_access(&user) {
            return Ok(next.run(request).await);
        }
        return Err(StatusCode::FORBIDDEN);
    }
    Err(StatusCode::UNAUTHORIZED)
}
