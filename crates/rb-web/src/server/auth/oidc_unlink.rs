use axum::{
    extract::Extension, response::{IntoResponse, Redirect}
};

use crate::server::auth::WebAuthSession;

/// Unlink OIDC account from the current user
#[cfg(feature = "server")]
pub async fn oidc_unlink(auth: WebAuthSession, pool: Extension<sqlx::SqlitePool>) -> impl IntoResponse {
    // Ensure user is authenticated
    let user_id = match auth.current_user.as_ref() {
        Some(user) => user.id,
        None => {
            return Redirect::to("/oidc/error?error=not_authenticated").into_response();
        }
    };

    match state_store::delete_oidc_link_for_user(&pool, user_id).await {
        Ok(result) => {
            let rows_affected = result;
            if rows_affected > 0 {
                tracing::info!(user_id = %user_id, rows = %rows_affected, "OIDC account unlinked");
                auth.cache_clear_user(user_id);
                Redirect::to("/?success=oidc_unlinked").into_response()
            } else {
                tracing::warn!(user_id = %user_id, "No OIDC link found to unlink");
                Redirect::to("/oidc/error?error=no_link_found").into_response()
            }
        }
        Err(e) => {
            tracing::error!(user_id = %user_id, error = %e, "Failed to unlink OIDC account");
            Redirect::to("/oidc/error?error=unlink_failed").into_response()
        }
    }
}
