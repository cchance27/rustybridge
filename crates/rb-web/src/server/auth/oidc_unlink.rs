use axum::response::{IntoResponse, Redirect};
use server_core::api as sc_api;
use tracing::{error, info, warn};

use crate::server::auth::WebAuthSession;

/// Unlink OIDC account from the current user
#[cfg(feature = "server")]
pub async fn oidc_unlink(
    auth: WebAuthSession,
    session: axum_session::Session<server_core::sessions::web::WebSessionManager>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> impl IntoResponse {
    // Ensure user is authenticated
    let user = match auth.current_user.as_ref() {
        Some(user) => user,
        None => {
            return Redirect::to("/oidc/error?error=not_authenticated").into_response();
        }
    };
    let user_id = user.id;

    let session_id = session.get_session_id().to_string();
    let ip_address = connect_info.0.ip().to_string();

    let ctx = rb_types::audit::AuditContext::web(user.id, user.username.clone(), ip_address, session_id, None);

    match sc_api::delete_oidc_link_for_user(&ctx, user_id).await {
        Ok(result) => {
            let rows_affected = result;
            if rows_affected > 0 {
                info!(user_id = %user_id, rows = %rows_affected, "oidc account unlinked");
                auth.cache_clear_user(user_id);
                Redirect::to("/?success=oidc_unlinked").into_response()
            } else {
                warn!(user_id = %user_id, "no oidc link found to unlink");
                Redirect::to("/oidc/error?error=no_link_found").into_response()
            }
        }
        Err(e) => {
            error!(user_id = %user_id, error = %e, "failed to unlink oidc account");
            Redirect::to("/oidc/error?error=unlink_failed").into_response()
        }
    }
}
