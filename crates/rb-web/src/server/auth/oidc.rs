use axum::{
    extract::{Extension, Query}, response::{IntoResponse, Redirect}
};
use openidconnect::{AuthorizationCode, TokenResponse};
use rb_types::auth::oidc::{LoginQuery, OidcConfig};
use serde::Deserialize;
use server_core::auth::oidc::{create_client, generate_auth_url};

use crate::server::auth::WebAuthSession;

#[derive(Deserialize)]
pub struct AuthRequest {
    code: String,
    state: String,
}

#[cfg(feature = "server")]
pub(super) async fn get_oidc_config(pool: &sqlx::SqlitePool) -> Option<OidcConfig> {
    let issuer_url = state_store::get_server_option(pool, "oidc_issuer_url").await.ok()??;
    let client_id = state_store::get_server_option(pool, "oidc_client_id").await.ok()??;
    let client_secret = state_store::get_server_option(pool, "oidc_client_secret").await.ok()??;
    let redirect_url = state_store::get_server_option(pool, "oidc_redirect_url").await.ok()??;

    Some(OidcConfig {
        issuer_url,
        client_id,
        client_secret,
        redirect_url,
    })
}

#[cfg(feature = "server")]
pub async fn oidc_login(Query(query): Query<LoginQuery>, auth: WebAuthSession, pool: Extension<sqlx::SqlitePool>) -> impl IntoResponse {
    let config = match get_oidc_config(&pool).await {
        Some(c) => c,
        None => {
            tracing::error!("OIDC configuration missing");
            return Redirect::to("/oidc/error?error=oidc_not_configured").into_response();
        }
    };

    // Clear any stale OIDC state from prior attempts so we don't mix flows.
    auth.session.remove("oidc_csrf_token");
    auth.session.remove("oidc_nonce");
    auth.session.remove("oidc_pkce_verifier");
    auth.session.remove("oidc_ssh_code");

    match create_client(&config).await {
        Ok(client) => {
            let (auth_url, csrf_token, nonce, pkce_verifier) = generate_auth_url(&client);

            // Store CSRF token, nonce, and PKCE verifier in session for validation
            auth.session.set("oidc_csrf_token", csrf_token.secret().clone());
            auth.session.set("oidc_nonce", nonce.secret().clone());
            auth.session.set("oidc_pkce_verifier", pkce_verifier.secret().clone());

            if let Some(code) = query.ssh_code {
                // Store SSH code associated with this OIDC flow
                auth.session.set("oidc_ssh_code", code.clone());
                tracing::info!("Initiating OIDC for SSH session: {}", code);
            }

            // Hint to the session layer that the data changed so it persists immediately.
            auth.session.update();

            tracing::info!("OIDC login state stored; redirecting to provider");
            Redirect::to(&auth_url).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to create OIDC client: {}", e);
            Redirect::to("/oidc/error?error=oidc_setup_failed").into_response()
        }
    }
}

#[cfg(feature = "server")]
pub async fn oidc_callback(Query(query): Query<AuthRequest>, auth: WebAuthSession, pool: Extension<sqlx::SqlitePool>) -> impl IntoResponse {
    tracing::info!("OIDC callback received");

    // Validate CSRF token (state parameter)
    let stored_csrf: Option<String> = auth.session.get("oidc_csrf_token");

    match stored_csrf {
        Some(stored) if stored == query.state => {
            // Valid CSRF token, continue
            auth.session.remove("oidc_csrf_token");
        }
        Some(_) => {
            tracing::error!("CSRF token mismatch");
            return Redirect::to("/oidc/error?error=csrf_mismatch").into_response();
        }
        None if auth.is_authenticated() => {
            // User already has an authenticated session; this is likely a replayed or stale callback after a restart.
            tracing::warn!("OIDC callback missing CSRF token but user is already authenticated; ignoring callback");
            return Redirect::to("/").into_response();
        }
        None => {
            tracing::error!("No CSRF token in session");
            return Redirect::to("/oidc/error?error=no_csrf_token").into_response();
        }
    }

    // Retrieve nonce from session
    let stored_nonce: Option<String> = auth.session.get("oidc_nonce");
    let nonce = match stored_nonce {
        Some(n) => {
            auth.session.remove("oidc_nonce");
            openidconnect::Nonce::new(n)
        }
        None => {
            tracing::error!("No nonce in session");
            return Redirect::to("/oidc/error?error=no_nonce").into_response();
        }
    };

    // Retrieve PKCE verifier from session
    let stored_pkce: Option<String> = auth.session.get("oidc_pkce_verifier");
    let pkce_verifier = match stored_pkce {
        Some(v) => {
            auth.session.remove("oidc_pkce_verifier");
            tracing::info!("Using PKCE for token exchange");
            Some(openidconnect::PkceCodeVerifier::new(v))
        }
        None => {
            tracing::warn!("No PKCE verifier in session - provider may not require PKCE");
            None
        }
    };

    let config = match get_oidc_config(&pool).await {
        Some(c) => c,
        None => {
            tracing::error!("OIDC configuration missing");
            return Redirect::to("/oidc/error?error=oidc_not_configured").into_response();
        }
    };

    let client = match create_client(&config).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to create OIDC client: {}", e);
            return Redirect::to("/oidc/error?error=oidc_client_failed").into_response();
        }
    };

    // Exchange code for token with PKCE verifier if available
    let pkce_used = pkce_verifier.is_some();
    let mut token_request = client.exchange_code(AuthorizationCode::new(query.code.clone()));
    if let Some(verifier) = pkce_verifier {
        token_request = token_request.set_pkce_verifier(verifier);
    }

    let token_response = match token_request.request_async(openidconnect::reqwest::async_http_client).await {
        Ok(res) => res,
        Err(e) => {
            tracing::error!("Failed to exchange code: {}", e);
            return Redirect::to("/oidc/error?error=token_exchange_failed").into_response();
        }
    };

    // Get ID token and extract claims
    let id_token = match token_response.id_token() {
        Some(t) => t,
        None => {
            tracing::error!("No ID token returned");
            return Redirect::to("/oidc/error?error=no_id_token").into_response();
        }
    };

    // Validate ID token with proper nonce
    let claims = match id_token.claims(&client.id_token_verifier(), &nonce) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to validate ID token: {}", e);
            return Redirect::to("/oidc/error?error=invalid_token").into_response();
        }
    };

    let subject = claims.subject().to_string();
    let email = claims.email().map(|e| e.as_str().to_string());

    // Extract name and picture from additional claims
    let name = claims.name().and_then(|n| n.get(None)).map(|n| n.as_str().to_string());
    let picture = claims.picture().and_then(|p| p.get(None)).map(|p| p.as_str().to_string());

    tracing::info!(
        subject = %subject,
        email = ?email,
        name = ?name,
        pkce_used = pkce_used,
        "OIDC authentication successful"
    );

    // Look up user by OIDC link
    let user_id = match state_store::find_user_id_by_oidc_subject(&pool, &config.issuer_url, &subject).await {
        Ok(Some(id)) => id,
        Ok(None) => {
            tracing::warn!(
                subject = %subject,
                email = ?email,
                "No user found for OIDC subject during login"
            );
            return Redirect::to("/oidc/error?error=account_not_linked").into_response();
        }
        Err(e) => {
            tracing::error!("Database error looking up OIDC link: {}", e);
            return Redirect::to("/oidc/error?error=database_error").into_response();
        }
    };

    // Update OIDC link with latest profile info
    if let Err(e) = state_store::update_oidc_profile_by_subject(&pool, &config.issuer_url, &subject, &email, &name, &picture).await {
        tracing::warn!("Failed to update OIDC link profile: {}", e);
    }

    // Invalidate cached user so updated profile loads
    auth.cache_clear_user(user_id);

    // Log the user in
    auth.login_user(user_id);

    tracing::info!(
        user_id = %user_id,
        pkce_used = pkce_used,
        "User logged in via OIDC"
    );

    if let Some(ssh_code) = auth.session.get::<String>("oidc_ssh_code") {
        match server_core::auth::ssh_auth::complete_ssh_auth_session(&ssh_code, user_id).await {
            Ok(()) => {
                tracing::info!(
                        ssh_code = %ssh_code,
                        user_id = %user_id,
                    "SSH OIDC authentication completed successfully"
                );
                // Redirect to SSH success page
                return Redirect::to("/auth/ssh-success").into_response();
            }
            Err(e) => {
                tracing::error!(
                    ssh_code = %ssh_code,
                    error = %e,
                    "Failed to complete SSH auth session"
                );
                return Redirect::to("/oidc/error?error=ssh_auth_failed").into_response();
            }
        }
    }
    Redirect::to("/").into_response()
}
