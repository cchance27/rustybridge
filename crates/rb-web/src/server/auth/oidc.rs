use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Query}, http::HeaderMap, response::{IntoResponse, Redirect}
};
use openidconnect::{AuthorizationCode, TokenResponse};
use rb_types::{
    audit::{AuthMethod, EventType}, auth::oidc::{LoginQuery, OidcConfig}
};
use serde::Deserialize;
use server_core::{
    api as sc_api, auth::oidc::{create_client, generate_auth_url}
};
use tracing::{error, info, warn};

use crate::server::auth::WebAuthSession;

#[derive(Deserialize)]
pub struct AuthRequest {
    code: String,
    state: String,
}

#[cfg(feature = "server")]
pub(super) async fn get_oidc_config() -> Option<OidcConfig> {
    sc_api::get_oidc_config().await.ok().flatten()
}

#[cfg(feature = "server")]
pub async fn oidc_login(Query(query): Query<LoginQuery>, auth: WebAuthSession) -> impl IntoResponse {
    let config = match get_oidc_config().await {
        Some(c) => c,
        None => {
            error!("oidc configuration missing");
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
                info!(code = %code, "initiating oidc for ssh session");
            }

            // Hint to the session layer that the data changed so it persists immediately.
            auth.session.update();

            info!("oidc login state stored; redirecting to provider");
            Redirect::to(&auth_url).into_response()
        }
        Err(e) => {
            error!(error = %e, "failed to create oidc client");
            Redirect::to("/oidc/error?error=oidc_setup_failed").into_response()
        }
    }
}

#[cfg(feature = "server")]
pub async fn oidc_callback(
    Query(query): Query<AuthRequest>,
    auth: WebAuthSession,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    info!("oidc callback received");

    let ip_address = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .or_else(|| headers.get("x-real-ip").and_then(|v| v.to_str().ok()).map(|s| s.to_string()))
        .unwrap_or_else(|| addr.ip().to_string());

    let session_id = auth.session.get_session_id().to_string();

    // Validate CSRF token (state parameter)
    let stored_csrf: Option<String> = auth.session.get("oidc_csrf_token");

    match stored_csrf {
        Some(stored) if stored == query.state => {
            // Valid CSRF token, continue
            auth.session.remove("oidc_csrf_token");
        }
        Some(_) => {
            error!("csrf token mismatch");
            server_core::audit::log_oidc_failure(
                Some(ip_address.clone()),
                session_id,
                Some("unknown".to_string()),
                "CSRF token mismatch".to_string(),
            )
            .await;
            return Redirect::to("/oidc/error?error=csrf_mismatch").into_response();
        }
        None if auth.is_authenticated() => {
            // User already has an authenticated session; this is likely a replayed or stale callback after a restart.
            warn!("oidc callback missing csrf token but user is already authenticated; ignoring callback");
            return Redirect::to("/").into_response();
        }
        None => {
            error!("no csrf token in session");
            server_core::audit::log_oidc_failure(
                Some(ip_address.clone()),
                session_id,
                Some("unknown".to_string()),
                "No CSRF token in session".to_string(),
            )
            .await;
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
            error!("no nonce in session");
            server_core::audit::log_oidc_failure(
                Some(ip_address.clone()),
                session_id,
                Some("unknown".to_string()),
                "No nonce in session".to_string(),
            )
            .await;
            return Redirect::to("/oidc/error?error=no_nonce").into_response();
        }
    };

    // Retrieve PKCE verifier from session
    let stored_pkce: Option<String> = auth.session.get("oidc_pkce_verifier");
    let pkce_verifier = match stored_pkce {
        Some(v) => {
            auth.session.remove("oidc_pkce_verifier");
            info!("using pkce for token exchange");
            Some(openidconnect::PkceCodeVerifier::new(v))
        }
        None => {
            warn!("no pkce verifier in session - provider may not require pkce");
            None
        }
    };

    let config = match get_oidc_config().await {
        Some(c) => c,
        None => {
            error!("oidc configuration missing");
            return Redirect::to("/oidc/error?error=oidc_not_configured").into_response();
        }
    };

    let client = match create_client(&config).await {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "failed to create oidc client");
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
            error!(error = %e, "failed to exchange code");
            server_core::audit::log_oidc_failure(
                Some(ip_address.clone()),
                session_id,
                Some("unknown".to_string()),
                format!("Token exchange failed: {}", e),
            )
            .await;
            return Redirect::to("/oidc/error?error=token_exchange_failed").into_response();
        }
    };

    // Get ID token and extract claims
    let id_token = match token_response.id_token() {
        Some(t) => t,
        None => {
            error!("no id token returned");
            server_core::audit::log_oidc_failure(
                Some(ip_address.clone()),
                session_id,
                Some("unknown".to_string()),
                "No ID token returned".to_string(),
            )
            .await;
            return Redirect::to("/oidc/error?error=no_id_token").into_response();
        }
    };

    // Validate ID token with proper nonce
    let claims = match id_token.claims(&client.id_token_verifier(), &nonce) {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "failed to validate id token");
            server_core::audit::log_oidc_failure(
                Some(ip_address.clone()),
                session_id,
                Some("unknown".to_string()),
                format!("ID token validation failed: {}", e),
            )
            .await;
            return Redirect::to("/oidc/error?error=invalid_token").into_response();
        }
    };

    let subject = claims.subject().to_string();
    let email = claims.email().map(|e| e.as_str().to_string());
    let username_log = email.clone().unwrap_or_else(|| subject.clone());

    // Extract name and picture from additional claims
    let name = claims.name().and_then(|n| n.get(None)).map(|n| n.as_str().to_string());
    let picture = claims.picture().and_then(|p| p.get(None)).map(|p| p.as_str().to_string());

    info!(
        subject = %subject,
        email = ?email,
        name = ?name,
        pkce_used = pkce_used,
        "oidc authentication successful"
    );

    // Look up user by OIDC link
    let user_id = match sc_api::find_user_id_by_oidc_subject(&config.issuer_url, &subject).await {
        Ok(Some(id)) => id,
        Ok(None) => {
            warn!(
                subject = %subject,
                email = ?email,
                "No user found for OIDC subject during login"
            );
            server_core::audit::log_oidc_failure(
                Some(ip_address.clone()),
                session_id,
                Some(username_log),
                "No user account linked to this OIDC identity".to_string(),
            )
            .await;
            return Redirect::to("/oidc/error?error=account_not_linked").into_response();
        }
        Err(e) => {
            error!(error = %e, "database error looking up oidc link");
            return Redirect::to("/oidc/error?error=database_error").into_response();
        }
    };

    // Update OIDC link with latest profile info
    if let Err(e) = sc_api::update_oidc_profile_by_subject(&config.issuer_url, &subject, &email, &name, &picture).await {
        warn!(error = %e, "failed to update oidc link profile");
    }

    // Invalidate cached user so updated profile loads
    auth.cache_clear_user(user_id);

    // Log the user in
    auth.login_user(user_id);

    // Log success
    // Only log Web LoginSuccess if NOT an SSH login (SSH side handles its own audit)
    let ssh_code_opt = auth.session.get::<String>("oidc_ssh_code");

    if ssh_code_opt.is_none() {
        server_core::audit::log_event_with_context_best_effort(
            Some(user_id),
            EventType::LoginSuccess {
                method: AuthMethod::Oidc,
                connection_id: session_id.clone(),
                username: username_log,
                client_type: rb_types::audit::ClientType::Web,
            },
            Some(ip_address),
            Some(session_id),
        )
        .await;
    }

    info!(
        user_id = %user_id,
        pkce_used = pkce_used,
        "User logged in via OIDC"
    );

    if let Some(ssh_code) = ssh_code_opt {
        match server_core::auth::ssh_auth::complete_ssh_auth_session(&ssh_code, user_id).await {
            Ok(()) => {
                info!(
                        ssh_code = %ssh_code,
                        user_id = %user_id,
                    "SSH OIDC authentication completed successfully"
                );
                // Redirect to SSH success page
                return Redirect::to("/auth/ssh-success").into_response();
            }
            Err(e) => {
                error!(
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
