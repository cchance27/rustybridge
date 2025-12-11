use axum::{
    extract::Query, response::{IntoResponse, Redirect}
};
use openidconnect::{AuthorizationCode, TokenResponse};
use serde::Deserialize;
use server_core::{
    api as sc_api, auth::oidc::{create_client, generate_auth_url}
};
use tracing::{error, info, warn};
use url::Url;

use crate::server::auth::WebAuthSession;

#[derive(Deserialize)]
pub struct LinkCallbackQuery {
    code: String,
    state: String,
}

#[derive(Deserialize)]
pub struct LinkStartQuery {
    return_to: Option<String>,
}

/// Initiate OIDC linking flow for already-authenticated user
#[cfg(feature = "server")]
pub async fn oidc_link_start(Query(query): Query<LinkStartQuery>, auth: WebAuthSession) -> impl IntoResponse {
    // Ensure user is authenticated
    if !auth.is_authenticated() {
        return Redirect::to("/login?error=not_authenticated").into_response();
    }

    let config = match super::oidc::get_oidc_config().await {
        Some(c) => c,
        None => {
            error!("oidc configuration missing");
            return Redirect::to("/oidc/error?error=oidc_not_configured").into_response();
        }
    };

    // Use a different redirect URL for linking
    let mut link_config = config.clone();
    link_config.redirect_url = format!("{}/link", config.redirect_url);

    match create_client(&link_config).await {
        Ok(client) => {
            let (auth_url, csrf_token, nonce, pkce_verifier) = generate_auth_url(&client);

            // Store CSRF token, nonce, and PKCE verifier in session for validation
            auth.session.set("oidc_link_csrf_token", csrf_token.secret().clone());
            auth.session.set("oidc_link_nonce", nonce.secret().clone());
            auth.session.set("oidc_link_pkce_verifier", pkce_verifier.secret().clone());

            // Store validated return URL from query param, default to "/"
            let return_url = sanitize_return_to(query.return_to.as_deref());
            auth.session.set("oidc_link_return_url", return_url);

            Redirect::to(&auth_url).into_response()
        }
        Err(e) => {
            error!(error = %e, "failed to create oidc client");
            Redirect::to("/oidc/error?error=oidc_setup_failed").into_response()
        }
    }
}

/// Handle OIDC callback for linking flow
#[cfg(feature = "server")]
pub async fn oidc_link_callback(Query(query): Query<LinkCallbackQuery>, auth: WebAuthSession) -> impl IntoResponse {
    // Ensure user is authenticated
    let user_id = match auth.current_user.as_ref() {
        Some(user) => user.id,
        None => {
            return Redirect::to("/login?error=not_authenticated").into_response();
        }
    };

    // Validate CSRF token (state parameter)
    let stored_csrf: Option<String> = auth.session.get("oidc_link_csrf_token");
    match stored_csrf {
        Some(stored) if stored == query.state => {
            auth.session.remove("oidc_link_csrf_token");
        }
        Some(_) => {
            error!("csrf token mismatch in link flow");
            return Redirect::to("/oidc/error?error=csrf_mismatch").into_response();
        }
        None => {
            error!("no csrf token in session for link flow");
            return Redirect::to("/oidc/error?error=no_csrf_token").into_response();
        }
    }

    // Retrieve nonce from session
    let stored_nonce: Option<String> = auth.session.get("oidc_link_nonce");
    let nonce = match stored_nonce {
        Some(n) => {
            auth.session.remove("oidc_link_nonce");
            openidconnect::Nonce::new(n)
        }
        None => {
            error!("no nonce in session for link flow");
            return Redirect::to("/oidc/error?error=no_nonce").into_response();
        }
    };

    // Retrieve PKCE verifier from session
    let stored_pkce: Option<String> = auth.session.get("oidc_link_pkce_verifier");
    let pkce_verifier = match stored_pkce {
        Some(v) => {
            auth.session.remove("oidc_link_pkce_verifier");
            info!("using pkce for link token exchange");
            Some(openidconnect::PkceCodeVerifier::new(v))
        }
        None => {
            warn!("no pkce verifier in session for link flow");
            None
        }
    };

    let config = match super::oidc::get_oidc_config().await {
        Some(c) => c,
        None => {
            error!("oidc configuration missing");
            return Redirect::to("/oidc/error?error=oidc_not_configured").into_response();
        }
    };

    let mut link_config = config.clone();
    link_config.redirect_url = format!("{}/link", config.redirect_url);

    let client = match create_client(&link_config).await {
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
            return Redirect::to("/oidc/error?error=token_exchange_failed").into_response();
        }
    };

    // Get ID token and extract claims
    let id_token = match token_response.id_token() {
        Some(t) => t,
        None => {
            error!("no id token returned");
            return Redirect::to("/oidc/error?error=no_id_token").into_response();
        }
    };

    // Validate ID token with proper nonce
    let claims = match id_token.claims(&client.id_token_verifier(), &nonce) {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "failed to validate id token in link flow");
            return Redirect::to("/oidc/error?error=invalid_token").into_response();
        }
    };

    let subject = claims.subject().to_string();
    let email = claims.email().map(|e| e.as_str().to_string());
    let _name: Option<String> = None;
    let _picture: Option<String> = None;

    // Check if this OIDC account is already linked to another user
    match sc_api::find_user_id_by_oidc_subject(&config.issuer_url, &subject).await {
        Ok(Some(existing_user_id)) if existing_user_id != user_id => {
            warn!(
                user_id = %user_id,
                existing_user_id = %existing_user_id,
                subject = %subject,
                "oidc account already linked to different user"
            );
            return Redirect::to("/oidc/error?error=already_linked").into_response();
        }
        Ok(Some(_)) => {
            // Already linked to this user, just update profile
            info!(user_id = %user_id, subject = %subject, "updating existing oidc link");
        }
        Ok(None) => {
            // Not linked yet, create new link
            info!(user_id = %user_id, subject = %subject, "creating new oidc link");
        }
        Err(e) => {
            error!(error = %e, "database error checking oidc link");
            return Redirect::to("/oidc/error?error=database_error").into_response();
        }
    }

    // Insert or update the link
    if let Err(e) = sc_api::upsert_oidc_link(user_id, &config.issuer_url, &subject, &email, &_name, &_picture).await {
        error!(error = %e, "failed to link oidc account");
        return Redirect::to("/oidc/error?error=link_failed").into_response();
    }

    // Bust auth cache so new profile/name take effect next request
    auth.cache_clear_user(user_id);

    info!(
        user_id = %user_id,
        subject = %subject,
        email = ?email,
        pkce_used = pkce_used,
        "successfully linked oidc account"
    );

    // Get return URL from session, re-validate, default to root
    let return_url: String = auth
        .session
        .get::<String>("oidc_link_return_url")
        .and_then(|v| normalize_return_to(&v))
        .unwrap_or_else(|| "/".to_string());
    auth.session.remove("oidc_link_return_url");

    Redirect::to(&format!("{}?success=oidc_linked", return_url)).into_response()
}

fn sanitize_return_to(raw: Option<&str>) -> String {
    raw.and_then(normalize_return_to).unwrap_or_else(|| "/".to_string())
}

fn normalize_return_to(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Reject absolute URLs (with scheme) to prevent open redirects
    if Url::parse(trimmed).is_ok() {
        return None;
    }

    // Disallow protocol-relative and non-path prefixes
    if trimmed.starts_with("//") || !trimmed.starts_with('/') {
        return None;
    }

    Some(trimmed.to_string())
}
