use openidconnect::{
    AuthenticationFlow, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, RedirectUrl, Scope, core::{CoreClient, CoreProviderMetadata, CoreResponseType}
};
use rb_types::auth::oidc::OidcConfig;

use crate::error::ServerResult;

pub async fn create_client(config: &OidcConfig) -> ServerResult<CoreClient> {
    let provider_metadata = CoreProviderMetadata::discover_async(
        IssuerUrl::new(config.issuer_url.clone())?,
        openidconnect::reqwest::async_http_client,
    )
    .await
    .map_err(|e| crate::error::ServerError::Oidc(format!("OIDC discovery failed: {}", e)))?;

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(config.client_id.clone()),
        Some(ClientSecret::new(config.client_secret.clone())),
    )
    .set_redirect_uri(RedirectUrl::new(config.redirect_url.clone())?);

    Ok(client)
}

pub fn generate_auth_url(client: &CoreClient) -> (String, CsrfToken, Nonce, openidconnect::PkceCodeVerifier) {
    // Generate PKCE challenge
    let (pkce_challenge, pkce_verifier) = openidconnect::PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token, nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("openid".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    (auth_url.to_string(), csrf_token, nonce, pkce_verifier)
}
