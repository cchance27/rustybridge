use openidconnect::{
    AuthenticationFlow, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl, Nonce, RedirectUrl, Scope, core::{CoreClient, CoreProviderMetadata, CoreResponseType}
};
use rb_types::auth::oidc::OidcConfig;

use crate::error::ServerResult;

pub type OidcClient = CoreClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet, EndpointMaybeSet>;

pub struct OidcClientBundle {
    pub client: OidcClient,
    pub http_client: reqwest::Client,
}

fn build_http_client() -> ServerResult<reqwest::Client> {
    Ok(reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build()?)
}

pub async fn create_client(config: &OidcConfig) -> ServerResult<OidcClientBundle> {
    let http_client = build_http_client()?;
    let provider_metadata = CoreProviderMetadata::discover_async(IssuerUrl::new(config.issuer_url.clone())?, &http_client)
        .await
        .map_err(|e| crate::error::ServerError::Oidc(format!("OIDC discovery failed: {}", e)))?;

    let token_uri = provider_metadata
        .token_endpoint()
        .cloned()
        .ok_or_else(|| crate::error::ServerError::InvalidEndpoint("OIDC provider missing token endpoint".to_string()))?;

    let client: OidcClient = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(config.client_id.clone()),
        Some(ClientSecret::new(config.client_secret.clone())),
    )
    .set_redirect_uri(RedirectUrl::new(config.redirect_url.clone())?)
    .set_token_uri(token_uri);

    Ok(OidcClientBundle { client, http_client })
}

pub fn generate_auth_url(client: &OidcClient) -> (String, CsrfToken, Nonce, openidconnect::PkceCodeVerifier) {
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
        .set_pkce_challenge(pkce_challenge)
        .url();

    (auth_url.to_string(), csrf_token, nonce, pkce_verifier)
}
