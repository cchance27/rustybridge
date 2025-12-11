use axum_session_auth::Authentication;
use rb_types::auth::AuthUserInfo;
use server_core::api;
use tracing::debug;

#[derive(Clone)]
pub struct WebUser(pub AuthUserInfo<'static>);

use std::ops::{Deref, DerefMut};

impl Deref for WebUser {
    type Target = AuthUserInfo<'static>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for WebUser {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[async_trait::async_trait]
impl Authentication<WebUser, i64, ()> for WebUser {
    async fn load_user(userid: i64, _pool: Option<&()>) -> Result<WebUser, anyhow::Error> {
        let user = api::fetch_user_auth_record_by_id(userid)
            .await?
            .ok_or_else(|| anyhow::anyhow!("User not found"))?;

        let claims = api::get_user_claims_by_id(userid).await.unwrap_or_default();

        // Fetch OIDC profile info if available (prioritize most recently updated link if multiple)
        let oidc_profile = api::get_latest_oidc_profile(userid).await?;

        let (name, picture) = oidc_profile.map(|profile| (profile.name, profile.picture)).unwrap_or((None, None));

        debug!(
            username = user.username,
            id = user.id,
            name = name,
            avatar = picture.is_some(),
            "Loaded User",
        );

        Ok(WebUser(AuthUserInfo {
            id: user.id,
            username: user.username,
            password_hash: user.password_hash,
            claims,
            name,
            picture,
        }))
    }

    fn is_authenticated(&self) -> bool {
        true
    }

    fn is_active(&self) -> bool {
        true
    }

    fn is_anonymous(&self) -> bool {
        false
    }
}
