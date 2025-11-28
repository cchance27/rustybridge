use axum_session_auth::Authentication;
use rb_types::auth::AuthUserInfo;
use sqlx::SqlitePool;

#[derive(Clone)]
pub struct WebUser(pub AuthUserInfo);

use std::ops::{Deref, DerefMut};

impl Deref for WebUser {
    type Target = AuthUserInfo;
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
impl Authentication<WebUser, i64, SqlitePool> for WebUser {
    async fn load_user(userid: i64, pool: Option<&SqlitePool>) -> Result<WebUser, anyhow::Error> {
        let pool = pool.ok_or_else(|| anyhow::anyhow!("No database pool provided"))?;

        let user = state_store::fetch_user_auth_record(pool, userid)
            .await?
            .ok_or_else(|| anyhow::anyhow!("User not found"))?;

        let mut conn = pool.acquire().await?;
        let claims = state_store::get_user_claims_by_id(&mut conn, userid).await.unwrap_or_default();

        // Fetch OIDC profile info if available (prioritize most recently updated link if multiple)
        let oidc_profile = state_store::get_latest_oidc_profile(pool, userid).await?;

        let (name, picture) = oidc_profile.map(|profile| (profile.name, profile.picture)).unwrap_or((None, None));

        tracing::info!(
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
