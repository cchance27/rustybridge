use axum_session_auth::Authentication;
use rb_types::auth::ClaimType;
use sqlx::SqlitePool;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default, Eq, Hash, PartialEq)]
pub struct WebUser {
    pub id: i64,
    pub username: String,
    pub password_hash: Option<String>,
    pub claims: Vec<ClaimType>,
    pub name: Option<String>,
    pub picture: Option<String>,
}

impl std::fmt::Display for WebUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.username)
    }
}

impl WebUser {
    /// Check if user has management access (any :view claim or wildcard)
    pub fn has_management_access(&self) -> bool {
        self.claims.iter().any(|c| {
            let claim_str = c.to_string();
            claim_str == "*" || claim_str.ends_with(":view")
        })
    }
}

#[async_trait::async_trait]
impl Authentication<WebUser, i64, SqlitePool> for WebUser {
    async fn load_user(userid: i64, pool: Option<&SqlitePool>) -> Result<WebUser, anyhow::Error> {
        let pool = pool.ok_or_else(|| anyhow::anyhow!("No database pool provided"))?;

        let user = state_store::fetch_user_auth_record(pool, userid)
            .await?
            .ok_or_else(|| anyhow::anyhow!("User not found"))?;

        let claims = state_store::get_user_claims(pool, &user.username).await.unwrap_or_default();

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

        Ok(WebUser {
            id: user.id,
            username: user.username,
            password_hash: user.password_hash,
            claims,
            name,
            picture,
        })
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
