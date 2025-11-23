use axum_session_auth::Authentication;
use rb_types::auth::ClaimType;
use sqlx::{Row, SqlitePool};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default, Eq, Hash, PartialEq)]
pub struct WebUser {
    pub id: i64,
    pub username: String,
    pub password_hash: Option<String>,
    pub claims: Vec<ClaimType>,
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

        let row = sqlx::query("SELECT id, username, password_hash FROM users WHERE id = ?")
            .bind(userid)
            .fetch_optional(pool)
            .await?
            .ok_or_else(|| anyhow::anyhow!("User not found"))?;

        let username: String = row.get("username");
        let claims = state_store::get_user_claims(pool, &username).await.unwrap_or_default();

        Ok(WebUser {
            id: row.get("id"),
            username,
            password_hash: row.get("password_hash"),
            claims,
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
