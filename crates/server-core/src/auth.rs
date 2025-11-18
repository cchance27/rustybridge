use anyhow::{Result, anyhow};
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use password_hash::{PasswordHash, PasswordVerifier};
use rand::rngs::OsRng;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoginTarget {
    pub username: String,
    pub relay: Option<String>,
}

pub fn parse_login_target(input: &str) -> LoginTarget {
    if let Some((user, relay)) = input.split_once(':') {
        LoginTarget {
            username: user.to_string(),
            relay: if relay.is_empty() { None } else { Some(relay.to_string()) },
        }
    } else {
        LoginTarget {
            username: input.to_string(),
            relay: None,
        }
    }
}

pub enum AuthDecision {
    Accept,
    Reject,
}

pub async fn authenticate_password(login: &LoginTarget, password: &str) -> Result<AuthDecision> {
    let handle = state_store::server_db().await.map_err(|e| anyhow!(e)).unwrap();
    state_store::migrate_server(&handle).await.map_err(|e| anyhow!(e)).unwrap();
    let pool = handle.into_pool();
    let Some(stored) = state_store::fetch_user_password_hash(&pool, &login.username).await? else {
        return Ok(AuthDecision::Reject);
    };
    if stored.is_empty() {
        return Ok(AuthDecision::Reject);
    }
    let parsed = PasswordHash::new(&stored).map_err(|e| anyhow!("invalid stored password hash: {e}"))?;
    match Argon2::default().verify_password(password.as_bytes(), &parsed) {
        Ok(_) => Ok(AuthDecision::Accept),
        Err(_) => Ok(AuthDecision::Reject),
    }
}

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hashed = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("failed to hash password: {e}"))?
        .to_string();
    Ok(hashed)
}
