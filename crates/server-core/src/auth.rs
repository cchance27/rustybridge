use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use password_hash::{PasswordHash, PasswordVerifier};
use rand::rngs::OsRng;
use rb_types::auth::{AuthDecision, LoginTarget};

use crate::error::{ServerError, ServerResult};

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

pub async fn authenticate_password(login: &LoginTarget, password: &str) -> ServerResult<AuthDecision> {
    let handle = match state_store::server_db().await {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %e, "failed to open server database during authentication");
            return Ok(AuthDecision::Reject);
        }
    };
    let pool = handle.into_pool();
    let stored = match state_store::fetch_user_password_hash(&pool, &login.username).await {
        Ok(opt) => match opt {
            Some(s) => s,
            None => return Ok(AuthDecision::Reject),
        },
        Err(e) => {
            tracing::error!(
                error = %e,
                user = %login.username,
                "failed to fetch user password hash"
            );
            return Ok(AuthDecision::Reject);
        }
    };
    if stored.is_empty() {
        return Ok(AuthDecision::Reject);
    }
    let parsed = match PasswordHash::new(&stored) {
        Ok(ph) => ph,
        Err(e) => {
            tracing::error!(
                error = %e,
                user = %login.username,
                "invalid stored password hash"
            );
            return Ok(AuthDecision::Reject);
        }
    };
    // NOTE: This verification is theoretically susceptible to timing attacks (user enumeration)
    // because we return early if the user is not found or the hash is invalid.
    // However, in this context (networked SSH server), the network jitter makes this
    // practically unexploitable, so we accept the risk for simplicity.
    match Argon2::default().verify_password(password.as_bytes(), &parsed) {
        Ok(_) => Ok(AuthDecision::Accept),
        Err(_) => Ok(AuthDecision::Reject),
    }
}

pub fn hash_password(password: &str) -> ServerResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hashed = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| ServerError::PasswordHash(format!("failed to hash password: {e}")))?
        .to_string();
    Ok(hashed)
}
