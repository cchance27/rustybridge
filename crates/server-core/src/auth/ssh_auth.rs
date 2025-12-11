use rand::{Rng, distributions::Alphanumeric};
use rb_types::auth::ssh::{SshAuthSession, SshAuthStatus};
use tracing::{info, warn};

use crate::error::{ServerError, ServerResult};

const SESSION_EXPIRY_SECONDS: i64 = 300; // 5 minutes
const SESSION_CODE_LENGTH: usize = 32;

/// Generate a cryptographically secure session code
fn generate_session_code() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(SESSION_CODE_LENGTH)
        .map(char::from)
        .collect::<String>()
        .to_uppercase()
}

/// Create a new SSH authentication session with a unique code
pub async fn create_ssh_auth_session(username: &str) -> ServerResult<SshAuthSession> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    // Check user exists
    let requested_user_id = state_store::fetch_user_id_by_name(&pool, username)
        .await?
        .ok_or_else(|| ServerError::not_found("user", username))?;

    // Generate unique code
    let code = generate_session_code();

    // Calculate expiration
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let expires_at = now + SESSION_EXPIRY_SECONDS;

    // Store in database
    state_store::create_ssh_auth_session(&pool, &code, expires_at, requested_user_id).await?;

    // Get auth URL from server options (default to localhost for dev)
    let base_url = state_store::get_server_option(&pool, "web_base_url")
        .await?
        .unwrap_or_else(|| "http://localhost:8080".to_string());

    let auth_url = format!("{}/api/auth/oidc/login?ssh_code={}", base_url, code);

    info!(
        username,
        code = %code,
        expires_in_secs = SESSION_EXPIRY_SECONDS,
        "SSH auth session created"
    );

    Ok(SshAuthSession {
        code,
        auth_url,
        expires_at,
    })
}

/// A checked SSH auth session including the requested user id for validation
pub struct CheckedSshAuthSession {
    pub status: SshAuthStatus,
    pub requested_user_id: i64,
}

/// Check the status of an SSH authentication session and enforce one-time use
pub async fn check_ssh_auth_session(code: &str) -> ServerResult<Option<CheckedSshAuthSession>> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    let session = state_store::get_ssh_auth_session(&pool, code).await?;

    match session {
        Some((status, user_id, requested_user_id)) => {
            let requested_user_id = match requested_user_id {
                Some(id) => id,
                None => {
                    warn!(
                        code = %code,
                        "SSH auth session missing requested_user_id; rejecting for safety"
                    );
                    return Ok(Some(CheckedSshAuthSession {
                        status: SshAuthStatus::Rejected,
                        requested_user_id: -1,
                    }));
                }
            };
            let auth_status = SshAuthStatus::from_db_string(&status, user_id);
            Ok(Some(CheckedSshAuthSession {
                status: auth_status,
                requested_user_id,
            }))
        }
        None => Ok(None),
    }
}

/// Complete an SSH authentication session by marking it as authenticated
pub async fn complete_ssh_auth_session(code: &str, user_id: i64) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    // Verify session exists and is still pending
    let session = state_store::get_ssh_auth_session(&pool, code)
        .await?
        .ok_or_else(|| ServerError::Other("SSH auth session not found".to_string()))?;

    let (status, _, requested_user_id) = session;
    if status != "pending" {
        return Err(ServerError::Other(format!("SSH auth session is not pending (status: {})", status)));
    }

    // Reject if the authenticated user does not match the requested user
    if let Some(requested) = requested_user_id {
        if requested != user_id {
            warn!(
                code = %code,
                requested_user_id = %requested,
                authenticated_user_id = %user_id,
                "OIDC user does not match requested SSH user; rejecting session"
            );
            state_store::update_ssh_auth_session(&pool, code, "rejected", Some(user_id)).await?;
            return Err(ServerError::Other(
                "Authenticated user does not match requested SSH user".to_string(),
            ));
        }
    } else {
        warn!(
            code = %code,
            authenticated_user_id = %user_id,
            "SSH auth session missing requested_user_id; rejecting"
        );
        state_store::update_ssh_auth_session(&pool, code, "rejected", Some(user_id)).await?;
        return Err(ServerError::Other("SSH auth session is missing requested user binding".to_string()));
    }

    // Mark as authenticated
    state_store::update_ssh_auth_session(&pool, code, "authenticated", Some(user_id)).await?;

    info!(
        code = %code,
        user_id,
        "SSH auth session marked as authenticated"
    );

    Ok(())
}

/// Mark a session as used after successful SSH-side validation
pub async fn mark_ssh_auth_session_used(code: &str, user_id: i64) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    state_store::update_ssh_auth_session(&pool, code, "used", Some(user_id)).await?;
    Ok(())
}

/// Reject a session (e.g., mismatched user) and prevent reuse
pub async fn reject_ssh_auth_session(code: &str, user_id: Option<i64>) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    state_store::update_ssh_auth_session(&pool, code, "rejected", user_id).await?;
    Ok(())
}

/// Mark a session as abandoned (e.g., client disconnected mid-flow) to distinguish from explicit rejection.
pub async fn abandon_ssh_auth_session(code: &str) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    state_store::update_ssh_auth_session(&pool, code, "abandoned", None).await?;
    Ok(())
}

/// Verify if a public key is authorized for a user
pub async fn verify_user_public_key(username: &str, public_key_bytes: &[u8]) -> ServerResult<bool> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    // Get all public keys for the user
    let stored_keys = state_store::get_user_public_keys(&pool, username).await?;

    // Parse the provided key
    let provided_key =
        ssh_key::PublicKey::from_bytes(public_key_bytes).map_err(|e| ServerError::Other(format!("Failed to parse public key: {}", e)))?;

    // Compare with stored keys
    for stored_key_str in stored_keys {
        match ssh_key::PublicKey::from_openssh(&stored_key_str) {
            Ok(stored_key) => {
                // Compare key data (algorithm and key material)
                if provided_key.algorithm() == stored_key.algorithm() && provided_key.key_data() == stored_key.key_data() {
                    info!(
                        username,
                        algorithm = %provided_key.algorithm(),
                        "Public key authentication successful"
                    );
                    return Ok(true);
                }
            }
            Err(e) => {
                warn!(
                    username,
                    error = %e,
                    "Failed to parse stored public key, skipping"
                );
                continue;
            }
        }
    }

    info!(username, "public key authentication failed: no matching key found");
    Ok(false)
}
