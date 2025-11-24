#[cfg(feature = "server")]
use anyhow::anyhow;
use dioxus::prelude::*;
#[cfg(feature = "server")]
use rb_types::auth::{ClaimLevel, ClaimType};
use rb_types::web::{CreateCredentialRequest, CredentialInfo, UpdateCredentialRequest};

#[cfg(feature = "server")]
use crate::server::auth::guards::{WebAuthSession, ensure_claim};

#[cfg(feature = "server")]
fn ensure_credential_claim(auth: &WebAuthSession, level: ClaimLevel) -> Result<()> {
    ensure_claim(auth, &ClaimType::Credentials(level))
}

#[cfg(feature = "server")]
async fn check_credential_has_secret(id: i64) -> Result<bool> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();
    let cred = state_store::get_relay_credential_by_id(&pool, id).await?;
    Ok(cred.map(|c| !c.secret.is_empty()).unwrap_or(false))
}

/// List all credentials with assignment counts
#[get(
    "/api/credentials",
    auth: WebAuthSession
)]
pub async fn list_credentials() -> Result<Vec<CredentialInfo>> {
    ensure_credential_claim(&auth, ClaimLevel::View)?;
    let creds = server_core::list_credentials_with_assignments()
        .await
        .map_err(|e| anyhow!("{}", e))?;

    let result = creds
        .into_iter()
        .map(
            |(id, name, kind, username, username_mode, password_required, assigned_relays)| CredentialInfo {
                id,
                name,
                kind,
                username,
                username_mode,
                password_required,
                has_secret: true,
                assigned_relays,
            },
        )
        .collect();

    Ok(result)
}

/// Create a new credential
#[post(
    "/api/credentials",
    auth: WebAuthSession
)]
pub async fn create_credential(req: CreateCredentialRequest) -> Result<()> {
    use rb_types::validation::CredentialValidationInput;

    ensure_credential_claim(&auth, ClaimLevel::Create)?;

    let errors = CredentialValidationInput {
        kind: &req.kind,
        username_mode: &req.username_mode,
        username: req.username.as_deref().unwrap_or(""),
        password_required: req.password_required,
        password: req.password.as_deref().unwrap_or(""),
        private_key: req.private_key.as_deref().unwrap_or(""),
        public_key: req.public_key.as_deref().unwrap_or(""),
        ..Default::default()
    }
    .validate();

    if !errors.is_empty() {
        return Err(anyhow!("Validation failed: {}", rb_types::validation::format_errors(&errors)).into());
    }

    match req.kind.as_str() {
        "password" => {
            let username = req.username.as_deref();
            // Only require password if username_mode is "fixed" AND password_required is true
            let password = if req.username_mode == "fixed" && req.password_required {
                req.password
                    .as_deref()
                    .ok_or_else(|| anyhow!("Password required for password credential"))?
            } else {
                // For interactive/passthrough modes, password is optional (will be prompted)
                req.password.as_deref().unwrap_or("")
            };
            server_core::create_password_credential(&req.name, username, password, &req.username_mode, req.password_required)
                .await
                .map_err(|e| anyhow!("{}", e))?;
        }
        "ssh_key" => {
            let username = req.username.as_deref();
            let key_data = req
                .private_key
                .as_deref()
                .ok_or_else(|| anyhow!("Private key required for SSH key credential"))?;
            let passphrase = req.passphrase.as_deref();
            server_core::create_ssh_key_credential(&req.name, username, key_data, None, passphrase, &req.username_mode)
                .await
                .map_err(|e| anyhow!("{}", e))?;
        }
        "agent" => {
            let username = req.username.as_deref();
            let pubkey = req
                .public_key
                .as_deref()
                .ok_or_else(|| anyhow!("Public key required for agent credential"))?;
            server_core::create_agent_credential(&req.name, username, pubkey, &req.username_mode)
                .await
                .map_err(|e| anyhow!("{}", e))?;
        }
        _ => return Err(anyhow!("Invalid credential type: {}", req.kind).into()),
    }
    Ok(())
}
/// Update an existing credential
#[put(
    "/api/credentials/{id}",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>
)]
pub async fn update_credential(id: i64, req: UpdateCredentialRequest) -> Result<()> {
    use rb_types::validation::CredentialValidationInput;

    ensure_credential_claim(&auth, ClaimLevel::Edit)?;

    // Fetch existing credential to check if password_required is changing
    let existing = state_store::get_relay_credential_by_id(&pool, id)
        .await?
        .ok_or_else(|| anyhow!("Credential not found"))?;

    let has_secret = check_credential_has_secret(id).await?;

    // If password_required is changing from false to true, don't treat empty password as "existing"
    // This forces the user to enter a password when enabling password_required
    let has_existing_password = if req.kind == "password" {
        has_secret && !(req.password_required && !existing.password_required)
    } else {
        has_secret
    };

    let errors = CredentialValidationInput {
        kind: &req.kind,
        username_mode: &req.username_mode,
        username: req.username.as_deref().unwrap_or(""),
        password_required: req.password_required,
        password: req.password.as_deref().unwrap_or(""),
        private_key: req.private_key.as_deref().unwrap_or(""),
        public_key: req.public_key.as_deref().unwrap_or(""),
        is_editing: true,
        has_existing_password,
        has_existing_private_key: has_secret,
        has_existing_public_key: has_secret,
    }
    .validate();

    if !errors.is_empty() {
        return Err(anyhow!("Validation failed: {}", rb_types::validation::format_errors(&errors)).into());
    }

    match req.kind.as_str() {
        "password" => {
            let username = req.username.as_deref();
            let password = req.password.as_deref();
            server_core::update_password_credential(id, &req.name, username, password, &req.username_mode, req.password_required)
                .await
                .map_err(|e| anyhow!("{}", e))?;
        }
        "ssh_key" => {
            let username = req.username.as_deref();
            let key_data = req.private_key.as_deref();
            let passphrase = req.passphrase.as_deref();
            server_core::update_ssh_key_credential(id, &req.name, username, key_data, None, passphrase, &req.username_mode)
                .await
                .map_err(|e| anyhow!("{}", e))?;
        }
        "agent" => {
            let username = req.username.as_deref();
            let pubkey = req.public_key.as_deref();
            server_core::update_agent_credential(id, &req.name, username, pubkey, &req.username_mode)
                .await
                .map_err(|e| anyhow!("{}", e))?;
        }
        _ => return Err(anyhow!("Invalid credential type: {}", req.kind).into()),
    }
    Ok(())
}

/// Delete a credential by ID
#[delete(
    "/api/credentials/{id}",
    auth: WebAuthSession
)]
pub async fn delete_credential(id: i64) -> Result<()> {
    ensure_credential_claim(&auth, ClaimLevel::Delete)?;
    server_core::delete_credential_by_id(id).await.map_err(|e| anyhow!("{}", e))?;
    Ok(())
}
