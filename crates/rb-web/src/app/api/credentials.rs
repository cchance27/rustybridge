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
        .map(|(id, name, kind, username, assigned_relays)| CredentialInfo {
            id,
            name,
            kind,
            username,
            has_secret: true,
            assigned_relays,
        })
        .collect();

    Ok(result)
}

/// Create a new credential
#[post(
    "/api/credentials",
    auth: WebAuthSession
)]
pub async fn create_credential(req: CreateCredentialRequest) -> Result<()> {
    ensure_credential_claim(&auth, ClaimLevel::Create)?;
    match req.kind.as_str() {
        "password" => {
            let username = req.username.as_deref();
            let password = req
                .password
                .as_deref()
                .ok_or_else(|| anyhow!("Password required for password credential"))?;
            server_core::create_password_credential(&req.name, username, password)
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
            server_core::create_ssh_key_credential(&req.name, username, key_data, None, passphrase)
                .await
                .map_err(|e| anyhow!("{}", e))?;
        }
        "agent" => {
            let username = req.username.as_deref();
            let pubkey = req
                .public_key
                .as_deref()
                .ok_or_else(|| anyhow!("Public key required for agent credential"))?;
            server_core::create_agent_credential(&req.name, username, pubkey)
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
    auth: WebAuthSession
)]
pub async fn update_credential(id: i64, req: UpdateCredentialRequest) -> Result<()> {
    ensure_credential_claim(&auth, ClaimLevel::Edit)?;
    match req.kind.as_str() {
        "password" => {
            let username = req.username.as_deref();
            let password = req.password.as_deref();
            server_core::update_password_credential(id, &req.name, username, password)
                .await
                .map_err(|e| anyhow!("{}", e))?;
        }
        "ssh_key" => {
            let username = req.username.as_deref();
            let key_data = req.private_key.as_deref();
            let passphrase = req.passphrase.as_deref();
            server_core::update_ssh_key_credential(id, &req.name, username, key_data, None, passphrase)
                .await
                .map_err(|e| anyhow!("{}", e))?;
        }
        "agent" => {
            let username = req.username.as_deref();
            let pubkey = req.public_key.as_deref();
            server_core::update_agent_credential(id, &req.name, username, pubkey)
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
