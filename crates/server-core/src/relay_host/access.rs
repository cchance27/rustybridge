use crate::error::ServerResult;
use rb_types::access::{PrincipalKind, RelayAccessPrincipal};
use tracing::info;

/// Grant relay access, tracking the full context of who performed the action.
///
/// # Examples
///
/// ```ignore
/// let ctx = AuditContext::web(user_id, username, ip_address, session_id);
/// grant_relay_access_by_id(&ctx, relay_id, PrincipalKind::User, user_id).await?;
/// ```
pub async fn grant_relay_access_by_id(
    ctx: &rb_types::audit::AuditContext,
    host_id: i64,
    principal_kind: PrincipalKind,
    principal_id: i64,
) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    // Fetch names for audit log
    let relay_info = state_store::fetch_relay_host_by_id(&pool, host_id).await?;
    let principal_name = match principal_kind {
        PrincipalKind::User => state_store::fetch_username_by_id(&pool, principal_id).await?,
        PrincipalKind::Group => state_store::fetch_group_name_by_id(&pool, principal_id).await?,
        PrincipalKind::Other => None, // Unknown principal type
    };

    state_store::grant_relay_access_principal(&pool, host_id, principal_kind.as_str(), principal_id).await?;
    info!(
        relay_host_id = host_id,
        principal_kind = principal_kind.as_str(),
        principal_id,
        context = %ctx,
        "granted access to relay host"
    );

    // Log audit event with full context
    if let (Some(relay), Some(principal_name)) = (relay_info, principal_name) {
        crate::audit!(
            ctx,
            AccessGranted {
                relay_name: relay.name,
                relay_id: host_id,
                principal_kind: principal_kind.as_str().to_string(),
                principal_name,
                principal_id,
            }
        );
    }

    Ok(())
}

/// Revoke relay access, tracking the full context of who performed the action.
///
/// # Examples
///
/// ```ignore
/// let ctx = AuditContext::web(user_id, username, ip_address, session_id);
/// revoke_relay_access_by_id(&ctx, relay_id, PrincipalKind::User, user_id).await?;
/// ```
pub async fn revoke_relay_access_by_id(
    ctx: &rb_types::audit::AuditContext,
    host_id: i64,
    principal_kind: PrincipalKind,
    principal_id: i64,
) -> ServerResult<()> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();

    // Fetch names for audit log
    let relay_info = state_store::fetch_relay_host_by_id(&pool, host_id).await?;
    let principal_name = match principal_kind {
        PrincipalKind::User => state_store::fetch_username_by_id(&pool, principal_id).await?,
        PrincipalKind::Group => state_store::fetch_group_name_by_id(&pool, principal_id).await?,
        PrincipalKind::Other => None, // Unknown principal type
    };

    state_store::revoke_relay_access_principal(&pool, host_id, &principal_kind, principal_id).await?;
    info!(
        relay_host_id = host_id,
        principal_kind = principal_kind.as_str(),
        principal_id,
        context = %ctx,
        "revoked access to relay host"
    );

    // Log audit event with full context
    if let (Some(relay), Some(principal_name)) = (relay_info, principal_name) {
        crate::audit!(
            ctx,
            AccessRevoked {
                relay_name: relay.name,
                relay_id: host_id,
                principal_kind: principal_kind.as_str().to_string(),
                principal_name,
                principal_id,
            }
        );
    }

    Ok(())
}

pub async fn list_access_by_id(host_id: i64) -> ServerResult<Vec<RelayAccessPrincipal>> {
    let db = state_store::server_db().await?;
    let pool = db.into_pool();
    let principals = state_store::fetch_relay_access_principals(&pool, host_id).await?;
    Ok(principals
        .into_iter()
        .map(|p| RelayAccessPrincipal {
            kind: p.kind,
            id: p.id,
            name: p.name,
        })
        .collect())
}
