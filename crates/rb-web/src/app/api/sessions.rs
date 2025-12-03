use dioxus::prelude::*;
use rb_types::ssh::{AdminSessionSummary, UserSessionSummary};
#[cfg(feature = "server")]
use server_core::sessions::SessionRegistry;
#[cfg(feature = "server")]
type SharedRegistry = std::sync::Arc<SessionRegistry>;

#[cfg(feature = "server")]
use state_store::user_has_relay_access;

#[cfg(feature = "server")]
use crate::server::auth::guards::{WebAuthSession, ensure_authenticated, ensure_claim};

#[get(
    "/api/sessions/all",
    auth: WebAuthSession,
    registry: axum::Extension<SharedRegistry>
)]
pub async fn list_all_sessions() -> Result<Vec<AdminSessionSummary>, ServerFnError> {
    // Require server:view claim to list all sessions

    use state_store::{ClaimLevel, ClaimType};
    ensure_claim(&auth, &ClaimType::Server(ClaimLevel::View)).map_err(|e| ServerFnError::new(e.to_string()))?;

    let sessions = registry.0.list_all_sessions().await;
    let mut summaries = Vec::new();

    // Add SSH sessions
    for session in sessions {
        summaries.push(AdminSessionSummary {
            user_id: session.user_id,
            username: session.username.clone(),
            session: session.to_summary().await,
        });
    }

    // Add Web sessions
    let web_sessions = registry.0.list_all_web_sessions().await;
    for web_session in web_sessions {
        use rb_types::ssh::{SessionKind, SessionStateSummary};

        summaries.push(AdminSessionSummary {
            user_id: web_session.user_id,
            username: web_session.username.clone(),
            session: UserSessionSummary {
                relay_id: 0,
                relay_name: "Web Dashboard".to_string(),
                session_number: 0,
                kind: SessionKind::Web,
                ip_address: Some(web_session.ip),
                user_agent: web_session.user_agent,
                state: SessionStateSummary::Attached,
                active_recent: true,
                active_app: None,
                detached_at: None,
                detached_timeout_secs: None,
                connections: rb_types::ssh::ConnectionAmounts { web: 1, ssh: 0 },
                viewers: rb_types::ssh::ConnectionAmounts { web: 1, ssh: 0 },
                created_at: web_session.connected_at,
                last_active_at: web_session.connected_at,
                admin_viewers: Vec::new(),
            },
        });
    }

    Ok(summaries)
}

#[get(
    "/api/sessions/my",
    auth: WebAuthSession,
    registry: axum::Extension<SharedRegistry>
)]
pub async fn list_my_sessions() -> Result<Vec<UserSessionSummary>, ServerFnError> {
    let user = ensure_authenticated(&auth).map_err(|e| ServerFnError::new(e.to_string()))?;

    let sessions = registry.0.list_sessions_for_user(user.id).await;
    let web_sessions = registry.0.list_web_sessions_for_user(user.id).await;
    let mut summaries = Vec::new();

    // Add SSH sessions
    for session in sessions {
        summaries.push(session.to_summary().await);
    }

    // Add Web sessions as pseudo-sessions
    for web_session in web_sessions {
        use rb_types::ssh::{SessionKind, SessionStateSummary};

        summaries.push(UserSessionSummary {
            relay_id: 0, // No relay for web sessions
            relay_name: "Web Dashboard".to_string(),
            session_number: 0, // No session number for web sessions
            kind: SessionKind::Web,
            ip_address: Some(web_session.ip),
            user_agent: web_session.user_agent,
            state: SessionStateSummary::Attached,
            active_recent: true,
            active_app: None,
            detached_at: None,
            detached_timeout_secs: None,
            connections: rb_types::ssh::ConnectionAmounts { web: 1, ssh: 0 },
            viewers: rb_types::ssh::ConnectionAmounts { web: 1, ssh: 0 },
            created_at: web_session.connected_at,
            last_active_at: web_session.connected_at,
            admin_viewers: Vec::new(),
        });
    }

    Ok(summaries)
}

#[post(
    "/api/sessions/close",
    auth: WebAuthSession,
    registry: axum::Extension<SharedRegistry>
)]
pub async fn close_session(user_id: i64, relay_id: i64, session_number: u32) -> Result<(), ServerFnError> {
    let user = ensure_authenticated(&auth).map_err(|e| ServerFnError::new(e.to_string()))?;

    // Check if user is closing their own session or has server:edit claim
    if user.id != user_id {
        use state_store::{ClaimLevel, ClaimType};

        ensure_claim(&auth, &ClaimType::Server(ClaimLevel::Edit)).map_err(|e| ServerFnError::new(e.to_string()))?;
    }

    if let Some(session) = registry.0.get_session(user_id, relay_id, session_number).await {
        session.close().await;
        registry.0.remove_session(user_id, relay_id, session_number).await;
    } else {
        return Err(ServerFnError::new("Session not found"));
    }

    Ok(())
}

/// Return a WebSocket URL for attaching to an existing SSH session.
/// Validates user ownership and relay access before returning the URL.
#[post(
    "/api/sessions/attach",
    auth: WebAuthSession,
    pool: axum::Extension<sqlx::SqlitePool>,
    registry: axum::Extension<SharedRegistry>
)]
pub async fn attach_to_session(session_user_id: i64, relay_id: i64, session_number: u32) -> Result<String, ServerFnError> {
    let user = ensure_authenticated(&auth).map_err(|e| ServerFnError::new(e.to_string()))?;

    // Check for server:attach_any claim
    use state_store::ClaimType;
    let has_attach_any = crate::server::auth::guards::ensure_claim(&auth, &ClaimType::Custom("server:attach_any".to_string())).is_ok();

    if !has_attach_any {
        // Only allow attaching to your own sessions
        if user.id != session_user_id {
            return Err(ServerFnError::new("Cannot attach to another user's session"));
        }

        // Verify relay access
        let has_access = user_has_relay_access(&*pool, user.id, relay_id)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        if !has_access {
            return Err(ServerFnError::new("Relay access denied"));
        }
    }

    // Ensure the session exists and matches the relay/user
    let session = registry
        .0
        .get_session(session_user_id, relay_id, session_number)
        .await
        .ok_or_else(|| ServerFnError::new("Session not found"))?;

    let mut url = format!(
        "/api/ws/ssh_connection/{}?session_number={}",
        session.relay_name, session.session_number
    );

    // If admin is attaching to another session_user_id, include target_user_id
    if user.id != session_user_id {
        use std::fmt::Write;
        let _ = write!(url, "&target_user_id={}", session_user_id);
    }

    Ok(url)
}
