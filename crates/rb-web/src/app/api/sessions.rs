use dioxus::prelude::*;
use rb_types::ssh::{AdminSessionSummary, UserSessionSummary};
#[cfg(feature = "server")]
use server_core::sessions::SessionRegistry;
#[cfg(feature = "server")]
type SharedRegistry = std::sync::Arc<SessionRegistry>;

#[cfg(feature = "server")]
use crate::server::auth::guards::{WebAuthSession, ensure_authenticated, ensure_claim};

#[get(
    "/api/sessions/all",
    auth: WebAuthSession,
    registry: axum::Extension<SharedRegistry>
)]
pub async fn list_all_sessions() -> Result<Vec<AdminSessionSummary>, ServerFnError> {
    // Require server:view claim to list all sessions

    use rb_types::auth::{ClaimLevel, ClaimType};
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
    audit: crate::server::audit::WebAuditContext,
    registry: axum::Extension<SharedRegistry>
)]
pub async fn close_session(user_id: i64, relay_id: i64, session_number: u32) -> Result<(), ServerFnError> {
    let user = ensure_authenticated(&auth).map_err(|e| ServerFnError::new(e.to_string()))?;

    // Check if user is closing their own session or has server:edit claim
    if user.id != user_id {
        use rb_types::auth::ATTACH_ANY_CLAIM;

        ensure_claim(&auth, &ATTACH_ANY_CLAIM).map_err(|e| ServerFnError::new(e.to_string()))?;
    }

    if let Some(session) = registry.0.get_session(user_id, relay_id, session_number).await {
        // Log audit event for force close
        let is_self_close = user.id == user_id;

        // Use proper UUID if available, otherwise fallback (though session.recorder should always have it)
        let session_uuid = session.recorder.session_id().to_string();

        let event = rb_types::audit::EventType::SessionForceClosed {
            session_id: session_uuid,
            session_number: session.session_number,
            relay_id: session.relay_id,
            relay_name: session.relay_name.clone(),
            target_username: session.username.clone(),
            reason: if is_self_close {
                "User closed own session"
            } else {
                "Admin force-closed session"
            }
            .to_string(),
        };

        server_core::audit::log_event_from_context_best_effort(&audit.0, event).await;

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
    registry: axum::Extension<SharedRegistry>
)]
pub async fn attach_to_session(session_user_id: i64, relay_id: i64, session_number: u32) -> Result<String, ServerFnError> {
    let user = ensure_authenticated(&auth).map_err(|e| ServerFnError::new(e.to_string()))?;

    // Check permissions using centralized helper
    crate::server::auth::guards::check_session_attach_access(&auth, session_user_id, relay_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

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
