#[cfg(feature = "server")]
use axum::http::HeaderMap;
use dioxus::{
    fullstack::{JsonEncoding, WebSocketOptions, Websocket}, prelude::*
};
#[cfg(feature = "server")]
use rb_types::auth::{ClaimLevel, ClaimType};
use rb_types::ssh::SessionEvent;
#[cfg(feature = "server")]
use server_core::sessions::SessionRegistry;
#[cfg(feature = "server")]
type SharedRegistry = std::sync::Arc<SessionRegistry>;

#[cfg(feature = "server")]
use crate::server::auth::guards::{WebAuthSession, ensure_claim};

pub type SessionEventsSocket = Websocket<String, SessionEvent, JsonEncoding>;

/// Cleanup guard that ensures web session unregistration happens even on abrupt disconnection
#[cfg(feature = "server")]
struct CleanupGuard {
    registry: SharedRegistry,
    user_id: i64,
    client_id: String,
    is_status_monitor: bool,
}

#[cfg(feature = "server")]
impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if !self.is_status_monitor {
            let registry = self.registry.clone();
            let user_id = self.user_id;
            let client_id = self.client_id.clone();

            // Spawn cleanup task to handle async unregistration
            tokio::spawn(async move {
                tracing::debug!(user_id, client_id, "Cleaning up web session registration");
                registry.unregister_web_session(user_id, &client_id).await;
            });
        }
    }
}

#[get(
    "/api/ws/ssh_web_events?client_id&scope",
    auth: WebAuthSession,
    registry: axum::Extension<SharedRegistry>,
    headers: HeaderMap
)]
#[allow(unused_variables)]
pub async fn ssh_web_events(
    client_id: String,
    scope: Option<String>,
    options: WebSocketOptions,
) -> Result<SessionEventsSocket, ServerFnError> {
    #[cfg(feature = "server")]
    {
        use crate::server::auth::ensure_authenticated;

        let user = ensure_authenticated(&auth).map_err(|e| ServerFnError::new(e.to_string()))?;
        let registry_inner = registry.0.clone();
        let user_id = user.id;
        let include_all = scope.as_deref() == Some("all");

        if include_all {
            ensure_claim(&auth, &ClaimType::Server(ClaimLevel::View)).map_err(|e| ServerFnError::new(e.to_string()))?;
        }
        // client_id is passed as argument

        // Extract IP and User Agent
        let ip = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
            .or_else(|| headers.get("x-real-ip").and_then(|v| v.to_str().ok()).map(|s| s.to_string()))
            .unwrap_or_else(|| {
                // Fallback for localhost dev without proxy
                let host = headers.get("host").and_then(|v| v.to_str().ok()).unwrap_or("");
                if host.contains("localhost") || host.contains("127.0.0.1") {
                    "127.0.0.1".to_string()
                } else {
                    "Unknown IP".to_string()
                }
            });

        let user_agent = headers.get("user-agent").and_then(|v| v.to_str().ok()).map(|s| s.to_string());

        Ok(options.on_upgrade(move |mut socket| async move {
            use rb_types::ssh::WebSessionMeta;

            tracing::info!(user = %user.username, client_id = %client_id, "Session events WebSocket connected");

            let is_status_monitor = client_id == "status-monitor";

            // Register connection for presence tracking, but skip the internal
            // status monitor so it doesn't show up as an "active session".
            if !is_status_monitor {
                let now = chrono::Utc::now();
                let meta = WebSessionMeta {
                    id: client_id.clone(),
                    user_id,
                    username: user.username.clone(),
                    ip,
                    user_agent,
                    connected_at: now,
                    last_seen: now,
                };
                registry_inner.register_web_session(user_id, meta).await;
            }

            let mut rx = registry_inner.event_tx.subscribe();

            // Send initial list of sessions
            if include_all {
                let sessions = registry_inner.list_all_sessions().await;
                let mut summaries = Vec::new();
                for session in sessions {
                    summaries.push(session.to_summary().await);
                }
                if let Err(e) = socket.send(SessionEvent::List(summaries)).await {
                    tracing::error!("Failed to send initial session list (admin scope): {}", e);
                }
            } else {
                let sessions = registry_inner.list_sessions_for_user(user_id).await;
                let mut summaries = Vec::new();
                for session in sessions {
                    summaries.push(session.to_summary().await);
                }
                if let Err(e) = socket.send(SessionEvent::List(summaries)).await {
                    tracing::error!("Failed to send initial session list: {}", e);
                    // Don't return, try to stay connected and send presence
                }
            }

            // Send initial presence list(s)
            if include_all {
                // Broadcast presence for every user the admin can view
                let web_sessions = registry_inner.list_all_web_sessions().await;
                let mut by_user: std::collections::HashMap<i64, Vec<WebSessionMeta>> = std::collections::HashMap::new();
                for session in web_sessions {
                    by_user.entry(session.user_id).or_default().push(session);
                }
                for (uid, list) in by_user {
                    let _ = socket.send(SessionEvent::Presence(uid, list)).await;
                }
            } else {
                let sessions = registry_inner.get_web_sessions(user_id).await;
                let _ = socket.send(SessionEvent::Presence(user_id, sessions)).await;
            }

            // Track connection lifecycle for proper cleanup
            let cleanup_guard = CleanupGuard {
                registry: registry_inner.clone(),
                user_id,
                client_id: client_id.clone(),
                is_status_monitor,
            };

            // Heartbeat interval - update last_seen every 30 seconds
            let mut heartbeat_interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
            heartbeat_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    Ok(event) = rx.recv() => {
                        // Filter events by user_id unless we're in admin scope
                        let should_send = if include_all {
                            // Admin sees all Created/Updated/Removed/Presence events
                            match &event {
                                SessionEvent::Created(_, _) | SessionEvent::Updated(_, _) | SessionEvent::Removed { .. } => true,
                                SessionEvent::Presence(_, _) => true, // Admins need to see presence updates for all users
                                SessionEvent::List(_) => false,
                            }
                        } else {
                            match &event {
                                SessionEvent::Created(uid, _) => *uid == user_id,
                                SessionEvent::Updated(uid, _) => *uid == user_id,
                                SessionEvent::Removed { user_id: uid, .. } => *uid == user_id,
                                SessionEvent::List(_) => false, // Should not be broadcasted
                                SessionEvent::Presence(uid, _) => *uid == user_id,
                            }
                        };

                        if should_send
                            && let Err(e) = socket.send(event).await {
                                tracing::warn!(user_id, client_id, "Failed to send event, connection likely closed: {}", e);
                                break;
                            }
                    }
                    result = socket.recv() => {
                        match result {
                            Ok(msg) => {
                                // Log but don't disconnect on unexpected messages (unless it's a close frame which Axum/Dioxus handles)
                                tracing::debug!(user_id, client_id, ?msg, "Received unexpected message from client, ignoring");
                            }
                            Err(e) => {
                                tracing::info!(user_id, client_id, error = ?e, "WebSocket connection closed");
                                break;
                            }
                        }
                    }
                    _ = heartbeat_interval.tick() => {
                        // Update last_seen timestamp to indicate this connection is still alive
                        if !is_status_monitor {
                            registry_inner.heartbeat_web_session(user_id, &client_id).await;
                        }
                    }
                }
            }

            // Cleanup happens via Drop impl of cleanup_guard
            drop(cleanup_guard);
            tracing::info!(user_id, client_id, "Session events WebSocket disconnected and cleaned up");
        }))
    }
    #[cfg(not(feature = "server"))]
    {
        Err(ServerFnError::new("Server only"))
    }
}
