#[cfg(feature = "server")]
use axum::http::HeaderMap;
use dioxus::{
    fullstack::{JsonEncoding, WebSocketOptions, Websocket}, prelude::*
};
use rb_types::ssh::SessionEvent;
#[cfg(feature = "server")]
use server_core::sessions::SessionRegistry;

#[cfg(feature = "server")]
use crate::server::auth::guards::WebAuthSession;

pub type SessionEventsSocket = Websocket<String, SessionEvent, JsonEncoding>;

#[get(
    "/api/ws/ssh_web_events?client_id",
    auth: WebAuthSession,
    registry: axum::Extension<SessionRegistry>,
    headers: HeaderMap
)]
#[allow(unused_variables)]
pub async fn ssh_web_events(client_id: String, options: WebSocketOptions) -> Result<SessionEventsSocket, ServerFnError> {
    #[cfg(feature = "server")]
    {
        use crate::server::auth::ensure_authenticated;

        let user = ensure_authenticated(&auth).map_err(|e| ServerFnError::new(e.to_string()))?;
        let registry_inner = registry.0.clone();
        let user_id = user.id;
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

            // Register connection
            let meta = WebSessionMeta {
                id: client_id.clone(),
                ip,
                user_agent,
                connected_at: chrono::Utc::now(),
            };
            registry_inner.register_web_session(user_id, meta).await;

            let mut rx = registry_inner.event_tx.subscribe();

            // Send initial list of sessions
            let sessions = registry_inner.list_sessions_for_user(user_id).await;
            let mut summaries = Vec::new();
            for session in sessions {
                summaries.push(session.to_summary().await);
            }
            if let Err(e) = socket.send(SessionEvent::List(summaries)).await {
                tracing::error!("Failed to send initial session list: {}", e);
                // Don't return, try to stay connected and send presence
            }

            // Send initial presence list
            let sessions = registry_inner.get_web_sessions(user_id).await;
            let _ = socket.send(SessionEvent::Presence(user_id, sessions)).await;

            loop {
                tokio::select! {
                    Ok(event) = rx.recv() => {
                        // Filter events by user_id
                        let should_send = match &event {
                            SessionEvent::Created(uid, _) => *uid == user_id,
                            SessionEvent::Updated(uid, _) => *uid == user_id,
                            SessionEvent::Removed { user_id: uid, .. } => *uid == user_id,
                            SessionEvent::List(_) => false, // Should not be broadcasted
                            SessionEvent::Presence(uid, _) => *uid == user_id,
                        };

                        if should_send {
                            let _ = socket.send(event).await;
                        }
                    }
                    _ = socket.recv() => {
                        // Client closed or sent message (we ignore client messages for now)
                        break;
                    }
                }
            }

            // Unregister connection
            registry_inner.unregister_web_session(user_id, &client_id).await;
        }))
    }
    #[cfg(not(feature = "server"))]
    {
        Err(ServerFnError::new("Server only"))
    }
}
