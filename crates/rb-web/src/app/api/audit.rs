#[cfg(feature = "server")]
use anyhow::anyhow;
#[cfg(feature = "server")]
use dioxus::prelude::ServerFnError;
use dioxus::{
    fullstack::{JsonEncoding, WebSocketOptions, Websocket}, prelude::*
};
use rb_types::audit::{RecordedSessionChunk, RecordedSessionSummary};
#[cfg(feature = "server")]
use rb_types::auth::{ClaimLevel, ClaimType};
use serde::{Deserialize, Serialize};
#[cfg(feature = "server")]
use vt100;

#[cfg(feature = "server")]
use crate::server::auth::guards::{WebAuthSession, ensure_claim};

// Shared DTO aliases so UI code remains unchanged
pub type RecordedSession = RecordedSessionSummary;
pub type SessionChunk = RecordedSessionChunk;
pub type SessionSummary = RecordedSessionSummary;

#[cfg(feature = "server")]
fn ensure_audit_claim(auth: &WebAuthSession, level: ClaimLevel) -> Result<(), ServerFnError> {
    ensure_claim(auth, &ClaimType::Server(level)).map_err(|e| ServerFnError::new(e.to_string()))
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub struct ListSessionsQuery {
    pub page: Option<i64>,
    pub limit: Option<i64>,
    pub sort_by: Option<String>,
    pub sort_dir: Option<String>,
    pub user_id: Option<i64>,
    pub relay_id: Option<i64>,
    pub start_date: Option<i64>,
    pub end_date: Option<i64>,
    pub username_contains: Option<String>,
    pub relay_name_contains: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PagedSessions {
    pub sessions: Vec<RecordedSession>,
    pub total: i64,
}

/// List recorded sessions (admin view - all sessions)
#[post("/api/audit/sessions", auth: WebAuthSession)]
pub async fn list_sessions(query: ListSessionsQuery) -> Result<PagedSessions> {
    ensure_audit_claim(&auth, ClaimLevel::View)?;

    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(50).clamp(1, 100);

    let result = server_core::api::query_sessions(
        server_core::api::SessionQuery {
            page,
            limit,
            user_id: query.user_id,
            relay_id: query.relay_id,
            start: query.start_date,
            end: query.end_date,
            username_contains: query.username_contains,
            relay_name_contains: query.relay_name_contains,
            sort_by: query.sort_by,
            sort_dir: query.sort_dir,
        },
        true,
    )
    .await
    .map_err(|e| ServerFnError::new(e.to_string()))?;

    let sessions = result.records.into_iter().map(|s| s.to_recorded()).collect();

    Ok(PagedSessions {
        sessions,
        total: result.total,
    })
}

/// List recorded sessions for current user only (profile view)
#[get("/api/audit/my-sessions", auth: WebAuthSession)]
pub async fn list_my_sessions() -> Result<Vec<RecordedSession>> {
    let user_id = auth.current_user.as_ref().ok_or_else(|| anyhow!("Not authenticated"))?.id;

    let result = server_core::api::query_sessions(
        server_core::api::SessionQuery {
            page: 1,
            limit: 50,
            user_id: Some(user_id),
            sort_by: Some("start_time".to_string()),
            sort_dir: Some("desc".to_string()),
            ..Default::default()
        },
        true,
    )
    .await
    .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(result.records.into_iter().map(|s| s.to_recorded()).collect())
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct SessionReplayResponse {
    pub session: RecordedSession,
    pub chunks: Vec<SessionChunk>,
}

#[cfg(feature = "server")]
async fn load_session_summary(id: &str) -> Result<RecordedSession> {
    let summary = server_core::api::get_session_summary(id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .ok_or_else(|| ServerFnError::new("Session not found"))?;
    Ok(summary.to_recorded())
}

#[cfg(feature = "server")]
async fn authorize_session_view(auth: &WebAuthSession, summary: &RecordedSession) -> Result<(), ServerFnError> {
    let current_user_id = auth
        .current_user
        .as_ref()
        .ok_or_else(|| ServerFnError::new("Not authenticated"))?
        .id;
    let has_admin_claim = ensure_audit_claim(auth, ClaimLevel::View).is_ok();

    if has_admin_claim || summary.user_id == current_user_id {
        Ok(())
    } else {
        Err(ServerFnError::new("Forbidden: You can only view your own sessions"))
    }
}

#[cfg(feature = "server")]
pub async fn replay_session_internal(id: String, auth: WebAuthSession) -> Result<SessionReplayResponse> {
    let summary = load_session_summary(&id).await?;
    authorize_session_view(&auth, &summary).await?;

    let chunks: Vec<SessionChunk> = server_core::api::fetch_session_chunks(&id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .into_iter()
        .map(RecordedSessionChunk::from)
        .collect();

    Ok(SessionReplayResponse { session: summary, chunks })
}

/// Get session chunks for replay
#[get("/api/audit/sessions/:id/replay", auth: WebAuthSession)]
pub async fn replay_session(id: String) -> Result<SessionReplayResponse> {
    replay_session_internal(id, auth).await
}

/// Lightweight metadata endpoint (no chunk payload) for the session player
#[get("/api/audit/sessions/:id/meta", auth: WebAuthSession)]
pub async fn session_summary(id: String) -> Result<SessionSummary> {
    let summary = load_session_summary(&id).await?;
    authorize_session_view(&auth, &summary).await?;
    Ok(summary)
}

#[cfg(feature = "server")]
fn estimate_total_db_chunks(chunks: &[SessionChunk]) -> usize {
    chunks
        .iter()
        .filter_map(|c| c.db_chunk_index)
        .max()
        .map(|m| m + 1)
        .unwrap_or_else(|| chunks.len())
}

#[cfg(feature = "server")]
fn take_chunk_batch(chunks: &[SessionChunk], cursor: usize, byte_budget: usize) -> (Vec<SessionChunk>, usize, bool) {
    let mut sent = 0usize;
    let mut idx = cursor;
    let mut batch = Vec::new();

    while idx < chunks.len() && sent < byte_budget {
        let ch = chunks[idx].clone();
        sent = sent.saturating_add(ch.data.len());
        batch.push(ch);
        idx += 1;
    }

    let done = idx >= chunks.len();
    (batch, idx, done)
}

#[cfg(feature = "server")]
fn build_snapshot_from_chunks(
    meta: &RecordedSession,
    chunks: &[SessionChunk],
    target_chunk: usize,
) -> Result<rb_types::ssh::TerminalSnapshot> {
    let term_rows = meta
        .metadata
        .get("terminal")
        .and_then(|t| t.get("rows"))
        .and_then(|v| v.as_u64())
        .unwrap_or(24) as usize;
    let term_cols = meta
        .metadata
        .get("terminal")
        .and_then(|t| t.get("cols"))
        .and_then(|v| v.as_u64())
        .unwrap_or(80) as usize;

    let mut vt = vt100::Parser::new(term_rows as u16, term_cols as u16, 0);
    let mut last_ts = 0i64;

    for ch in chunks.iter().take_while(|c| c.db_chunk_index.unwrap_or(0) <= target_chunk) {
        use base64::Engine as _;

        if ch.direction != 0 {
            continue;
        }
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&ch.data)
            .map_err(|e| anyhow!("snapshot decode failed: {e}"))?;
        vt.process(&decoded);
        last_ts = ch.timestamp;
    }

    let screen = vt.screen();
    let state = screen.state_formatted();
    let screen_buffer = String::from_utf8_lossy(&state).to_string();
    let (cursor_row, cursor_col) = screen.cursor_position();

    Ok(rb_types::ssh::TerminalSnapshot {
        screen_buffer,
        cursor_row: cursor_row as usize,
        cursor_col: cursor_col as usize,
        chunk_index: target_chunk,
        timestamp: last_ts,
        terminal_size: (term_rows, term_cols),
    })
}

/// WebSocket streaming endpoint for session playback with server-side seek support
#[get("/api/audit/sessions/:id/ws", auth: WebAuthSession)]
pub async fn session_stream_ws(
    id: String,
    options: WebSocketOptions,
) -> Result<Websocket<SessionStreamClient, SessionStreamServer, JsonEncoding>> {
    let summary = load_session_summary(&id).await?;
    authorize_session_view(&auth, &summary).await?;

    // Preload chunks once; streaming slices them to respect byte budgets.
    let all_chunks: Vec<SessionChunk> = server_core::api::fetch_session_chunks(&id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .into_iter()
        .map(RecordedSessionChunk::from)
        .collect();

    let total_chunks = all_chunks.len();
    let total_db_chunks = estimate_total_db_chunks(&all_chunks);

    Ok(options.on_upgrade(move |mut socket| {
        let id = id.clone();
        let summary = summary.clone();
        let chunks = all_chunks.clone();
        async move {
            let mut cursor = 0usize;

            while let Ok(msg) = socket.recv().await {
                match msg {
                    SessionStreamClient::Hello { start_index, byte_budget } => {
                        cursor = start_index.min(chunks.len());
                        let (batch, next, done) = take_chunk_batch(&chunks, cursor, byte_budget.max(64 * 1024));
                        cursor = next;
                        let _ = socket
                            .send(SessionStreamServer::ChunkBatch {
                                start_index,
                                total_chunks,
                                total_db_chunks,
                                chunks: batch,
                                done,
                            })
                            .await;
                        if done {
                            let _ = socket
                                .send(SessionStreamServer::End {
                                    reason: "completed".into(),
                                })
                                .await;
                        }
                    }
                    SessionStreamClient::RequestMore { cursor: _, byte_budget } => {
                        let start = cursor;
                        let (batch, next, done) = take_chunk_batch(&chunks, cursor, byte_budget.max(64 * 1024));
                        cursor = next;
                        let _ = socket
                            .send(SessionStreamServer::ChunkBatch {
                                start_index: start,
                                total_chunks,
                                total_db_chunks,
                                chunks: batch,
                                done,
                            })
                            .await;
                        if done {
                            let _ = socket
                                .send(SessionStreamServer::End {
                                    reason: "completed".into(),
                                })
                                .await;
                        }
                    }
                    SessionStreamClient::Seek {
                        target_chunk,
                        want_snapshot,
                    } => {
                        if want_snapshot {
                            let snapshot = match server_core::api::fetch_session_snapshot(&id, target_chunk).await {
                                Ok(Some(snap)) => Some(snap),
                                Ok(None) => build_snapshot_from_chunks(&summary, &chunks, target_chunk).ok(),
                                Err(_) => build_snapshot_from_chunks(&summary, &chunks, target_chunk).ok(),
                            };

                            if let Some(snap) = snapshot {
                                let _ = socket.send(SessionStreamServer::Snapshot(snap)).await;
                            } else {
                                let _ = socket
                                    .send(SessionStreamServer::Error {
                                        message: "failed to build snapshot".into(),
                                        chunk_index: Some(target_chunk),
                                    })
                                    .await;
                                continue;
                            };
                        }
                        cursor = target_chunk.min(chunks.len());
                        let (batch, next, done) = take_chunk_batch(&chunks, cursor, 256 * 1024);
                        cursor = next;
                        let _ = socket
                            .send(SessionStreamServer::ChunkBatch {
                                start_index: target_chunk,
                                total_chunks,
                                total_db_chunks,
                                chunks: batch,
                                done,
                            })
                            .await;
                        if done {
                            let _ = socket
                                .send(SessionStreamServer::End {
                                    reason: "completed".into(),
                                })
                                .await;
                        }
                    }
                    SessionStreamClient::Close => {
                        let _ = socket
                            .send(SessionStreamServer::End {
                                reason: "client closed".into(),
                            })
                            .await;
                        break;
                    }
                }
            }
        }
    }))
}

/// Get all input events for a session (for timeline/sidebar)
#[get("/api/audit/sessions/:id/events", auth: WebAuthSession)]
pub async fn get_session_events(id: String) -> Result<Vec<SessionChunk>> {
    let summary = load_session_summary(&id).await?;
    authorize_session_view(&auth, &summary).await?;

    let chunks: Vec<SessionChunk> = server_core::api::fetch_session_chunks(&id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .into_iter()
        .map(RecordedSessionChunk::from)
        .collect();

    Ok(chunks.into_iter().filter(|c| c.direction != 0).collect())
}

/// Export session to asciinema v2 format or plain text
#[cfg(feature = "server")]
pub async fn export_session(
    axum::extract::Path((id, export_type)): axum::extract::Path<(String, String)>,
    auth: WebAuthSession,
) -> impl axum::response::IntoResponse {
    use axum::{
        http::{StatusCode, header}, response::IntoResponse
    };
    use base64::Engine;

    tracing::info!("Export session request: {} format: {}", id, export_type);

    let response = match replay_session_internal(id.clone(), auth).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Export session failed: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("Error exporting session: {}", e)).into_response();
        }
    };

    let session = response.session;
    let chunks = response.chunks;

    match export_type.as_str() {
        "txt" => {
            let mut content = String::new();

            for chunk in chunks {
                if chunk.direction == 0
                    && let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&chunk.data)
                    && let Ok(text) = String::from_utf8(decoded)
                {
                    content.push_str(&strip_ansi(&text));
                }
            }

            let filename = format!(
                "session-{}-{}.txt",
                session.relay_name.as_deref().unwrap_or("unknown"),
                session.session_number
            );

            (
                [
                    (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                    (header::CONTENT_DISPOSITION, &format!("attachment; filename=\"{}\"", filename)),
                ],
                content,
            )
                .into_response()
        }
        _ => {
            let mut lines = Vec::new();

            let header = serde_json::json!({
                "version": 2,
                "width": 80,
                "height": 24,
                "timestamp": session.start_time / 1000,
                "title": format!(
                    "Session #{} ({})",
                    session.session_number,
                    session.relay_name.as_deref().unwrap_or("unknown")
                ),
                "env": {"TERM": "xterm-256color", "SHELL": "/bin/bash"}
            });
            lines.push(serde_json::to_string(&header).unwrap());

            let start_time = session.start_time as f64 / 1000.0;
            for chunk in chunks {
                if chunk.direction == 0
                    && let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&chunk.data)
                    && let Ok(text) = String::from_utf8(decoded)
                {
                    let time = (chunk.timestamp as f64 / 1000.0) - start_time;
                    let line = serde_json::json!([time.max(0.0), "o", text]);
                    lines.push(serde_json::to_string(&line).unwrap());
                }
            }

            let content = lines.join("\n");
            let filename = format!(
                "session-{}-{}.cast",
                session.relay_name.as_deref().unwrap_or("unknown"),
                session.session_number
            );

            (
                [
                    (header::CONTENT_TYPE, "application/x-asciicast"),
                    (header::CONTENT_DISPOSITION, &format!("attachment; filename=\"{}\"", filename)),
                ],
                content,
            )
                .into_response()
        }
    }
}

/// Messages from client to server over the session websocket
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum SessionStreamClient {
    Hello { start_index: usize, byte_budget: usize },
    RequestMore { cursor: usize, byte_budget: usize },
    Seek { target_chunk: usize, want_snapshot: bool },
    Close,
}

/// Messages from server to client over the session websocket
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum SessionStreamServer {
    ChunkBatch {
        start_index: usize,
        total_chunks: usize,
        total_db_chunks: usize,
        chunks: Vec<SessionChunk>,
        done: bool,
    },
    Snapshot(rb_types::ssh::TerminalSnapshot),
    End {
        reason: String,
    },
    Error {
        message: String,
        chunk_index: Option<usize>,
    },
}

/// Helper to strip ANSI escape sequences from text
#[cfg(feature = "server")]
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if let Some(&'[') = chars.peek() {
                chars.next();
                while let Some(&n) = chars.peek() {
                    if ('\u{20}'..='\u{3F}').contains(&n) {
                        chars.next();
                    } else {
                        break;
                    }
                }
                if let Some(&n) = chars.peek()
                    && ('\u{40}'..='\u{7E}').contains(&n)
                {
                    chars.next();
                }
                continue;
            }

            if let Some(&']') = chars.peek() {
                chars.next();
                while let Some(n) = chars.next() {
                    if n == '\x07' {
                        break;
                    }
                    if n == '\x1b'
                        && let Some(&'\\') = chars.peek()
                    {
                        chars.next();
                        break;
                    }
                }
                continue;
            }
        }
        out.push(c);
    }
    out
}
