#[cfg(feature = "server")]
use anyhow::anyhow;
#[cfg(feature = "server")]
use dioxus::prelude::ServerFnError;
use dioxus::{
    fullstack::{JsonEncoding, WebSocketOptions, Websocket}, prelude::*
};
use rb_types::audit::{AuditEvent, RecordedSessionChunk, RecordedSessionSummary};
#[cfg(feature = "server")]
use rb_types::audit::{EventCategory, EventFilter};
#[cfg(feature = "server")]
use rb_types::auth::{ClaimLevel, ClaimType};
use serde::{Deserialize, Serialize};
#[cfg(feature = "server")]
use tracing::{debug, error, info};
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

// ==== Audit Events API ====

/// Query parameters for listing audit events
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub struct ListEventsQuery {
    pub page: Option<i64>,
    pub limit: Option<i64>,
    pub actor_id: Option<i64>,
    pub category: Option<String>,
    pub action_types: Option<Vec<String>>,
    pub session_id: Option<String>,
    pub parent_session_id: Option<String>,
    pub start_time: Option<i64>,
    pub end_time: Option<i64>,
    pub sort_dir: Option<String>,
}

/// Paginated response for audit events
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PagedEvents {
    pub events: Vec<AuditEvent>,
    pub total: i64,
}

/// List audit events with filtering and pagination (admin only)
#[post("/api/audit/events", auth: WebAuthSession)]
pub async fn list_audit_events(query: ListEventsQuery) -> Result<PagedEvents> {
    ensure_audit_claim(&auth, ClaimLevel::View)?;

    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let offset = (page - 1) * limit;

    // Build filter
    let mut filter = EventFilter::new().with_limit(limit).with_offset(offset);

    if let Some(actor_id) = query.actor_id {
        filter = filter.with_actor(actor_id);
    }

    if let Some(ref cat_str) = query.category
        && let Ok(cat) = serde_json::from_value::<EventCategory>(serde_json::Value::String(cat_str.clone()))
    {
        filter = filter.with_category(cat);
    }

    if let Some(ref action_types) = query.action_types {
        filter = filter.with_action_types(action_types.clone());
    }

    if let Some(ref session_id) = query.session_id {
        filter.session_id = Some(session_id.clone());
    }

    if let Some(ref parent_session_id) = query.parent_session_id {
        filter.parent_session_id = Some(parent_session_id.clone());
    }

    if let Some(start) = query.start_time {
        filter.start_time = Some(start);
    }

    if let Some(end) = query.end_time {
        filter.end_time = Some(end);
    }

    // Query events
    let events = server_core::audit::query_events(filter.clone())
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Count total for pagination (without limit/offset)
    let mut count_filter = filter.clone();
    count_filter.limit = None;
    count_filter.offset = None;
    let total = server_core::audit::count_events(count_filter)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(PagedEvents { events, total })
}

/// Get audit events for a specific session (for timeline view)
#[get("/api/audit/sessions/:id/audit-events", auth: WebAuthSession)]
pub async fn get_session_audit_events(id: String) -> Result<Vec<AuditEvent>> {
    let summary = load_session_summary(&id).await?;
    authorize_session_view(&auth, &summary).await?;

    let events = server_core::audit::query_events_by_session(id, Some(500))
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(events)
}

// ==== Group Summary API for Drill-Down View ====

/// Query parameters for getting group summaries with counts
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub struct GroupSummaryQuery {
    pub group_by: String,         // "actor", "session", "category"
    pub category: Option<String>, // Optional category filter
    pub limit: Option<i64>,       // Limit number of groups (top N)
    pub start_time: Option<i64>,
    pub end_time: Option<i64>,
}

/// Group summary with true count from database
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct GroupSummaryWithCount {
    pub key: String,
    pub label: String,
    pub actor_id: Option<i64>,        // For actor grouping
    pub session_id: Option<String>,   // For session grouping
    pub category_key: Option<String>, // For category grouping
    pub count: i64,
    pub latest_timestamp: i64,
}

/// Get event group summaries with true counts
#[post("/api/audit/events/groups", auth: WebAuthSession)]
pub async fn get_event_groups(query: GroupSummaryQuery) -> Result<Vec<GroupSummaryWithCount>> {
    ensure_audit_claim(&auth, ClaimLevel::View)?;

    let mut filter = EventFilter::new();

    if let Some(ref cat_str) = query.category
        && let Ok(cat) = serde_json::from_value::<EventCategory>(serde_json::Value::String(cat_str.clone()))
    {
        filter = filter.with_category(cat);
    }

    if let Some(start) = query.start_time {
        filter.start_time = Some(start);
    }
    if let Some(end) = query.end_time {
        filter.end_time = Some(end);
    }

    let groups = server_core::audit::query_event_groups(&query.group_by, filter, query.limit)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let results: Vec<GroupSummaryWithCount> = groups
        .into_iter()
        .map(|g| {
            let key = g.key.clone().unwrap_or_else(|| "system".to_string());
            let label = match query.group_by.as_str() {
                "actor" => g.actor_id.map(|id| format!("User #{}", id)).unwrap_or_else(|| "System".to_string()),
                "session" => {
                    let s = key.clone();
                    if s.len() > 16 { format!("{}...", &s[..16]) } else { s }
                }
                "category" => key.clone(),
                _ => key.clone(),
            };

            // Set the appropriate filter field based on grouping type
            let (actor_id, session_id, category_key) = match query.group_by.as_str() {
                "actor" => (g.actor_id, None, None),
                "session" => (None, Some(key.clone()), None),
                "category" => (None, None, Some(key.clone())),
                _ => (None, None, None),
            };

            GroupSummaryWithCount {
                key,
                label,
                actor_id,
                session_id,
                category_key,
                count: g.count,
                latest_timestamp: g.latest_timestamp,
            }
        })
        .collect();

    Ok(results)
}

// ==== Streaming Events API for Virtualized Scrolling ====

/// Query parameters for streaming events with cursor-based pagination
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub struct StreamEventsQuery {
    pub limit: Option<i64>,
    pub cursor: Option<i64>,           // Timestamp cursor for pagination
    pub group_by: Option<String>,      // "actor", "session", "category", or None (deprecated for drill-down)
    pub category: Option<String>,      // Category filter
    pub session_id: Option<String>,    // Session filter (specific session)
    pub actor_id: Option<i64>,         // Actor filter (specific actor ID)
    pub actor_is_null: Option<bool>,   // If true, filter to only events WHERE actor_id IS NULL
    pub session_is_null: Option<bool>, // If true, filter to only events WHERE session_id IS NULL
    pub start_time: Option<i64>,
    pub end_time: Option<i64>,
}

/// A single event with group boundary marker
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct GroupedEvent {
    pub group_key: String,
    pub is_group_start: bool,
    pub event: AuditEvent,
}

/// Group summary (for collapsed view)
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct GroupSummary {
    pub key: String,
    pub label: String,
    pub count: i64,
    pub latest_timestamp: i64,
}

/// Response for streaming events
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct StreamEventsResponse {
    pub events: Vec<GroupedEvent>,
    pub groups: Vec<GroupSummary>, // Summaries for all groups in current filter
    pub next_cursor: Option<i64>,
    pub has_more: bool,
}

/// Stream audit events with cursor-based pagination and grouping
#[post("/api/audit/events/stream", auth: WebAuthSession)]
pub async fn stream_audit_events(query: StreamEventsQuery) -> Result<StreamEventsResponse> {
    ensure_audit_claim(&auth, ClaimLevel::View)?;

    let limit = query.limit.unwrap_or(50).clamp(1, 200);

    // Build filter
    let mut filter = EventFilter::new().with_limit(limit);

    if let Some(ref cat_str) = query.category
        && let Ok(cat) = serde_json::from_value::<EventCategory>(serde_json::Value::String(cat_str.clone()))
    {
        filter = filter.with_category(cat);
    }

    if let Some(ref session_id) = query.session_id {
        filter.session_id = Some(session_id.clone());
    } else if query.session_is_null == Some(true) {
        filter.session_is_null = true;
    }

    // Actor filter for drill-down view
    if let Some(actor_id) = query.actor_id {
        filter = filter.with_actor(actor_id);
    } else if query.actor_is_null == Some(true) {
        filter.actor_is_null = true;
    }

    // Cursor-based pagination: get events before cursor timestamp
    if let Some(cursor) = query.cursor {
        filter.end_time = Some(cursor - 1); // Events before cursor
    }

    if let Some(start) = query.start_time {
        filter.start_time = Some(start);
    }

    if let Some(end) = query.end_time
        && filter.end_time.is_none()
    {
        filter.end_time = Some(end);
    }

    debug!(
        "stream_audit_events: category={:?}, group_by={:?}, filter={:?}",
        query.category, query.group_by, filter
    );

    // Query events (ordered by timestamp DESC by default)
    let mut events = server_core::audit::query_events(filter.clone()).await.map_err(|e| {
        error!(error = %e, "stream_audit_events query error");
        ServerFnError::new(e.to_string())
    })?;

    debug!(count = events.len(), "stream_audit_events: got events");

    // When grouping, sort events by group key first, then by timestamp DESC
    // This ensures each group appears contiguously in the list
    if let Some(group_by_key) = query.group_by.as_deref() {
        events.sort_by(|a, b| {
            let key_a = match group_by_key {
                "actor" => a.actor_id.map(|id| format!("{:020}", id)).unwrap_or_else(|| "z_system".to_string()),
                "session" => a.session_id.clone().unwrap_or_else(|| "z_none".to_string()),
                "category" => format!("{:?}", a.category),
                _ => String::new(),
            };
            let key_b = match group_by_key {
                "actor" => b.actor_id.map(|id| format!("{:020}", id)).unwrap_or_else(|| "z_system".to_string()),
                "session" => b.session_id.clone().unwrap_or_else(|| "z_none".to_string()),
                "category" => format!("{:?}", b.category),
                _ => String::new(),
            };
            // Sort by group key first, then by timestamp DESC within group
            match key_a.cmp(&key_b) {
                std::cmp::Ordering::Equal => b.timestamp.cmp(&a.timestamp),
                other => other,
            }
        });
    }

    // Determine next cursor (timestamp of last event) - note: may not be reliable with grouping
    let next_cursor = events.last().map(|e| e.timestamp);
    let has_more = events.len() as i64 >= limit;

    // Build grouped events with boundary markers
    let group_by_key = query.group_by.as_deref();
    let mut grouped_events = Vec::with_capacity(events.len());
    let mut last_group_key: Option<String> = None;

    for event in &events {
        let group_key = match group_by_key {
            Some("actor") => event
                .actor_id
                .map(|id| format!("actor:{}", id))
                .unwrap_or_else(|| "actor:system".to_string()),
            Some("session") => event
                .session_id
                .clone()
                .map(|s| format!("session:{}", s))
                .unwrap_or_else(|| "session:none".to_string()),
            Some("category") => format!("category:{:?}", event.category),
            _ => "all".to_string(),
        };

        let is_group_start = last_group_key.as_ref() != Some(&group_key);
        last_group_key = Some(group_key.clone());

        grouped_events.push(GroupedEvent {
            group_key,
            is_group_start,
            event: event.clone(),
        });
    }

    // Get group summaries (count per group) - for collapsed headers
    // TODO: This could be optimized with a separate GROUP BY query
    let mut group_counts: std::collections::HashMap<String, (i64, i64)> = std::collections::HashMap::new();
    for ge in &grouped_events {
        let entry = group_counts.entry(ge.group_key.clone()).or_insert((0, 0));
        entry.0 += 1;
        if ge.event.timestamp > entry.1 {
            entry.1 = ge.event.timestamp;
        }
    }

    let groups: Vec<GroupSummary> = group_counts
        .into_iter()
        .map(|(key, (count, latest))| {
            let label = if key.starts_with("actor:") {
                key.strip_prefix("actor:").unwrap_or(&key).to_string()
            } else if key.starts_with("session:") {
                let s = key.strip_prefix("session:").unwrap_or(&key);
                if s.len() > 16 { format!("{}...", &s[..16]) } else { s.to_string() }
            } else if key.starts_with("category:") {
                key.strip_prefix("category:").unwrap_or(&key).to_string()
            } else {
                key.clone()
            };
            GroupSummary {
                key,
                label,
                count,
                latest_timestamp: latest,
            }
        })
        .collect();

    Ok(StreamEventsResponse {
        events: grouped_events,
        groups,
        next_cursor,
        has_more,
    })
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

    info!(id, export_type, "export session request");

    let response = match replay_session_internal(id.clone(), auth).await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "export session failed");
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
