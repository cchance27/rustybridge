#[cfg(feature = "server")]
use anyhow::anyhow;
#[cfg(feature = "server")]
use dioxus::fullstack::TypedWebsocket;
use dioxus::{
    fullstack::{JsonEncoding, WebSocketOptions, Websocket}, prelude::*
};
#[cfg(feature = "server")]
use rb_types::auth::{ClaimLevel, ClaimType};
use serde::{Deserialize, Serialize};
#[cfg(feature = "server")]
use sqlx::Row;
#[cfg(feature = "server")]
use vt100;

#[cfg(feature = "server")]
use crate::server::auth::guards::{WebAuthSession, ensure_claim};

#[cfg(feature = "server")]
fn ensure_audit_claim(auth: &WebAuthSession, level: ClaimLevel) -> Result<()> {
    ensure_claim(auth, &ClaimType::Server(level))
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct RecordedSession {
    pub id: String,
    pub user_id: i64,
    pub relay_id: i64,
    pub session_number: u32,
    pub start_time: i64,
    pub end_time: Option<i64>,
    pub metadata: serde_json::Value,
    pub username: Option<String>,
    pub relay_name: Option<String>,
    pub original_size_bytes: Option<i64>,
    pub compressed_size_bytes: Option<i64>,
    pub encrypted_size_bytes: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct SessionChunk {
    pub timestamp: i64,
    pub direction: u8,
    pub data: String,
    pub connection_id: Option<String>,
    pub user_id: Option<i64>,
    pub username: Option<String>,
    pub connection_type: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub ssh_client: Option<String>,
    pub is_admin_input: bool,
    pub timing_markers: Option<Vec<(usize, i64)>>, // (byte_offset, delay_ms) pairs
    pub db_chunk_index: Option<usize>,             // The original DB chunk index this mini-chunk belongs to
}

/// Terminal snapshot used for seek (server-side prerender)
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct TerminalSnapshot {
    pub screen_buffer: String, // ANSI-encoded screen state
    pub cursor_row: usize,
    pub cursor_col: usize,
    pub chunk_index: usize,
    pub timestamp: i64,
    pub terminal_size: (usize, usize), // (rows, cols)
}

/// Messages from client to server over the session websocket
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum SessionStreamClient {
    /// Initial hello, provide start index and byte budget
    Hello { start_index: usize, byte_budget: usize },
    /// Request more data starting from cursor (next chunk index)
    RequestMore { cursor: usize, byte_budget: usize },
    /// Seek to target chunk; optionally ask for snapshot
    Seek { target_chunk: usize, want_snapshot: bool },
    /// Close gracefully
    Close,
}

/// Messages from server to client over the session websocket
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum SessionStreamServer {
    /// A batch of chunks encoded as base64 strings (CBOR-friendly)
    ChunkBatch {
        start_index: usize,
        total_chunks: usize,
        total_db_chunks: usize, // Total number of original DB chunks (not mini-chunks)
        chunks: Vec<SessionChunk>,
        done: bool,
    },
    /// Server-rendered terminal snapshot at chunk_index
    Snapshot(TerminalSnapshot),
    /// Stream ended (normal)
    End { reason: String },
    /// Error while processing a chunk or request
    Error { message: String, chunk_index: Option<usize> },
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
#[post(
    "/api/audit/sessions",
    auth: WebAuthSession
)]
pub async fn list_sessions(query: ListSessionsQuery) -> Result<PagedSessions> {
    ensure_audit_claim(&auth, ClaimLevel::View)?;

    let audit_db = state_store::audit::audit_db().await.map_err(|e| anyhow!("{}", e))?;
    let pool = &audit_db.pool;

    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(50).max(1).min(100);
    let offset = (page - 1) * limit;

    // Pre-lookup user IDs if filtering by username
    let mut filter_user_ids = None;
    if let Some(username_pattern) = &query.username_contains {
        if let Ok(server_db) = state_store::server_db().await {
            let matches = sqlx::query_scalar::<_, i64>("SELECT id FROM users WHERE username LIKE ?")
                .bind(format!("%{}%", username_pattern))
                .fetch_all(&server_db.pool)
                .await
                .ok();
            filter_user_ids = matches;
        }
    }

    // Extract owned vector for IN clause if needed
    let user_ids_for_filter = filter_user_ids.clone();

    // Pre-filter by relay name if specified (search in metadata JSON)
    let relay_name_filter = query.relay_name_contains.clone();

    // Dynamic builder construction
    let mut builder = sqlx::QueryBuilder::new("SELECT * FROM recorded_sessions WHERE 1=1");
    let mut count_builder = sqlx::QueryBuilder::new("SELECT COUNT(*) FROM recorded_sessions WHERE 1=1");

    if let Some(uid) = query.user_id {
        builder.push(" AND user_id = ");
        builder.push_bind(uid);
        count_builder.push(" AND user_id = ");
        count_builder.push_bind(uid);
    } else if let Some(ref uids) = user_ids_for_filter {
        if uids.is_empty() {
            builder.push(" AND 1=0");
            count_builder.push(" AND 1=0");
        } else {
            builder.push(" AND user_id IN (");
            for (i, uid) in uids.iter().enumerate() {
                if i > 0 {
                    builder.push(", ");
                }
                builder.push_bind(uid);
            }
            builder.push(")");

            count_builder.push(" AND user_id IN (");
            for (i, uid) in uids.iter().enumerate() {
                if i > 0 {
                    count_builder.push(", ");
                }
                count_builder.push_bind(uid);
            }
            count_builder.push(")");
        }
    }

    if let Some(rid) = query.relay_id {
        builder.push(" AND relay_id = ");
        builder.push_bind(rid);
        count_builder.push(" AND relay_id = ");
        count_builder.push_bind(rid);
    } else if let Some(ref relay_pattern) = relay_name_filter {
        // Filter by relay name using JSON metadata search
        builder.push(" AND json_extract(metadata, '$.relay_name') LIKE ");
        builder.push_bind(format!("%{}%", relay_pattern));
        count_builder.push(" AND json_extract(metadata, '$.relay_name') LIKE ");
        count_builder.push_bind(format!("%{}%", relay_pattern));
    }
    if let Some(start) = query.start_date {
        builder.push(" AND start_time >= ");
        builder.push_bind(start);
        count_builder.push(" AND start_time >= ");
        count_builder.push_bind(start);
    }
    if let Some(end) = query.end_date {
        builder.push(" AND start_time <= ");
        builder.push_bind(end);
        count_builder.push(" AND start_time <= ");
        count_builder.push_bind(end);
    }

    // Default sorting
    let sort_col = match query.sort_by.as_deref() {
        Some("start_time") => "start_time",
        Some("user_id") => "user_id",
        Some("relay_id") => "relay_id",
        Some("session_number") => "session_number",
        Some("original_size_bytes") => "original_size_bytes",
        Some("duration") => "end_time - start_time", // Approximate
        _ => "start_time",
    };
    let sort_dir = match query.sort_dir.as_deref() {
        Some("asc") => "ASC",
        _ => "DESC",
    };

    builder.push(format!(" ORDER BY {} {} LIMIT ", sort_col, sort_dir));
    builder.push_bind(limit);
    builder.push(" OFFSET ");
    builder.push_bind(offset);

    let total: i64 = count_builder
        .build_query_scalar()
        .fetch_one(pool)
        .await
        .map_err(|e| anyhow!("{}", e))?;
    let rows: Vec<sqlx::sqlite::SqliteRow> = builder.build().fetch_all(pool).await.map_err(|e| anyhow!("{}", e))?;

    // Collect user IDs to fetch usernames
    let mut user_ids = std::collections::HashSet::new();
    for row in &rows {
        let user_id: i64 = row.get("user_id");
        user_ids.insert(user_id);
    }

    // Fetch usernames from main DB
    let mut username_map = std::collections::HashMap::new();
    if let Ok(server_db) = state_store::server_db().await {
        for uid in user_ids {
            if let Ok(Some(user)) = state_store::fetch_user_auth_record(&server_db.pool, uid).await {
                username_map.insert(uid, user.username);
            }
        }
    }

    let mut sessions = Vec::new();
    for row in rows {
        let metadata: serde_json::Value = serde_json::from_str(row.get("metadata")).unwrap_or(serde_json::json!({}));

        let user_id: i64 = row.get("user_id");
        let username_from_db = username_map.get(&user_id).cloned();
        // Fallback to metadata if DB lookup fails
        let username = username_from_db.or_else(|| metadata["username"].as_str().map(|s| s.to_string()));

        let relay_name = metadata["relay_name"].as_str().map(|s| s.to_string());

        sessions.push(RecordedSession {
            id: row.get("id"),
            user_id,
            relay_id: row.get("relay_id"),
            session_number: row.get("session_number"),
            start_time: row.get("start_time"),
            end_time: row.get("end_time"),
            metadata,
            username,
            relay_name,
            original_size_bytes: row.get("original_size_bytes"),
            compressed_size_bytes: row.get("compressed_size_bytes"),
            encrypted_size_bytes: row.get("encrypted_size_bytes"),
        });
    }

    Ok(PagedSessions { sessions, total })
}

/// List recorded sessions for current user only (profile view)
#[get(
    "/api/audit/my-sessions",
    auth: WebAuthSession
)]
pub async fn list_my_sessions() -> Result<Vec<RecordedSession>> {
    let user_id = auth.current_user.as_ref().ok_or_else(|| anyhow!("Not authenticated"))?.id;

    let audit_db = state_store::audit::audit_db().await.map_err(|e| anyhow!("{}", e))?;
    let pool = &audit_db.pool;

    // Only get sessions for the current user
    let query = sqlx::query("SELECT * FROM recorded_sessions WHERE user_id = ? ORDER BY start_time DESC LIMIT 50").bind(user_id);
    let rows = query.fetch_all(pool).await.map_err(|e| anyhow!("{}", e))?;

    // Fetch username from main DB
    let username = if let Ok(server_db) = state_store::server_db().await {
        if let Ok(Some(user)) = state_store::fetch_user_auth_record(&server_db.pool, user_id).await {
            Some(user.username)
        } else {
            None
        }
    } else {
        None
    };

    let mut sessions = Vec::new();
    for row in rows {
        use sqlx::Row;
        let metadata: serde_json::Value = serde_json::from_str(row.get("metadata")).unwrap_or(serde_json::json!({}));
        let relay_name = metadata["relay_name"].as_str().map(|s| s.to_string());

        sessions.push(RecordedSession {
            id: row.get("id"),
            user_id,
            relay_id: row.get("relay_id"),
            session_number: row.get("session_number"),
            start_time: row.get("start_time"),
            end_time: row.get("end_time"),
            metadata,
            username: username.clone(),
            relay_name,
            original_size_bytes: row.get("original_size_bytes"),
            compressed_size_bytes: row.get("compressed_size_bytes"),
            encrypted_size_bytes: row.get("encrypted_size_bytes"),
        });
    }

    Ok(sessions)
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct SessionReplayResponse {
    pub session: RecordedSession,
    pub chunks: Vec<SessionChunk>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct SessionSummary {
    pub session: RecordedSession,
    pub chunk_count: usize,
    pub first_chunk_ts: Option<i64>,
    pub last_chunk_ts: Option<i64>,
}

#[cfg(feature = "server")]
pub async fn replay_session_internal(id: String, auth: WebAuthSession) -> Result<SessionReplayResponse> {
    let current_user_id = auth.current_user.as_ref().ok_or_else(|| anyhow!("Not authenticated"))?.id;
    let has_admin_claim = ensure_audit_claim(&auth, ClaimLevel::View).is_ok();

    let audit_db = state_store::audit::audit_db().await.map_err(|e| anyhow!("{}", e))?;

    // Verify access & fetch session details
    let session_row = sqlx::query("SELECT * FROM recorded_sessions WHERE id = ?")
        .bind(&id)
        .fetch_optional(&audit_db.pool)
        .await
        .map_err(|e| anyhow!("{}", e))?
        .ok_or_else(|| anyhow!("Session not found"))?;

    use sqlx::Row;
    let session_owner_id: i64 = session_row.get("user_id");

    // Check if user has access (own session or admin)
    if !has_admin_claim && session_owner_id != current_user_id {
        return Err(anyhow!("Forbidden: You can only view your own sessions").into());
    }

    // Fetch chunks with connection metadata
    let rows = sqlx::query(
        r#"
        SELECT 
            sc.timestamp, 
            sc.direction, 
            sc.data,
            sc.connection_id,
            sc.timing_markers,
            c.user_id,
            c.connection_type,
            c.ip_address,
            c.user_agent,
            c.ssh_client
        FROM session_chunks sc
        LEFT JOIN connections c ON sc.connection_id = c.id
        WHERE sc.session_id = ? 
        ORDER BY sc.timestamp ASC, sc.chunk_index ASC
        "#,
    )
    .bind(&id)
    .fetch_all(&audit_db.pool)
    .await
    .map_err(|e| anyhow!("{}", e))?;

    // Collect unique user IDs to fetch usernames
    let mut user_ids = std::collections::HashSet::new();
    // Add the session owner
    user_ids.insert(session_owner_id);

    for row in &rows {
        if let Some(uid) = row.get::<Option<i64>, _>("user_id") {
            user_ids.insert(uid);
        }
    }

    tracing::debug!("Collected user_ids for username lookup: {:?}", user_ids);

    // Fetch usernames from main DB
    let mut username_map = std::collections::HashMap::new();
    if let Ok(server_db) = state_store::server_db().await {
        for uid in user_ids {
            if let Ok(Some(user)) = state_store::fetch_user_auth_record(&server_db.pool, uid).await {
                tracing::debug!("Found username for user_id {}: {}", uid, user.username);
                username_map.insert(uid, user.username);
            } else {
                tracing::warn!("Could not fetch username for user_id {}", uid);
            }
        }
    } else {
        tracing::error!("Failed to connect to server_db for username lookup");
    }

    tracing::debug!("Username map: {:?}", username_map);

    // Construct session object
    let metadata: serde_json::Value = serde_json::from_str(session_row.get("metadata")).unwrap_or(serde_json::json!({}));
    let relay_name = metadata["relay_name"].as_str().map(|s| s.to_string());

    let username = username_map
        .get(&session_owner_id)
        .cloned()
        .or_else(|| metadata["username"].as_str().map(|s| s.to_string()));

    let session = RecordedSession {
        id: session_row.get("id"),
        user_id: session_owner_id,
        relay_id: session_row.get("relay_id"),
        session_number: session_row.get("session_number"),
        start_time: session_row.get("start_time"),
        end_time: session_row.get("end_time"),
        metadata,
        username,
        relay_name,
        original_size_bytes: session_row.get("original_size_bytes"),
        compressed_size_bytes: session_row.get("compressed_size_bytes"),
        encrypted_size_bytes: session_row.get("encrypted_size_bytes"),
    };

    let mut chunks = Vec::new();
    for row in rows {
        let encrypted_data: Vec<u8> = row.get("data");

        // Decrypt
        // Format: salt(16) + nonce(24) + ciphertext
        if encrypted_data.len() < 40 {
            continue; // Invalid chunk
        }
        let (salt, rest) = encrypted_data.split_at(16);
        let (nonce, ciphertext) = rest.split_at(24);

        let (compressed, _) =
            server_core::secrets::decrypt_secret(salt, nonce, ciphertext).map_err(|e| anyhow!("Decryption failed: {}", e))?;

        // Decompress (zstd)
        use secrecy::ExposeSecret;
        let plaintext = zstd::decode_all(compressed.expose_secret().as_slice()).map_err(|e| anyhow!("Decompression failed: {}", e))?;

        let chunk_user_id: Option<i64> = row.get("user_id");
        let direction: i32 = row.get("direction");

        // For output chunks (direction=0), use session owner's username
        // For input chunks (direction=1), use the connection's user
        let username = if direction == 0 {
            username_map.get(&session_owner_id).cloned()
        } else {
            chunk_user_id.and_then(|uid| username_map.get(&uid).cloned())
        };

        let is_admin_input = chunk_user_id.map(|uid| uid != session_owner_id).unwrap_or(false);

        // Parse timing markers from JSON
        let timing_markers: Option<Vec<(usize, i64)>> = row
            .get::<Option<String>, _>("timing_markers")
            .and_then(|json_str| serde_json::from_str(&json_str).ok());

        use base64::Engine;
        chunks.push(SessionChunk {
            timestamp: row.get("timestamp"),
            direction: direction as u8,
            data: base64::engine::general_purpose::STANDARD.encode(plaintext),
            connection_id: row.get("connection_id"),
            user_id: chunk_user_id,
            username,
            connection_type: row.get("connection_type"),
            ip_address: row.get("ip_address"),
            user_agent: row.get("user_agent"),
            ssh_client: row.get("ssh_client"),
            is_admin_input,
            timing_markers,
            db_chunk_index: None, // Not used in legacy replay
        });
    }

    Ok(SessionReplayResponse { session, chunks })
}

/// Get session chunks for replay
#[get(
    "/api/audit/sessions/:id/replay",
    auth: WebAuthSession
)]
pub async fn replay_session(id: String) -> Result<SessionReplayResponse> {
    replay_session_internal(id, auth).await
}

/// Lightweight metadata endpoint (no chunk payload) for the session player
#[get(
    "/api/audit/sessions/:id/meta",
    auth: WebAuthSession
)]
pub async fn session_summary(id: String) -> Result<SessionSummary> {
    let current_user_id = auth.current_user.as_ref().ok_or_else(|| anyhow!("Not authenticated"))?.id;
    let has_admin_claim = ensure_audit_claim(&auth, ClaimLevel::View).is_ok();

    let audit_db = state_store::audit::audit_db().await.map_err(|e| anyhow!("{}", e))?;
    let pool = &audit_db.pool;

    // Fetch session row and enforce access
    let session_row = sqlx::query("SELECT * FROM recorded_sessions WHERE id = ?")
        .bind(&id)
        .fetch_optional(pool)
        .await
        .map_err(|e| anyhow!("{}", e))?
        .ok_or_else(|| anyhow!("Session not found"))?;

    use sqlx::Row;
    let session_owner: i64 = session_row.get("user_id");
    if !has_admin_claim && session_owner != current_user_id {
        return Err(anyhow!("Forbidden: You can only view your own sessions").into());
    }

    // Map to RecordedSession
    let metadata: serde_json::Value = serde_json::from_str(session_row.get("metadata")).unwrap_or(serde_json::json!({}));
    let relay_name = metadata["relay_name"].as_str().map(|s| s.to_string());

    let mut username = metadata["username"].as_str().map(|s| s.to_string());
    if let Ok(server_db) = state_store::server_db().await {
        if let Ok(Some(user)) = state_store::fetch_user_auth_record(&server_db.pool, session_owner).await {
            username = Some(user.username);
        }
    }

    let session = RecordedSession {
        id: session_row.get("id"),
        user_id: session_owner,
        relay_id: session_row.get("relay_id"),
        session_number: session_row.get("session_number"),
        start_time: session_row.get("start_time"),
        end_time: session_row.get("end_time"),
        metadata,
        username,
        relay_name,
        original_size_bytes: session_row.get("original_size_bytes"),
        compressed_size_bytes: session_row.get("compressed_size_bytes"),
        encrypted_size_bytes: session_row.get("encrypted_size_bytes"),
    };

    // Aggregate chunk info without pulling payloads
    let agg = sqlx::query(
        r#"
        SELECT COUNT(*) as cnt,
               MIN(timestamp) as first_ts,
               MAX(timestamp) as last_ts
        FROM session_chunks
        WHERE session_id = ?
        "#,
    )
    .bind(&id)
    .fetch_one(pool)
    .await
    .map_err(|e| anyhow!("{}", e))?;

    let chunk_count: i64 = agg.get("cnt");
    let first_chunk_ts: Option<i64> = agg.get("first_ts");
    let last_chunk_ts: Option<i64> = agg.get("last_ts");

    Ok(SessionSummary {
        session,
        chunk_count: chunk_count.max(0) as usize,
        first_chunk_ts,
        last_chunk_ts,
    })
}

#[cfg(feature = "server")]
/// State for streaming chunks with sub-slicing of very large chunks.
#[cfg(feature = "server")]
struct StreamState {
    db_index: usize,       // current DB chunk_index we are reading
    db_offset: usize,      // byte offset inside the current chunk plaintext
    logical_cursor: usize, // number of slices emitted so far
    logical_total: usize,  // total slices estimated (grows when we discover splits)
}

#[cfg(feature = "server")]
async fn stream_batch(
    pool: &sqlx::SqlitePool,
    session_id: &str,
    session_owner_id: i64,
    state: &mut StreamState,
    byte_budget: usize,
    socket: &mut TypedWebsocket<SessionStreamClient, SessionStreamServer, JsonEncoding>,
) -> Result<()> {
    const MAX_CHUNKS_PER_BATCH: usize = 4;
    const MAX_SLICE_SIZE: usize = 64 * 1024; // 64KB slices

    // Preload usernames once
    let total_db_chunks: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM session_chunks WHERE session_id = ?")
        .bind(session_id)
        .fetch_one(pool)
        .await
        .unwrap_or(0);
    if state.logical_total == 0 {
        state.logical_total = total_db_chunks as usize;
    }

    let mut user_ids = std::collections::HashSet::new();
    user_ids.insert(session_owner_id);
    // Collect from all rows once (cheap vs per-row fetch)
    let rows_users = sqlx::query(
        r#"
        SELECT c.user_id
        FROM session_chunks sc
        LEFT JOIN connections c ON sc.connection_id = c.id
        WHERE sc.session_id = ?
        "#,
    )
    .bind(session_id)
    .fetch_all(pool)
    .await?;
    for row in rows_users {
        if let Some(uid) = row.get::<Option<i64>, _>("user_id") {
            user_ids.insert(uid);
        }
    }
    let mut username_map = std::collections::HashMap::new();
    if let Ok(server_db) = state_store::server_db().await {
        for uid in user_ids {
            if let Ok(Some(user)) = state_store::fetch_user_auth_record(&server_db.pool, uid).await {
                username_map.insert(uid, user.username);
            }
        }
    }

    let batch_start_cursor = state.logical_cursor;
    let mut sent_bytes = 0usize;
    let mut batch = Vec::new();

    while sent_bytes < byte_budget && batch.len() < MAX_CHUNKS_PER_BATCH {
        if state.db_index as i64 >= total_db_chunks {
            break;
        }

        // Fetch the current DB chunk
        let row = sqlx::query(
            r#"
            SELECT 
                sc.chunk_index,
                sc.timestamp, 
                sc.direction, 
                sc.data,
                sc.connection_id,
                sc.timing_markers,
                c.user_id,
                c.connection_type,
                c.ip_address,
                c.user_agent,
                c.ssh_client
            FROM session_chunks sc
            LEFT JOIN connections c ON sc.connection_id = c.id
            WHERE sc.session_id = ? AND sc.chunk_index = ?
            LIMIT 1
            "#,
        )
        .bind(session_id)
        .bind(state.db_index as i64)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| anyhow!("chunk {} not found", state.db_index))?;

        let encrypted_data: Vec<u8> = row.get("data");
        if encrypted_data.len() < 40 {
            tracing::warn!("chunk {} skipped: data too short", state.db_index);
            state.db_index += 1;
            state.db_offset = 0;
            continue;
        }
        let (salt, rest) = encrypted_data.split_at(16);
        let (nonce, ciphertext) = rest.split_at(24);

        let (compressed, _) = match server_core::secrets::decrypt_secret(salt, nonce, ciphertext) {
            Ok(result) => result,
            Err(e) => {
                tracing::warn!("chunk {} decrypt failed: {}", state.db_index, e);
                return Err(anyhow!("decrypt failed at chunk {}", state.db_index).into());
            }
        };

        use secrecy::ExposeSecret;
        let plaintext = match zstd::decode_all(compressed.expose_secret().as_slice()) {
            Ok(data) => data,
            Err(e) => {
                tracing::warn!("chunk {} decompress failed: {}", state.db_index, e);
                return Err(anyhow!("decompress failed at chunk {}", state.db_index).into());
            }
        };

        if state.db_offset >= plaintext.len() {
            state.db_index += 1;
            state.db_offset = 0;
            continue;
        }

        let remaining = &plaintext[state.db_offset..];
        let mut slice_len = remaining.len().min(MAX_SLICE_SIZE).min(byte_budget.saturating_sub(sent_bytes));

        // Ensure we cut on a UTF-8 boundary to avoid invalid text when decoding client-side.
        if slice_len < remaining.len() {
            while slice_len > 0 && (remaining[slice_len - 1] & 0b1100_0000) == 0b1000_0000 {
                slice_len -= 1;
            }
            if slice_len == 0 {
                // fallback: take the original size (let the client lossy-decode)
                slice_len = remaining.len().min(MAX_SLICE_SIZE).min(byte_budget.saturating_sub(sent_bytes));
            }
        }

        let chunk_user_id: Option<i64> = row.get("user_id");
        let username = if row.get::<i32, _>("direction") == 0 {
            username_map.get(&session_owner_id).cloned()
        } else {
            chunk_user_id.and_then(|uid| username_map.get(&uid).cloned())
        };
        let is_admin_input = chunk_user_id.map(|uid| uid != session_owner_id).unwrap_or(false);

        // Only include timing markers on the first slice of a chunk; they won't align after slicing.
        let timing_markers: Option<Vec<(usize, i64)>> = if state.db_offset == 0 {
            row.get::<Option<String>, _>("timing_markers")
                .and_then(|json_str| serde_json::from_str(&json_str).ok())
        } else {
            None
        };

        use base64::Engine;
        let data_b64 = base64::engine::general_purpose::STANDARD.encode(&remaining[..slice_len]);
        let chunk = SessionChunk {
            timestamp: row.get("timestamp"),
            direction: row.get::<i32, _>("direction") as u8,
            data: data_b64,
            connection_id: row.get("connection_id"),
            user_id: chunk_user_id,
            username,
            connection_type: row.get("connection_type"),
            ip_address: row.get("ip_address"),
            user_agent: row.get("user_agent"),
            ssh_client: row.get("ssh_client"),
            is_admin_input,
            timing_markers,
            db_chunk_index: Some(state.db_index), // Track the original DB chunk
        };

        let encoded_len = slice_len.div_ceil(3) * 4;
        sent_bytes += encoded_len;
        batch.push(chunk);

        state.logical_cursor += 1;
        state.db_offset += slice_len;

        if slice_len < remaining.len() {
            // More slices remain in this DB chunk; bump logical_total for future slices
            let remaining_bytes = remaining.len() - slice_len;
            let extra_parts = remaining_bytes.div_ceil(MAX_SLICE_SIZE);
            state.logical_total = state.logical_total.saturating_add(extra_parts);
        } else {
            // Finished this DB chunk
            state.db_index += 1;
            state.db_offset = 0;
        }
    }

    let done = state.db_index as i64 >= total_db_chunks && state.db_offset == 0;

    socket
        .send(SessionStreamServer::ChunkBatch {
            start_index: batch_start_cursor,
            total_chunks: state.logical_total,
            total_db_chunks: total_db_chunks as usize,
            chunks: batch,
            done,
        })
        .await?;

    if done {
        let _ = socket
            .send(SessionStreamServer::End {
                reason: "completed".into(),
            })
            .await;
    }

    Ok(())
}

#[cfg(feature = "server")]
async fn build_snapshot(pool: &sqlx::SqlitePool, session_id: &str, chunk_index: usize) -> Result<TerminalSnapshot> {
    use sqlx::Row;

    // Look up terminal size from recorded_sessions metadata, falling back to 24x80.
    let (term_rows, term_cols) = {
        let row_opt = sqlx::query("SELECT metadata FROM recorded_sessions WHERE id = ?")
            .bind(session_id)
            .fetch_optional(pool)
            .await?;

        if let Some(row) = row_opt {
            let metadata_json: String = row.get("metadata");
            let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap_or_default();

            if let Some(term) = metadata.get("terminal") {
                let cols = term.get("cols").and_then(|v| v.as_u64()).unwrap_or(80) as usize;
                let rows = term.get("rows").and_then(|v| v.as_u64()).unwrap_or(24) as usize;
                (rows.max(1), cols.max(1))
            } else {
                (24, 80)
            }
        } else {
            (24, 80)
        }
    };

    // Create virtual terminal emulator using the recorded dimensions
    let mut vt = vt100::Parser::new(term_rows as u16, term_cols as u16, 0);

    let mut last_timestamp = 0;

    let rows = sqlx::query(
        r#"
        SELECT data, direction, chunk_index, timestamp
        FROM session_chunks
        WHERE session_id = ? AND chunk_index <= ?
        ORDER BY chunk_index ASC
        "#,
    )
    .bind(session_id)
    .bind(chunk_index as i64)
    .fetch_all(pool)
    .await?;

    for row in rows {
        last_timestamp = row.get("timestamp");
        let direction: i32 = row.get("direction");
        if direction != 0 {
            continue; // only output
        }
        let encrypted_data: Vec<u8> = row.get("data");
        if encrypted_data.len() < 40 {
            continue;
        }
        let (salt, rest) = encrypted_data.split_at(16);
        let (nonce, ciphertext) = rest.split_at(24);
        let (compressed, _) =
            server_core::secrets::decrypt_secret(salt, nonce, ciphertext).map_err(|e| anyhow!("snapshot decrypt failed: {}", e))?;
        use secrecy::ExposeSecret;
        let plaintext =
            zstd::decode_all(compressed.expose_secret().as_slice()).map_err(|e| anyhow!("snapshot decompress failed: {}", e))?;
        vt.process(&plaintext);
    }

    let screen = vt.screen();
    // Use formatted state (including colors and attributes) so snapshots
    // faithfully reproduce TUIs when written back into xterm.
    let screen_state = screen.state_formatted();
    let screen_buffer = String::from_utf8_lossy(&screen_state).to_string();
    let (cursor_row, cursor_col) = screen.cursor_position();

    Ok(TerminalSnapshot {
        screen_buffer,
        cursor_row: cursor_row as usize,
        cursor_col: cursor_col as usize,
        chunk_index,
        timestamp: last_timestamp,
        terminal_size: (term_rows, term_cols),
    })
}

/// WebSocket streaming endpoint for session playback with server-side seek support
#[get(
    "/api/audit/sessions/:id/ws",
    auth: WebAuthSession
)]
pub async fn session_stream_ws(
    id: String,
    options: WebSocketOptions,
) -> Result<Websocket<SessionStreamClient, SessionStreamServer, JsonEncoding>> {
    let current_user_id = auth.current_user.as_ref().ok_or_else(|| anyhow!("Not authenticated"))?.id;
    let has_admin_claim = ensure_audit_claim(&auth, ClaimLevel::View).is_ok();

    // Fetch session and verify access
    let audit_db = state_store::audit::audit_db().await.map_err(|e| anyhow!("{}", e))?;
    let pool = audit_db.pool.clone();

    let session_row = sqlx::query("SELECT user_id FROM recorded_sessions WHERE id = ?")
        .bind(&id)
        .fetch_optional(&pool)
        .await
        .map_err(|e| anyhow!("{}", e))?
        .ok_or_else(|| anyhow!("Session not found"))?;

    use sqlx::Row;
    let session_user_id: i64 = session_row.get("user_id");
    if !has_admin_claim && session_user_id != current_user_id {
        return Err(anyhow!("Forbidden: You can only view your own sessions").into());
    }

    Ok(options.on_upgrade(move |mut socket| async move {
        let byte_default: usize = 256 * 1024; // default budget
        let mut state = StreamState {
            db_index: 0,
            db_offset: 0,
            logical_cursor: 0,
            logical_total: 0,
        };

        loop {
            let msg = match socket.recv().await {
                Ok(m) => m,
                Err(e) => {
                    tracing::trace!("audit player ws recv error: {}", e);
                    break;
                }
            };

            match msg {
                SessionStreamClient::Hello { start_index, byte_budget } => {
                    // Reset state
                    state.db_index = start_index;
                    state.db_offset = 0;
                    state.logical_cursor = start_index;
                    state.logical_total = 0;

                    let budget = byte_budget.max(64 * 1024); // guard against zero/too-small budgets
                    if let Err(e) = stream_batch(&pool, &id, session_user_id, &mut state, budget, &mut socket).await {
                        let _ = socket
                            .send(SessionStreamServer::Error {
                                message: e.to_string(),
                                chunk_index: None,
                            })
                            .await;
                        break;
                    }
                }
                SessionStreamClient::RequestMore {
                    cursor: _cursor,
                    byte_budget,
                } => {
                    // We trust server-side state; cursor from client is informational
                    let budget = byte_budget.max(64 * 1024);
                    if let Err(e) = stream_batch(&pool, &id, session_user_id, &mut state, budget, &mut socket).await {
                        let _ = socket
                            .send(SessionStreamServer::Error {
                                message: e.to_string(),
                                chunk_index: None,
                            })
                            .await;
                        break;
                    }
                }
                SessionStreamClient::Seek {
                    target_chunk,
                    want_snapshot,
                } => {
                    if want_snapshot {
                        match build_snapshot(&pool, &id, target_chunk).await {
                            Ok(snapshot) => {
                                let _ = socket.send(SessionStreamServer::Snapshot(snapshot)).await;

                                // Update stream state to continue from after this chunk
                                state.db_index = target_chunk + 1;
                                state.db_offset = 0;
                                state.logical_cursor = target_chunk + 1;
                            }
                            Err(e) => {
                                let _ = socket
                                    .send(SessionStreamServer::Error {
                                        message: e.to_string(),
                                        chunk_index: Some(target_chunk),
                                    })
                                    .await;
                                continue;
                            }
                        }
                    }
                    state.db_index = target_chunk + 1;
                    state.db_offset = 0;
                    state.logical_cursor = target_chunk + 1;
                    let budget = byte_default;
                    if let Err(e) = stream_batch(&pool, &id, session_user_id, &mut state, budget, &mut socket).await {
                        let _ = socket
                            .send(SessionStreamServer::Error {
                                message: e.to_string(),
                                chunk_index: Some(target_chunk),
                            })
                            .await;
                        break;
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
    }))
}

/// Get all input events for a session (for timeline/sidebar)
#[get(
    "/api/audit/sessions/:id/events",
    auth: WebAuthSession
)]
pub async fn get_session_events(id: String) -> Result<Vec<SessionChunk>> {
    let current_user_id = auth.current_user.as_ref().ok_or_else(|| anyhow!("Not authenticated"))?.id;
    let has_admin_claim = ensure_audit_claim(&auth, ClaimLevel::View).is_ok();

    let audit_db = state_store::audit::audit_db().await.map_err(|e| anyhow!("{}", e))?;
    let pool = &audit_db.pool;

    // Verify access
    let session_row = sqlx::query("SELECT user_id FROM recorded_sessions WHERE id = ?")
        .bind(&id)
        .fetch_optional(pool)
        .await
        .map_err(|e| anyhow!("{}", e))?
        .ok_or_else(|| anyhow!("Session not found"))?;

    use sqlx::Row;
    let session_owner_id: i64 = session_row.get("user_id");
    if !has_admin_claim && session_owner_id != current_user_id {
        return Err(anyhow!("Forbidden: You can only view your own sessions").into());
    }

    // Fetch input chunks (direction != 0)
    let rows = sqlx::query(
        r#"
        SELECT 
            sc.chunk_index,
            sc.timestamp, 
            sc.direction, 
            CASE WHEN sc.direction = 0 THEN '' ELSE sc.data END as data,
            sc.connection_id,
            sc.timing_markers,
            c.user_id,
            c.connection_type,
            c.ip_address,
            c.user_agent,
            c.ssh_client
        FROM session_chunks sc
        LEFT JOIN connections c ON sc.connection_id = c.id
        WHERE sc.session_id = ?
        ORDER BY sc.timestamp ASC, sc.chunk_index ASC
        "#,
    )
    .bind(&id)
    .fetch_all(pool)
    .await
    .map_err(|e| anyhow!("{}", e))?;

    // Collect user IDs for username lookup
    let mut user_ids = std::collections::HashSet::new();
    user_ids.insert(session_owner_id);
    for row in &rows {
        if let Some(uid) = row.get::<Option<i64>, _>("user_id") {
            user_ids.insert(uid);
        }
    }

    // Fetch usernames
    let mut username_map = std::collections::HashMap::new();
    if let Ok(server_db) = state_store::server_db().await {
        for uid in user_ids {
            if let Ok(Some(user)) = state_store::fetch_user_auth_record(&server_db.pool, uid).await {
                username_map.insert(uid, user.username);
            }
        }
    }

    let mut chunks = Vec::new();
    for row in rows {
        let encrypted_data: Vec<u8> = row.get("data");

        let plaintext_res = (|| -> Result<Vec<u8>> {
            if encrypted_data.len() < 40 {
                return Ok(Vec::new());
            }
            let (salt, rest) = encrypted_data.split_at(16);
            let (nonce, ciphertext) = rest.split_at(24);
            let (compressed, _) = server_core::secrets::decrypt_secret(salt, nonce, ciphertext)?;
            use secrecy::ExposeSecret;
            let plaintext = zstd::decode_all(compressed.expose_secret().as_slice())?;
            Ok(plaintext)
        })();

        let plaintext = plaintext_res.unwrap_or_default();

        use base64::Engine;
        let data_b64 = base64::engine::general_purpose::STANDARD.encode(plaintext);

        let chunk_user_id: Option<i64> = row.get("user_id");
        let direction: i32 = row.get("direction");

        let username = chunk_user_id.and_then(|uid| username_map.get(&uid).cloned());
        let is_admin_input = chunk_user_id.map(|uid| uid != session_owner_id).unwrap_or(false);

        let timing_markers: Option<Vec<(usize, i64)>> = row
            .get::<Option<String>, _>("timing_markers")
            .and_then(|json_str| serde_json::from_str(&json_str).ok());

        chunks.push(SessionChunk {
            timestamp: row.get("timestamp"),
            direction: direction as u8,
            data: data_b64,
            connection_id: row.get("connection_id"),
            user_id: chunk_user_id,
            username,
            connection_type: row.get("connection_type"),
            ip_address: row.get("ip_address"),
            user_agent: row.get("user_agent"),
            ssh_client: row.get("ssh_client"),
            is_admin_input,
            timing_markers,
            db_chunk_index: Some(row.get::<i64, _>("chunk_index") as usize),
        });
    }

    Ok(chunks)
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

    // Authorization is checked in replay_session (own session or admin claim)
    // So we don't need to check here

    // Reuse replay logic to get chunks
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
            // Plain text export - just concatenate output chunks
            let mut content = String::new();

            for chunk in chunks {
                // Only export output chunks (direction == 0)
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
            // Asciinema v2 format (default)
            // {"version": 2, "width": 80, "height": 24, "timestamp": 1234567890, "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"}}
            let mut lines = Vec::new();

            let header = serde_json::json!({
                "version": 2,
                "width": 80, // TODO: Store terminal size in session metadata
                "height": 24,
                "timestamp": session.start_time / 1000,
                "title": format!("Session #{} ({})", session.session_number, session.relay_name.as_deref().unwrap_or("unknown")),
                "env": {
                    "TERM": "xterm-256color",
                    "SHELL": "/bin/bash"
                }
            });
            lines.push(serde_json::to_string(&header).unwrap());

            // Chunks
            // [0.248844, "o", "foo"]
            let start_time = session.start_time as f64 / 1000.0;

            for chunk in chunks {
                // Only export output chunks for playback (direction == 0)
                if chunk.direction == 0
                    && let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&chunk.data)
                    && let Ok(text) = String::from_utf8(decoded)
                {
                    let time = (chunk.timestamp as f64 / 1000.0) - start_time;
                    // Ensure time is non-negative
                    let time = if time < 0.0 { 0.0 } else { time };

                    let line = serde_json::json!([time, "o", text]);
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

/// Helper to strip ANSI escape sequences from text
#[cfg(feature = "server")]
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Check for CSI: ESC [ ... Final
            if let Some(&'[') = chars.peek() {
                chars.next(); // consume '['

                // Consume Parameter Bytes (0x30-0x3F) and Intermediate Bytes (0x20-0x2F)
                // Combined range: 0x20-0x3F
                while let Some(&n) = chars.peek() {
                    if n >= '\u{20}' && n <= '\u{3F}' {
                        chars.next();
                    } else {
                        break;
                    }
                }

                // Consume Final Byte (0x40-0x7E)
                if let Some(&n) = chars.peek() {
                    if n >= '\u{40}' && n <= '\u{7E}' {
                        chars.next();
                    }
                }
                continue;
            }

            // Check for OSC: ESC ] ... BEL or ESC \
            if let Some(&']') = chars.peek() {
                chars.next(); // consume ']'
                while let Some(n) = chars.next() {
                    if n == '\x07' {
                        break;
                    }
                    if n == '\x1b' {
                        if let Some(&'\\') = chars.peek() {
                            chars.next();
                            break;
                        }
                    }
                }
                continue;
            }

            // Basic ESC-sequencing skipping (like ESC 7, ESC 8, ESC M) - just 1 char
            // But be careful not to eat real text if it's a stray ESC.
            // For now, let's just handle CSI and OSC as they are the bulk of "garbage".
        }
        out.push(c);
    }
    out
}
