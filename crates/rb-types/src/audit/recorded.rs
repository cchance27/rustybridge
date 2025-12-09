//! Recorded session DTOs used by audit/replay surfaces.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecordedSessionSummary {
    pub id: String,
    pub user_id: i64,
    pub relay_id: i64,
    pub session_number: i64,
    pub start_time: i64,
    pub end_time: Option<i64>,
    pub metadata: serde_json::Value,
    pub username: Option<String>,
    pub relay_name: Option<String>,
    pub original_size_bytes: Option<i64>,
    pub compressed_size_bytes: Option<i64>,
    pub encrypted_size_bytes: Option<i64>,
    pub chunk_count: Option<i64>,
    pub first_chunk_ts: Option<i64>,
    pub last_chunk_ts: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecordedSessionChunk {
    pub timestamp: i64,
    pub direction: u8,
    /// Base64-encoded plaintext chunk data (after decrypt + decompress)
    pub data: String,
    pub connection_id: Option<String>,
    pub user_id: Option<i64>,
    pub username: Option<String>,
    pub connection_type: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub ssh_client: Option<String>,
    pub is_admin_input: bool,
    pub timing_markers: Option<Vec<(usize, i64)>>,
    pub db_chunk_index: Option<usize>,
}
