use std::{
    sync::{
        Arc, atomic::{AtomicBool, AtomicU64, Ordering}
    }, time::Duration
};

use chrono::Utc;
use rb_types::state::DbHandle;
use tokio::sync::Mutex;
use tracing::{debug, error};
use uuid::Uuid;

use crate::secrets;

// Configuration constants
/// Compression level for zstd (1-22). Level 3 provides good balance between speed and compression ratio.
/// Higher levels use more CPU but achieve better compression. Lower levels are faster but compress less.
const COMPRESSION_LEVEL: i32 = 3;

/// Maximum size for session metadata JSON in bytes (64 KB).
/// Prevents large client-supplied metadata from bloating database rows and slowing inserts.
#[allow(dead_code)] // Used for documentation; validation happens at call site
const MAX_METADATA_SIZE: usize = 64 * 1024;

/// Maximum number of buffered chunks before dropping oldest data (approx 1 MB at 1KB/chunk average).
/// Prevents unbounded memory growth during persistent database failures.
/// TODO: Make this configurable with policies for handling buffer overflow:
///   - Drop oldest (current default)
///   - Disable recording
///   - Close affected sessions
///   - Trigger server shutdown (for strict audit requirements)
const MAX_BUFFER_CHUNKS: usize = 1024;

// Chunk direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkDirection {
    Output = 0,
    Input = 1,
}

// Internal chunk structure before flushing
struct BufferedChunk {
    timestamp: i64,
    direction: ChunkDirection,
    data: Vec<u8>,
    connection_id: Option<String>, // NULL for output, populated for input
}

// Timing marker: (byte_offset, delay_ms)
// Indicates after byte_offset, there was a delay_ms pause before the next data
type TimingMarker = (usize, i64);

// Coalesced chunk with timing markers. This is what we buffer between flushes
// so that timing metadata survives retry paths.
struct CoalescedChunk {
    chunk: BufferedChunk,
    timing_markers: Vec<TimingMarker>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputType {
    Text,
    Special, // Escape sequences
}

// Staging area for active input grouping
struct ActiveInputChunk {
    start_timestamp: i64,
    last_updated: i64,
    data: Vec<u8>,
    connection_id: String,
    input_type: InputType,
}

pub struct SessionRecorder {
    session_id: Uuid,
    db: DbHandle,
    buffer: Arc<Mutex<Vec<CoalescedChunk>>>,
    active_input: Arc<Mutex<Option<ActiveInputChunk>>>,
    // Serialize flush calls to avoid concurrent transactions and index races
    flush_lock: Mutex<()>,
    chunk_index: Arc<AtomicU64>,
    // Size tracking - updated atomically during flush
    original_size: Arc<AtomicU64>,
    compressed_size: Arc<AtomicU64>,
    encrypted_size: Arc<AtomicU64>,
    recording_enabled: Arc<AtomicBool>,
}

impl SessionRecorder {
    pub async fn new(
        db: DbHandle,
        user_id: i64,
        relay_id: i64,
        session_number: u32,
        metadata: serde_json::Value,
        connection_id: Option<String>,
    ) -> Arc<Self> {
        let session_id = Uuid::now_v7();
        let start_time = Utc::now().timestamp_millis();

        // Create session record before any chunks can flush so FK exists
        let session_id_str = session_id.to_string();
        let metadata_str = metadata.to_string();
        let recording_enabled = Arc::new(AtomicBool::new(true));

        if let Err(e) = sqlx::query(
            "INSERT INTO relay_sessions (id, user_id, relay_host_id, session_number, start_time, metadata, initiator_client_session_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&session_id_str)
        .bind(user_id)
        .bind(relay_id)
        .bind(session_number)
        .bind(start_time)
        .bind(metadata_str)
        .bind(&connection_id)
        .execute(&db.pool)
        .await
        {
            // Without the parent row, every chunk insert would FK-fail and be dropped.
            error!(session_id = %session_id_str, error = ?e, "failed to create session record; recording will be discarded");
            recording_enabled.store(false, Ordering::Relaxed);
        }

        // Record the initiator as a participant
        if let Some(conn_id) = &connection_id
            && let Err(e) =
                sqlx::query("INSERT INTO relay_session_participants (relay_session_id, client_session_id, joined_at) VALUES (?, ?, ?)")
                    .bind(&session_id_str)
                    .bind(conn_id)
                    .bind(start_time)
                    .execute(&db.pool)
                    .await
        {
            error!(session_id = %session_id_str, error = ?e, "failed to record initiator participant");
        }

        let buffer = Arc::new(Mutex::new(Vec::new()));
        let active_input = Arc::new(Mutex::new(None));
        let chunk_index = Arc::new(AtomicU64::new(0));

        let recorder = Arc::new(Self {
            session_id,
            db,
            buffer: buffer.clone(),
            active_input: active_input.clone(),
            flush_lock: Mutex::new(()),
            chunk_index: chunk_index.clone(),
            original_size: Arc::new(AtomicU64::new(0)),
            compressed_size: Arc::new(AtomicU64::new(0)),
            encrypted_size: Arc::new(AtomicU64::new(0)),
            recording_enabled,
        });

        // Spawn background flusher
        let recorder_weak = Arc::downgrade(&recorder);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                if let Some(recorder) = recorder_weak.upgrade() {
                    // Exit task if recording is disabled to save CPU cycles
                    if !recorder.recording_enabled.load(Ordering::Relaxed) {
                        // Clear buffers one last time before exiting
                        recorder.flush().await;
                        debug!(session_id = %recorder.session_id, "background flush task exiting (recording disabled)");
                        break;
                    }
                    recorder.flush().await;
                } else {
                    break;
                }
            }
        });

        recorder
    }

    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    /// Record a participant joining an existing session (reattach).
    /// The initial connection is recorded automatically in `new()`.
    pub async fn record_participant_join(&self, client_session_id: &str) {
        let now = Utc::now().timestamp_millis();
        let session_id_str = self.session_id.to_string();

        if let Err(e) =
            sqlx::query("INSERT INTO relay_session_participants (relay_session_id, client_session_id, joined_at) VALUES (?, ?, ?)")
                .bind(&session_id_str)
                .bind(client_session_id)
                .bind(now)
                .execute(&self.db.pool)
                .await
        {
            error!(session_id = %session_id_str, error = ?e, "failed to record participant join");
        }
    }

    pub async fn record_participant_leave(&self, client_session_id: &str) {
        let now = Utc::now().timestamp_millis();
        let session_id_str = self.session_id.to_string();

        if let Err(e) = sqlx::query(
            "UPDATE relay_session_participants SET left_at = ? WHERE relay_session_id = ? AND client_session_id = ? AND left_at IS NULL",
        )
        .bind(now)
        .bind(&session_id_str)
        .bind(client_session_id)
        .execute(&self.db.pool)
        .await
        {
            error!(session_id = %session_id_str, error = ?e, "failed to record participant leave");
        }
    }

    pub async fn record_output(&self, data: &[u8]) {
        if !self.recording_enabled.load(Ordering::Relaxed) {
            return;
        }
        self.push_chunk(ChunkDirection::Output, data, None, None).await;
    }

    pub async fn record_input(&self, data: &[u8], connection_id: String) {
        if !self.recording_enabled.load(Ordering::Relaxed) {
            return;
        }
        if data.is_empty() {
            return;
        }

        let input_type = classify_input(data);
        let has_enter = contains_enter(data);

        loop {
            let now = Utc::now().timestamp_millis();

            // Phase 1: Check if we need to flush active chunk (incompatibility)
            let chunk_to_flush = {
                let mut active_opt = self.active_input.lock().await;
                if let Some(active) = active_opt.as_ref() {
                    let different_user = active.connection_id != connection_id;
                    let different_type = input_type.is_none() || (input_type.is_some() && input_type != Some(active.input_type));

                    if different_user || different_type {
                        active_opt.take()
                    } else {
                        None
                    }
                } else {
                    None
                }
            };

            if let Some(chunk) = chunk_to_flush {
                self.push_chunk(
                    ChunkDirection::Input,
                    &chunk.data,
                    Some(chunk.connection_id),
                    Some(chunk.start_timestamp),
                )
                .await;
                continue;
            }

            // Phase 2: Buffer or Push
            let (push_direct, push_active_chunk) = {
                let mut active_opt = self.active_input.lock().await;

                if let Some(chunk_type) = input_type {
                    // Bufferable
                    if let Some(active) = active_opt.as_mut() {
                        // Compatible active exists
                        active.data.extend_from_slice(data);
                        active.last_updated = now;

                        if has_enter { (false, active_opt.take()) } else { (false, None) }
                    } else {
                        // No active
                        if has_enter {
                            (true, None)
                        } else {
                            *active_opt = Some(ActiveInputChunk {
                                start_timestamp: now,
                                last_updated: now,
                                data: data.to_vec(),
                                connection_id: connection_id.clone(),
                                input_type: chunk_type,
                            });
                            (false, None)
                        }
                    }
                } else {
                    // Non-bufferable (active_opt is None guaranteed by Phase 1)
                    (true, None)
                }
            };

            if let Some(chunk) = push_active_chunk {
                self.push_chunk(
                    ChunkDirection::Input,
                    &chunk.data,
                    Some(chunk.connection_id),
                    Some(chunk.start_timestamp),
                )
                .await;
            } else if push_direct {
                self.push_chunk(ChunkDirection::Input, data, Some(connection_id), Some(now)).await;
            }

            break;
        }
    }

    async fn push_chunk(&self, direction: ChunkDirection, data: &[u8], connection_id: Option<String>, timestamp: Option<i64>) {
        if data.is_empty() {
            return;
        }

        let mut buffer = self.buffer.lock().await;
        buffer.push(CoalescedChunk {
            chunk: BufferedChunk {
                timestamp: timestamp.unwrap_or_else(|| Utc::now().timestamp_millis()),
                direction,
                data: data.to_vec(),
                connection_id,
            },
            timing_markers: Vec::new(),
        });
    }

    pub async fn flush(&self) {
        // Ensure only one flush runs at a time for this recorder
        let _guard = self.flush_lock.lock().await;

        if !self.recording_enabled.load(Ordering::Relaxed) {
            // Recording disabled (e.g., session insert failed); drop buffered data to avoid unbounded growth.
            let mut buffer = self.buffer.lock().await;
            buffer.clear();
            let mut active_opt = self.active_input.lock().await;
            *active_opt = None;
            return;
        }

        // First, check if active input chunk has timed out
        let timeout_chunk = {
            let mut active_opt = self.active_input.lock().await;
            if let Some(active) = active_opt.as_ref() {
                let now = Utc::now().timestamp_millis();
                if now - active.last_updated > 1000 {
                    active_opt.take()
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some(chunk) = timeout_chunk {
            self.push_chunk(
                ChunkDirection::Input,
                &chunk.data,
                Some(chunk.connection_id),
                Some(chunk.start_timestamp),
            )
            .await;
        }

        let chunks = {
            let mut buffer = self.buffer.lock().await;
            if buffer.is_empty() {
                return;
            }

            // Smart Flush Logic:
            // Avoid flushing small, frequent output chunks (e.g. htop) to reduce DB fragmentation.
            // We FLUSH if:
            // 1. We have Input chunks (interactive latency is critical)
            // 2. We have accumulated > 16KB of data (memory/safety cap)
            // 3. The oldest data is > 3 seconds old (persistence guarantee)

            let mut has_input = false;
            let mut total_size = 0;
            let first_timestamp = buffer.first().map(|c| c.chunk.timestamp).unwrap_or(0);

            for entry in buffer.iter() {
                let chunk = &entry.chunk;
                if chunk.direction == ChunkDirection::Input {
                    has_input = true;
                    break;
                }
                total_size += chunk.data.len();
            }

            let now = Utc::now().timestamp_millis();
            let age = now - first_timestamp;

            if !has_input && total_size < 16 * 1024 && age < 3000 {
                // Keep buffering
                return;
            }

            std::mem::take(&mut *buffer)
        };

        // Coalesce adjacent chunks to reduce fragmentation and DB overhead.
        // Track timing markers to preserve intra-chunk delays for accurate playback.
        const TIMING_THRESHOLD_MS: i64 = 50; // Only record delays > 50ms

        let mut coalesced: Vec<CoalescedChunk> = Vec::with_capacity(chunks.len());
        for entry in chunks {
            if let Some(last) = coalesced.last_mut()
                && last.chunk.direction == entry.chunk.direction
                && last.chunk.connection_id == entry.chunk.connection_id
            {
                // Calculate delay since last chunk
                let delay_ms = entry.chunk.timestamp - last.chunk.timestamp;

                // Offset within the coalesced data where this gap occurs
                let base_offset = last.chunk.data.len();

                // Record timing marker if delay is significant
                if delay_ms > TIMING_THRESHOLD_MS {
                    last.timing_markers.push((base_offset, delay_ms));
                }

                // Merge data into coalesced chunk
                last.chunk.data.extend_from_slice(&entry.chunk.data);

                // Preserve any existing timing markers on the incoming entry,
                // shifting their offsets to account for the new base.
                if !entry.timing_markers.is_empty() {
                    last.timing_markers.extend(
                        entry
                            .timing_markers
                            .into_iter()
                            .map(|(offset, delay)| (base_offset + offset, delay)),
                    );
                }

                // Update timestamp to track for next potential merge
                last.chunk.timestamp = entry.chunk.timestamp;
                continue;
            }

            // Start new coalesced chunk (carry through any existing markers as-is)
            coalesced.push(entry);
        }

        let mut tx = match self.db.pool.begin().await {
            Ok(tx) => tx,
            Err(e) => {
                error!(error = ?e, "failed to begin transaction for flush");
                // Requeue chunks so we can retry on next flush instead of losing data.
                let mut buffer = self.buffer.lock().await;

                let requeue_size = coalesced.len();

                // Check if adding these chunks would exceed the buffer cap
                if buffer.len() + requeue_size > MAX_BUFFER_CHUNKS {
                    let to_drop = (buffer.len() + requeue_size) - MAX_BUFFER_CHUNKS;
                    error!(
                        session_id = %self.session_id.to_string(),
                        current_buffer_size = buffer.len(),
                        requeue_size = requeue_size,
                        max_buffer_chunks = MAX_BUFFER_CHUNKS,
                        dropping_chunks = to_drop,
                        "CRITICAL: Buffer capacity exceeded during database failure. Dropping oldest chunks to prevent OOM. AUDIT DATA BEING LOST!"
                    );
                    buffer.drain(0..to_drop);
                }

                buffer.splice(0..0, coalesced);
                return;
            }
        };

        let mut successful_chunks = Vec::with_capacity(coalesced.len());
        let mut remaining_chunks = Vec::new();
        let mut iter = coalesced.into_iter();

        let mut pending_original = 0u64;
        let mut pending_compressed = 0u64;
        let mut pending_encrypted = 0u64;
        let mut successful_count = 0u64;

        // Reserve a contiguous index range for this flush, but only
        // advance the shared counter after the transaction commits.
        let mut next_idx = self.chunk_index.load(Ordering::SeqCst) as i64;

        while let Some(coalesced_chunk) = iter.next() {
            let chunk = &coalesced_chunk.chunk;
            let original_len = chunk.data.len() as u64;

            // 1. Compress
            let compressed = match zstd::encode_all(chunk.data.as_slice(), COMPRESSION_LEVEL) {
                Ok(c) => c,
                Err(e) => {
                    error!(error = ?e, "failed to compress chunk, requeueing batch");
                    remaining_chunks.push(coalesced_chunk);
                    remaining_chunks.extend(iter);
                    break;
                }
            };
            let compressed_len = compressed.len() as u64;

            // 2. Encrypt
            let encrypted_blob = match secrets::encrypt_secret(&compressed) {
                Ok(b) => b,
                Err(e) => {
                    error!(error = ?e, "failed to encrypt chunk, requeueing batch");
                    remaining_chunks.push(coalesced_chunk);
                    remaining_chunks.extend(iter);
                    break;
                }
            };

            // Serialize EncryptedBlob to store in DB (salt + nonce + ciphertext)
            let mut stored_data = Vec::with_capacity(16 + 24 + encrypted_blob.ciphertext.len());
            stored_data.extend_from_slice(&encrypted_blob.salt);
            stored_data.extend_from_slice(&encrypted_blob.nonce);
            stored_data.extend_from_slice(&encrypted_blob.ciphertext);
            let encrypted_len = stored_data.len() as u64;

            let chunk_id = Uuid::now_v7().to_string();
            let session_id_str = self.session_id.to_string();
            let dir = chunk.direction as i32;
            let connection_id = chunk.connection_id.as_deref();

            // Serialize timing markers to JSON (only if non-empty)
            let timing_markers_json = if coalesced_chunk.timing_markers.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&coalesced_chunk.timing_markers).unwrap_or_else(|_| "[]".to_string()))
            };

            // Allocate chunk_index from our local window so that indices
            // stay contiguous even if the transaction later rolls back.
            let idx = next_idx;
            next_idx += 1;

            let res = sqlx::query(
                "INSERT INTO session_chunks (id, relay_session_id, timestamp, chunk_index, direction, data, client_session_id, timing_markers) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(chunk_id)
            .bind(session_id_str)
            .bind(chunk.timestamp)
            .bind(idx)
            .bind(dir)
            .bind(stored_data)
            .bind(connection_id)
            .bind(timing_markers_json)
            .execute(&mut *tx)
            .await;

            if let Err(e) = res {
                error!(error = ?e, "failed to insert chunk, requeueing batch");
                remaining_chunks.push(coalesced_chunk);
                remaining_chunks.extend(iter);
                break;
            } else {
                // Track successful chunks; the global chunk_index will only
                // be advanced once the transaction commit succeeds.
                successful_chunks.push(coalesced_chunk);
                successful_count += 1;
                pending_original += original_len;
                pending_compressed += compressed_len;
                pending_encrypted += encrypted_len;
            }
        }

        if !successful_chunks.is_empty() {
            if let Err(e) = tx.commit().await {
                error!(error = ?e, "failed to commit flush transaction, requeueing all chunks");
                let mut all_chunks = successful_chunks;
                all_chunks.append(&mut remaining_chunks);

                let mut buffer = self.buffer.lock().await;

                // Check if adding these chunks would exceed the buffer cap
                if buffer.len() + all_chunks.len() > MAX_BUFFER_CHUNKS {
                    let to_drop = (buffer.len() + all_chunks.len()) - MAX_BUFFER_CHUNKS;
                    error!(
                        session_id = %self.session_id.to_string(),
                        current_buffer_size = buffer.len(),
                        requeue_size = all_chunks.len(),
                        max_buffer_chunks = MAX_BUFFER_CHUNKS,
                        dropping_chunks = to_drop,
                        "CRITICAL: Buffer capacity exceeded during commit failure. Dropping oldest chunks to prevent OOM. AUDIT DATA BEING LOST!"
                    );
                    buffer.drain(0..to_drop);
                }

                buffer.splice(0..0, all_chunks);
            } else {
                // Only now that the chunks are durably stored do we advance
                // the shared chunk index, keeping the sequence gapless.
                if successful_count > 0 {
                    self.chunk_index.fetch_add(successful_count, Ordering::SeqCst);
                }

                self.original_size.fetch_add(pending_original, Ordering::Relaxed);
                self.compressed_size.fetch_add(pending_compressed, Ordering::Relaxed);
                self.encrypted_size.fetch_add(pending_encrypted, Ordering::Relaxed);

                if !remaining_chunks.is_empty() {
                    let mut buffer = self.buffer.lock().await;
                    buffer.splice(0..0, remaining_chunks);
                }
            }
        } else if !remaining_chunks.is_empty() {
            let mut buffer = self.buffer.lock().await;
            buffer.splice(0..0, remaining_chunks);
        }
    }

    pub async fn close(&self) {
        if !self.recording_enabled.load(Ordering::Relaxed) {
            return;
        }
        // Force commit any active input
        {
            let mut active_opt = self.active_input.lock().await;
            if let Some(chunk) = active_opt.take() {
                drop(active_opt);
                self.push_chunk(
                    ChunkDirection::Input,
                    &chunk.data,
                    Some(chunk.connection_id),
                    Some(chunk.start_timestamp),
                )
                .await;
            } else {
                drop(active_opt);
            }
        }

        // Final flush
        self.flush().await;

        // Update end_time and size totals
        let end_time = Utc::now().timestamp_millis();
        let session_id_str = self.session_id.to_string();

        let original = self.original_size.load(Ordering::Relaxed) as i64;
        let compressed = self.compressed_size.load(Ordering::Relaxed) as i64;
        let encrypted = self.encrypted_size.load(Ordering::Relaxed) as i64;

        let res = sqlx::query(
            "UPDATE relay_sessions 
             SET end_time = ?, original_size_bytes = ?, compressed_size_bytes = ?, encrypted_size_bytes = ? 
             WHERE id = ?",
        )
        .bind(end_time)
        .bind(original)
        .bind(compressed)
        .bind(encrypted)
        .bind(session_id_str)
        .execute(&self.db.pool)
        .await;

        if let Err(e) = res {
            error!(error = ?e, "failed to update session end time and sizes");
        }
    }
}

// Helpers for smart chunking
fn classify_input(data: &[u8]) -> Option<InputType> {
    if data.is_empty() {
        return None;
    }

    // If it starts with escape, treat as special sequence (Arrows, F-keys, etc)
    if data[0] == 0x1b {
        return Some(InputType::Special);
    }

    for &b in data {
        // Mixed escape sequences? Return None to be safe and flush
        if b == 0x1b {
            return None;
        }

        // Control characters that aren't whitespace or deletion (Ctrl-C, Ctrl-D, etc)
        // 0x08 = Backspace, 0x7f = Delete, 0x09 = Tab, 0x0A = LF, 0x0D = CR
        if b < 0x20 && b != b'\r' && b != b'\n' && b != 0x08 && b != 0x09 && b != 0x7f {
            return None;
        }
    }

    Some(InputType::Text)
}

fn contains_enter(data: &[u8]) -> bool {
    data.contains(&b'\r') || data.contains(&b'\n')
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use base64::Engine;
    use serde_json::json;
    use serial_test::serial;
    use sqlx::{Row, sqlite::SqlitePoolOptions};
    use state_store::{DbHandle, migrate_audit};

    use super::*;

    async fn setup_recorder() -> (DbHandle, Arc<SessionRecorder>) {
        let key = base64::engine::general_purpose::STANDARD
            .decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .unwrap();
        secrets::set_master_key_for_test(&key);

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("sqlite in-memory should be available");
        let db = DbHandle {
            pool,
            url: "sqlite::memory:".to_string(),
            path: None,
            freshly_created: true,
        };
        migrate_audit(&db).await.expect("migrations should succeed");

        let recorder = SessionRecorder::new(db.clone(), 1, 1, 1, json!({}), None).await;
        (db, recorder)
    }

    #[tokio::test]
    #[serial]
    async fn record_input_flush_preserves_triggering_bytes() {
        let (db, recorder) = setup_recorder().await;

        assert!(
            recorder.recording_enabled.load(Ordering::Relaxed),
            "recorder should be enabled after successful setup"
        );

        let session_count: i64 = sqlx::query("SELECT COUNT(*) AS cnt FROM relay_sessions")
            .fetch_one(&db.pool)
            .await
            .expect("session query should succeed")
            .get("cnt");

        assert_eq!(session_count, 1, "session row should exist");

        // Buffer first chunk for one user
        recorder.record_input(b"abc", "user1".to_string()).await;

        // Switching users forces a flush of the active chunk; the new data must still be recorded
        recorder.record_input(b"Z\n", "admin".to_string()).await;

        recorder.flush().await;

        let row = sqlx::query("SELECT COUNT(*) AS cnt FROM session_chunks")
            .fetch_one(&db.pool)
            .await
            .expect("query should succeed");
        let count: i64 = row.get("cnt");

        assert_eq!(count, 2, "triggering input bytes must not be dropped");
    }

    #[tokio::test]
    #[serial]
    async fn test_idle_flush_creates_no_chunks() {
        let (db, recorder) = setup_recorder().await;

        // Initial state
        let count: i64 = sqlx::query("SELECT COUNT(*) AS cnt FROM session_chunks")
            .fetch_one(&db.pool)
            .await
            .unwrap()
            .get("cnt");
        assert_eq!(count, 0);

        // Flush with no data
        recorder.flush().await;

        let count: i64 = sqlx::query("SELECT COUNT(*) AS cnt FROM session_chunks")
            .fetch_one(&db.pool)
            .await
            .unwrap()
            .get("cnt");
        assert_eq!(count, 0, "Flush on empty buffer should not create chunks");

        // Record empty data
        recorder.record_output(&[]).await;
        recorder.flush().await;

        let count: i64 = sqlx::query("SELECT COUNT(*) AS cnt FROM session_chunks")
            .fetch_one(&db.pool)
            .await
            .unwrap()
            .get("cnt");
        assert_eq!(count, 0, "Recording empty data should not create chunks");
    }

    #[tokio::test]
    #[serial]
    async fn test_smart_flush_buffering() {
        let (db, recorder) = setup_recorder().await;

        // 1. Record small output - should NOT flush immediately (buffered)
        recorder.record_output(b"small data").await;

        // Manual flush check - should be ignored by smart flush logic (age < 3s, size < 16KB)
        recorder.flush().await;

        let count: i64 = sqlx::query("SELECT COUNT(*) AS cnt FROM session_chunks")
            .fetch_one(&db.pool)
            .await
            .unwrap()
            .get("cnt");
        assert_eq!(count, 0, "Smart flush should buffer small output");

        // 2. Record Input - should trigger flush immediately
        // Use a newline to ensure it's treated as a complete command and pushed to buffer immediately
        // Otherwise it sits in active_input waiting for more typing
        recorder.record_input(b"input\n", "user".to_string()).await;
        recorder.flush().await;

        let count: i64 = sqlx::query("SELECT COUNT(*) AS cnt FROM session_chunks")
            .fetch_one(&db.pool)
            .await
            .unwrap()
            .get("cnt");
        // Should have 2 chunks now (the buffered output + the new input)
        // Note: they might be coalesced if we had logic for that, but output/input usually don't coalesce.
        assert_eq!(count, 2, "Input should trigger flush of buffered data");
    }

    #[tokio::test]
    #[serial]
    async fn test_smart_flush_size_limit() {
        let (db, recorder) = setup_recorder().await;

        // Record 15KB (under 16KB limit)
        let big_chunk = vec![0u8; 15 * 1024];
        recorder.record_output(&big_chunk).await;
        recorder.flush().await;

        let count: i64 = sqlx::query("SELECT COUNT(*) AS cnt FROM session_chunks")
            .fetch_one(&db.pool)
            .await
            .unwrap()
            .get("cnt");
        assert_eq!(count, 0, "Should buffer 15KB");

        // Add 2KB (total 17KB > 16KB)
        let small_chunk = vec![0u8; 2 * 1024];
        recorder.record_output(&small_chunk).await;
        recorder.flush().await;

        let count: i64 = sqlx::query("SELECT COUNT(*) AS cnt FROM session_chunks")
            .fetch_one(&db.pool)
            .await
            .unwrap()
            .get("cnt");
        // Should coalesce into 1 large chunk or be 2 chunks depending on coalescing logic.
        // Our coalescing handles adjacent same-direction chunks.
        assert_eq!(count, 1, "Should flush and coalesce when size limit exceeded");
    }
}
