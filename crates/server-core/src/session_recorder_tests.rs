//! Unit tests for session recorder.

use std::sync::{OnceLock, atomic::Ordering};

use base64::Engine;
use serde_json::json;
use sqlx::{Row, sqlite::SqlitePoolOptions};
use state_store::{DbHandle, migrate_audit};

use super::*;

static SECRETS_INIT: OnceLock<()> = OnceLock::new();

fn init_test_secrets() {
    SECRETS_INIT.get_or_init(|| {
        let key = base64::engine::general_purpose::STANDARD
            .decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .unwrap();
        secrets::set_master_key_for_test(&key);
    });
}

async fn setup_recorder() -> (DbHandle, Arc<SessionRecorder>) {
    init_test_secrets();

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
