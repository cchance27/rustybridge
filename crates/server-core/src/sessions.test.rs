use std::{sync::Arc, time::Duration};

use tokio::sync::{broadcast, mpsc};

use super::*;
use crate::sessions::session_backend::LegacyChannelBackend;

#[tokio::test]
async fn test_session_creation_and_retrieval() {
    let registry = SessionRegistry::new();
    let (input_tx, _) = mpsc::channel(1);
    let (output_tx, _) = broadcast::channel(1);
    let backend = Arc::new(LegacyChannelBackend::new(input_tx, output_tx));

    let (session_number, session) = registry
        .create_next_session(
            1,
            1,
            "test-relay".to_string(),
            "test-user".to_string(),
            backend,
            rb_types::ssh::SessionOrigin::Ssh { user_id: 1 },
            Some("127.0.0.1".to_string()),
            None,
        )
        .await;

    assert_eq!(session_number, 1);
    assert_eq!(session.session_number, 1);

    let retrieved = registry.get_session(1, 1, session_number).await;
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().session_number, session_number);
}

#[tokio::test]
async fn test_next_session_number() {
    let registry = SessionRegistry::new();
    let (input_tx1, _) = mpsc::channel(1);
    let (output_tx1, _) = broadcast::channel(1);
    let backend1 = Arc::new(LegacyChannelBackend::new(input_tx1, output_tx1));

    let (input_tx2, _) = mpsc::channel(1);
    let (output_tx2, _) = broadcast::channel(1);
    let backend2 = Arc::new(LegacyChannelBackend::new(input_tx2, output_tx2));

    let (num1, _) = registry
        .create_next_session(
            1,
            1,
            "test-relay".to_string(),
            "test-user".to_string(),
            backend1,
            rb_types::ssh::SessionOrigin::Ssh { user_id: 1 },
            Some("127.0.0.1".to_string()),
            None,
        )
        .await;
    let (num2, _) = registry
        .create_next_session(
            1,
            1,
            "test-relay".to_string(),
            "test-user".to_string(),
            backend2,
            rb_types::ssh::SessionOrigin::Ssh { user_id: 1 },
            Some("127.0.0.1".to_string()),
            None,
        )
        .await;

    assert_eq!(num1, 1);
    assert_eq!(num2, 2);
}

#[tokio::test]
async fn test_session_cleanup() {
    let registry = SessionRegistry::new();
    let (input_tx, _) = mpsc::channel(1);
    let (output_tx, _) = broadcast::channel(1);
    let backend = Arc::new(LegacyChannelBackend::new(input_tx, output_tx));

    let (session_number, session) = registry
        .create_next_session(
            1,
            1,
            "test-relay".to_string(),
            "test-user".to_string(),
            backend,
            rb_types::ssh::SessionOrigin::Ssh { user_id: 1 },
            Some("127.0.0.1".to_string()),
            None,
        )
        .await;

    // Detach with 0 timeout (should expire immediately)
    session.detach(Duration::from_secs(0)).await;

    // Wait a tiny bit to ensure time passes
    tokio::time::sleep(Duration::from_millis(10)).await;

    registry.cleanup_expired_sessions().await;

    let retrieved = registry.get_session(1, 1, session_number).await;
    assert!(retrieved.is_none());
}

#[tokio::test]
async fn test_history_buffer() {
    let registry = SessionRegistry::new();
    let (input_tx, _) = mpsc::channel(1);
    let (output_tx, _) = broadcast::channel(1);
    let backend = Arc::new(LegacyChannelBackend::new(input_tx, output_tx));

    let (_, session) = registry
        .create_next_session(
            1,
            1,
            "test-relay".to_string(),
            "test-user".to_string(),
            backend,
            rb_types::ssh::SessionOrigin::Ssh { user_id: 1 },
            Some("127.0.0.1".to_string()),
            None,
        )
        .await;

    // Append some data
    session.append_to_history(b"hello ").await;
    session.append_to_history(b"world").await;

    let history = session.get_history().await;
    assert_eq!(history, b"hello world");
}
