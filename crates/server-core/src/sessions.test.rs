use std::time::Duration;

use tokio::sync::{broadcast, mpsc};

use super::*;

#[tokio::test]
async fn test_session_creation_and_retrieval() {
    let registry = SessionRegistry::new();
    let (input_tx, _) = mpsc::channel(1);
    let (output_tx, _) = broadcast::channel(1);
    let (close_tx, _) = broadcast::channel(1);

    let (session_number, session) = registry.create_next_session(1, 1, input_tx, output_tx, close_tx).await;

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
    let (close_tx1, _) = broadcast::channel(1);

    let (input_tx2, _) = mpsc::channel(1);
    let (output_tx2, _) = broadcast::channel(1);
    let (close_tx2, _) = broadcast::channel(1);

    let (num1, _) = registry.create_next_session(1, 1, input_tx1, output_tx1, close_tx1).await;
    let (num2, _) = registry.create_next_session(1, 1, input_tx2, output_tx2, close_tx2).await;

    assert_eq!(num1, 1);
    assert_eq!(num2, 2);
}

#[tokio::test]
async fn test_session_cleanup() {
    let registry = SessionRegistry::new();
    let (input_tx, _) = mpsc::channel(1);
    let (output_tx, _) = broadcast::channel(1);
    let (close_tx, _) = broadcast::channel(1);

    let (session_number, session) = registry.create_next_session(1, 1, input_tx, output_tx, close_tx).await;

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
    let (close_tx, _) = broadcast::channel(1);

    let (_, session) = registry.create_next_session(1, 1, input_tx, output_tx, close_tx).await;

    // Append some data
    session.append_to_history(b"hello ").await;
    session.append_to_history(b"world").await;

    let history = session.get_history().await;
    assert_eq!(history, b"hello world");
}
