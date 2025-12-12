use server_core::sessions::session_backend::{LegacyChannelBackend, SessionBackend};
use tokio::sync::{broadcast, mpsc};

#[tokio::test]
async fn test_legacy_backend_send_and_subscribe() {
    // Create channels
    let (input_tx, mut input_rx) = mpsc::channel(10);
    let (output_tx, _) = broadcast::channel(10);

    // Create backend
    let backend = LegacyChannelBackend::new(input_tx, output_tx.clone());

    // Test subscribe
    let mut sub = backend.subscribe();

    // Test send (input)
    backend.send(b"test input".to_vec()).await.unwrap();
    let received_input = input_rx.recv().await.unwrap();
    assert_eq!(received_input, b"test input");

    // Test broadcast (output)
    output_tx.send(b"test output".to_vec()).unwrap();
    let received_output = sub.recv().await.unwrap();
    assert_eq!(received_output, b"test output");
}

#[tokio::test]
async fn test_legacy_backend_resize_ignored() {
    let (input_tx, _) = mpsc::channel(10);
    let (output_tx, _) = broadcast::channel(10);
    let backend = LegacyChannelBackend::new(input_tx, output_tx);

    // Resize should be Ok but do nothing
    let result = backend.resize(80, 24).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_legacy_backend_close() {
    let (input_tx, _) = mpsc::channel(10);
    let (output_tx, _) = broadcast::channel(10);
    let backend = LegacyChannelBackend::new(input_tx, output_tx);

    // Close should be Ok
    let result = backend.close().await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_broadcast_send_fails_without_receivers() {
    let (tx, rx) = broadcast::channel::<Vec<u8>>(10);
    drop(rx); // no receivers
    assert!(tx.send(b"first".to_vec()).is_err());

    let mut rx2 = tx.subscribe();
    tx.send(b"second".to_vec()).unwrap();
    assert_eq!(rx2.recv().await.unwrap(), b"second".to_vec());
}

#[tokio::test]
async fn test_receiver_resubscribe_starts_from_same_point() {
    let (tx, rx1) = broadcast::channel::<Vec<u8>>(10);
    let mut rx1 = rx1;
    let mut rx2 = rx1.resubscribe();

    tx.send(b"hello".to_vec()).unwrap();
    assert_eq!(rx1.recv().await.unwrap(), b"hello".to_vec());
    assert_eq!(rx2.recv().await.unwrap(), b"hello".to_vec());
}
