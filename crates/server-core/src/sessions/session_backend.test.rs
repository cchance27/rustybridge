#[cfg(test)]
mod tests {
    use tokio::sync::{broadcast, mpsc};

    use super::*;

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
}
