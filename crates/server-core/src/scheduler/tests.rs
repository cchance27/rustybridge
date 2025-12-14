//! Unit tests for task executor middleware (timeout, retry, panic-catching).

use super::executor::{TaskConfig, execute_with_middleware};
use rb_types::tasks::{MaxRetries, TaskOutcome, TimeoutSecs};
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_execution_success() {
    let config = TaskConfig::default();
    let outcome = execute_with_middleware("test_success", &config, || async { Ok::<(), String>(()) }).await;

    match outcome {
        TaskOutcome::Success { .. } => {}
        _ => panic!("Expected success, got {:?}", outcome),
    }
}

#[tokio::test]
async fn test_execution_failure_no_retry() {
    let config = TaskConfig {
        max_retries: MaxRetries(0),
        ..TaskConfig::default()
    };

    let outcome = execute_with_middleware("test_fail", &config, || async { Err::<(), String>("boom".to_string()) }).await;

    match outcome {
        TaskOutcome::Failed { error, .. } => assert_eq!(error, "boom"),
        _ => panic!("Expected failed, got {:?}", outcome),
    }
}

#[tokio::test]
async fn test_execution_retry_success() {
    let config = TaskConfig {
        max_retries: MaxRetries(2),
        retry_delay_secs: 0, // Instant retry for test
        ..TaskConfig::default()
    };

    let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let outcome = execute_with_middleware("test_retry", &config, || {
        let c = counter.clone();
        async move {
            if c.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 2 {
                Err::<(), String>("transient error".to_string())
            } else {
                Ok(())
            }
        }
    })
    .await;

    match outcome {
        TaskOutcome::Success { .. } => {}
        _ => panic!("Expected success after retry, got {:?}", outcome),
    }

    assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 3);
}

#[tokio::test]
async fn test_execution_timeout() {
    let config = TaskConfig {
        timeout: Some(TimeoutSecs(1)),
        max_retries: MaxRetries(0),
        ..TaskConfig::default()
    };

    let outcome = execute_with_middleware("test_timeout", &config, || async {
        sleep(Duration::from_millis(1500)).await;
        Ok::<(), String>(())
    })
    .await;

    match outcome {
        TaskOutcome::TimedOut { timeout_secs } => assert_eq!(timeout_secs, 1),
        _ => panic!("Expected timeout, got {:?}", outcome),
    }
}

#[tokio::test]
async fn test_execution_panic_catch() {
    let config = TaskConfig::default();

    let outcome = execute_with_middleware("test_panic", &config, || async {
        panic!("unexpected panic");
        #[allow(unreachable_code)]
        Ok::<(), String>(())
    })
    .await;

    match outcome {
        TaskOutcome::Panicked { .. } => {}
        _ => panic!("Expected panic catch, got {:?}", outcome),
    }
}
