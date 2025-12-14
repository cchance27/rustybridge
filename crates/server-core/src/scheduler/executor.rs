//! Task execution logic with retry, timeout, panic-catching.

use futures::FutureExt;
use rb_types::tasks::*;
use std::panic::AssertUnwindSafe;
use tokio::time::{Duration, timeout};
use tracing::{error, info, warn};

/// Per-task execution configuration.
#[derive(Clone, Debug)]
pub struct TaskConfig {
    /// Maximum execution time before timeout (None = no limit).
    pub timeout: Option<TimeoutSecs>,
    /// Number of retry attempts on failure.
    pub max_retries: MaxRetries,
    /// Seconds to wait between retries.
    pub retry_delay_secs: u64,
}

impl Default for TaskConfig {
    fn default() -> Self {
        Self {
            timeout: Some(TimeoutSecs(300)), // 5 minutes default
            max_retries: MaxRetries(0),
            retry_delay_secs: 10,
        }
    }
}

/// Execute a task with all middleware applied.
pub async fn execute_with_middleware<F, Fut, E>(task_name: &str, config: &TaskConfig, task_fn: F) -> TaskOutcome
where
    F: Fn() -> Fut + Send + Sync,
    Fut: std::future::Future<Output = Result<(), E>> + Send,
    E: std::fmt::Display + Send + 'static,
{
    let mut attempts = 0;
    // max_retries 0 means 1 attempt total
    let max_attempts = config.max_retries.0 + 1;
    let start = std::time::Instant::now();

    loop {
        attempts += 1;

        // Wrap future with timeout first, then catch_unwind
        let fut = async {
            if let Some(timeout_secs) = config.timeout {
                match timeout(Duration::from_secs(timeout_secs.0), task_fn()).await {
                    Ok(res) => res.map_err(|e| e.to_string()),
                    Err(_) => Err("timeout".to_string()),
                }
            } else {
                task_fn().await.map_err(|e| e.to_string())
            }
        };

        // Catch panics in the future execution
        let result = AssertUnwindSafe(fut).catch_unwind().await;

        match result {
            // Panic caught
            Err(_) => {
                error!(task = task_name, "task panicked");
                return TaskOutcome::Panicked {
                    message: "Task panicked".to_string(),
                };
            }
            // Execution completed (Ok or Err from task/timeout)
            Ok(execution_result) => {
                match execution_result {
                    Ok(_) => {
                        let duration_ms = start.elapsed().as_millis() as u64;
                        if attempts > 1 {
                            info!(task = task_name, attempts, "task succeeded after retries");
                        }
                        return TaskOutcome::Success { duration_ms };
                    }
                    Err(error_msg) => {
                        if error_msg == "timeout" {
                            warn!(task = task_name, "task timed out");
                        } else {
                            warn!(task = task_name, error = %error_msg, "task failed");
                        }

                        if attempts < max_attempts {
                            // Wait before retry
                            tokio::time::sleep(Duration::from_secs(config.retry_delay_secs)).await;
                            continue;
                        }

                        let duration_ms = start.elapsed().as_millis() as u64;
                        if error_msg == "timeout" {
                            return TaskOutcome::TimedOut {
                                timeout_secs: config.timeout.map(|t| t.0).unwrap_or(0),
                            };
                        } else {
                            return TaskOutcome::Failed {
                                error: error_msg,
                                duration_ms,
                            };
                        }
                    }
                }
            }
        }
    }
}
