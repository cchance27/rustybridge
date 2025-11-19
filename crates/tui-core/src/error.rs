use thiserror::Error;

/// Errors that can occur in TUI applications
#[derive(Error, Debug)]
pub enum TuiError {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Terminal backend error
    #[error("terminal error: {0}")]
    Terminal(String),

    /// App-specific error
    #[error("app error: {0}")]
    App(String),
}

/// Result type alias for TUI operations
pub type TuiResult<T> = Result<T, TuiError>;
