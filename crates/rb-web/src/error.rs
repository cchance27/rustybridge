//! API error types for rb-web.
//!
//! This module provides structured error handling with proper HTTP status code mapping.

#[cfg(feature = "server")]
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// API errors with semantic HTTP status code mapping.
///
/// In debug builds, internal error details are exposed for easier debugging.
/// In release builds, internal errors return a generic message and log the details server-side.
#[derive(Error, Debug, Serialize, Deserialize, Clone)]
pub enum ApiError {
    /// 400 Bad Request - Validation failed
    #[error("validation failed: {message}")]
    Validation { message: String },

    /// 400 Bad Request - Invalid request format
    #[error("invalid request: {message}")]
    BadRequest { message: String },

    /// 401 Unauthorized - Authentication required
    #[error("unauthorized")]
    Unauthorized,

    /// 403 Forbidden - Insufficient permissions
    #[error("forbidden: {message}")]
    Forbidden { message: String },

    /// 404 Not Found - Resource doesn't exist
    #[error("{kind} '{identifier}' not found")]
    NotFound { kind: String, identifier: String },

    /// 409 Conflict - Resource already exists
    #[error("{kind} '{identifier}' already exists")]
    AlreadyExists { kind: String, identifier: String },

    /// 500 Internal Server Error - Unexpected error
    #[error("{}", internal_display_message(.message))]
    Internal { message: String },
}

/// Returns the display message for internal errors based on build mode.
fn internal_display_message(msg: &str) -> String {
    if cfg!(debug_assertions) {
        format!("internal error: {}", msg)
    } else {
        "an internal error occurred".to_string()
    }
}

impl ApiError {
    /// Create an internal error, logging in release mode.
    pub fn internal(err: impl std::fmt::Display) -> Self {
        let message = err.to_string();
        if !cfg!(debug_assertions) {
            tracing::error!(error = %message, "internal api error");
        }
        Self::Internal { message }
    }

    /// Convenience constructor for validation errors.
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation { message: message.into() }
    }

    /// Convenience constructor for bad request errors.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest { message: message.into() }
    }

    /// Convenience constructor for forbidden errors.
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::Forbidden { message: message.into() }
    }

    /// Convenience constructor for not found errors.
    pub fn not_found(kind: impl Into<String>, identifier: impl Into<String>) -> Self {
        Self::NotFound {
            kind: kind.into(),
            identifier: identifier.into(),
        }
    }

    /// Convenience constructor for already exists errors.
    pub fn already_exists(kind: impl Into<String>, identifier: impl Into<String>) -> Self {
        Self::AlreadyExists {
            kind: kind.into(),
            identifier: identifier.into(),
        }
    }
}

#[cfg(feature = "server")]
impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        use dioxus::fullstack::AsStatusCode as _;
        let status = self.as_status_code();
        (status, self.to_string()).into_response()
    }
}

// ============================================================================
// From implementations for error conversion
// ============================================================================

#[cfg(feature = "server")]
impl From<server_core::error::ServerError> for ApiError {
    fn from(err: server_core::error::ServerError) -> Self {
        use server_core::error::ServerError;
        match err {
            ServerError::NotFound(kind, id) => ApiError::NotFound { kind, identifier: id },
            ServerError::AlreadyExists(kind, id) => ApiError::AlreadyExists { kind, identifier: id },
            ServerError::NotPermitted(msg) => ApiError::Forbidden { message: msg },
            // StateStore errors flow through ServerError
            err => ApiError::internal(err),
        }
    }
}

/// Conversion from ApiError to Dioxus ServerFnError for server function compatibility.
impl From<ApiError> for dioxus::prelude::ServerFnError {
    fn from(err: ApiError) -> Self {
        dioxus::prelude::ServerFnError::new(err.to_string())
    }
}

/// Conversion from Dioxus ServerFnError to ApiError.
/// This is required when using `?` on Dioxus internal operations within a handler returning `Result<T, ApiError>`.
impl From<dioxus::prelude::ServerFnError> for ApiError {
    fn from(err: dioxus::prelude::ServerFnError) -> Self {
        ApiError::internal(err)
    }
}

#[cfg(feature = "server")]
impl dioxus::fullstack::AsStatusCode for ApiError {
    fn as_status_code(&self) -> axum::http::StatusCode {
        match self {
            Self::Validation { .. } | Self::BadRequest { .. } => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden { .. } => StatusCode::FORBIDDEN,
            Self::NotFound { .. } => StatusCode::NOT_FOUND,
            Self::AlreadyExists { .. } => StatusCode::CONFLICT,
            Self::Internal { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
