# Error Handling & Logging Refactor Plan

## Overview
This document outlines the plan to refactor error handling and logging across the `rustybridge` codebase. The goal is to move towards a more consistent, Rust-centric error handling strategy and adopt structured tracing for better observability.

## Objectives
1.  **Unify Error Handling**: Eliminate inconsistent error returns (e.g., mixing `Result`, `Option`, and custom error types unpredictably).
2.  **Structured Logging**: Migrate from format-string style logging (e.g., `info!("User {} logged in", user)`) to structured tracing (e.g., `info!(user = %user, "user logged in")`).
3.  **Prevent Error Leaks**: Ensure internal error details (stack traces, database errors) are not leaked to the frontend or API clients.
4.  **Contextual Errors**: Use `anyhow::Context` or similar mechanisms to provide rich context for errors as they propagate up the stack.

## Action Items

### 1. Error Types
- [ ] Audit existing error types in `server-core` and `rb-web`.
- [ ] Define a comprehensive `AppError` enum (or similar) that categorizes errors (e.g., `AuthError`, `DatabaseError`, `ValidationError`).
- [ ] Ensure all public API endpoints return sanitized error messages safe for client consumption.

### 2. Structured Tracing
- [ ] Audit all `tracing::{info, warn, error, debug}` calls.
- [ ] Convert format strings to structured key-value pairs.
  - **Before:** `info!("Failed to connect to relay {}", relay_id);`
  - **After:** `info!(relay_id = %relay_id, "failed to connect to relay");`
- [ ] Ensure sensitive data (passwords, secrets) is never logged, even in debug mode. Use `SecretString` or `Redacted` wrappers.

### 3. Error Leaks & Observability
- [ ] Review API error responses to ensure no internal implementation details are exposed.
- [ ] Implement a global error handler (e.g., in Axum middleware) to catch unhandled errors and log them securely while returning a generic 500 to the user.
- [ ] Add request IDs to all logs to trace requests across the system.

### 4. Implementation Strategy
- This refactor will be executed in phases to minimize disruption.
- **Phase 1:** Logging migration (low risk).
- **Phase 2:** Error type unification (medium risk).
- **Phase 3:** API error sanitization (high importance).
