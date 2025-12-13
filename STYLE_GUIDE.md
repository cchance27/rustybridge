# Project Style Guide

This document outlines the required rules and conventions for the `rustybridge` project. All contributors (human and AI) must adhere to these guidelines to ensure code quality, maintainability, and consistency.

## 1. Control Flow
*   **collapsed_if**: If statements should always be collapsed if possible instead of nesting them.
    *   *Bad:*
        ```rust
        if x {
            if y {
                // ...
            }
        }
        ```
    *   *Good:*
        ```rust
        if x && y {
            // ...
        }
        ```

## 2. Formatting
*   **Toolchain**: Always use `cargo +nightly fmt`. Nightly is required due to our specific configuration settings.

## 3. Module Structure
*   **Module Style**: Prefer file-style modules (e.g., `anchor.rs` and `anchor/`) over folder-style modules (e.g., `anchor/mod.rs`). This is the modern Rust convention and keeps the file tree cleaner, Nested modules should result in `anchor.rs` and `anchor/submodule.rs`.

## 4. Data Access
*   **State Store**: The `state-store` crate should encompass *all* database access functions. No direct DB queries should exist in consumer crates.

## 5. Business Logic Separation
*   **Core Crates**:
    *   `server-core`: Handles all server-side business logic.
    *   `client-core`: Handles all client-side (CLI) business logic.
*   The web/server crates should primarily handle routing and API interfacing, delegating logic to the core crates.

## 6. Type Definitions
*   **Shared Types**: All shared types should be implemented in `rb-types`. Avoid defining types in leaf crates if there is any chance they will be needed elsewhere.

## 7. Complex Types
*   **Internal Types**: Complex type annotations should be defined as internal types (e.g., `type MyComplexMap = HashMap<String, Vec<Arc<Mutex<Data>>>>;`) and stored in `rb-types`. This improves readability and refactoring.

## 8. File Size Limits
*   **Maintainability**: File sizes should be between **300-600 lines maximum**.
*   **Refactoring**: If a file grows beyond this limit, it must be refactored. Break it down into helpers, sub-modules, or separate components.

## 9. Helper Functions
*   **Proactive Design**: Think ahead. If a function might be useful in other areas, aggressively create helpers rather than inlining logic. 
*   **DRY**: Don't Repeat Yourself.

## 10. Documentation
*   **Requirement**: All functions must have clear documentation.
*   **Maintenance**: Docs must be updated immediately if changes are made to the underlying function.
*   **Style**: Use short, concise, and accurate descriptions.

## 11. Dependency Management
*   **Workspace Dependencies**: Cargo dependencies should be managed at the workspace level (in the root `Cargo.toml` `[workspace.dependencies]`) to standardize features and versions across all crates.

## 12. Reusability Check
*   **Search First**: Before implementing new functionality, properly search the existing codebase to ensure you are not reimplementing functionality that already exists.

## 13. Code Deduplication
*   **Aggressive Deduplication**: Actively look to deduplicate code through:
    *   Helper functions
    *   Smart use of macros

## 14. Testing

### Unit Tests (Sibling Files)
Unit tests that need access to private/internal items should be placed in sibling `_tests.rs` files:

```
src/
├── my_module.rs
└── my_module_tests.rs
```

Include the test file in the source module:
```rust
#[cfg(test)]
#[path = "my_module_tests.rs"]
mod tests;
```

**When to use:** Testing private functions, internal state, or implementation details.

### Integration Tests (`tests/` Directory)
Integration tests that only use the public API should be placed in the `tests/` directory at the crate root:

```
crate_root/
├── src/
└── tests/
    └── feature_test.rs
```

**When to use:** Testing the crate's public API as an external consumer would.

### Test Utilities
Shared test utilities (fixtures, mocks, helpers) should be placed in `src/test_support.rs` and exported conditionally:

```rust
#[cfg(feature = "test-support")]
pub mod test_support;
```

### Naming Conventions
- Unit test files: `<module>_tests.rs`
- Integration test files: `<feature>_test.rs` or `<feature>.rs`
- Test functions: `test_<what_is_being_tested>()`

### What NOT to Do
- **Avoid**: Inline `#[cfg(test)] mod tests { ... }` blocks in source files
- **Avoid**: Test files mixed into `src/` without the `_tests.rs` suffix

## 15. Audit Logging
*   **Requirement**: All server-side events, state changes, and sensitive actions must trigger audit events.
*   **Implementation**: Use the project's Audit system (`rb-types::audit`, `server-core::audit`). Ensure every API endpoint that modifies state logs an event.
*   **Macro Usage**: Use the `audit!()` macro for consistent audit logging:
    ```rust
    audit!(context, UserCreated { user_id: id, username: name });
    ```
*   **Tracing Integration**: The `audit!()` macro automatically emits a corresponding `tracing` event at the appropriate level (INFO for most actions, WARN/ERROR for failures). **Do not add redundant `tracing` calls immediately before or after `audit!()` calls.**

## 16. Tracing & Logging
*   **Crate**: Use `tracing` for all logging. Do not use `log`, `println!`, or `web_sys::console` directly.
*   **Message Style**:
    *   **Lowercase**: All log messages should start with a lowercase letter.
        *   *Bad:* `info!("User created");`
        *   *Good:* `info!("user created");`
    *   **Structured Fields**: Use structured fields instead of string concatenation:
        *   *Bad:* `info!("user {} created", user_id);`
        *   *Good:* `info!(user_id, "user created");`
    *   **Field Prefixes**: Use appropriate display prefixes:
        *   `%val` for `Display` formatting
        *   `?val` for `Debug` formatting
        *   Example: `info!(user_id = %id, details = ?metadata, "operation complete");`
*   **Imports**: Prefer direct imports over fully-qualified paths:
    *   *Bad:* `tracing::info!(...)`
    *   *Good:* `use tracing::{info, warn, error}; ... info!(...)`
*   **Feature Guards**: Logging is available on all platforms via `tracing-web` (WASM) and `tracing-subscriber` (server). **Do not add `#[cfg(feature = "web")]` guards around logging calls.**
*   **Log Levels**:
    *   `ERROR`: Unrecoverable errors, panics, critical failures
    *   `WARN`: Recoverable issues, validation failures, deprecated usage
    *   `INFO`: Significant state changes, user actions, lifecycle events
    *   `DEBUG`: Detailed flow information for debugging
    *   `TRACE`: Very verbose, step-by-step execution details
*   **Dynamic Configuration**:
    *   Server log level is stored in the database (`server_options.log_level`), configurable via Server Settings UI.
    *   Client (WASM) log level is stored in `localStorage` (`rb_web_log_level`), configurable via Profile page.

## 17. Dioxus & Server Functions
*   **Macros**: Use Dioxus 0.7+ server macros: `#[get]`, `#[post]`, `#[put]`, `#[delete]`. Do not use `#[server]`.
*   **DI Style Imports**: Use Dependency Injection style for extractors. Define them in the macro attributes and use them directly in the function body. Do not add them as function arguments.
    *   *Example:*
        ```rust
        #[get("/api/example", auth: WebAuthSession)]
        pub async fn example_endpoint() -> Result<(), ServerFnError> {
            // 'auth' is available here automatically
            ensure_server_claim(&auth, ClaimLevel::View)?;
            Ok(())
        }
        ```

## 18. Error Handling (Recommended)
*   **Result Types**: Prefer returning `Result` types for any fallible operations.
*   **Propagation**: Uses `?` operator for clean error propagation.
*   **Context**: When wrapping errors, ensure sufficient context is preserved to debug the issue.

---

## 19. AI Agent Notes
*   **Compilation**: AI Agents should always use `cargo --message-format=short` when running checks or builds to limit token usage and reduce noise in output.
