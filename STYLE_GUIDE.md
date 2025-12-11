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
*   **Folder Style**: Prefer folder-style modules (e.g., `anchor/mod.rs`) over file-style modules (e.g., `anchor.rs`). This supports future expansion without renaming files later.

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
*   **Location**: Tests should be placed in a dedicated `tests/` folder at the crate root, adjacent to `src/`.
*   **Avoid**: Do not use inline `#[cfg(test)] mod tests` for integration or unit tests that can be separated. Do not use separate test files mixed into `src`.

## 15. Audit Logging
*   **Requirement**: All server-side events, state changes, and sensitive actions must trigger audit events.
*   **Implementation**: Use the project's Audit system (e.g., `rb-types::audit`, `server-core::audit`). Ensure every API endpoint that modifies state logs an event.

## 16. Dioxus & Server Functions
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

## 17. Error Handling (Recommended)
*   **Result Types**: Prefer returning `Result` types for any fallible operations.
*   **Propagation**: Uses `?` operator for clean error propagation.
*   **Context**: When wrapping errors, ensure sufficient context is preserved to debug the issue.

---

## 18. AI Agent Notes
*   **Compilation**: AI Agents should always use `cargo --message-format=short` when running checks or builds to limit token usage and reduce noise in output.
