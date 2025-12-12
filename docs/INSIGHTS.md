# Codebase Insights & Architectural Overview

## Project Structure & Architecture
**RustyBridge** is designed as a modular SSH bastion/relay system with a clear separation of concerns. The workspace is structured into logical crates that promote maintainability and parallel development.

### Key Strengths
- **Modular Design:** The separation into `client-core`, `server-core`, `rb-types`, and `state-store` prevents tight coupling and circular dependencies.
- **Data/Persistence Separation:** The architectural decision to separate data definitions (`rb-types`) from persistence logic (`state-store`) is a strong pattern.
- **Smart Feature Usage:** `state-store` utilizes `client` and `server` feature flags to tailor the persistence layer for different contexts (lightweight vs. full database), maximizing code reuse.
- **Security-First RBAC:** The `rb-types` crate implements a robust, hierarchical, claims-based Role-Based Access Control system (`claims.rs`).

## Security Observations

### ⚠️ Critical Findings
- **Windows File Permissions:** In `crates/server-core/src/secrets.rs`, the `ensure_secure_permissions` function defaults to `Ok(false)` on non-Unix platforms. This means critical security files (like `secrets.salt`) are created with default OS permissions on Windows, potentially leaving them readable by other users.
    - **Action Required:** Implement ACL handling for Windows to restrict access to the file owner.

### Noted Risks
- **Timing Attacks:** The password verification logic in `server-core/src/auth.rs` explicitly notes susceptibility to timing attacks but accepts the risk due to the networked nature of the service.
- **Legacy Cryptography:** `ssh-core` contains manually implemented legacy PEM parsing (using MD5/DES) to support older key formats. While necessary for compatibility, this code path relies on weak algorithms.
- **Sensitive Data in Memory:** Passwords, private keys, and OIDC client secrets are currently stored as plain `String`. They do not implement `Zeroize`, meaning sensitive material may persist in memory after use.

## Refactoring Opportunities

### "God Object" Decoupling
- **Target:** `crates/server-core/src/handler/session.rs` (`ServerHandler`)
- **Issue:** The `ServerHandler` currently manages too many responsibilities: SSH channel lifecycle, TUI state management, and Relay connection logic.
- **Recommendation:** Decompose this into specialized handlers (e.g., `TuiHandler`, `RelayHandler`) that the main session handler delegates to.

### Secrets Management
- **Target:** `crates/server-core/src/secrets.rs`
- **Issue:** The file mixes logic for "v1" (Argon2-based) and "v2" (HKDF-based) encryption schemes with global functions.
- **Recommendation:** Encapsulate versioning logic into a dedicated `SecretManager` struct to cleaner abstraction and easier future upgrades.

## Technical Debt
- **Manual PEM Parsing:** `crates/ssh-core/src/keys.rs` contains custom parsing logic for "BEGIN RSA PRIVATE KEY" blocks. This should ideally be offloaded to a standard crate like `ssh-key` if possible.
- **Web Routing:** `crates/rb-web` contains TODOs regarding moving OIDC routes to standard Dioxus handlers to unify the routing model.
- **Hardcoded Claims:** `rb-types` contains hardcoded claim lists which may require recompilation to change permissions.

## Deep Dive: Strong Typing & State Safety

A comprehensive review of `rb-types` and usage in `server-core` reveals significant opportunities to leverage the Rust type system to prevent bugs and improve maintainability.

### 1. Primitive Obsession
Concepts that have distinct meanings are currently represented by generic primitives (`i64`, `String`). This allows for accidental swapping of IDs (e.g., passing a `UserId` where a `RelayId` is expected) and requires manual validation logic scattered throughout the codebase.
- **IDs:** `UserId`, `RelayId`, `SessionId`, `GroupId`, `RoleId` are raw `i64` or `u32`.
    - *Fix:* Introduce `struct UserId(i64)`, `struct RelayId(i64)`, etc.
- **Names:** `Username` is `String`.
    - *Fix:* Introduce `struct Username(String)` to enforce validation rules (length, allowed characters) at the boundary.
- **Network Addresses:** `RelayAddress` is `Vec<String>`. Endpoints are `String` ("host:port").
    - *Fix:* Use `std::net::SocketAddr` or a dedicated `HostPort` struct.
- **Parsing Logic:** `LoginTarget` parsing happens manually in `server-core/src/handler/auth.rs`.
    - *Fix:* Implement `FromStr` for a `LoginTarget` type in `rb-types`.

### 2. String-Based Enums
Finite sets of options are represented as strings. This is fragile (typo-prone) and inefficient.
- **Credential Kind:** `CredentialInfo.kind` uses strings like `"password"`, `"ssh_key"`, `"agent"`.
- **Username Mode:** `"fixed"`, `"blank"`, `"passthrough"`.
- **Auth Web Config:** `"none"`, `"saved"`, `"custom"`.
    - *Fix:* Replace all these with proper Rust `enum` definitions with `#[derive(Serialize, Deserialize)]`.

### 3. Invalid State Representability
Data structures currently allow combinations of data that should be impossible.
- **Session Summaries:** `UserSessionSummary` is a flat struct with a `state` enum and optional fields like `detached_at`. It is currently possible to construct a session that is `Attached` but has a `detached_at` timestamp.
    - *Fix:* Refactor into a state machine enum:
      ```rust
      enum UserSession {
          Attached(AttachedSessionData),
          Detached(DetachedSessionData),
          Closed(ClosedSessionData),
      }
      ```
- **Request Objects:** `CreateCredentialRequest` has optional fields for all secret types (`password`, `private_key`). A user could technically send both or neither, requiring runtime validation.
    - *Fix:* Use an enum for the payload: `enum CreateCredentialPayload { Password(String), SshKey { key: String, passphrase: Option<String> }, ... }`.

### 4. Sensitive Data Handling
- **Issue:** Secrets (passwords, keys, tokens) are plain `String`s.
- **Fix:** Wrap these in a `Secret<String>` type (using the `secrecy` crate or custom wrapper) that implements `Zeroize` to ensure they are wiped from memory when dropped.

## Deep Dive: `server-core` Architectural Violations and Refactor Candidates

### 1. Widespread SQL Bypasses
- **Issue:** `server-core` extensively uses raw `sqlx` queries directly, completely bypassing the `state-store` abstraction layer. This creates tight coupling between `server-core` and the database schema, making schema evolution difficult and business logic harder to test.
    - **Example Locations:** `ssh_server.rs` (FIXME comment acknowledges this), `relay_host/management.rs`, `relay_host/options.rs`, `relay/connection.rs`, `user.rs`, `tui.rs`, `credential.rs`, `handler/relay.rs`.
    - **Action Required:** All database access logic *must* be encapsulated within the `state-store` crate. `server-core` should only interact with `state-store`'s public API.

### 2. Types Requiring Relocation to `rb-types`
- **Session State:** `server-core/src/sessions.rs` defines `SessionState`. This enum is crucial for the web UI (`rb-web`) and other components to understand session status.
    - **Action Required:** Move `SessionState` to `rb-types`.
- **Session Backend Error:** `server-core/src/sessions/session_backend.rs` defines `SessionError`. A common error type for session-related issues should reside in `rb-types`.
    - **Action Required:** Move `SessionError` to `rb-types`.
- **Session Registry Key:** The `SessionRegistry` in `server-core/src/sessions.rs` uses a tuple `(i64, i64, u32)` as a key, with a `FIXME` comment noting it as "disgusting".
    - **Action Required:** Define a newtype struct in `rb-types` (e.g., `SessionKey { user_id: UserId, relay_id: RelayId, session_number: SessionNumber }`) to improve type safety and readability.

### 3. "God Structs" and Poor Separation of Concerns
- **`SshSession` Struct:** In `server-core/src/sessions.rs`, `SshSession` is a prime "God Struct" candidate. It manages state, metrics, history, I/O backend, and various connection counts. Its constructor has a `FIXME` about too many arguments.
    - **Action Required:** Break `SshSession` into smaller, more focused structs or components, potentially using a composition pattern.

### 4. Generic Logic for `ssh-core`
- **Issue:** While not fully analyzed, the presence of SSH-specific logic (e.g., certificate handling) within `server-core/src/auth/ssh_cert.rs` suggests it might belong in `ssh-core`.
    - **Action Required:** Investigate and move generic SSH logic to `ssh-core` where appropriate.

## Deep Dive: `client-core` and `ssh-core` for Duplication and Type Safety

### 1. Duplicated Client-side SSH Authentication Logic
- **Issue:** Very similar client-side SSH authentication flows are implemented in both `client-core/src/auth.rs` and `server-core/src/relay/auth.rs`. This includes handling various authentication methods (password, publickey, agent, keyboard-interactive) using `russh::client`.
- **Action Required:** Consolidate this logic into a shared module within `ssh-core` or, if `ssh-core` is meant for fundamental primitives, create a new `ssh-client-utils` crate.

### 2. Duplicated Host Key Verification Logic
- **Issue:** The core logic for connecting to an SSH server as a client to fetch and verify its host key is duplicated across `client-core/src/hostkeys.rs`, `server-core/src/relay_host/management.rs`, and `server-core/src/tui.rs`.
- **Action Required:** Centralize the core logic of establishing a connection, capturing the public key, and comparing fingerprints into `ssh-core`. The user interaction and storage aspects can remain local to the respective crates.

### 3. Public Key Utilities
- **Issue:** While private key loading is centralized in `ssh_core::keys::load_private_key_from_str`, public key parsing and serialization are somewhat scattered.
- **Action Required:** Add more comprehensive and consistent public key utilities (parsing, serialization, fingerprinting) to `ssh-core`.

### 4. `ssh-core` Legacy Cryptography and Weak Error Types
- **Manual Legacy PEM Parsing and Cryptography:**
    - **Issue:** `ssh-core::keys.rs` contains custom, potentially vulnerable implementations (`parse_rsa_pem`, `decrypt_des_ede3`, `evp_bytes_to_key`, `load_pkcs1`) for handling legacy PEM private keys.
    - **Action Required:** Prioritize investigating and adopting a thoroughly vetted, higher-level cryptographic library (if one exists and is suitable) to replace these custom implementations for robustness and security. Clearly mark this legacy support as a potential risk.
- **Weak Error Types:**
    - **Issue:** `ssh-core::keys.rs` frequently converts specific errors into `SshCoreError::Other(format!(...))`. This obscures the root cause of errors.
    - **Action Required:** Introduce more granular error variants within `ssh-core::error::SshCoreError` (e.g., `KeyParsingError`, `UnsupportedCipher`, `DecryptionError`) to provide clearer diagnostics and enable more precise error handling.