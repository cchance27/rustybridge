# Repository Guidelines

## Project Structure & Module Organization
- Workspace root (`Cargo.toml`) orchestrates five crates: `rb-cli` (entry binaries), `client-core`, `server-core`, `ssh-core`, and `state-store`.
- Shared assets: SQLx migrations live under `crates/state-store/migrations/{client,server}`; default SQLite files are created under the user's data/state dirs.
- `rb-cli/src/bin/rb.rs` launches the client CLI; `rb-cli/src/bin/rb-server.rs` is the jump-host wrapper.

## Build, Test, and Development Commands
- `cargo fmt` — formats every crate; run before committing. Warnings about nightly-only options are expected.
- `cargo check` — fast validation of the entire workspace (preferred during development).
- `cargo test -p <crate>` — run tests for a specific crate once they are added (e.g., `cargo test -p client-core`).
- `cargo run -p rb-cli --bin rb -- <args>` — start the client CLI; swap `rb` for `rb-server` to boot the relay server.

## Coding Style & Naming Conventions
- Rust 2024 edition with standard rustfmt configuration (`rustfmt.toml` at root), requires +nightly for cargo fmt when run. Stick to idiomatic snake_case for modules/functions and CamelCase for types.
- Keep modules small and reuse shared utilities by adding code to `ssh-core` or `state-store` instead of duplicating logic.
- Prefer workspace dependencies declared in the root `Cargo.toml`; add new crates there so versions remain synchronized.

## Testing Guidelines
- Tests should live in (`mod tests` inside source files) or under a dedicated `tests/` directory per crate.
- Name tests after the behavior under test (e.g., `fn rejects_unknown_host_key()`), and aim for coverage of error paths, especially around SQLx interactions.
- For stateful tests, use in-memory SQLite URLs (`sqlite::memory:`) to avoid touching real user data.

## Commit & Pull Request Guidelines
- Write imperative commit messages (“Add relay host model”, “Refactor client CLI”). Group related changes into single commits.
- Pull requests should describe the motivation, summarize changes, and note any testing performed (`cargo check`, `cargo fmt`, etc.). Attach screenshots or logs when UI/TUI output changes.

## Security & Configuration Tips
- Never log secrets: scrub passwords before emitting tracing output, and prefer `warn!`/`info!` only for high-level events.
- When adding new persistence paths, ensure `state-store` handles directory creation and logs when migrations initialize.
