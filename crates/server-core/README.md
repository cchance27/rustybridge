# server-core

`server-core` exposes the embedded SSH server and relay management used by `rb-server`. It handles:
- russh server configuration with legacy-friendly cipher suites (opt-in) and Ed25519 host keys.
- SQLite-backed state for server options and relay hosts via `state-store`.
- A minimal TUI/handler stack so inbound sessions see a friendly prompt before being proxied.

## Usage
```rust
let cfg = server_core::ServerConfig { bind: "0.0.0.0".into(), port: 2222, roll_hostkey: false };
server_core::run_server(cfg).await?;
server_core::add_relay_host("10.0.0.5:22", "legacy-db").await?;
```
`rb-server` is the canonical consumer; import this crate if you want to embed the jump host elsewhere.
