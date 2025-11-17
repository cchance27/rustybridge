# rb-cli

`rb-cli` hosts the workspace binaries:
- `rb`: a legacy-friendly SSH client that supports password, public-key, agent, keyboard-interactive, and certificate authentication plus optional agent forwarding.
- `rb-server`: the jump-host wrapper that embeds the relaxed SSH server from `server-core` and manages relay host metadata.

## Usage
```bash
cargo run -p rb-cli --bin rb -- demo@example.com                # connect as demo
cargo run -p rb-cli --bin rb -- --identity ~/.ssh/id_legacy host
cargo run -p rb-cli --bin rb-server -- --bind 0.0.0.0 --port 2222
```
The CLI simply parses flags/envvars and delegates to `client-core` / `server-core`, keeping binaries thin and feature-flag friendly.
