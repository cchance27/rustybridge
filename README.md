# rustybridge

A legacy-friendly SSH toolkit that keeps forgotten hardware reachable while still giving modern operators control. rustybridge ships both a relaxed SSH client (`rb`) and an embeddable jump host (`rb-server`). By default we stick to modern crypto, but you can explicitly opt into older ciphers, hashes, or KEX so you can nurse decades-old routers, kiosks, or lab gear through one more upgrade cycle.

## Highlights
- **Legacy crypto on tap**: Toggle relaxed suites (`--insecure`) when you must talk to ancient firmware; we require explicit approval each time.
- **Modular workspace**: Separate crates for CLI, client/session logic, server logic, SSH helpers, and SQLite state handling keep contributions focused.
- **SQLite-backed trust stores**: Client host keys and server state are versioned via SQLx migrations and initialized automatically per user.
- **Feature-rich client**: Password, public-key, agent, keyboard-interactive, and certificate auth are all supported, along with Xterm-friendly terminal handling.

## Workspace Layout
```
crates/
  rb-cli       # bin targets and CLI parsing
  client-core  # SSH client runtime & auth strategies
  server-core  # Jump host server + relay management
  ssh-core     # Shared session/terminal utilities
  state-store  # SQLite bootstrap + migrations
```

## Quick Start
```bash
cargo run -p rb-cli --bin rb -- user@host             # standard password auth
rb --identity ~/.ssh/id_ed25519 host.example.com      # public-key auth
rb --agent-auth --forward-agent legacy-host           # SSH agent signatures & forwarding
rb --keyboard-interactive bastion.example.com         # otp/mfa prompts

rb-server --bind 0.0.0.0 --port 2222                  # run the jump host
rb-server --add-host 10.0.0.5:22 --hostname legacy-db # manage relay targets
```
All binaries source their SQLite state from `~/Library/Application Support/rustybridge/` (macOS) or the platform’s data/state dirs. The first run logs when a database is created and migrations applied.

## Security & Safety Notes
- Legacy algorithms drastically reduce security; only pass `--insecure` (client) or enable relaxed KEX server-side when you fully trust the endpoint and network.
- We never log raw credentials, but you should still clear shell history when sharing terminals.
- Host key prompts default to “reject”, so you must opt in per-host (with `--accept-hostkey`/`--accept-store-hostkey`).

## Contributing
See `AGENTS.md` for project structure, coding style, test guidance, and pull-request expectations. Contributions that improve safety (e.g., per-host crypto policies, audit logging) are especially welcome.
