# rb-cli

`rb-cli` hosts the workspace binaries:
- `rb`: a legacy-friendly SSH client that supports password, public-key, agent, keyboard-interactive, and certificate authentication plus optional agent forwarding.
- `rb-server`: the jump-host wrapper that embeds the SSH server from `server-core` (secure defaults for inbound) and manages relay host metadata.

## Usage
```bash
cargo run -p rb-cli --bin rb -- demo@example.com                # connect as demo
cargo run -p rb-cli --bin rb -- --identity ~/.ssh/id_legacy host
cargo run -p rb-cli --bin rb-server -- --bind 0.0.0.0 --port 2222
```
Forwarding & subsystems:
```bash
rb -L 8080:internal:80 user@host                 # local TCP forward
rb -R 0.0.0.0:6200:jump:6200 user@host          # remote TCP forward
rb -D 1080 user@host                            # dynamic SOCKS
rb --local-unix-forward /tmp/l=/var/run/r user@host  # unix socket (Unix)
rb --send-env LANG=en_US.UTF-8 --forward-locale=lang user@host
rb --subsystem sftp user@host                   # run subsystem
```

Interactive escapes (Enter then `~`): `~.` disconnect, `~R` rekey, `~V/~v` verbosity up/down, `~#` list forwards, `~~` literal `~`, `~^Z` suspend (Unix), `~&` detach stdin (reattach with `SIGUSR1`).

The CLI simply parses flags/envvars and delegates to `client-core` / `server-core`, keeping binaries thin and feature-flag friendly.
