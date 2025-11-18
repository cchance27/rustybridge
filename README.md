# rustybridge

> [!WARNING]
> **EXPERIMENTAL REPO** - This code is experimental and has not been extensively tested for security. It might be insecure generally, and is definitely insecure when using `--insecure` to make connections due to insecure KEX and other legacy cryptographic methods. Use at your own risk.

A legacy-friendly SSH toolkit that keeps forgotten hardware reachable while still giving modern operators control. rustybridge ships both a relaxed SSH client (`rb`) and an embeddable jump host (`rb-server`). By default we stick to modern crypto, but you can explicitly opt into older ciphers, hashes, or KEX so you can nurse decades-old routers, kiosks, or lab gear through one more upgrade cycle.

## Highlights
- **Legacy crypto on tap**: Toggle relaxed suites (`--insecure`) when you must talk to ancient firmware; we require explicit approval each time.
- **Forwarding parity**: Local/remote TCP (`-L`/`-R`), dynamic SOCKS (`-D`), Unix sockets (Unix), environment + locale propagation, and subsystem channels (`--subsystem`, e.g. sftp).
- **Escape sequences**: Type Enter then `~` to open the local control menu with colored status tag; supports `~.` (disconnect), `~R` (rekey), `~V/~v` (change verbosity), `~#` (list forwards), `~~` (literal `~`), `~^Z` (suspend on Unix), and `~&` (detach stdin; reattach via `SIGUSR1`).
- **Modular workspace**: Separate crates for CLI, client/session logic, server logic, SSH helpers, and SQLite state handling keep contributions focused.
- **SQLite-backed trust stores**: Client host keys and server state are versioned via SQLx migrations and initialized automatically per user.
- **Feature-rich client**: Password, public-key, agent, keyboard-interactive, and certificate auth are all supported, along with terminal newline mapping and agent forwarding.

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

# Forwards and subsystems
rb -L 8080:internal:80 demo@host                      # local TCP forward
rb -R 0.0.0.0:6200:jump:6200 demo@host               # remote TCP forward
rb -D 1080 demo@host                                  # dynamic SOCKS
rb --local-unix-forward /tmp/l.sock=/var/run/r.sock host  # unix socket (Unix)
rb --send-env LANG=en_US.UTF-8 --forward-locale=lang  host # env/locale propagation
rb --subsystem sftp host                               # run a subsystem instead of a shell

rb-server --bind 0.0.0.0 --port 2222                  # run the jump host
rb-server --add-host 10.0.0.5:22 --hostname legacy-db # manage relay targets
```
All binaries source their SQLite state from `~/Library/Application Support/rustybridge/` (macOS) or the platform’s data/state dirs. The first run logs when a database is created and migrations applied.

## Security & Safety Notes
- Legacy algorithms drastically reduce security; only pass `--insecure` (client) or enable relaxed KEX server-side when you fully trust the endpoint and network.
- We never log raw credentials, but you should still clear shell history when sharing terminals.
- Host key prompts default to “reject”, so you must opt in per-host (with `--accept-hostkey`/`--accept-store-hostkey`).

## Escape Sequences (interactive shell)
- Press Enter then `~` to show the menu and prompt.
- Supported: `~.` disconnect, `~R` rekey, `~V/~v` verbosity up/down, `~#` list forwards, `~~` literal `~`, `~^Z` suspend (Unix), `~&` detach stdin.
- Reattach stdin after `~&` with `kill -USR1 <pid>` (PID is displayed when you detach).

---

## Disclaimer

This software is provided "as is" and without any warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.

Use this software at your own risk. The authors are not responsible for any loss of data, security breaches, or other incidents that may result from the use of this software.
