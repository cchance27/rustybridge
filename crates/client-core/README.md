# client-core

`client-core` implements the SSH client runtime used by the `rb` binary. It wires russh config, host-key persistence, all authentication strategies, and session/terminal helpers from `ssh-core` into a reusable library.

## Features
- Pluggable auth pipeline (password, identities, OpenSSH certs, SSH agent, keyboard-interactive).
- Host-key verification backed by SQLx migrations to keep fingerprints consistent across runs.
- Optional agent forwarding support for both shell and exec channels.
- Forwarding manager for `-L/-R/-D`, Unix sockets (Unix), environment + locale propagation, and subsystem channels.
- Interactive escape menu (Enter + `~`) for disconnect, rekey, verbosity, listing forwards, suspend, and detaching stdin.

## Example
```rust
let cfg = client_core::ClientConfig { /* build from CLI or config file */ };
client_core::run_client(cfg).await?;
```
`client-core` expects tokio + russh in the parent binary; see `rb-cli` for a reference integration.
