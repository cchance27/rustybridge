# Forwarding Checklist

This document tracks the status of SSH forwarding-related features so we can keep parity goals visible while we build out the individual sub-crates.

## Current Capabilities

- CLI plumbing: `rb` now accepts `-L/-R/-D`, `--local-unix-forward`, `--remote-unix-forward`, `--forward-x11`, `--subsystem`, `--send-env`, and `--forward-locale` so users can describe the forwards they expect (see `crates/rb-cli/src/client_cli.rs`).
- Unified data model: `ssh-core::forwarding::ForwardingConfig` describes every forwarding directive and comes with parsing helpers that both the CLI and future server-side components can reuse.
- Per-channel hooks: `ForwardingManager` is instantiated by `client-core` (`crates/client-core/src/lib.rs`) and injected into `ssh-core::session::{run_shell, run_command}` so each session channel can perform any required setup before exec/shell requests.
- Environment propagation: `ForwardingManager::prepare_channel` already pushes requested environment variables and locale settings (`--send-env`, `--forward-locale`) using `Channel::set_env`, eliminating the last gap noted in `TODO_CLIENT.md`.
- Local TCP forwards: the `-L` flag now creates actual listeners and tunnels accepted connections to the remote target via `direct-tcpip` channels (`ssh-core/src/forwarding.rs`), including graceful shutdown via `ForwardingManager::shutdown`.
- Remote TCP forwards: `-R` requests are registered with the server, and incoming `forwarded-tcpip` channels are proxied back to the desired local host/port, matching OpenSSH’s behavior.
- Dynamic SOCKS: `-D` spins up a SOCKS5 listener that accepts unauthenticated CONNECT requests and feeds them through new SSH channels, giving us parity with OpenSSH’s dynamic forwarding.
- Unix socket forwards: both `--local-unix-forward` and `--remote-unix-forward` now work on Unix platforms, binding local sockets, issuing `direct-streamlocal` requests, and proxying inbound channels back to the requested local paths.

## Pending Work

- **X11 forwarding:** handle DISPLAY detection, MIT-MAGIC-COOKIE generation, and respond to server `x11` channels based on the new CLI flags.
- **Subsystem support:** issue `channel.request_subsystem()` calls when `--subsystem` is supplied and surface the streams to the user (e.g., for `sftp`).
- **User feedback + lifecycle:** integrate forwarding status with the upcoming escape sequence UI so users can list active forwards, tear them down, or see errors.
- **X11 CLI guard:** flags are marked `[unimplemented]` in the CLI and currently error out to prevent accidental use; remove this guard when support lands.

As each feature lands, update the “Current Capabilities” list with short references to the relevant modules to keep this document a quick map for parity tracking.
