# ssh-core

`ssh-core` is the shared toolbox for both the client and server stacks. It provides:
- Crypto preference helpers (`default_preferred`, `legacy_preferred`).
- Forwarding engine (`ForwardingManager`) for local/remote TCP, dynamic SOCKS, Unix sockets, env/locale propagation, and subsystem requests.
- Session helpers for running commands, subsystems, or interactive shells with newline control and agent forwarding toggles.
- Terminal utilities for reading local termios state and mapping newline modes.
- Escape sequence parser and shell integration (Enter + `~` for the menu; supports `~.`/`~R`/`~V`/`~v`/`~#`/`~~`/`~^Z`/`~&`).

If you need to extend rustybridge with new binaries, depend on `ssh-core` to avoid duplicating russh plumbing.
