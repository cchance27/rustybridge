# ssh-core

`ssh-core` is the shared toolbox for both the client and server stacks. It provides:
- Crypto preference helpers (`default_preferred`, `legacy_preferred`).
- Session helpers for running commands or shells with newline control and agent forwarding toggles.
- Terminal utilities for reading local termios state and mapping newline modes.

If you need to extend rustybridge with new binaries, depend on `ssh-core` to avoid duplicating russh plumbing.
