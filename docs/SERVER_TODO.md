# rb-server: Relay Mode Status (username:relay-host@)

This document tracks the current state of the relay-mode feature and what remains.

## Modes

- Echo: `username@` opens the embedded management TUI or relay TUI, depending on the user's permissions (TODO: implement ACLs for management TUI).
- Relay: `username:relay-host@` authenticates, enforces ACLs, then connects to the relay target and bridges IO until disconnect.

## Missing / TODO

- Relay credentials: shared, secure storage
  - Introduce reusable credentials that can be assigned to multiple relay hosts.
  - Support password and SSH key/certificate now; allow OIDC/agent later.
  - Enforce robust, at-rest encryption for any reversible secret material.
