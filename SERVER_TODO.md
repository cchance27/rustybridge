# rb-server: Relay Mode Status (username:relay-host@)

This document tracks the current state of the relay-mode feature and what remains.

## Modes

- Echo: `username@` opens the embedded echo TUI (unchanged).
- Relay: `username:relay-host@` authenticates, enforces ACLs, then connects to the relay target and bridges IO until disconnect.

## Implemented

- Username parsing and session gating
  - Split `user` into base `username` and optional `relay_target`.
  - In TUI mode, start the echo TUI; in relay mode, proceed to ACL + connect.

- User auth and lifecycle
  - Users table with Argon2 password hashes.
  - Server refuses to start if no users exist (guides admin to `--add-user`).
  - Password authentication verifies against stored Argon2 hash.

- ACLs and authorization
  - `relay_host_acl(username, relay_host_id)` enforced before connecting.
  - Logs rejections with `warn!` when host is unknown or user lacks access, and informs the client.

- Relay host configuration
  - `relay_hosts(name, ip, port)` and `relay_host_options(relay_host_id, key, value)`.
  - Supported options:
    - `auth.method` = password | publickey
    - `auth.username`, `auth.password`, `auth.identity`
    - `compression` = true|false
    - `insecure` = true|false (legacy crypto)

- Host key policy (relay targets)
  - Enforces exact match if `hostkey.openssh` is stored.
  - If missing, accepts the session once, logs a server warning with algorithm + SHA256 fingerprint, and prints a friendly notice to the client with the same details.
  - `--add-host` fetches the host key and prompts to store under `hostkey.openssh`.
  - `--refresh-target-hostkey` wipes any stored key and reuses the same fetch+prompt flow to refresh it.

- Relay bridge
  - Outbound SSH client, connects with configured auth, opens PTY/shell.
  - Bridges relay stdout/stderr → client, and client input → relay.
  - Propagates window-size changes.

- Admin CLI
  - Hosts: `--add-host IP:PORT --hostname NAME`, `--list-hosts`
  - Options: `--set-option --hostname NAME --key K --value V`, `--unset-option --hostname NAME --key K`, `--list-options --hostname NAME`
  - Access: `--grant-access --hostname NAME --user USER`, `--revoke-access --hostname NAME --user USER`, `--list-access --hostname NAME`
  - Users: `--add-user --user USER [--password PASS]`, `--remove-user --user USER`, `--list-user` (alias `--list-users`)
  - Host key maintenance: `--refresh-target-hostkey --hostname NAME`

## Missing / TODO

- Server-side authentication methods
  - Public-key auth for users (authorized keys / certs) and OIDC login flow scaffolding.

- Exec request passthrough
  - Support `exec_request` proxy to relay without opening an interactive shell.

- Relay publickey improvements
  - Support passphrase-encrypted identities and agent-based auth for relay.

- Secrets + policy
  - Harden relay secret storage (env/secrets manager). Provide policy for host key updates.

- Tests
  - Unit tests for username parsing, ACL checks, and host-key enforcement (sqlite::memory:).
  - Integration tests (behind `forwarding-tests`) that exercise end-to-end bridging, access denial, and host-key behaviors.

## Notes

- SQLx dynamic queries are used for portability (no macros prepared offline).
- Logging avoids secrets; we warn on access denials and host-key issues.
- Default crypto is secure; `insecure=true` flips to legacy ciphers explicitly.

## Next Milestones

1) Enforce relay host-key verification for all paths (done) and add a CLI to store without prompting if desired.
2) Add server-side user public-key auth and OIDC scaffolding.
3) Implement exec passthrough mode.
4) Add tests (unit + optional integration) and tighten error surfaces.
