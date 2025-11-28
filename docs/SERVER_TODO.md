# rb-server: Relay Mode Status (username:relay-host@)

This document tracks the current state of the relay-mode feature and what remains.

## Modes

- Echo: `username@` opens the embedded management TUI or relay TUI, depending on the user's permissions (TODO: implement ACLs for management TUI).
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
  - Unified ACL per host with principals (`user` or `group`) enforced before connecting.
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

- At-rest encryption
  - All relay host options values are encrypted at rest.
  - Relay credentials are stored encrypted with per-record salt + nonce.
  - Master secret is provided via `RB_SERVER_SECRETS_KEY` (base64‑32 bytes) or `RB_SERVER_SECRETS_PASSPHRASE` (KDF via Argon2id).

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
  - Secrets rotation: `--rotate-secrets-key` (prompts for old/new, re-encrypts credentials + options; admin must restart with new env secret)

## Missing / TODO

- Server-side user authentication methods
  - Public-key auth for users (authorized keys / certs) and OIDC login flow scaffolding.

- Exec passthrough
  - Support `exec_request` proxy to relay without opening an interactive shell.

- Relay credentials: shared, secure storage
  - Introduce reusable credentials that can be assigned to multiple relay hosts.
  - Support password and SSH key/certificate now; allow OIDC/agent later.
  - Enforce robust, at-rest encryption for any reversible secret material.

- Relay publickey improvements
  - Support passphrase-encrypted identities and agent-based auth for relay.

- Tests
  - Unit tests for username parsing, ACL checks, and host-key enforcement (sqlite::memory:).
  - Integration tests (behind `forwarding-tests`) that exercise end-to-end bridging, access denial, and host-key behaviors.

## Shared Credentials & Secret Storage (Design)

- Credential model (server-side)
  - Table `relay_credentials`:
    - `id INTEGER PRIMARY KEY AUTOINCREMENT`
    - `name TEXT UNIQUE NOT NULL` (human-friendly reference)
    - `kind TEXT NOT NULL` (e.g., `password`, `ssh_key`, `ssh_cert_key`, `oidc`)
    - `secret BLOB NOT NULL` (AEAD-encrypted payload; see encryption format below)
    - `meta TEXT` (optional JSON; non-sensitive fields like username or cert principals)
    - `created_at`, `updated_at` (timestamps)
  - Host linkage:
    - Set `auth.source=credential`, `auth.id=<credential_id>` in `relay_host_options`.
    - Precedence: `auth.id` overrides inline `auth.username`/`auth.password`/`auth.identity` if present.

- Admin CLI (credentials)
  - `--create-credential --name <NAME> --type password|ssh-key [--username <USER>] [--from-file <PATH>]` (prompts for secret when not provided)
  - `--list-credentials` (name, kind, brief meta)
  - `--delete-credential --name <NAME>` (refuse if assigned unless `--force`)
  - `--assign-credential --hostname <HOST> --name <CRED>` (writes `auth.source=credential`, `auth.id`)
  - `--unassign-credential --hostname <HOST>` (clears `auth.id`, optionally falls back to inline options)

- Relay auth resolution
  - If `auth.id` present: load credential, decrypt secret using the configured key provider, and use it for the chosen method (password/publickey).
  - Else: use inline options (current behavior).

- Encryption at rest (v1 implemented)
  - AEAD `XChaCha20-Poly1305` with per-entry nonce; per-entry KDF salt and ciphertext stored.
  - Master secret from `RB_SERVER_SECRETS_KEY` (base64 32B) or `RB_SERVER_SECRETS_PASSPHRASE` (Argon2id KDF) — required at runtime.
  - Rotation: planned `--rotate-secrets-key` to re-encrypt entries under a new master.
  - Hygiene: redact secrets in logs; avoid printing decrypted material; consider zeroizing buffers.

- Security posture
  - One-way hashing for non-reversible data (server user passwords): Argon2id (already implemented).
  - AEAD encryption for reversible relay material (passwords, private keys, OIDC refresh tokens).
  - Strict file permissions on DB and any on-disk key files; avoid printing secrets anywhere.

## Notes

- Logging avoids secrets; we warn on access denials and host-key issues.
- Default crypto is secure; `insecure=true` flips to legacy ciphers explicitly.

## Next Milestones

1) Server-side user public-key auth and OIDC scaffolding
2) Exec passthrough mode
