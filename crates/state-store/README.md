# state-store

`state-store` centralizes SQLite pool creation and migrations for the workspace. It separates client and server schemas, automatically creates per-user DB paths (respecting `XDG`/platform conventions), and logs when a fresh database is initialized.

## Key APIs
- `client_db()` / `server_db()` → return a `DbHandle` with a ready-to-use `SqlitePool` plus path metadata.
- `migrate_client(&DbHandle)` and `migrate_server(&DbHandle)` → apply SQLx migrations bundled under `migrations/{client,server}`.

Use this crate whenever you introduce new persisted state so every binary benefits from the same bootstrap logic and logging.

## Server Secrets & Encryption (used by server-core)

The server encrypts sensitive material (relay credentials and all relay host options values) at rest. A master secret must be provided via environment for decryption at runtime:

- `RB_SERVER_SECRETS_KEY`: base64-encoded 32‑byte key (preferred)
- `RB_SERVER_SECRETS_PASSPHRASE`: passphrase; a per-record key is derived using Argon2id

The encryption/decryption routines live in `server-core` (module `secrets`). `state-store` persists opaque ciphertext and non-sensitive metadata; it does not handle secrets directly.
