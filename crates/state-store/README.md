# state-store

`state-store` centralizes SQLite pool creation and migrations for the workspace. It separates client and server schemas, automatically creates per-user DB paths (respecting `XDG`/platform conventions), and logs when a fresh database is initialized.

## Key APIs
- `client_db()` / `server_db()` → return a `DbHandle` with a ready-to-use `SqlitePool` plus path metadata.
- `migrate_client(&DbHandle)` and `migrate_server(&DbHandle)` → apply SQLx migrations bundled under `migrations/{client,server}`.

Use this crate whenever you introduce new persisted state so every binary benefits from the same bootstrap logic and logging.
