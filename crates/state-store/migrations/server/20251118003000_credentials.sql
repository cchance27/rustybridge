CREATE TABLE IF NOT EXISTS relay_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    salt BLOB NOT NULL,
    nonce BLOB NOT NULL,
    secret BLOB NOT NULL,
    meta TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

