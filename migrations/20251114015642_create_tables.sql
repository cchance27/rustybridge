CREATE TABLE IF NOT EXISTS server_options (
    key TEXT PRIMARY KEY, 
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS client_hostkeys (
    authority TEXT PRIMARY KEY,
    key TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

