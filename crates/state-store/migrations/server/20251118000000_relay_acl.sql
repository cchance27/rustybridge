CREATE TABLE IF NOT EXISTS relay_host_acl (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    relay_host_id INTEGER NOT NULL REFERENCES relay_hosts(id) ON DELETE CASCADE,
    UNIQUE(username, relay_host_id)
);

