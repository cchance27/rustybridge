-- Remove foreign key constraint from connections table
-- The foreign key to users table cannot be enforced since users table is in a different database

-- SQLite doesn't support ALTER TABLE DROP CONSTRAINT, so we need to recreate the table
CREATE TABLE connections_new (
    id TEXT PRIMARY KEY NOT NULL, -- UUIDv7
    user_id INTEGER NOT NULL,
    connection_type TEXT NOT NULL, -- 'web' or 'ssh'
    ip_address TEXT NOT NULL,
    connected_at INTEGER NOT NULL, -- Timestamp (ms)
    disconnected_at INTEGER, -- Timestamp (ms), NULL if still connected
    -- Web-specific metadata (nullable for SSH connections)
    user_agent TEXT,
    -- SSH-specific metadata (nullable for web connections)
    ssh_client TEXT
    -- Removed: FOREIGN KEY(user_id) REFERENCES users(user_id)
);

-- Copy data from old table
INSERT INTO connections_new SELECT * FROM connections;

-- Drop old table
DROP TABLE connections;

-- Rename new table
ALTER TABLE connections_new RENAME TO connections;

-- Recreate indexes
CREATE INDEX idx_connections_user ON connections(user_id);
CREATE INDEX idx_connections_type ON connections(connection_type);
