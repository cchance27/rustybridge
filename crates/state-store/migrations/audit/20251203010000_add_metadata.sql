-- Audit Metadata Enhancement Migration
-- Adds connection tracking and size metadata for session recording

-- Unified Connection Metadata Table
-- Stores metadata about all user connections (web and SSH) for audit trail
CREATE TABLE connections (
    id TEXT PRIMARY KEY NOT NULL, -- UUIDv7
    user_id INTEGER NOT NULL,
    connection_type TEXT NOT NULL, -- 'web' or 'ssh'
    ip_address TEXT NOT NULL,
    connected_at INTEGER NOT NULL, -- Timestamp (ms)
    disconnected_at INTEGER, -- Timestamp (ms), NULL if still connected
    -- Web-specific metadata (nullable for SSH connections)
    user_agent TEXT,
    -- SSH-specific metadata (nullable for web connections)
    ssh_client TEXT,
    FOREIGN KEY(user_id) REFERENCES users(user_id) -- Cross-DB reference (documentation only)
);

CREATE INDEX idx_connections_user ON connections(user_id);
CREATE INDEX idx_connections_type ON connections(connection_type);

-- Add connection tracking to chunks
-- NULL for output (belongs to session), populated for input (tracks who typed it)
ALTER TABLE session_chunks ADD COLUMN connection_id TEXT;

-- Add size tracking to sessions
ALTER TABLE recorded_sessions ADD COLUMN original_size_bytes INTEGER DEFAULT 0;
ALTER TABLE recorded_sessions ADD COLUMN compressed_size_bytes INTEGER DEFAULT 0;
ALTER TABLE recorded_sessions ADD COLUMN encrypted_size_bytes INTEGER DEFAULT 0;

-- Add indexes for new fields
CREATE INDEX idx_session_chunks_connection ON session_chunks(connection_id);
