-- Audit Database Initialization

-- Recorded Sessions Table
CREATE TABLE recorded_sessions (
    id TEXT PRIMARY KEY NOT NULL, -- UUIDv7
    user_id INTEGER NOT NULL,
    relay_id INTEGER NOT NULL,
    session_number INTEGER NOT NULL,
    start_time INTEGER NOT NULL, -- Timestamp (ms)
    end_time INTEGER, -- Timestamp (ms), nullable if active
    metadata TEXT NOT NULL -- JSON: ip, user_agent, etc.
);

CREATE INDEX idx_recorded_sessions_user_id ON recorded_sessions(user_id);
CREATE INDEX idx_recorded_sessions_relay_id ON recorded_sessions(relay_id);
CREATE INDEX idx_recorded_sessions_start_time ON recorded_sessions(start_time);

-- Session Chunks Table
CREATE TABLE session_chunks (
    id TEXT PRIMARY KEY NOT NULL, -- UUIDv7
    session_id TEXT NOT NULL, -- UUIDv7 Foreign Key
    timestamp INTEGER NOT NULL, -- Timestamp (ms)
    chunk_index INTEGER NOT NULL, -- Ordering
    direction INTEGER NOT NULL, -- 0=Output, 1=Input
    data BLOB NOT NULL, -- Compressed & Encrypted data
    FOREIGN KEY(session_id) REFERENCES recorded_sessions(id) ON DELETE CASCADE
);

CREATE INDEX idx_session_chunks_session_id ON session_chunks(session_id);
CREATE INDEX idx_session_chunks_session_order ON session_chunks(session_id, chunk_index);

-- System Events Table
CREATE TABLE system_events (
    id TEXT PRIMARY KEY NOT NULL, -- UUIDv7
    timestamp INTEGER NOT NULL, -- Timestamp (ms)
    actor_id INTEGER, -- User ID who performed action (nullable for system)
    action_type TEXT NOT NULL, -- e.g. "LOGIN", "CONFIG_CHANGE"
    resource_id TEXT, -- ID of affected resource
    details TEXT NOT NULL -- JSON details
);

CREATE INDEX idx_system_events_timestamp ON system_events(timestamp);
CREATE INDEX idx_system_events_actor_id ON system_events(actor_id);
CREATE INDEX idx_system_events_action_type ON system_events(action_type);
