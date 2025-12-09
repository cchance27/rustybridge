-- Refactor Session Schema to clarify Client vs Relay Sessions

-- 1. Rename connections to client_sessions (The "Physical" Connection / Axum Session)
ALTER TABLE connections RENAME TO client_sessions;

-- 2. Rename recorded_sessions to relay_sessions (The "Logical" Relay/TUI Session)
ALTER TABLE recorded_sessions RENAME TO relay_sessions;

-- 3. Fix column names in relay_sessions for clarity
-- Avoid confusion between Relay Host ID and Relay Session ID
ALTER TABLE relay_sessions RENAME COLUMN relay_id TO relay_host_id;
-- Clarify that this is the Client Session that initiated the Relay Session
ALTER TABLE relay_sessions RENAME COLUMN connection_id TO initiator_client_session_id;

-- 4. Update session_chunks to match new terminology
-- Link to the Relay Session (the recording)
ALTER TABLE session_chunks RENAME COLUMN session_id TO relay_session_id;
-- Link to the Client Session (the input source)
ALTER TABLE session_chunks RENAME COLUMN connection_id TO client_session_id;

-- 5. Create participants table for many-to-many (Multiple clients viewing one relay session)
CREATE TABLE relay_session_participants (
    relay_session_id TEXT NOT NULL,
    client_session_id TEXT NOT NULL,
    joined_at INTEGER NOT NULL,
    left_at INTEGER,
    FOREIGN KEY(relay_session_id) REFERENCES relay_sessions(id) ON DELETE CASCADE,
    FOREIGN KEY(client_session_id) REFERENCES client_sessions(id) ON DELETE CASCADE,
    PRIMARY KEY(relay_session_id, client_session_id, joined_at)
);

-- 6. Recreate Indexes with new names
DROP INDEX IF EXISTS idx_connections_user;
DROP INDEX IF EXISTS idx_connections_type;
CREATE INDEX idx_client_sessions_user ON client_sessions(user_id);
CREATE INDEX idx_client_sessions_type ON client_sessions(connection_type);

DROP INDEX IF EXISTS idx_recorded_sessions_user_id;
DROP INDEX IF EXISTS idx_recorded_sessions_relay_id;
DROP INDEX IF EXISTS idx_recorded_sessions_start_time;
DROP INDEX IF EXISTS idx_recorded_sessions_connection_id;
CREATE INDEX idx_relay_sessions_user_id ON relay_sessions(user_id);
CREATE INDEX idx_relay_sessions_relay_host_id ON relay_sessions(relay_host_id);
CREATE INDEX idx_relay_sessions_start_time ON relay_sessions(start_time);
CREATE INDEX idx_relay_sessions_initiator ON relay_sessions(initiator_client_session_id);

DROP INDEX IF EXISTS idx_session_chunks_session_id;
DROP INDEX IF EXISTS idx_session_chunks_session_order;
DROP INDEX IF EXISTS idx_session_chunks_connection;
CREATE INDEX idx_session_chunks_relay_session_id ON session_chunks(relay_session_id);
CREATE INDEX idx_session_chunks_order ON session_chunks(relay_session_id, chunk_index);
CREATE INDEX idx_session_chunks_client_session_id ON session_chunks(client_session_id);

-- 7. Update system_events to be explicit?
-- Currently has 'session_id'. This is ambiguous.
-- Most system events (Login, etc) are tied to a Client Session.
-- Some might be tied to a Relay Session.
-- For now, we assume 'session_id' in system_events refers to client_sessions.id.
