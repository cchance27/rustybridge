-- Add connection_id to recorded_sessions to link sessions to top-level connections
ALTER TABLE recorded_sessions ADD COLUMN connection_id TEXT REFERENCES connections(id);
CREATE INDEX idx_recorded_sessions_connection_id ON recorded_sessions(connection_id);
