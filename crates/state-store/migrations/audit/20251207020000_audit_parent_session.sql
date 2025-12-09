-- Add parent_session_id to system_events for event grouping
ALTER TABLE system_events ADD COLUMN parent_session_id TEXT;
CREATE INDEX idx_system_events_parent_session ON system_events(parent_session_id);
