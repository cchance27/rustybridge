-- Add parent_session_id to client_sessions to link web sessions to Axum sessions
ALTER TABLE client_sessions ADD COLUMN parent_session_id TEXT;
