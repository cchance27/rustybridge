-- Enhance system_events table with additional context fields
-- These fields improve filtering and provide better audit context

-- Add category field for efficient filtering by event type
ALTER TABLE system_events ADD COLUMN category TEXT;

-- Add IP address tracking for actor context
ALTER TABLE system_events ADD COLUMN ip_address TEXT;

-- Add session ID for correlating events with connections/sessions
ALTER TABLE system_events ADD COLUMN session_id TEXT;

-- Create composite indexes for common query patterns
CREATE INDEX idx_system_events_actor_timestamp ON system_events(actor_id, timestamp DESC);
CREATE INDEX idx_system_events_category_timestamp ON system_events(category, timestamp DESC);
CREATE INDEX idx_system_events_resource ON system_events(resource_id);
CREATE INDEX idx_system_events_session ON system_events(session_id);
