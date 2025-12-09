-- Add timing markers to preserve intra-chunk timing during playback
-- Timing markers are stored as JSON: [[byte_offset, delay_ms], ...]
-- Only significant delays (>50ms) are recorded to minimize bloat

ALTER TABLE session_chunks ADD COLUMN timing_markers TEXT;
