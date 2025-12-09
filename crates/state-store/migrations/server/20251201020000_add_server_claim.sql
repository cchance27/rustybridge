-- Add server:* claim to Super Admin role
-- This claim gates server-wide administrative functions like:
-- - Viewing all active sessions (server:view)
-- - Force closing any user's sessions (server:edit)
-- - Server-wide settings and configuration (server:edit)
-- - Connection reports and monitoring (server:view)

INSERT OR IGNORE INTO role_claims (role_id, claim_key)
SELECT id, 'server:*' FROM roles WHERE name = 'Super Admin';
