-- Bind SSH OIDC sessions to the requested user to prevent account swapping
ALTER TABLE ssh_auth_sessions ADD COLUMN requested_user_id INTEGER;

-- Best-effort backfill: reuse authenticated user if it exists
UPDATE ssh_auth_sessions SET requested_user_id = user_id WHERE requested_user_id IS NULL;

-- Note: future inserts always populate requested_user_id; rows missing it will be rejected at runtime.
