-- Add flexible credential authentication fields
-- username_mode: 'fixed' (use stored username), 'blank' (interactive), 'passthrough' (from relay user)
-- password_required: 0 = interactive password entry, 1 = password stored in secret

ALTER TABLE relay_credentials ADD COLUMN username_mode TEXT NOT NULL DEFAULT 'fixed';
ALTER TABLE relay_credentials ADD COLUMN password_required INTEGER NOT NULL DEFAULT 1;

-- Existing credentials default to current behavior:
-- - username_mode='fixed' means use the username in meta JSON (or None)
-- - password_required=1 means password is stored (current behavior)
