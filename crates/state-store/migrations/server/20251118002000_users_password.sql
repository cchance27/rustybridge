-- Add password hash column for user authentication
ALTER TABLE users ADD COLUMN password_hash TEXT;

