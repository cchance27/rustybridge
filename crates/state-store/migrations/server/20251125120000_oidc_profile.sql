-- Add name and picture columns to user_oidc_links table
ALTER TABLE user_oidc_links ADD COLUMN name TEXT;
ALTER TABLE user_oidc_links ADD COLUMN picture TEXT;
