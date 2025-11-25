-- Table for linking users to OIDC subjects
CREATE TABLE user_oidc_links (
    user_id INTEGER NOT NULL,
    provider_id TEXT NOT NULL, -- e.g., "google", "authelia" (can be derived from issuer URL or config key)
    subject_id TEXT NOT NULL, -- The 'sub' claim from the ID token
    email TEXT, -- Optional email for display/debugging
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, provider_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Table for temporary SSH authentication sessions (Out-of-Band OIDC)
CREATE TABLE ssh_auth_sessions (
    id TEXT PRIMARY KEY, -- Unique code/session ID
    user_id INTEGER, -- Null initially, populated upon successful web auth
    status TEXT NOT NULL DEFAULT 'pending', -- pending, authenticated, rejected, expired
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Table for user SSH public keys
CREATE TABLE user_public_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    public_key TEXT NOT NULL, -- The raw public key string (e.g., "ssh-ed25519 AAA...")
    comment TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Index for faster lookups
CREATE INDEX idx_user_oidc_links_subject ON user_oidc_links(subject_id);
CREATE INDEX idx_user_public_keys_user ON user_public_keys(user_id);
