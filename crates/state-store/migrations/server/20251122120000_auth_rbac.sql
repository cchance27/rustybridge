-- RBAC Schema: Roles and Claims

-- Roles table
CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at INTEGER NOT NULL
);

-- User Roles mapping
CREATE TABLE IF NOT EXISTS user_roles (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    UNIQUE(user_id, role_id)
);

-- Role Claims (permissions assigned to a role)
CREATE TABLE IF NOT EXISTS role_claims (
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    claim_key TEXT NOT NULL,
    UNIQUE(role_id, claim_key)
);

-- User Claims (direct permissions assigned to a user, overriding or adding to roles)
CREATE TABLE IF NOT EXISTS user_claims (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    claim_key TEXT NOT NULL,
    UNIQUE(user_id, claim_key)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_role_claims_role ON role_claims(role_id);
CREATE INDEX IF NOT EXISTS idx_user_claims_user ON user_claims(user_id);

-- Seed default roles
INSERT OR IGNORE INTO roles (name, description, created_at) 
VALUES ('Super Admin', 'Full system access', strftime('%s', 'now'));

INSERT OR IGNORE INTO roles (name, description, created_at) 
VALUES ('User', 'Standard user access', strftime('%s', 'now'));

-- Seed Super Admin permissions (wildcard)
INSERT OR IGNORE INTO role_claims (role_id, claim_key)
SELECT id, '*' FROM roles WHERE name = 'Super Admin';

-- Seed User permissions (relay connection only)
INSERT OR IGNORE INTO role_claims (role_id, claim_key)
SELECT id, 'relay:connect' FROM roles WHERE name = 'User';

-- Migration Logic: Assign Super Admin role to the 'admin' user if it exists, or the first user found.
-- We use a temporary trigger or just a direct insert with select to handle this one-time setup.

INSERT OR IGNORE INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u, roles r
WHERE r.name = 'Super Admin'
AND (u.username = 'admin' OR u.id = (SELECT min(id) FROM users))
LIMIT 1;

