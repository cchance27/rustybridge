-- Add explicit composite primary keys to junction tables
-- This improves schema clarity and compatibility with tools
-- SQLite doesn't support ALTER TABLE ADD PRIMARY KEY, so we recreate tables

-- user_roles
CREATE TABLE new_user_roles (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY(user_id, role_id)
);

INSERT INTO new_user_roles SELECT user_id, role_id FROM user_roles;
DROP TABLE user_roles;
ALTER TABLE new_user_roles RENAME TO user_roles;

CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role_id);

-- user_groups
CREATE TABLE new_user_groups (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY(user_id, group_id)
);

INSERT INTO new_user_groups SELECT user_id, group_id FROM user_groups;
DROP TABLE user_groups;
ALTER TABLE new_user_groups RENAME TO user_groups;

CREATE INDEX IF NOT EXISTS idx_user_groups_group ON user_groups(group_id);

-- group_roles
CREATE TABLE new_group_roles (
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY(group_id, role_id)
);

INSERT INTO new_group_roles SELECT group_id, role_id FROM group_roles;
DROP TABLE group_roles;
ALTER TABLE new_group_roles RENAME TO group_roles;

CREATE INDEX IF NOT EXISTS idx_group_roles_role ON group_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_group_roles_group ON group_roles(group_id);

-- role_claims
CREATE TABLE new_role_claims (
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    claim_key TEXT NOT NULL,
    PRIMARY KEY(role_id, claim_key)
);

INSERT INTO new_role_claims SELECT role_id, claim_key FROM role_claims;
DROP TABLE role_claims;
ALTER TABLE new_role_claims RENAME TO role_claims;

CREATE INDEX IF NOT EXISTS idx_role_claims_role ON role_claims(role_id);

-- user_claims
CREATE TABLE new_user_claims (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    claim_key TEXT NOT NULL,
    PRIMARY KEY(user_id, claim_key)
);

INSERT INTO new_user_claims SELECT user_id, claim_key FROM user_claims;
DROP TABLE user_claims;
ALTER TABLE new_user_claims RENAME TO user_claims;

CREATE INDEX IF NOT EXISTS idx_user_claims_user ON user_claims(user_id);

-- group_claims
CREATE TABLE new_group_claims (
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    claim_key TEXT NOT NULL,
    PRIMARY KEY(group_id, claim_key)
);

INSERT INTO new_group_claims SELECT group_id, claim_key FROM group_claims;
DROP TABLE group_claims;
ALTER TABLE new_group_claims RENAME TO group_claims;

CREATE INDEX IF NOT EXISTS idx_group_claims_group ON group_claims(group_id);
