-- Rework relay host ACLs to support users and groups as principals.

-- Drop legacy user-only ACL table (dev stage; data loss acceptable).
DROP TABLE IF EXISTS relay_host_acl;

-- Principal collections
CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS user_groups (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    UNIQUE(user_id, group_id)
);

-- Unified ACL: principals can be users or groups.
CREATE TABLE IF NOT EXISTS relay_host_acl (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    relay_host_id INTEGER NOT NULL REFERENCES relay_hosts(id) ON DELETE CASCADE,
    principal_kind TEXT NOT NULL CHECK (principal_kind IN ('user', 'group')),
    principal_name TEXT NOT NULL,
    UNIQUE(relay_host_id, principal_kind, principal_name)
);

CREATE INDEX IF NOT EXISTS idx_relay_acl_principal ON relay_host_acl(principal_kind, principal_name);
CREATE INDEX IF NOT EXISTS idx_relay_acl_host ON relay_host_acl(relay_host_id);
