-- Rework relay host ACLs to use principal IDs instead of names.
-- This enables robust renaming of users and groups.

CREATE TABLE new_relay_host_acl (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    relay_host_id INTEGER NOT NULL REFERENCES relay_hosts(id) ON DELETE CASCADE,
    principal_kind TEXT NOT NULL CHECK (principal_kind IN ('user', 'group')),
    principal_id INTEGER NOT NULL,
    UNIQUE(relay_host_id, principal_kind, principal_id)
);

-- Migrate Users: Join on username to get ID
INSERT INTO new_relay_host_acl (relay_host_id, principal_kind, principal_id)
SELECT a.relay_host_id, 'user', u.id
FROM relay_host_acl a
JOIN users u ON a.principal_name = u.username
WHERE a.principal_kind = 'user';

-- Migrate Groups: Join on group name to get ID
INSERT INTO new_relay_host_acl (relay_host_id, principal_kind, principal_id)
SELECT a.relay_host_id, 'group', g.id
FROM relay_host_acl a
JOIN groups g ON a.principal_name = g.name
WHERE a.principal_kind = 'group';

-- Drop old table and rename new one
DROP TABLE relay_host_acl;
ALTER TABLE new_relay_host_acl RENAME TO relay_host_acl;

-- Recreate indexes
CREATE INDEX IF NOT EXISTS idx_relay_acl_principal ON relay_host_acl(principal_kind, principal_id);
CREATE INDEX IF NOT EXISTS idx_relay_acl_host ON relay_host_acl(relay_host_id);
