-- Group Roles mapping (groups can be assigned roles)
-- This supports the hierarchy: Users → Groups → Roles → Claims

CREATE TABLE IF NOT EXISTS group_roles (
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    UNIQUE(group_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_group_roles_group ON group_roles(group_id);
CREATE INDEX IF NOT EXISTS idx_group_roles_role ON group_roles(role_id);
