-- Add indexes for name-based lookups (still needed for SSH/CLI paths)
-- These improve performance when converting names to IDs
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_groups_name ON groups(name);
CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);
CREATE INDEX IF NOT EXISTS idx_relay_credentials_name ON relay_credentials(name);
CREATE INDEX IF NOT EXISTS idx_relay_hosts_name ON relay_hosts(name);

-- Additional performance indexes for joins
CREATE INDEX IF NOT EXISTS idx_relay_host_acl_principal ON relay_host_acl(principal_kind, principal_name);
CREATE INDEX IF NOT EXISTS idx_user_groups_group ON user_groups(group_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_group_roles_role ON group_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_group_roles_group ON group_roles(group_id);
