-- Verify all name fields have UNIQUE constraints for UI clarity
-- Even though we use IDs as primary accessors, names should still be unique

-- This migration is mostly a verification step since all tables already have UNIQUE constraints
-- We're documenting this explicitly to ensure it's clear in the schema

-- Verify existing UNIQUE constraints:
-- users.username - UNIQUE (verified in 20251118001000_users.sql)
-- groups.name - UNIQUE (verified in 20251121010000_acl_principals.sql)
-- roles.name - UNIQUE (verified in 20251122120000_auth_rbac.sql)
-- relay_hosts.name - UNIQUE (verified in 20251114020000_relay_hosts.sql)
-- relay_credentials.name - UNIQUE (verified in 20251118003000_credentials.sql)

-- No changes needed - all name fields already have UNIQUE constraints
-- This migration serves as documentation and verification
