-- Add server:attach_any claim to Super Admin role
INSERT INTO role_claims (role_id, claim_key)
SELECT id, 'server:attach_any'
FROM roles
WHERE name = 'Super Admin'
ON CONFLICT DO NOTHING;
