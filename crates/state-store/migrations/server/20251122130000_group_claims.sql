-- Group Claims (permissions assigned to a group)
CREATE TABLE IF NOT EXISTS group_claims (
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    claim_key TEXT NOT NULL,
    UNIQUE(group_id, claim_key)
);

CREATE INDEX IF NOT EXISTS idx_group_claims_group ON group_claims(group_id);
