-- V201 — the settled self-roster receipts of one self, indexed.
-- Postgres dialect. v59.0.0 (CIRISPersist#1099; CC 3.3.6.3, rc9 69fd22e).
--
-- SQLITE PARITY: migrations/sqlite/lens/V201__self_roster_settled_index.sql
--
-- WHY
-- ---
-- The genesis key's eviction counts only when it LANDED through the
-- two-path door: a proposal this node's door settled `lands_quorum` /
-- `lands_lone` (V199). `self_roster::genesis_evicted_at` reads one self's
-- settled receipts on every roster fold; V199 indexes only the open ones.
CREATE INDEX IF NOT EXISTS federation_self_roster_proposals_settled
    ON cirislens.federation_self_roster_proposals (identity_key_id, settled_at)
    WHERE settled_at IS NOT NULL;
