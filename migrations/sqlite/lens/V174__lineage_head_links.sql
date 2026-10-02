-- V174 — the lineage head names its predecessor and its charter
-- v53.0.0 (CC 3.2 T6, operator ruling B-1 on CIRISConstitution#136)
--
-- POSTGRES PARITY: migrations/postgres/lens/V174__lineage_head_links.sql
--
-- A family or community record at a version IS its lineage head. Two signed
-- members join it: `prev_head_digest`, the persist_row_hash of the version it
-- succeeds ('' on a founding version), and `charter_digest`, the
-- persist_row_hash of the `trust:charter:v1` row in force at that version (''
-- when it names none). A charter row no version names is not in force, so a
-- charter re-scrub takes effect only through a new version and the head moves
-- with it. Both are preimage members of the row hash, so both are stored.
ALTER TABLE federation_families ADD COLUMN prev_head_digest TEXT NOT NULL DEFAULT '';
ALTER TABLE federation_families ADD COLUMN charter_digest TEXT NOT NULL DEFAULT '';
ALTER TABLE federation_communities ADD COLUMN prev_head_digest TEXT NOT NULL DEFAULT '';
ALTER TABLE federation_communities ADD COLUMN charter_digest TEXT NOT NULL DEFAULT '';
