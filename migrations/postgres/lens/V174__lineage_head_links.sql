-- V174 — the lineage head names its predecessor and its charter
-- v53.0.0 (CC 3.2 T6, operator ruling B-1 on CIRISConstitution#136)
--
-- SQLITE PARITY: migrations/sqlite/lens/V174__lineage_head_links.sql
--
-- See the sqlite twin. Both are signed members of the record; '' (the
-- default) is a founding version / a version naming no charter.
ALTER TABLE cirislens.federation_families
    ADD COLUMN IF NOT EXISTS prev_head_digest TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS charter_digest TEXT NOT NULL DEFAULT '';
ALTER TABLE cirislens.federation_communities
    ADD COLUMN IF NOT EXISTS prev_head_digest TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS charter_digest TEXT NOT NULL DEFAULT '';
