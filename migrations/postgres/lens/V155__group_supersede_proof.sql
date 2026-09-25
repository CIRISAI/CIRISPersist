-- V155 — the quorum proof a group amendment replicates with
-- v49.0.0 (CIRISPersist#910 item 5, FSD ROOM_ROSTER_AUTHORITY.md §10)
--
-- SQLITE PARITY: migrations/sqlite/lens/V155__group_supersede_proof.sql
-- (that file's header carries the reasoning; this one carries the DDL).
ALTER TABLE cirislens.federation_families
    ADD COLUMN IF NOT EXISTS supersede_proof JSONB;
ALTER TABLE cirislens.federation_communities
    ADD COLUMN IF NOT EXISTS supersede_proof JSONB;
