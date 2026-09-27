-- V158 — a community row's co-signatures and lineage (the ciris-canonical chain)
-- v50.0.0 (CIRISPersist#926, FSD SECOND_DEVICE.md §9)
--
-- SQLITE PARITY: migrations/sqlite/lens/V158__community_cosignatures.sql
-- (that file's header carries the reasoning; this one carries the DDL).
ALTER TABLE cirislens.federation_communities
    ADD COLUMN IF NOT EXISTS cosignatures JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE cirislens.federation_communities
    ADD COLUMN IF NOT EXISTS lineage JSONB NOT NULL DEFAULT '[]'::jsonb;
