-- V153 — co-signatures on the three membership-row planes
-- v49.0.0 (CIRISPersist#908, FSD ROOM_ROSTER_AUTHORITY.md §3)
--
-- SQLITE PARITY: migrations/sqlite/lens/V153__roster_cosignatures.sql
-- (that file's header carries the reasoning; this one carries the DDL).
ALTER TABLE cirislens.federation_community_membership_widenings
    ADD COLUMN IF NOT EXISTS cosignatures JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE cirislens.federation_community_membership_revocations
    ADD COLUMN IF NOT EXISTS cosignatures JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE cirislens.federation_family_membership_revocations
    ADD COLUMN IF NOT EXISTS cosignatures JSONB NOT NULL DEFAULT '[]'::jsonb;
