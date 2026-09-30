-- V162 — a family row's founding co-signatures
-- v52.0.0 (CIRISPersist#955, FSD MEMBERSHIP_ACCEPTANCE.md §9 Q1)
--
-- SQLITE PARITY: migrations/sqlite/lens/V162__family_cosignatures.sql
--
-- See the sqlite twin for the reasoning: a founding member's consent is their
-- co-signature on the founding record, persisted and served beside the
-- authority signature.
ALTER TABLE cirislens.federation_families
    ADD COLUMN IF NOT EXISTS cosignatures JSONB NOT NULL DEFAULT '[]'::jsonb;
