-- V166 — a family's terminal dissolution
-- v52.0.0 (CIRISPersist#956)
--
-- SQLITE PARITY: migrations/sqlite/lens/V166__family_dissolution.sql
--
-- See the sqlite twin: a quorum-verified terminal amendment sets
-- `dissolved_at` (the instant the quorum signed); NULL on every live family.
ALTER TABLE cirislens.federation_families
    ADD COLUMN IF NOT EXISTS dissolved_at TIMESTAMPTZ NULL;
