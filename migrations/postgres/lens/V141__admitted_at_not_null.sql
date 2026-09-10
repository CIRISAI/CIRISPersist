-- V141 — `admitted_at` is NOT NULL on sqlite, as it has been here since V130
-- (CIRISPersist#828), PostgreSQL dialect
--
-- SQLITE PARITY: migrations/sqlite/lens/V141__admitted_at_not_null.sql
-- (fourteen table rebuilds there — see that file for the full reasoning and
-- the per-table backfill sources.)
--
-- NO DDL HERE. Postgres backfilled `admitted_at` and `ALTER COLUMN ... SET NOT
-- NULL` when the column was added: V123 (`federation_revocations`), V126
-- (`federation_keys`) and V130 (the other twelve). SQLite could not, and this
-- version is where its tree catches up. The twin exists so that BOTH trees
-- carry V141 for the same change — a reviewer who finds the sqlite rebuild
-- should find, under the same number, the statement that postgres needed
-- nothing, rather than infer it from a gap.
--
-- The catalog comments below are the one thing this file does: they record
-- on each column that the two dialects now agree, so the divergence that
-- lived undeclared from V130 to v43.0.0 (because the schema-parity replayer
-- could not read `SET NOT NULL`) is written down where a DBA reads.
--
-- Refinery wraps each migration in its own transaction; no explicit
-- BEGIN/COMMIT here.

COMMENT ON COLUMN cirislens.federation_attestations.admitted_at IS
    'NOT NULL on both dialects since sqlite V141 (CIRISPersist#828); postgres has been NOT NULL since V130.';
COMMENT ON COLUMN cirislens.federation_communities.admitted_at IS
    'NOT NULL on both dialects since sqlite V141 (CIRISPersist#828); postgres has been NOT NULL since V130.';
COMMENT ON COLUMN cirislens.federation_community_membership_revocations.admitted_at IS
    'NOT NULL on both dialects since sqlite V141 (CIRISPersist#828); postgres has been NOT NULL since V130.';
COMMENT ON COLUMN cirislens.federation_families.admitted_at IS
    'NOT NULL on both dialects since sqlite V141 (CIRISPersist#828); postgres has been NOT NULL since V130.';
COMMENT ON COLUMN cirislens.federation_family_membership_revocations.admitted_at IS
    'NOT NULL on both dialects since sqlite V141 (CIRISPersist#828); postgres has been NOT NULL since V130.';
COMMENT ON COLUMN cirislens.federation_identity_occurrence_revocations.admitted_at IS
    'NOT NULL on both dialects since sqlite V141 (CIRISPersist#828); postgres has been NOT NULL since V130.';
COMMENT ON COLUMN cirislens.federation_identity_occurrences.admitted_at IS
    'NOT NULL on both dialects since sqlite V141 (CIRISPersist#828); postgres has been NOT NULL since V130.';
COMMENT ON COLUMN cirislens.federation_keys.admitted_at IS
    'NOT NULL on both dialects since sqlite V141 (CIRISPersist#828); postgres has been NOT NULL since V126.';
COMMENT ON COLUMN cirislens.federation_location_proofs.admitted_at IS
    'NOT NULL on both dialects since sqlite V141 (CIRISPersist#828); postgres has been NOT NULL since V130.';
COMMENT ON COLUMN cirislens.federation_organizations.admitted_at IS
    'NOT NULL on both dialects since sqlite V141 (CIRISPersist#828); postgres has been NOT NULL since V130.';
COMMENT ON COLUMN cirislens.federation_org_memberships.admitted_at IS
    'NOT NULL on both dialects since sqlite V141 (CIRISPersist#828); postgres has been NOT NULL since V130.';
COMMENT ON COLUMN cirislens.federation_partner_records.admitted_at IS
    'NOT NULL on both dialects since sqlite V141 (CIRISPersist#828); postgres has been NOT NULL since V130.';
COMMENT ON COLUMN cirislens.federation_revocations.admitted_at IS
    'NOT NULL on both dialects since sqlite V141 (CIRISPersist#828); postgres has been NOT NULL since V123.';
COMMENT ON COLUMN cirislens.transport_destinations.admitted_at IS
    'NOT NULL on both dialects since sqlite V141 (CIRISPersist#828); postgres has been NOT NULL since V130.';
