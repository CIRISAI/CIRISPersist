-- V146 — the KeyGrant emission ledger and the pending-content index,
-- PostgreSQL dialect
-- v44.3.0 (CIRISPersist#848 / PR #850 review, FSD/BLOB_REPLICATION.md §13, §14)
--
-- SQLITE PARITY: migrations/sqlite/lens/V146__key_grant_emission_ledger.sql
-- (the WHY is there).
--
-- Additive: two nullable columns and one table. No rebuild, no backfill.
ALTER TABLE cirislens.federation_community_dek
    ADD COLUMN key_grant_emitted_at TIMESTAMPTZ;
ALTER TABLE cirislens.federation_blobs
    ADD COLUMN key_grant_emitted_at TIMESTAMPTZ;

CREATE TABLE cirislens.federation_key_grant_pending (
    at_rest_sha256   BYTEA NOT NULL CHECK (octet_length(at_rest_sha256) = 32),
    cohort_scope     TEXT NOT NULL,
    attestation_id   TEXT NOT NULL,
    signer_key_id    TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (at_rest_sha256, cohort_scope, attestation_id)
);

COMMENT ON COLUMN cirislens.federation_community_dek.key_grant_emitted_at IS
    'When this node last emitted the epoch''s KeyGrant set; NULL or not later than the newest member grant means DIRTY — the next write door or the boot sweep emits (CIRISPersist#848, BLOB_REPLICATION.md §14).';
COMMENT ON COLUMN cirislens.federation_blobs.key_grant_emitted_at IS
    'When this node last emitted the blob''s content-axis KeyGrant set; NULL or not later than the newest at-rest grant means DIRTY (CIRISPersist#848, §14).';
COMMENT ON TABLE cirislens.federation_key_grant_pending IS
    'Content-axis KeyGrant sets admitted before their bytes; the adopt takes its rows by (sha, scope) and projects the author-signed ones (CIRISPersist#848, §13).';
