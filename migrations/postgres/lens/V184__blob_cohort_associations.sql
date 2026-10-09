-- V184 — every room a plaintext blob was written into, Postgres dialect
-- v54.0.0 (CIRISPersist#995 row 4, Codex on PR #987)
--
-- SQLITE PARITY: migrations/sqlite/lens/V184__blob_cohort_associations.sql
-- See that file's header for the rationale.

CREATE TABLE IF NOT EXISTS cirislens.federation_blob_associations (
    sha256        BYTEA NOT NULL CHECK (length(sha256) = 32),
    cohort_scope  TEXT NOT NULL,
    group_key_id  TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (sha256, cohort_scope, group_key_id)
);

INSERT INTO cirislens.federation_blob_associations (sha256, cohort_scope, group_key_id)
SELECT sha256, cohort_scope, COALESCE(group_key_id, '')
  FROM cirislens.federation_blobs
 WHERE crypto_tier = 'plaintext'
ON CONFLICT DO NOTHING;
