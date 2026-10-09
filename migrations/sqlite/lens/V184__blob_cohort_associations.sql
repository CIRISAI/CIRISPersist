-- V184 — every room a plaintext blob was written into
-- v54.0.0 (CIRISPersist#995 row 4, Codex on PR #987)
--
-- POSTGRES PARITY: migrations/postgres/lens/V184__blob_cohort_associations.sql
--
-- A plaintext blob is content-addressed and legitimately shared: the same
-- bytes written into room A and room B are ONE `federation_blobs` row, and
-- its INSERT is `ON CONFLICT (sha256) DO NOTHING`, so the row kept the FIRST
-- writer's `cohort_scope` / `group_key_id`. Room B's write succeeded and
-- announced, but custody and durability read room A: a custody report naming
-- B was refused `custody_ack_malformed`. One provenance column cannot hold a
-- shared blob; this table holds one row per `(sha256, cohort_scope, group)`
-- a write named. `group_key_id` is '' for a write that named no group (the
-- commons), so the primary key needs no NULL handling.
--
-- Backfilled from every plaintext row's own provenance: a blob already
-- shared before this migration keeps only its first writer's association
-- (the second writer's was never recorded), and gains the rest when its
-- other rooms write it again.

CREATE TABLE IF NOT EXISTS federation_blob_associations (
    sha256        BLOB NOT NULL CHECK (length(sha256) = 32),
    cohort_scope  TEXT NOT NULL,
    group_key_id  TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (sha256, cohort_scope, group_key_id)
);

INSERT OR IGNORE INTO federation_blob_associations (sha256, cohort_scope, group_key_id)
SELECT sha256, cohort_scope, COALESCE(group_key_id, '')
  FROM federation_blobs
 WHERE crypto_tier = 'plaintext';
