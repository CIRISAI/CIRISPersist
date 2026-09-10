-- V143 — a stream belongs to its first append, Postgres dialect
-- CIRISPersist#837 (FSD/BLOB_ENCRYPTION_AT_REST.md §12.9, I41)
--
-- SQLITE PARITY: migrations/sqlite/lens/V143__federation_streams.sql
-- See that file's header for the rationale; the shape is the same.

CREATE TABLE IF NOT EXISTS cirislens.federation_streams (
    stream_id          TEXT NOT NULL PRIMARY KEY,
    cohort_scope       TEXT NOT NULL,
    community_key_id   TEXT NULL,
    owner_key_id       TEXT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO cirislens.federation_streams
    (stream_id, cohort_scope, community_key_id, owner_key_id, created_at)
SELECT c.stream_id,
       b.cohort_scope,
       e.community_key_id,
       NULL,
       c.created_at
  FROM cirislens.federation_stream_chunks c
  JOIN cirislens.federation_blobs b ON b.sha256 = c.chunk_sha
  LEFT JOIN cirislens.federation_community_blob_epoch e ON e.at_rest_sha256 = c.chunk_sha
 WHERE c.seq = (SELECT MIN(m.seq) FROM cirislens.federation_stream_chunks m
                 WHERE m.stream_id = c.stream_id)
ON CONFLICT (stream_id) DO NOTHING;

COMMENT ON TABLE cirislens.federation_streams IS
    '#837 (§12.9, I41) — one row per stream_id: the cohort, community and first ATTRIBUTED writer (derived key id) of its first append. Written insert-if-absent by the chunk floor in the first chunk''s transaction; every later append must match all three or is refused at that chunk. owner_key_id NULL = unclaimed (backfilled or commons-started); the first attributed append adopts it.';

COMMENT ON COLUMN cirislens.federation_streams.owner_key_id IS
    'The first attributed writer''s DERIVED federation key id (never an alias, I23). NULL = unclaimed. A refusal to a non-owner never names this value.';
