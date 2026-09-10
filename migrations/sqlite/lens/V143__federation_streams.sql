-- V143 — a stream belongs to its first append, SQLite dialect
-- CIRISPersist#837 (FSD/BLOB_ENCRYPTION_AT_REST.md §12.9, I41)
--
-- POSTGRES PARITY: migrations/postgres/lens/V143__federation_streams.sql
--
-- `federation_stream_chunks` is PRIMARY KEY (stream_id, seq) and carries no
-- cohort, community or writer: two writers on one stream_id interleaved at
-- different seqs and were caught only at the seal (I32). This table is the
-- stream itself — ONE row per stream_id, written insert-if-absent by the
-- chunk floor in the FIRST chunk's transaction and compared on every later
-- append: cohort, community and owner must all match or the append is
-- refused at that chunk, storing nothing.
--
--   cohort_scope      the cohort the first append named (§11.1 vocabulary)
--   community_key_id  the community (or owner / family key) it named; NULL
--                     for the commons
--   owner_key_id      the first ATTRIBUTED writer's DERIVED federation key
--                     id; NULL = unclaimed (this backfill, and every stream
--                     the commons put_blob_chunk starts — that door has no
--                     signer). The first attributed append adopts it.
--
-- Backfill: every existing stream from its LOWEST-seq chunk — cohort from
-- that chunk's blob row (V139 classified every row), community from the
-- chunk's epoch binding where one exists, owner NULL (no writer column ever
-- existed to attribute it from). `created_at` is that chunk's append instant.
--
-- No FK from federation_stream_chunks to this table: SQLite has no ADD
-- CONSTRAINT, and the floor is the only writer of both, in one transaction.

CREATE TABLE IF NOT EXISTS federation_streams (
    stream_id          TEXT NOT NULL PRIMARY KEY,
    cohort_scope       TEXT NOT NULL,
    community_key_id   TEXT NULL,
    owner_key_id       TEXT NULL,
    created_at         TEXT NOT NULL DEFAULT (datetime('now', 'subsec'))
);

INSERT OR IGNORE INTO federation_streams
    (stream_id, cohort_scope, community_key_id, owner_key_id, created_at)
SELECT c.stream_id,
       b.cohort_scope,
       e.community_key_id,
       NULL,
       c.created_at
  FROM federation_stream_chunks c
  JOIN federation_blobs b ON b.sha256 = c.chunk_sha
  LEFT JOIN federation_community_blob_epoch e ON e.at_rest_sha256 = c.chunk_sha
 WHERE c.seq = (SELECT MIN(m.seq) FROM federation_stream_chunks m
                 WHERE m.stream_id = c.stream_id);
