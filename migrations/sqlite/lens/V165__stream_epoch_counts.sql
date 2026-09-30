-- V165 — the per-(stream, epoch) chunk counter, SQLite dialect
-- v52.0.0 (CIRISPersist#957, FSD BLOB_REPLICATION.md §6.7).
--
-- The chunk floor's nonce-cap check (CEG §10.5.3: a (stream, epoch) holds at
-- most MAX_CHUNKS_PER_EPOCH chunks) was a `COUNT(*)` over the stream's index
-- range on EVERY append, so appending or adopting a stream was quadratic in its
-- length (25 ms → 201 ms per chunk on Edge's multi-GiB pull). This table holds
-- the count; the floor reads it by primary key and increments it in the same
-- transaction as the index insert, and every production DELETE of
-- federation_stream_chunks rows deletes the matching counter rows
-- (abandon_stream). Derived and rebuildable: it always equals
-- SELECT stream_id, epoch, COUNT(*) FROM federation_stream_chunks GROUP BY 1, 2
-- (I288 asserts exactly that).
--
-- Postgres parity: migrations/postgres/lens/V165__stream_epoch_counts.sql

CREATE TABLE IF NOT EXISTS federation_stream_epoch_counts (
    stream_id    TEXT NOT NULL,
    epoch        INTEGER NOT NULL,
    chunk_count  INTEGER NOT NULL CHECK (chunk_count >= 0),
    PRIMARY KEY (stream_id, epoch)
);

INSERT INTO federation_stream_epoch_counts (stream_id, epoch, chunk_count)
SELECT stream_id, epoch, COUNT(*)
  FROM federation_stream_chunks
 GROUP BY stream_id, epoch
ON CONFLICT (stream_id, epoch) DO UPDATE SET chunk_count = excluded.chunk_count;
