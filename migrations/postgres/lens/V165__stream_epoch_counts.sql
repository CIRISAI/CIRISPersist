-- V165 — the per-(stream, epoch) chunk counter
-- v52.0.0 (CIRISPersist#957, FSD BLOB_REPLICATION.md §6.7)
--
-- SQLITE PARITY: migrations/sqlite/lens/V165__stream_epoch_counts.sql
-- (that file's header carries the reasoning; this one carries the DDL).
CREATE TABLE IF NOT EXISTS cirislens.federation_stream_epoch_counts (
    stream_id    TEXT NOT NULL,
    epoch        BIGINT NOT NULL,
    chunk_count  BIGINT NOT NULL CHECK (chunk_count >= 0),
    PRIMARY KEY (stream_id, epoch)
);

INSERT INTO cirislens.federation_stream_epoch_counts (stream_id, epoch, chunk_count)
SELECT stream_id, epoch, COUNT(*)
  FROM cirislens.federation_stream_chunks
 GROUP BY stream_id, epoch
ON CONFLICT (stream_id, epoch) DO UPDATE SET chunk_count = EXCLUDED.chunk_count;
