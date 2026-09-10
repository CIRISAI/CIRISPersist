-- V142 — a stream chunk records its PLAINTEXT size, SQLite dialect
-- CIRISPersist#832 (FSD/BLOB_ENCRYPTION_AT_REST.md §12.6)
--
-- POSTGRES PARITY: migrations/postgres/lens/V142__stream_chunk_plaintext_size.sql
--
-- A chunk sealed under the envelope (§12.1) is content-addressed by its
-- CIPHERTEXT and its federation_blobs row stores the envelope, so
-- `size_bytes` here — the stored length — is 36 bytes more than the content
-- the chunk carries. The sealed manifest lists PLAINTEXT sizes (§12.2): a
-- plaintext byte range maps to a chunk set by prefix sum over them, and
-- `stream_chunks` reports them to a DVR consumer before any seal exists.
--
-- Recorded rather than derived: `stored − 36` is envelope arithmetic that
-- would put the CRBLOB layout's overhead into every reader of this table.
-- Every preimage field is persisted; the door computes this once from the
-- bytes it sealed and the floor refuses a value that contradicts the body.
--
-- Backfill: every pre-V142 row was written by the commons `put_blob_chunk`,
-- which stores bytes as given — its plaintext size IS its stored size.
-- `DEFAULT 0` exists only because SQLite's ADD COLUMN NOT NULL needs one;
-- both backends bind the column explicitly on every insert.

ALTER TABLE federation_stream_chunks
    ADD COLUMN plaintext_size_bytes INTEGER NOT NULL DEFAULT 0
        CHECK (plaintext_size_bytes >= 0);

UPDATE federation_stream_chunks SET plaintext_size_bytes = size_bytes;
