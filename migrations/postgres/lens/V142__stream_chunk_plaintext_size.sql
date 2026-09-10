-- V142 — a stream chunk records its PLAINTEXT size, Postgres dialect
-- CIRISPersist#832 (FSD/BLOB_ENCRYPTION_AT_REST.md §12.6)
--
-- SQLITE PARITY: migrations/sqlite/lens/V142__stream_chunk_plaintext_size.sql
-- See that file's header for the rationale. The DEFAULT is kept on both
-- dialects for the same shape; both backends bind the column explicitly.

ALTER TABLE cirislens.federation_stream_chunks
    ADD COLUMN plaintext_size_bytes BIGINT NOT NULL DEFAULT 0
        CHECK (plaintext_size_bytes >= 0);

UPDATE cirislens.federation_stream_chunks SET plaintext_size_bytes = size_bytes;

COMMENT ON COLUMN cirislens.federation_stream_chunks.plaintext_size_bytes IS
    '#832 (§12.6) — the chunk''s CONTENT length. Equals size_bytes for a plaintext chunk; size_bytes − 36 (CRBLOB envelope overhead) for a sealed one. The sealed manifest and stream_chunks report this, never the stored length.';
