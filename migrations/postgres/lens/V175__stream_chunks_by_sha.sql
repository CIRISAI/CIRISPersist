-- V175 — find a stream chunk's position from its content address
-- v53.0.0 (CIRISPersist#969, #842)
--
-- SQLITE PARITY: migrations/sqlite/lens/V175__stream_chunks_by_sha.sql
--
-- See the sqlite twin.
CREATE INDEX IF NOT EXISTS federation_stream_chunks_chunk_sha
    ON cirislens.federation_stream_chunks (chunk_sha);
