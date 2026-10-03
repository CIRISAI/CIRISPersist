-- V175 — find a stream chunk's position from its content address
-- v53.0.0 (CIRISPersist#969, #842)
--
-- POSTGRES PARITY: migrations/postgres/lens/V175__stream_chunks_by_sha.sql
--
-- A self/family chunk sealed under its stream's (stream, epoch) DEK carries no
-- per-chunk grant, so the whole-blob read doors authorize it through the
-- chunk's stream position. That lookup goes by chunk_sha.
CREATE INDEX IF NOT EXISTS federation_stream_chunks_chunk_sha
    ON federation_stream_chunks (chunk_sha);
