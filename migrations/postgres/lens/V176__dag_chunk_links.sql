-- V176 — which sealed manifest each held chunk belongs to
-- v53.1.0 (CIRISPersist#979, CC 2.3; CIRISEdge#771)
--
-- SQLITE PARITY: migrations/sqlite/lens/V176__dag_chunk_links.sql
--
-- See the sqlite twin.
CREATE TABLE IF NOT EXISTS cirislens.federation_dag_chunks (
    manifest_sha256  BYTEA NOT NULL CHECK (octet_length(manifest_sha256) = 32),
    seq              BIGINT NOT NULL CHECK (seq >= 0),
    chunk_sha256     BYTEA NOT NULL CHECK (octet_length(chunk_sha256) = 32),
    stream_id        TEXT NOT NULL,
    PRIMARY KEY (manifest_sha256, seq)
);

CREATE INDEX IF NOT EXISTS federation_dag_chunks_by_chunk
    ON cirislens.federation_dag_chunks (chunk_sha256);
