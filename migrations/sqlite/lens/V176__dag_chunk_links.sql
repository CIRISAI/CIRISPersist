-- V176 — which sealed manifest each held chunk belongs to
-- v53.1.0 (CIRISPersist#979, CC 2.3; CIRISEdge#771)
--
-- POSTGRES PARITY: migrations/postgres/lens/V176__dag_chunk_links.sql
--
-- Referencing rows bind a DAG's MANIFEST, never its chunks, so a chunk of a
-- withdrawn file read as unbound and was served. This table relates a
-- manifest to its chunks so the tombstone fold, the serve door and eviction
-- can judge a chunk by the file it belongs to. Persist writes it ITSELF, in
-- the transaction that makes the manifest a chunk_dag: at the seal (from the
-- stream's own chunk rows, whose count the seal checks) and at the promote of
-- an adopted manifest (whose chunk list the promote has opened and checked
-- against the held chunk rows). No row is ever written from an author's
-- claim, so a forged referencing row cannot link a chunk to a manifest.
--
-- An eviction removes bytes and keeps these rows, as it keeps the at-rest
-- grants: the relation is structure, not a holding.
CREATE TABLE IF NOT EXISTS federation_dag_chunks (
    manifest_sha256  BLOB NOT NULL CHECK (length(manifest_sha256) = 32),
    seq              INTEGER NOT NULL CHECK (seq >= 0),
    chunk_sha256     BLOB NOT NULL CHECK (length(chunk_sha256) = 32),
    stream_id        TEXT NOT NULL,
    PRIMARY KEY (manifest_sha256, seq)
);

CREATE INDEX IF NOT EXISTS federation_dag_chunks_by_chunk
    ON federation_dag_chunks (chunk_sha256);
