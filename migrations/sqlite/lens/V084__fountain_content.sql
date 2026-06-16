-- V084 — fountain-coded content primitive (CIRISPersist#227, SQLite
--        translation).
--
-- Mirrors migrations/postgres/lens/V084__fountain_content.sql. The
-- store-and-evict half of the `FountainContentV1` contract (RATIFIED +
-- LOCKED on CIRISPersist#227 / CIRISEdge#133). See the postgres copy for
-- the full rationale; this is the dialect translation.
--
-- Project rule (NO pg/sqlite asymmetry): same two tables, same columns,
-- same PK + eviction index — only the dialect differs:
--   * SQLite has no schema namespace → bare tables (PG uses
--     `cirislens.content_manifest`).
--   * symbol_hashes / envelope are TEXT (JSON-as-text) here, JSONB on PG.
--   * symbol_bytes is BLOB here, BYTEA on PG.
--   * admitted_at is TEXT (ISO-8601) here, TIMESTAMPTZ on PG; persist
--     writes the timestamp explicitly (no DB-default function).
--
-- Versioning rule: V1 is frozen the moment this migration ships. Never
-- mutate V1; additive changes get a new manifest_version + migration.

CREATE TABLE IF NOT EXISTS content_manifest (
    content_id              TEXT     NOT NULL,
    corpus_kind             TEXT     NOT NULL,
    manifest_version        INTEGER  NOT NULL,
    n_source                INTEGER  NOT NULL,
    k_repair                INTEGER  NOT NULL,
    symbol_size             INTEGER  NOT NULL,
    original_content_length INTEGER  NOT NULL,
    min_viable_symbols      INTEGER  NOT NULL,
    symbol_hashes           TEXT     NOT NULL,  -- JSON array of hex strings
    envelope                TEXT     NOT NULL,  -- corpus's opaque signed header (JSON)
    signature               TEXT     NOT NULL,  -- Ed25519 b64 (classical)
    signature_ml_dsa_65     TEXT     NOT NULL,  -- ML-DSA-65 b64 (REQUIRED, #225 hard cut)
    pqc_key_id              TEXT     NOT NULL,
    admitted_at             TEXT     NOT NULL,  -- ISO-8601 UTC
    PRIMARY KEY (content_id, corpus_kind)
);

CREATE TABLE IF NOT EXISTS content_symbols (
    content_id         TEXT     NOT NULL,
    symbol_id          INTEGER  NOT NULL,
    retention_priority INTEGER  NOT NULL,  -- u8 on the wire; eviction key
    symbol_bytes       BLOB     NOT NULL,
    PRIMARY KEY (content_id, symbol_id)
);

CREATE INDEX IF NOT EXISTS content_symbols_evict
    ON content_symbols (content_id, retention_priority);
