-- V086 — §19.7 inter-object aggregation: the forever-memory pyramid
--        metadata (CEG 1.0-RC12 §19.7 / CIRISPersist#230, v8.3.0; SQLite
--        translation).
--
-- Mirrors migrations/postgres/lens/V086__content_aggregation.sql. See the
-- postgres copy for the full §19.7 rationale + the wire-churn-firewall
-- design (opaque aggregation_meta persist never parses). This is the
-- dialect translation.
--
-- Project rule (NO pg/sqlite asymmetry): same table, same columns, same
-- PK + navigation index — only the dialect differs:
--   * SQLite has no schema namespace → bare table (PG uses
--     `cirislens.content_aggregation`).
--   * aggregation_meta is BLOB here, BYTEA on PG.
--   * BIGINT columns are INTEGER here.
--
-- persist STORES `member_commitment` but does NOT verify it this cut
-- (§19.7-freeze-gated). NO `verified` column (§19.0 F-5; no aggregation
-- gate yet). The composite itself is a FountainContentV1 admitted via the
-- EXISTING #225 hybrid gate (content_manifest / content_symbols, V084).

CREATE TABLE IF NOT EXISTS content_aggregation (
    aggregate_content_id  TEXT    NOT NULL,
    source_corpus_kind    TEXT    NOT NULL,
    aggregation_level     INTEGER NOT NULL,  -- BIGINT on PG
    fan_in                INTEGER NOT NULL,  -- BIGINT on PG
    member_commitment     TEXT    NOT NULL,  -- Merkle root (hex); stored, not verified this cut
    aggregation_meta      BLOB    NOT NULL,  -- OPAQUE §19.7 wire payload; never parsed (BYTEA on PG)
    aggregated_at_unix_ms INTEGER NOT NULL,  -- epoch ms
    PRIMARY KEY (aggregate_content_id)
);

CREATE INDEX IF NOT EXISTS content_aggregation_level_recency
    ON content_aggregation (aggregation_level, aggregated_at_unix_ms);
