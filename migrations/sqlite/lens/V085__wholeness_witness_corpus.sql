-- V085 — WholenessWitness corpus (CEG 1.0-RC11 §19.1, SQLite
--        translation; CIRISPersist#228 item 1 / #229 item 1).
--
-- Mirrors migrations/postgres/lens/V085__wholeness_witness_corpus.sql.
-- See the postgres copy for the full rationale; this is the dialect
-- translation.
--
-- Project rule (NO pg/sqlite asymmetry): same table, same columns, same
-- PK + recency index — only the dialect differs:
--   * SQLite has no schema namespace → bare table (PG uses
--     `cirislens.wholeness_witness_corpus`).
--   * claim_namespaces is TEXT (JSON-as-text) here, JSONB on PG.
--   * admitted_at is TEXT (ISO-8601) here, TIMESTAMPTZ on PG; persist
--     writes the timestamp explicitly (no DB-default function).
--
-- § F-5 rule: NO `verified` column (verify at the gate). Every stored row
-- already passed the verify-before-persist hybrid-PQC gate; the
-- ML-DSA-65 half is REQUIRED (§19.0 PQC-mandatory; no classical-only).

CREATE TABLE IF NOT EXISTS wholeness_witness_corpus (
    peer_id             TEXT     NOT NULL,
    epoch_id            INTEGER  NOT NULL,  -- per-peer monotonic (N4)
    observed_at_unix_ms INTEGER  NOT NULL,
    claim_namespaces    TEXT     NOT NULL,  -- JSON array (WW-2-filtered)
    merkle_root         TEXT     NOT NULL,  -- lowercase hex (64 chars)
    leaf_count          INTEGER  NOT NULL,
    witness_version     INTEGER  NOT NULL,
    signature           TEXT     NOT NULL,  -- Ed25519 b64 (classical)
    signature_ml_dsa_65 TEXT     NOT NULL,  -- ML-DSA-65 b64 (REQUIRED)
    pqc_key_id          TEXT     NOT NULL,
    admitted_at         TEXT     NOT NULL,  -- ISO-8601 UTC
    PRIMARY KEY (peer_id, epoch_id, observed_at_unix_ms)
);

CREATE INDEX IF NOT EXISTS wholeness_witness_corpus_peer_recency
    ON wholeness_witness_corpus (peer_id, observed_at_unix_ms DESC);
