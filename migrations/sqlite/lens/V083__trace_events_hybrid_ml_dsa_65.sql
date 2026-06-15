-- V083 — per-trace ML-DSA-65 hybrid signature columns (CIRISPersist#225,
--        SQLite translation).
--
-- Mirrors migrations/postgres/lens/V083__trace_events_hybrid_ml_dsa_65.sql.
-- The trace-tier hybrid hard cut: the producer's per-trace-envelope
-- signature must carry + verify ML-DSA-65 (HNDL forge-later on the
-- durable trace corpus). See the postgres copy for the full rationale.
--
-- Three NULLABLE columns mirroring the federation key split:
--   * signature_ml_dsa_65 — base64 ML-DSA-65 producer signature.
--   * pubkey_ml_dsa_65     — base64 producer ML-DSA-65 public key
--                            (asserted on the envelope; bound into the
--                            hybrid verify).
--   * pqc_key_id           — producer ML-DSA-65 key identifier.
--
-- NULLABLE is load-bearing: the migration + existing classical rows +
-- the `2.7.legacy` pre-verified carve-out must not break. Presence for
-- NEW Full-mode writes is enforced by the ingest gate, NOT a column
-- constraint (the gate can tell a legacy/pre-verified row from a
-- Full-mode admission; a DB CHECK cannot).
--
-- SQLite supports `ALTER TABLE … ADD COLUMN` since 3.2.0. SQLite has no
-- schema namespace, so the table is bare `trace_events` (the PG copy
-- uses `cirislens.trace_events`). No `IF NOT EXISTS` on ADD COLUMN, but
-- refinery runs each migration exactly once.

ALTER TABLE trace_events ADD COLUMN signature_ml_dsa_65 TEXT;
ALTER TABLE trace_events ADD COLUMN pubkey_ml_dsa_65    TEXT;
ALTER TABLE trace_events ADD COLUMN pqc_key_id          TEXT;

CREATE INDEX IF NOT EXISTS trace_events_pqc_key
    ON trace_events (pqc_key_id, ts DESC)
    WHERE signature_ml_dsa_65 IS NOT NULL;
