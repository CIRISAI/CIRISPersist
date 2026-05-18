-- V023 — trace_events pipeline JSONB columns (SQLite parity with PG V009).
--
-- v1.5.8 (CIRISPersist#57 follow-up) — closes the PG-only gap for
-- get_classifications / get_features. The v1.5.1 parity sweep had left
-- these 2 methods returning a typed "pipeline-read primitives are
-- Postgres-only" error on SQLite; v1.5.8 makes SQLite a first-class
-- substrate for the pipeline read+write path (sovereign-mode + agent's
-- AdaptiveFilter round-trip).
--
-- Mirror of migrations/postgres/lens/V009__pipeline_columns.sql. PG uses
-- `cirislens.trace_events` + JSONB; SQLite uses unqualified
-- `trace_events` (no schemas) + TEXT (json1 reads TEXT as JSON, and the
-- v0.1.8 WireDateTime doctrine treats payload bytes as opaque —
-- serde_json::from_str on the way out).
--
-- All 3 columns nullable: pre-V023 rows stay valid (rollback-safe);
-- pipeline-aware consumers detect "no pipeline ran" via
-- `extracted_features IS NULL`.
--
-- # Indexing
--
-- No new indexes in V023 (matches PG V009's deferred-indexing stance —
-- JSON scans are linear at sovereign-mode scale; revisit if RATCHET or
-- agent dashboards ask for classifications-by-class hot-path queries).
--
-- # Refinery transaction wrapping
--
-- Refinery wraps each migration in its own transaction, so no explicit
-- BEGIN/COMMIT here — nesting would fail at the driver with "cannot
-- start a transaction within a transaction" (same pattern V019 + V022
-- fix on PG / SQLite).

ALTER TABLE trace_events ADD COLUMN extracted_features  TEXT;
ALTER TABLE trace_events ADD COLUMN classifications     TEXT;
ALTER TABLE trace_events ADD COLUMN pipeline_metadata   TEXT;
