-- V179 — the trace listing's page is named from an index, Postgres dialect
-- v53.1.5 (CIRISServer's canonical node OOM-looped, 2026-10-06)
--
-- SQLITE PARITY: migrations/sqlite/lens/V179__trace_events_trace_ts_scope.sql
-- See that file's header for the rationale. The production fault was
-- SQLite's; the read is two-phase on both dialects so the page is named
-- by (trace_id, MIN(ts)) and the aggregates run over those ids alone.
--
-- Postgres has INCLUDE (the V042 `trace_events_an_trace_summary` shape):
-- the key stays (trace_id, ts) and the scope columns ride as payload, so
-- phase 1 under any caller scope and the default filter is index-only.
--
-- Refinery wraps each migration in a transaction, so plain CREATE INDEX,
-- not CONCURRENTLY (V042's precedent). `cirislens.trace_events` is a
-- plain table (no partitioning, no TimescaleDB).

CREATE INDEX IF NOT EXISTS trace_events_trace_ts_scope
    ON cirislens.trace_events (trace_id, ts)
    INCLUDE (cohort_scope, cohort_target_id);
