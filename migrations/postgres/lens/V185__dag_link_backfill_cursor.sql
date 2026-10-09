-- V185 — where the V176 chunk-relation backfill resumes, Postgres dialect
-- v54.0.0 (CIRISPersist#994, Codex on PR #1050)
--
-- SQLITE PARITY: migrations/sqlite/lens/V185__dag_link_backfill_cursor.sql
-- See that file's header for the rationale.

CREATE TABLE IF NOT EXISTS cirislens.dag_link_backfill_cursor (
    singleton     BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    after_sha256  BYTEA NULL CHECK (after_sha256 IS NULL OR length(after_sha256) = 32),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
