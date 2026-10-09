-- V185 — where the V176 chunk-relation backfill resumes
-- v54.0.0 (CIRISPersist#994, Codex on PR #1050)
--
-- POSTGRES PARITY: migrations/postgres/lens/V185__dag_link_backfill_cursor.sql
--
-- The backfill walks `chunk_dag` manifests with no V176 relation in sha
-- order, at most a cap per pass. A manifest it cannot link (not granted to
-- this node, or its stream moved) stays unlinked, so a pass that always
-- started from the lowest sha re-examined the same capped prefix forever
-- once that many unlinkable manifests sorted first, and never reached a
-- linkable DAG after them. One row holds the sha the last capped pass
-- stopped after; the next pass resumes there and wraps around, so every
-- unlinked manifest is examined in turn. NULL (or no row) starts from the
-- lowest sha.

CREATE TABLE IF NOT EXISTS dag_link_backfill_cursor (
    singleton     INTEGER PRIMARY KEY CHECK (singleton = 1),
    after_sha256  BLOB NULL CHECK (after_sha256 IS NULL OR length(after_sha256) = 32),
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
