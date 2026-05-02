-- V003 — scrub envelope columns (v0.1.3, SQLite translation).
--
-- Mirrors migrations/postgres/lens/V003__scrub_envelope.sql.
-- Cryptographic provenance of deployment handling. FSD §3.3 step 3.5
-- + §3.4 robustness primitive #7 + §3.7. THREAT_MODEL.md AV-24/25.
--
-- SQLite supports `ALTER TABLE … ADD COLUMN` since 3.2.0. Every v0.1.3+
-- row populates these four; pre-v0.1.3 rows have NULLs (historical
-- artifact bounded by 30-day retention).
--
-- SQLite has no `IF NOT EXISTS` qualifier on ADD COLUMN, but refinery
-- runs each migration exactly once so re-application is not a concern.
-- For sovereign-mode operators applying migrations manually, the
-- standard guard is "check sqlite_master / table_info before running"
-- — out of scope for the refinery-driven path.

ALTER TABLE trace_events ADD COLUMN original_content_hash TEXT;
ALTER TABLE trace_events ADD COLUMN scrub_signature       TEXT;
ALTER TABLE trace_events ADD COLUMN scrub_key_id          TEXT;
ALTER TABLE trace_events ADD COLUMN scrub_timestamp       TEXT;

CREATE INDEX IF NOT EXISTS trace_events_scrub_key
    ON trace_events (scrub_key_id, ts DESC)
    WHERE scrub_signature IS NOT NULL;
