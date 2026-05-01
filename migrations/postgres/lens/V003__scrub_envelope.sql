-- V003 — scrub envelope columns (v0.1.3).
--
-- Cryptographic provenance of deployment handling. FSD §3.3 step 3.5
-- + §3.4 robustness primitive #7 + §3.7. THREAT_MODEL.md AV-24/25.
--
-- Every v0.1.3+ row populates these four; pre-v0.1.3 rows have NULLs
-- (historical artifact bounded by 30-day retention).

ALTER TABLE cirislens.trace_events
    ADD COLUMN IF NOT EXISTS original_content_hash TEXT,
    ADD COLUMN IF NOT EXISTS scrub_signature       TEXT,
    ADD COLUMN IF NOT EXISTS scrub_key_id          TEXT,
    ADD COLUMN IF NOT EXISTS scrub_timestamp       TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS trace_events_scrub_key
    ON cirislens.trace_events (scrub_key_id, ts DESC)
    WHERE scrub_signature IS NOT NULL;
