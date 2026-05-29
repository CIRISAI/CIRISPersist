-- V053 — federation_blobs access tracking, SQLite dialect
-- (CIRISPersist#123).
--
-- Postgres parity (postgres/lens/V053): TIMESTAMPTZ → TEXT (ISO8601),
-- BIGINT → INTEGER. SQLite ALTER TABLE … ADD COLUMN supports a literal
-- DEFAULT but not a function call; we default the new last_accessed_at
-- to a sentinel ISO8601 epoch string and the application backfills
-- new rows via the put_blob INSERT path (which now writes the column
-- explicitly). The backfill UPDATE below catches existing rows.

ALTER TABLE federation_blobs
    ADD COLUMN last_accessed_at TEXT NOT NULL
        DEFAULT '1970-01-01T00:00:00+00:00';

ALTER TABLE federation_blobs
    ADD COLUMN access_count INTEGER NOT NULL DEFAULT 0;

-- Backfill last_accessed_at for existing rows to their first_seen_at.
-- New rows land with the application-supplied value (see put_blob).
UPDATE federation_blobs
   SET last_accessed_at = first_seen_at
 WHERE last_accessed_at = '1970-01-01T00:00:00+00:00';

CREATE INDEX IF NOT EXISTS federation_blobs_eviction_score
    ON federation_blobs (last_accessed_at ASC, access_count ASC);
