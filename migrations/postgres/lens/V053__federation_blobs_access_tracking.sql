-- V053 — federation_blobs access tracking (CIRISPersist#123).
--
-- Adds the two columns the EvictionSweeper reads to compute the
-- LRU+frequency score: a per-row last_accessed_at and a monotonic
-- access_count. Each get_blob / has_blob hit bumps the row.
--
-- # Why on federation_blobs (and not a sibling table)
--
-- The eviction policy ranks blobs against a host's storage budget;
-- the row identity IS the rank target. Keeping the counters on the
-- same row keeps the sweeper SQL to a single ORDER BY without a
-- join, and the access bump on get_blob / has_blob to a single UPDATE.
--
-- # Defaults match v0 ingest semantics
--
-- For rows that existed before this migration:
--   - last_accessed_at defaults to first_seen_at (rows are "as old as
--     their birth" — no read activity to date).
--   - access_count defaults to 0 (zero observed reads).
--
-- The sweeper applies the configured decay function to last_accessed_at
-- so older rows score lower; access_count breaks ties when last-touch
-- times match.
--
-- # Index choice
--
-- (last_accessed_at ASC, access_count ASC) — sweeper scans ASC so
-- the index returns eviction candidates first. The composite ordering
-- mirrors the score-derivation: oldest-then-coldest leads.

ALTER TABLE cirislens.federation_blobs
    ADD COLUMN IF NOT EXISTS last_accessed_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW();

ALTER TABLE cirislens.federation_blobs
    ADD COLUMN IF NOT EXISTS access_count BIGINT NOT NULL DEFAULT 0;

-- Backfill last_accessed_at for pre-V053 rows to their first_seen_at
-- so the sweeper treats existing rows as "as old as their birth".
-- DEFAULT NOW() handles future inserts; this UPDATE handles backfill.
UPDATE cirislens.federation_blobs
   SET last_accessed_at = first_seen_at
 WHERE last_accessed_at >= first_seen_at;

CREATE INDEX IF NOT EXISTS federation_blobs_eviction_score
    ON cirislens.federation_blobs (last_accessed_at ASC, access_count ASC);

COMMENT ON COLUMN cirislens.federation_blobs.last_accessed_at IS
    'v3.4.0 (CIRISPersist#123) — wall-clock of the most recent get_blob / has_blob hit. Backfilled to first_seen_at for pre-V053 rows; bumped by put-side reads via UPDATE … RETURNING in the same statement that selects the row.';

COMMENT ON COLUMN cirislens.federation_blobs.access_count IS
    'v3.4.0 (CIRISPersist#123) — monotonic count of get_blob / has_blob hits since the row was inserted. Used by the EvictionSweeper to break ties when last_accessed_at matches.';
