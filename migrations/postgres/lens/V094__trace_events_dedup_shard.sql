-- V094 — app-level hashed shards for the trace-ingest dedup index
--        (CIRISPersist#226) (Postgres dialect).
--
-- # Why
--
-- The CEWP "store at massive scale" claim is an AGGREGATE claim, but the
-- persist step is a 5+-tuple `ON CONFLICT DO NOTHING` upsert against ONE
-- shared UNIQUE index (`trace_events_dedup`, V001). Fan aggregate ingest
-- across cores/connections and every concurrent writer contends on exactly
-- that index — the right-edge leaf pages as `ts` climbs, plus the
-- uniqueness probe — so aggregate throughput goes sublinear well before
-- cores × per-core. #226's operator decision: relieve it CENTRALLY, in
-- persist, so every deployment benefits — plain PG + SQLite, NO extensions,
-- NO per-deployment tuning, NO TimescaleDB. App-level hashed shards.
--
-- # How
--
-- Add a `shard_key` SMALLINT in `[0, 64)` (persist's `TRACE_DEDUP_SHARD_
-- COUNT`) derived deterministically from a SUBSET of the dedup key
-- (`agent_id_hash, trace_id, thought_id, event_type, attempt_index` —
-- deliberately NOT `ts`) by the Rust `trace_dedup_shard_key` (FNV-1a/64).
-- The dedup index is then PREFIXED with `shard_key`, so concurrent inserts
-- spread across 64 disjoint B-tree subtrees instead of colliding on one
-- hot page.
--
-- Dedup semantics are preserved EXACTLY: `shard_key` is a pure function of
-- the other key columns, so a true duplicate (identical full tuple) always
-- computes the identical shard and still collides. Uniqueness over
-- `(shard_key, agent_id_hash, trace_id, thought_id, event_type,
-- attempt_index, ts)` forbids precisely the same rows the old 6-column
-- `trace_events_dedup` did — the shard column adds no distinguishing power.
--
-- # Backfill (legacy rows)
--
-- Pre-#226 rows have `shard_key = NULL`. They are correct as-is under the
-- new UNIQUE index (a NULL leading column is DISTINCT, so no legacy row can
-- collide during the window), but a NULL row could not dedup against a
-- POST-migration re-ingest of the same trace (whose computed shard is
-- non-NULL). So persist backfills them in Rust immediately after this
-- migration, inside the same `run_migrations` call, BEFORE the engine
-- serves any write — computing the byte-identical FNV shard the insert path
-- uses (`Backend::run_migrations` → `backfill_trace_dedup_shard_keys`). The
-- FNV hash is not expressible in portable, extension-free SQL across both
-- backends, so the backfill lives in Rust (identical on PG + SQLite); this
-- migration only does the DDL.
--
-- The partial index below keeps the "any row still NULL?" probe O(1): it
-- covers ONLY the not-yet-backfilled rows, shrinks to empty as the backfill
-- runs, and — because every new insert writes a non-NULL shard — stays
-- empty forever after (near-zero maintenance cost). It doubles as the
-- backfill work-list.
--
-- No TimescaleDB (operator directive): plain postgres:16, ordinary index.
-- No explicit BEGIN/COMMIT — refinery wraps each migration in a transaction.

-- ── 1. The shard column (nullable → legacy rows are NULL until backfilled) ──
ALTER TABLE cirislens.trace_events
    ADD COLUMN IF NOT EXISTS shard_key SMALLINT;

-- ── 2. The sharded dedup UNIQUE index (prefixed with shard_key) ────────────
--
-- Building this over legacy rows (all shard_key NULL) is safe: NULLs are
-- DISTINCT in a UNIQUE index, and the old 6-column index already guaranteed
-- the rest of the tuple unique, so no conflict can arise at build time.
CREATE UNIQUE INDEX IF NOT EXISTS trace_events_dedup_sharded
    ON cirislens.trace_events (
        shard_key, agent_id_hash, trace_id, thought_id, event_type,
        attempt_index, ts
    );

-- ── 3. Retire the old single hot dedup index ──────────────────────────────
--
-- Keeping it would keep the contention (every insert would still probe it).
-- The sharded index above is now the sole — and equivalent — dedup guard.
DROP INDEX IF EXISTS cirislens.trace_events_dedup;

-- ── 4. Backfill work-list / cheap NULL-probe (empty once backfilled) ───────
CREATE INDEX IF NOT EXISTS trace_events_shard_backfill
    ON cirislens.trace_events (event_id)
    WHERE shard_key IS NULL;
