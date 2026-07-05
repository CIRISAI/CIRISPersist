-- V094 — app-level hashed shards for the trace-ingest dedup index
--        (CIRISPersist#226) (SQLite dialect).
--
-- SQLite translation of migrations/postgres/lens/V094__trace_events_dedup_
-- shard.sql. Same logical change; only the dialect differs (NO pg/sqlite
-- asymmetry — the shard column, the sharded UNIQUE index, and the Rust
-- backfill are identical on both backends).
--
-- Type mapping: Postgres SMALLINT → SQLite INTEGER (SQLite's INTEGER is
-- variable-width; the shard is a small `[0, 64)` value). Schema-qualified
-- `cirislens.` prefixes are dropped (SQLite has no schemas).
--
-- Rationale (see the postgres V094 header for the full story): the dedup
-- UNIQUE index `trace_events_dedup` (V001) is a single hot B-tree that all
-- concurrent aggregate-ingest writers contend on. #226 prefixes it with a
-- `shard_key` in `[0, 64)` derived deterministically from a SUBSET of the
-- dedup key (`agent_id_hash, trace_id, thought_id, event_type,
-- attempt_index` — NOT `ts`) by the Rust `trace_dedup_shard_key`
-- (FNV-1a/64), spreading inserts across 64 disjoint subtrees. Dedup is
-- preserved EXACTLY: the shard is a pure function of the other key columns,
-- so a true duplicate computes the same shard and still collides.
--
-- Legacy rows (shard_key NULL) are backfilled in Rust right after this
-- migration, before any write is served — `Backend::run_migrations` →
-- `backfill_trace_dedup_shard_keys` — computing the byte-identical FNV
-- shard. The partial index below is both the O(1) NULL-probe and the
-- backfill work-list; it empties as the backfill runs and stays empty
-- (new inserts always write a non-NULL shard).

-- ── 1. The shard column (nullable → legacy rows NULL until backfilled) ──
ALTER TABLE trace_events ADD COLUMN shard_key INTEGER;

-- ── 2. The sharded dedup UNIQUE index (prefixed with shard_key) ────────
CREATE UNIQUE INDEX IF NOT EXISTS trace_events_dedup_sharded
    ON trace_events (
        shard_key, agent_id_hash, trace_id, thought_id, event_type,
        attempt_index, ts
    );

-- ── 3. Retire the old single hot dedup index ───────────────────────────
DROP INDEX IF EXISTS trace_events_dedup;

-- ── 4. Backfill work-list / cheap NULL-probe (empty once backfilled) ───
CREATE INDEX IF NOT EXISTS trace_events_shard_backfill
    ON trace_events (event_id)
    WHERE shard_key IS NULL;
