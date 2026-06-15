-- V081 — replace the #196 TimescaleDB continuous aggregate with a plain,
--        backend-agnostic rollup TABLE (CIRISPersist#222 follow-up).
--
-- The operator deployment is plain PostgreSQL / SQLite — TimescaleDB is
-- NOT available and MUST NOT be required. V079 built
-- `cirislens.trace_events_factor_rollup_1h` as a TimescaleDB continuous
-- aggregate (CREATE MATERIALIZED VIEW … WITH (timescaledb.continuous) via
-- a dblink autonomous connection). This migration tears that down and
-- re-creates the SAME relation name as an ordinary table with identical
-- columns + semantics. The hour bucket is `date_trunc('hour', ts)` (plain
-- PG, no `time_bucket()`); SQLite uses `strftime('%Y-%m-%dT%H:00:00Z', ts)`
-- (see sqlite/lens/V081). The rollup is maintained incrementally by an
-- idempotent upsert (`refresh_factor_rollup`) driven lazily on the batch
-- read — NO TimescaleDB continuous-aggregate policy.
--
-- ═══ Idempotency / replay safety ═══
--   * On a plain-PG deployment the CAGG never existed, so the
--     `DROP MATERIALIZED VIEW` is a guarded no-op.
--   * On a deployment that previously ran the V079 CAGG (a timescale image
--     in CI history), we drop the continuous-aggregate policy + the CAGG
--     (CASCADE) before creating the plain table under the same name.
--   * `CREATE TABLE IF NOT EXISTS` so a hand-replay is a no-op.
--
-- ═══ §10.1.4 structural invisibility ═══
-- The rollup carries `cohort_scope` + `cohort_target_id` as GROUPING
-- columns; the refresh upsert filters `cohort_scope NOT IN ('self',
-- 'family')` at materialization, so self/family buckets are never written
-- (same invariant the V079 CAGG enforced — a read-path bug cannot leak a
-- bucket that was never materialized).

-- ── 1. Tear down the old TimescaleDB CAGG, if one exists ──────────────
DO $$
DECLARE
    has_timescale BOOLEAN;
    has_cagg      BOOLEAN;
BEGIN
    SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb')
        INTO has_timescale;

    IF has_timescale THEN
        -- The CAGG is registered in timescaledb_information; only then is
        -- it a continuous aggregate we must drop the policy for.
        SELECT EXISTS (
            SELECT 1 FROM timescaledb_information.continuous_aggregates
            WHERE view_schema = 'cirislens'
              AND view_name   = 'trace_events_factor_rollup_1h'
        ) INTO has_cagg;

        IF has_cagg THEN
            -- Drop the refresh policy first (IF EXISTS — tolerant of a
            -- CAGG that was created WITH NO DATA and never got a policy).
            BEGIN
                PERFORM remove_continuous_aggregate_policy(
                    'cirislens.trace_events_factor_rollup_1h',
                    if_exists => TRUE
                );
            EXCEPTION WHEN OTHERS THEN
                -- Older timescale builds lack the if_exists arg; ignore.
                NULL;
            END;
            -- CASCADE drops the materialization hypertable + the view.
            EXECUTE 'DROP MATERIALIZED VIEW IF EXISTS '
                 || 'cirislens.trace_events_factor_rollup_1h CASCADE';
            RAISE NOTICE 'V081: dropped legacy timescaledb CAGG trace_events_factor_rollup_1h.';
        END IF;
    END IF;
END
$$;

-- Belt-and-braces: if a relation of this name still exists and is NOT a
-- plain table (e.g. a plain materialized view from a hand-replay), drop
-- it so the CREATE TABLE below owns the name. A plain TABLE is left alone
-- (CREATE TABLE IF NOT EXISTS no-ops).
DO $$
DECLARE
    relkind_now "char";
BEGIN
    SELECT c.relkind INTO relkind_now
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'cirislens'
      AND c.relname = 'trace_events_factor_rollup_1h';

    -- relkind 'r' = ordinary table, 'p' = partitioned table. Anything
    -- else (m = matview, v = view) that survived the drop above gets
    -- removed so the plain table can be created.
    IF relkind_now IS NOT NULL AND relkind_now NOT IN ('r', 'p') THEN
        EXECUTE 'DROP MATERIALIZED VIEW IF EXISTS '
             || 'cirislens.trace_events_factor_rollup_1h CASCADE';
    END IF;
END
$$;

-- ── 2. The plain, agnostic rollup table ───────────────────────────────
--
-- One row per (hour-bucket, agent, deployment_domain, cohort_scope,
-- cohort_target_id). Stores NUMERATORS + the DENOMINATOR (never a
-- pre-divided rate) so an arbitrary caller window is summed across whole
-- buckets and divided once on read. Same column set the V079 CAGG
-- materialized.
CREATE TABLE IF NOT EXISTS cirislens.trace_events_factor_rollup_1h (
    bucket_start                       TIMESTAMPTZ NOT NULL,
    agent_id_hash                      TEXT,
    deployment_domain                  TEXT,
    cohort_scope                       TEXT,
    cohort_target_id                   TEXT,

    -- AV-43 sample_count denominator (COUNT(DISTINCT trace_id) per bucket).
    trace_count                        BIGINT NOT NULL DEFAULT 0,

    -- DMA means as SUM + COUNT of the score-bearing events.
    csdma_sum                          DOUBLE PRECISION NOT NULL DEFAULT 0,
    csdma_n                            BIGINT NOT NULL DEFAULT 0,
    k_eff_sum                          DOUBLE PRECISION NOT NULL DEFAULT 0,
    k_eff_n                            BIGINT NOT NULL DEFAULT 0,
    correlation_risk_sum               DOUBLE PRECISION NOT NULL DEFAULT 0,
    correlation_risk_n                 BIGINT NOT NULL DEFAULT 0,

    -- Per-trace rate numerators (denominator is trace_count).
    override_trace_count               BIGINT NOT NULL DEFAULT 0,
    fragility_trace_count              BIGINT NOT NULL DEFAULT 0,
    conscience_fail_trace_count        BIGINT NOT NULL DEFAULT 0,
    entropy_fail_trace_count           BIGINT NOT NULL DEFAULT 0,
    coherence_fail_trace_count         BIGINT NOT NULL DEFAULT 0,
    optimization_veto_fail_trace_count BIGINT NOT NULL DEFAULT 0,
    epistemic_humility_fail_trace_count BIGINT NOT NULL DEFAULT 0,

    -- Audit-chain totals (per-trace presence).
    audit_seq_trace_count              BIGINT NOT NULL DEFAULT 0,
    audit_sig_trace_count              BIGINT NOT NULL DEFAULT 0
);

-- Conflict target: a UNIQUE INDEX over the COALESCE'd grouping columns so
-- a NULL agent_id_hash / domain / scope / target is ONE conflict key, not
-- many (NULLs are distinct under a plain UNIQUE; Postgres also can't put
-- expressions in a table PRIMARY KEY). The upsert's ON CONFLICT clause
-- lists the IDENTICAL expressions so it binds to this index.
CREATE UNIQUE INDEX IF NOT EXISTS trace_events_factor_rollup_1h_key
    ON cirislens.trace_events_factor_rollup_1h (
        bucket_start,
        COALESCE(agent_id_hash, ''),
        COALESCE(deployment_domain, ''),
        COALESCE(cohort_scope, ''),
        COALESCE(cohort_target_id, '')
    );

CREATE INDEX IF NOT EXISTS trace_events_factor_rollup_1h_agent_bucket
    ON cirislens.trace_events_factor_rollup_1h (agent_id_hash, bucket_start);

-- ── 3. Refresh watermark (incremental-maintenance bookkeeping) ────────
--
-- A single-row table holding the high-water `ts` already folded into the
-- rollup. `refresh_factor_rollup(since)` re-aggregates buckets touching
-- [since, now] and advances the watermark. Lazy refresh-on-read uses it
-- so the fleet sweep only ever re-folds the trailing tail, never the full
-- history.
CREATE TABLE IF NOT EXISTS cirislens.trace_events_factor_rollup_meta (
    id                  BOOLEAN PRIMARY KEY DEFAULT TRUE,
    last_refreshed_ts   TIMESTAMPTZ,
    CONSTRAINT trace_events_factor_rollup_meta_singleton CHECK (id)
);
INSERT INTO cirislens.trace_events_factor_rollup_meta (id, last_refreshed_ts)
VALUES (TRUE, NULL)
ON CONFLICT (id) DO NOTHING;
