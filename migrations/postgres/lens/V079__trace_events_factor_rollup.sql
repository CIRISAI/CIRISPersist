-- V079 — per-agent scoring-factor rollup as a TimescaleDB continuous
--        aggregate (CIRISPersist#196, substrate side of CIRISLensCore#45).
--
-- `aggregate_scoring_factors_batch` aggregated raw `cirislens.trace_events`
-- on every cold call — O(agents × traces-in-window), ~65s for 151 agents
-- × 30 days on the deployed lens. `trace_events` is already a TimescaleDB
-- hypertable (V001), so the substrate has the on-ingest signal to maintain
-- an incremental per-agent 1h rollup. The batch read then sums the small
-- materialized buckets (30d × 24 × 151 ≈ 109k rows) — sub-second.
--
-- ═══ Substrate decision (a) — SCORE SOURCE: payload JSONB ═══
--
-- The DMA / conscience / action / fragility scalars live in the
-- `trace_events.payload` JSON, NOT in physical columns (see the V060
-- header note: "v3.x trace_events stores DMA/conscience/action/fragility
-- scalars inside the payload JSON … NOT as physical columns"). The V009
-- `extracted_features` column is NULLABLE and only populated when the
-- post-ingest pipeline ran (pipeline-skipped / pre-v0.6.0 rows are NULL),
-- so it cannot back a fleet-wide rollup without silently dropping every
-- pre-pipeline row. The existing `aggregate_scoring_factors_uncached`
-- compute already reads `payload->>'…'`; the rollup pre-aggregates the
-- SAME source so the rollup-backed answer equals the direct answer.
--
-- ═══ Substrate decision (b) — STRUCTURAL INVISIBILITY (CEG §10.1.4) ═══
--
-- The public rollup MUST NOT expose `cohort_scope ∈ {self, family}` rows
-- (CEG 0.10 §10.1.4 — those are byte-level structurally invisible). We
-- keep `cohort_scope` + `cohort_target_id` as GROUPING columns but the
-- CAGG's own WHERE filters self/family OUT at materialization, so those
-- rows are never written to the rollup at all. Rationale for the
-- grouping-column-with-filter shape over separate per-scope rollups:
--   * `community` + the broad belonging-tiers ARE public-federatable
--     (V060: community content "is NOT structurally invisible") and the
--     §4.3 read-gate admits them by (cohort_scope, cohort_target_id)
--     set-membership — keeping both columns lets the batch read apply the
--     IDENTICAL set-membership predicate against the rollup it applies
--     against raw `trace_events`, so the fast path and the fall-through
--     path enforce the same gate with the same SQL shape.
--   * self/family are filtered at the CAGG boundary (not just on read)
--     so the materialized rows are PROVABLY clean — a future read-path
--     bug cannot leak a self/family bucket that was never materialized.
-- A caller whose scope resolves to self/family rows therefore gets NO
-- rollup coverage; the Rust batch path detects that (CallerScope carries
-- self/family admission) and falls through to the direct raw-trace_events
-- aggregation for those agents (correct, just not CAGG-fast). See
-- `aggregate_scoring_factors_batch`.
--
-- ═══ Substrate decision (c) — AV-43 sample_count = trace_count ═══
--
-- `trace_count` (COUNT(DISTINCT trace_id) per bucket, summed across
-- buckets on read) IS the AV-43 `sample_count` the lens k-anon-gates on.
--
-- ═══ COUNTS, NOT PRE-DIVIDED RATES (summable across buckets) ═══
--
-- A 1h bucket must be summed over an arbitrary caller window, so the
-- rollup stores NUMERATORS + the DENOMINATOR, never a pre-divided rate:
-- the batch read sums the per-bucket `*_trace_count` numerators and the
-- `trace_count` denominator across the window and divides ONCE. Same for
-- the DMA means — stored as `SUM(value)` + `COUNT(value)` so the windowed
-- mean is `SUM(sum)/SUM(count)`. Pre-dividing per bucket and averaging
-- the rates would weight a 2-trace hour equally with a 2000-trace hour.
--
-- Per-trace collapse: TimescaleDB CAGGs forbid sub-queries in FROM (so
-- the batch's `GROUP BY trace_id` pre-collapse is impossible inside the
-- CAGG), but THIS TimescaleDB (>=2.x on pg16) accepts
-- `COUNT(DISTINCT trace_id) FILTER (…)`, which reconstructs the per-trace
-- booleans EXACTLY: a trace with N retried CONSCIENCE_RESULT events is
-- counted once in both numerator and denominator. The DMA means are
-- per-EVENT averages of the score-bearing events (the batch reads the
-- same `payload->>'…'` per row); stored as SUM+COUNT they remain exact.
--
-- ═══ CAGG-IN-MIGRATION CONSTRAINT — how this file handles it ═══
--
-- TimescaleDB forbids `CREATE MATERIALIZED VIEW … WITH
-- (timescaledb.continuous)` and `add_continuous_aggregate_policy()`
-- inside a transaction block. refinery 0.9.2's tokio-postgres driver
-- wraps EVERY migration in a transaction (drivers/tokio_postgres.rs:
-- `self.transaction()` → `batch_execute` → `commit`) with NO
-- per-migration no-transaction annotation. So the CAGG DDL cannot run
-- directly in this file.
--
-- WORKAROUND — autonomous connection via `dblink`. Inside the wrapping
-- transaction we open a fresh self-loop libpq connection with `dblink`
-- and run the CAGG DDL THROUGH it; that statement executes in its OWN
-- session outside refinery's transaction, so TimescaleDB accepts it. The
-- outer migration transaction only records the schema-history row. This
-- is the standard refinery+TimescaleDB pattern (refinery 0.9 has no
-- `runtime_config(no_transaction)` escape hatch). The loopback conn
-- string carries `user=current_user` so dblink reconnects as the
-- migration role (a bare loopback defaults to OS user `postgres`, which
-- is not a role on the timescale/timescaledb image).
--
-- Guards: whole block no-ops when timescaledb is absent (pure-Postgres,
-- FSD §7 #7 — the rollup is a PG-only acceleration; the Rust methods
-- stay functional on plain PG / sqlite via direct aggregation) and when
-- the CAGG already exists (hand-replay / pre-existing lens-side CAGG).

DO $$
DECLARE
    has_timescale BOOLEAN;
    has_cagg      BOOLEAN;
    conn_str      TEXT;
    -- Refresh-lag knob (CIRISPersist#196): 10min suits Capacity
    -- dashboards; the Coherence-Ratchet detection path can tighten it
    -- post-migration via `alter_job(<job_id>, schedule_interval => …)`
    -- with no new migration.
    refresh_schedule_interval CONSTANT TEXT := '10 minutes';
BEGIN
    SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb')
        INTO has_timescale;

    IF NOT has_timescale THEN
        RAISE NOTICE 'V079: timescaledb absent — skipping trace_events_factor_rollup_1h (rollup is a PG-only acceleration; aggregate_scoring_factors_* fall through to direct aggregation).';
        RETURN;
    END IF;

    SELECT EXISTS (
        SELECT 1 FROM timescaledb_information.continuous_aggregates
        WHERE view_schema = 'cirislens'
          AND view_name   = 'trace_events_factor_rollup_1h'
    ) INTO has_cagg;

    IF has_cagg THEN
        RAISE NOTICE 'V079: trace_events_factor_rollup_1h already exists — no-op.';
        RETURN;
    END IF;

    CREATE EXTENSION IF NOT EXISTS dblink;
    conn_str := format('dbname=%s user=%s', current_database(), current_user);

    -- ── The continuous aggregate, run OUTSIDE this transaction ──
    PERFORM dblink_exec(conn_str, $cagg$
        CREATE MATERIALIZED VIEW cirislens.trace_events_factor_rollup_1h
        WITH (timescaledb.continuous) AS
        SELECT
            time_bucket(INTERVAL '1 hour', ts) AS bucket_start,
            agent_id_hash,
            deployment_domain,
            cohort_scope,
            cohort_target_id,

            -- AV-43 sample_count denominator.
            COUNT(DISTINCT trace_id)::bigint AS trace_count,

            -- DMA means as SUM + COUNT of the score-bearing events
            -- (per-event, matching the batch's per-row payload read).
            COALESCE(SUM((payload->>'csdma_plausibility_score')::float8), 0)::float8
                AS csdma_sum,
            COUNT((payload->>'csdma_plausibility_score'))::bigint
                AS csdma_n,
            COALESCE(SUM((payload->>'idma_k_eff')::float8), 0)::float8
                AS k_eff_sum,
            COUNT((payload->>'idma_k_eff'))::bigint
                AS k_eff_n,
            COALESCE(SUM((payload->>'idma_correlation_risk')::float8), 0)::float8
                AS correlation_risk_sum,
            COUNT((payload->>'idma_correlation_risk'))::bigint
                AS correlation_risk_n,

            -- Per-trace rate numerators (denominator is trace_count).
            COUNT(DISTINCT trace_id) FILTER (
                WHERE event_type = 'CONSCIENCE_RESULT'
                  AND (payload->>'action_was_overridden')::bool
            )::bigint AS override_trace_count,
            COUNT(DISTINCT trace_id) FILTER (
                WHERE (payload->>'idma_fragility_flag')::bool
            )::bigint AS fragility_trace_count,

            -- conscience_pass: a trace "passes" iff NO CONSCIENCE_RESULT
            -- event in it failed. Materialize the FAIL count and derive
            -- pass = trace_count - fail on read (CAGGs can't express the
            -- per-trace BOOL_AND directly; the negation is summable).
            COUNT(DISTINCT trace_id) FILTER (
                WHERE event_type = 'CONSCIENCE_RESULT'
                  AND (payload->>'conscience_passed')::bool = false
            )::bigint AS conscience_fail_trace_count,
            COUNT(DISTINCT trace_id) FILTER (
                WHERE event_type = 'CONSCIENCE_RESULT'
                  AND (payload->>'entropy_passed')::bool = false
            )::bigint AS entropy_fail_trace_count,
            COUNT(DISTINCT trace_id) FILTER (
                WHERE event_type = 'CONSCIENCE_RESULT'
                  AND (payload->>'coherence_passed')::bool = false
            )::bigint AS coherence_fail_trace_count,
            COUNT(DISTINCT trace_id) FILTER (
                WHERE event_type = 'CONSCIENCE_RESULT'
                  AND (payload->>'optimization_veto_passed')::bool = false
            )::bigint AS optimization_veto_fail_trace_count,
            COUNT(DISTINCT trace_id) FILTER (
                WHERE event_type = 'CONSCIENCE_RESULT'
                  AND (payload->>'epistemic_humility_passed')::bool = false
            )::bigint AS epistemic_humility_fail_trace_count,

            -- NB — unsafe_action_rate is NOT rollup-derivable. The batch's
            -- unsafe = (conscience FAILED) AND (action SUCCEEDED) is a
            -- per-trace conjunction across DIFFERENT event rows of the
            -- same trace; a CAGG single-row FILTER cannot see both and
            -- CAGGs forbid the sub-query that would pre-collapse per
            -- trace. The rollup therefore does NOT materialize unsafe; the
            -- Rust batch path computes unsafe_action_rate directly (one
            -- cheap extra round-trip) and fills every other scalar from
            -- the summed buckets. Same for the per-trace-sequenced /
            -- baseline-dependent fields (recovery_events, drift_z_score,
            -- coherence_decay_series, audit_chain_gaps, identity_changes,
            -- calibration_error) — see `aggregate_scoring_factors_batch`.

            -- Audit-chain totals (per-trace presence).
            COUNT(DISTINCT trace_id) FILTER (
                WHERE audit_sequence_number IS NOT NULL
            )::bigint AS audit_seq_trace_count,
            COUNT(DISTINCT trace_id) FILTER (
                WHERE audit_signature IS NOT NULL
            )::bigint AS audit_sig_trace_count
        FROM cirislens.trace_events
        WHERE cohort_scope NOT IN ('self', 'family')
        GROUP BY bucket_start, agent_id_hash, deployment_domain,
                 cohort_scope, cohort_target_id
        WITH NO DATA;
    $cagg$);

    -- `add_continuous_aggregate_policy` RETURNS the job id, so it must go
    -- through `dblink(...)` (record-returning) not `dblink_exec(...)`
    -- (`dblink_exec` rejects result-returning statements). The returned
    -- job id is discarded via PERFORM.
    PERFORM * FROM dblink(conn_str, format(
        $pol$
        SELECT add_continuous_aggregate_policy(
            'cirislens.trace_events_factor_rollup_1h',
            start_offset      => INTERVAL '7 days',
            end_offset        => INTERVAL '1 hour',
            schedule_interval => INTERVAL %L
        )::text;
        $pol$, refresh_schedule_interval)) AS t(job_id text);

    RAISE NOTICE 'V079: trace_events_factor_rollup_1h continuous aggregate created (schedule_interval=%).', refresh_schedule_interval;
END
$$;
