-- V082 — neutralize V001's TimescaleDB hypertable on trace_events /
--        trace_llm_calls (CIRISPersist#222 follow-up).
--
-- V001 is shipped + immutable. On plain-PostgreSQL deployments its
-- `create_hypertable(...)` calls were guarded behind
-- `IF EXISTS (… pg_extension WHERE extname='timescaledb')` and therefore
-- NEVER RAN — `trace_events` / `trace_llm_calls` are already ordinary
-- tables. The operator target is plain PG, so the COMMON PATH of this
-- migration is a clean NO-OP (the guard below short-circuits when
-- timescaledb is absent, and even when present, when the relations are
-- not hypertables).
--
-- ═══ Plain-PG no-op proof ═══
-- The outer guard is `IF NOT has_timescale THEN RETURN`. On a database
-- with no timescaledb extension that branch returns immediately, touching
-- nothing. CI (plain postgres:16) takes exactly this branch.
--
-- ═══ TimescaleDB-deployment path (data-preserving conversion) ═══
-- If a legacy timescale image DID create the hypertable, we convert it
-- back to a plain table data-preservingly, per relation:
--   1. Rename the hypertable aside (…__ht_old).
--   2. CREATE TABLE … (LIKE … INCLUDING ALL) to clone the exact column +
--      constraint + index shape as a PLAIN table.
--   3. INSERT … SELECT every row across (copies all chunks' data).
--   4. DROP the old hypertable (CASCADE drops its chunks).
-- This runs inside refinery's migration transaction; a failure rolls the
-- whole thing back, so a partial conversion can never be committed.
--
-- ⚠️  RISK FLAGGED (CIRISPersist#222): the convert path materializes the
--     ENTIRE table into a new plain table in one transaction. On a large
--     production hypertable this is a long, lock-heavy, disk-doubling
--     operation and SHOULD be run in a maintenance window with adequate
--     free space — NOT silently on boot. Because the operator deployment
--     is plain PG (no hypertable → no-op), this path does not execute in
--     the target environment; it exists only to make a mistakenly-on-a-
--     timescale-image deployment self-heal to the agnostic shape. An
--     operator who knowingly runs TimescaleDB and wants to keep the
--     hypertable should NOT apply this migration set / should detach the
--     chunks manually. The conservative default here converts because the
--     whole point of #222 is to remove the TimescaleDB dependency.

DO $$
DECLARE
    has_timescale BOOLEAN;
    rel           TEXT;
    is_ht         BOOLEAN;
BEGIN
    SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb')
        INTO has_timescale;

    IF NOT has_timescale THEN
        -- Plain-PG / sqlite-equivalent path: nothing to do. The tables are
        -- already plain. This is the operator's deployment.
        RAISE NOTICE 'V082: timescaledb absent — trace_events/trace_llm_calls already plain tables (no-op).';
        RETURN;
    END IF;

    FOREACH rel IN ARRAY ARRAY['trace_events', 'trace_llm_calls']
    LOOP
        -- Is this relation a timescaledb hypertable?
        SELECT EXISTS (
            SELECT 1 FROM timescaledb_information.hypertables
            WHERE hypertable_schema = 'cirislens'
              AND hypertable_name   = rel
        ) INTO is_ht;

        IF NOT is_ht THEN
            RAISE NOTICE 'V082: cirislens.% is not a hypertable — no-op.', rel;
            CONTINUE;
        END IF;

        RAISE WARNING 'V082: converting hypertable cirislens.% to a plain table (data-preserving copy; see #222 risk note).', rel;

        EXECUTE format(
            'ALTER TABLE cirislens.%I RENAME TO %I',
            rel, rel || '__ht_old'
        );
        EXECUTE format(
            'CREATE TABLE cirislens.%I (LIKE cirislens.%I INCLUDING ALL)',
            rel, rel || '__ht_old'
        );
        EXECUTE format(
            'INSERT INTO cirislens.%I SELECT * FROM cirislens.%I',
            rel, rel || '__ht_old'
        );
        EXECUTE format(
            'DROP TABLE cirislens.%I CASCADE',
            rel || '__ht_old'
        );
        RAISE WARNING 'V082: cirislens.% converted to a plain table.', rel;
    END LOOP;
END
$$;
