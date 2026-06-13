-- V076 — retention_policies: durable per-table retention config for the
--        pressure-gated sweeper (CIRISPersist#209; CIRISLens#21).
--        Postgres dialect. SQLite parity: sqlite/lens/V076.
--
-- trace_events / trace_llm_calls grew unbounded post-cutover (the old
-- accord_traces 90d retention didn't carry to the new write targets).
-- Lens shipped a stopgap DELETE sweeper, but reaching into persist-owned
-- tables from the lens is the wrong layer — schema lifecycle belongs to
-- the substrate. This table stores the operator's per-table policy so the
-- sweeper (MaintenanceService::run_retention) is durable across restarts.
--
-- min_keep is the SACRED FLOOR — rows younger than it are never deleted,
-- regardless of pressure. pressure_trigger/target (nullable) gate the
-- sweep on pg_database_size: below trigger = no-op (no churn); at/above =
-- sweep oldest rows past min_keep. NULL pressure cols = flat
-- drop-after-min_keep. time_column is the ordering axis (the hypertable
-- time column, default `ts`); it + table_name are validated as strict
-- identifiers before reaching any SQL (identifiers can't be bound).

CREATE TABLE IF NOT EXISTS cirislens.retention_policies (
    table_name             TEXT PRIMARY KEY,
    time_column            TEXT NOT NULL DEFAULT 'ts',
    min_keep_secs          BIGINT NOT NULL,
    pressure_trigger_bytes BIGINT,
    pressure_target_bytes  BIGINT,
    interval_secs          BIGINT NOT NULL,
    updated_at             TIMESTAMPTZ NOT NULL
);
