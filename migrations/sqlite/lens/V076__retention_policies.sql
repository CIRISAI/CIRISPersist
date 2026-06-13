-- V076 — retention_policies: durable per-table retention config for the
--        pressure-gated sweeper (CIRISPersist#209; CIRISLens#21).
--        SQLite dialect. Postgres parity: postgres/lens/V076.
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
-- sweep on db size: below trigger = no-op (no churn); at/above = sweep
-- oldest rows past min_keep. NULL pressure cols = flat drop-after-min_keep.
-- time_column is the ordering axis (the hypertable time column, default
-- `ts`); it + table_name are validated as strict identifiers before they
-- reach any SQL (no parameter binding for identifiers).

CREATE TABLE retention_policies (
    table_name             TEXT PRIMARY KEY,   -- validated identifier (schema.table)
    time_column            TEXT NOT NULL DEFAULT 'ts',
    min_keep_secs          INTEGER NOT NULL,   -- sacred floor
    pressure_trigger_bytes INTEGER,            -- NULL = flat (no pressure gate)
    pressure_target_bytes  INTEGER,            -- NULL = flat
    interval_secs          INTEGER NOT NULL,   -- sweeper cadence (advisory; scheduler honours)
    updated_at             TEXT NOT NULL       -- RFC-3339 UTC
);
