-- V081 — plain, backend-agnostic scoring-factor rollup TABLE (SQLite).
--        CIRISPersist#222 follow-up; postgres parity:
--        postgres/lens/V081.
--
-- SQLite NEVER had the V079 TimescaleDB continuous aggregate (V079 is a
-- postgres-only file; SQLite's lens migration set skips it). So there is
-- nothing to tear down here — this migration just CREATEs the same plain
-- rollup table the postgres V081 creates, so the #196 fleet-sweep
-- acceleration is available on sovereign-mode (Pi / iOS) SQLite
-- deployments too.
--
-- Hour bucket on read/refresh is `strftime('%Y-%m-%dT%H:00:00Z', ts)`
-- (NO time_bucket()); the column stores that TEXT form so it is directly
-- comparable to the RFC3339 `ts` strings the rest of the schema uses
-- (`+00:00`-normalized writers → lexical order == chronological order).
--
-- §10.1.4: cohort_scope/cohort_target_id are grouping columns; the
-- refresh upsert filters self/family OUT at materialization (see
-- src/store/sqlite.rs refresh_factor_rollup), so those buckets are never
-- written to the public rollup.

CREATE TABLE IF NOT EXISTS trace_events_factor_rollup_1h (
    -- TEXT bucket key: strftime('%Y-%m-%dT%H:00:00Z', ts). Stored as the
    -- hour-truncated RFC3339 string so window bounds (also RFC3339 TEXT)
    -- compare lexically.
    bucket_start                       TEXT    NOT NULL,
    agent_id_hash                      TEXT,
    deployment_domain                  TEXT,
    cohort_scope                       TEXT,
    cohort_target_id                   TEXT,

    trace_count                        INTEGER NOT NULL DEFAULT 0,

    csdma_sum                          REAL    NOT NULL DEFAULT 0,
    csdma_n                            INTEGER NOT NULL DEFAULT 0,
    k_eff_sum                          REAL    NOT NULL DEFAULT 0,
    k_eff_n                            INTEGER NOT NULL DEFAULT 0,
    correlation_risk_sum               REAL    NOT NULL DEFAULT 0,
    correlation_risk_n                 INTEGER NOT NULL DEFAULT 0,

    override_trace_count               INTEGER NOT NULL DEFAULT 0,
    fragility_trace_count              INTEGER NOT NULL DEFAULT 0,
    conscience_fail_trace_count        INTEGER NOT NULL DEFAULT 0,
    entropy_fail_trace_count           INTEGER NOT NULL DEFAULT 0,
    coherence_fail_trace_count         INTEGER NOT NULL DEFAULT 0,
    optimization_veto_fail_trace_count INTEGER NOT NULL DEFAULT 0,
    epistemic_humility_fail_trace_count INTEGER NOT NULL DEFAULT 0,

    audit_seq_trace_count              INTEGER NOT NULL DEFAULT 0,
    audit_sig_trace_count              INTEGER NOT NULL DEFAULT 0
);

-- Conflict target: a UNIQUE INDEX over the COALESCE'd grouping columns so
-- a NULL agent / domain / scope / target is ONE conflict key (SQLite — like
-- Postgres — treats NULLs as distinct under a plain UNIQUE and prohibits
-- expressions in a table PRIMARY KEY; an expression UNIQUE INDEX is the
-- portable form). The upsert's ON CONFLICT lists the IDENTICAL expressions
-- so it binds to this index.
CREATE UNIQUE INDEX IF NOT EXISTS trace_events_factor_rollup_1h_key
    ON trace_events_factor_rollup_1h (
        bucket_start,
        COALESCE(agent_id_hash, ''),
        COALESCE(deployment_domain, ''),
        COALESCE(cohort_scope, ''),
        COALESCE(cohort_target_id, '')
    );

CREATE INDEX IF NOT EXISTS trace_events_factor_rollup_1h_agent_bucket
    ON trace_events_factor_rollup_1h (agent_id_hash, bucket_start);

-- Single-row refresh watermark — `last_refreshed_ts` is the high-water
-- RFC3339 `ts` already folded into the rollup; refresh_factor_rollup
-- re-folds [since, now] and advances it.
CREATE TABLE IF NOT EXISTS trace_events_factor_rollup_meta (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    last_refreshed_ts   TEXT
);
INSERT OR IGNORE INTO trace_events_factor_rollup_meta (id, last_refreshed_ts)
VALUES (1, NULL);
