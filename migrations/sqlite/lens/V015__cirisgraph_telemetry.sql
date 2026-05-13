-- V015 — telemetry + TSDB consolidation, SQLite dialect (v0.8.6, #38).
--
-- Postgres parity (postgres/lens/V015): same shapes, same AV-52/53/54
-- semantics. Dialect translations:
--
--   PostgreSQL                      → SQLite
--   ─────────────────────────────────────────────────────────────────
--   UUID                            → TEXT (36-char hyphenated)
--   TIMESTAMPTZ                     → TEXT (RFC 3339)
--   JSONB labels                    → TEXT (canonical JSON)
--   DOUBLE PRECISION                → REAL
--   NOW()                           → datetime('now', 'subsec')
--   CHECK (period_end > period_start) → same (SQLite supports this)

CREATE TABLE IF NOT EXISTS cirisgraph_telemetry_metrics (
    metric_id         TEXT PRIMARY KEY,
    metric_name       TEXT NOT NULL,
    tenant_id         TEXT NOT NULL,
    value             REAL NOT NULL,
    labels            TEXT NOT NULL DEFAULT '{}',
    observed_at       TEXT NOT NULL,
    expires_at        TEXT NOT NULL,
    created_at        TEXT NOT NULL DEFAULT (datetime('now', 'subsec'))
);

CREATE INDEX IF NOT EXISTS telemetry_window
    ON cirisgraph_telemetry_metrics (tenant_id, metric_name, observed_at);
CREATE INDEX IF NOT EXISTS telemetry_expires
    ON cirisgraph_telemetry_metrics (expires_at);

CREATE TABLE IF NOT EXISTS cirisgraph_consolidation_locks (
    period_start      TEXT NOT NULL,
    period_end        TEXT NOT NULL,
    tenant_id         TEXT NOT NULL,
    locked_by         TEXT NOT NULL,
    locked_at         TEXT NOT NULL DEFAULT (datetime('now', 'subsec')),

    PRIMARY KEY (period_start, tenant_id),
    CHECK (period_end > period_start)
);

CREATE INDEX IF NOT EXISTS consolidation_locks_locked_at
    ON cirisgraph_consolidation_locks (locked_at);
