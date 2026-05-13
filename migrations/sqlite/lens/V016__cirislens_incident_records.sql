-- V016 — incident records, SQLite dialect (v0.8.7, CIRISPersist#38).
--
-- Postgres parity (postgres/lens/V016): same column shapes, same
-- AV-55/AV-56 semantics. Dialect translations:
--
--   PostgreSQL JSONB correlation_keys → TEXT (JSON array string)
--   JSONB ?| / ?& / ?               → json_each(...) joined SELECT
--   UUID                              → TEXT (36-char hyphenated)
--   TIMESTAMPTZ                       → TEXT (RFC 3339)
--   GIN on correlation_keys           → no index (JSON array
--                                       scans linear; OK at
--                                       sovereign-mode scale)
--   Partial index on (tenant, state, last_seen) WHERE state IN
--   ('open','investigating')          → same syntax — SQLite
--                                       supports partial indexes

CREATE TABLE IF NOT EXISTS cirislens_incident_records (
    incident_id           TEXT PRIMARY KEY,
    tenant_id             TEXT NOT NULL,
    severity              TEXT NOT NULL
        CHECK (severity IN ('info', 'warning', 'error', 'critical')),
    category              TEXT NOT NULL,
    title                 TEXT NOT NULL,
    description           TEXT,
    correlation_keys      TEXT NOT NULL DEFAULT '[]',
    state                 TEXT NOT NULL
        CHECK (state IN ('open', 'investigating', 'resolved', 'closed')),
    first_seen_at         TEXT NOT NULL,
    last_seen_at          TEXT NOT NULL,
    resolved_at           TEXT,
    resolution_notes      TEXT,
    occurrences           INTEGER NOT NULL DEFAULT 1
        CHECK (occurrences >= 1),

    -- Audit envelope.
    signature             TEXT,
    signing_key_id        TEXT,
    signature_verified    INTEGER NOT NULL DEFAULT 0,
    persist_row_hash      TEXT NOT NULL,
    created_at            TEXT NOT NULL DEFAULT (datetime('now', 'subsec'))
);

-- Partial index on open/investigating incidents (same shape as PG).
CREATE INDEX IF NOT EXISTS incident_open_recent
    ON cirislens_incident_records (tenant_id, state, last_seen_at)
    WHERE state IN ('open', 'investigating');

-- Per-tenant timeline scans.
CREATE INDEX IF NOT EXISTS incident_first_seen
    ON cirislens_incident_records (tenant_id, first_seen_at);
