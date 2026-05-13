-- V016 — incident records (v0.8.3, CIRISPersist#37).
--
-- Absorbs CIRISAgent's IncidentManagementService. Correlation-keyed
-- deduplication on record (matching open incident → bump
-- occurrences) + open→investigating→resolved→closed state machine.
-- Last of the five v0.8.x Phase 1B substrate cuts (#34, #35, #36,
-- #37 ✓; auth_tokens deferred to v0.9.x).

BEGIN;

CREATE TABLE IF NOT EXISTS cirislens.incident_records (
    incident_id           UUID PRIMARY KEY,

    -- Per-tenant isolation (same gate as cirisaudit AV-51).
    tenant_id             TEXT NOT NULL,

    -- 4-value severity ladder.
    severity              TEXT NOT NULL
        CHECK (severity IN ('info', 'warning', 'error', 'critical')),

    -- Free-form category — `service_failure`, `integrity_violation`,
    -- `rate_anomaly`, `consent_revoked`, etc. Agent owns the
    -- vocabulary; persist enforces it stays TEXT.
    category              TEXT NOT NULL,

    -- Human-readable summary.
    title                 TEXT NOT NULL,
    description           TEXT,

    -- AV-56: correlation join keys (max 32 per incident, max 256
    -- bytes per key; runtime-enforced at trait surface). GIN index
    -- below serves the reverse-lookup path used by `correlate`.
    -- Stored as a JSONB array of strings.
    correlation_keys      JSONB NOT NULL DEFAULT '[]'::jsonb,

    -- AV-55 state machine: open → investigating → resolved → closed.
    -- No backflow; transitions checked server-side.
    state                 TEXT NOT NULL
        CHECK (state IN ('open', 'investigating', 'resolved', 'closed')),

    first_seen_at         TIMESTAMPTZ NOT NULL,
    last_seen_at          TIMESTAMPTZ NOT NULL,
    resolved_at           TIMESTAMPTZ,
    resolution_notes      TEXT,

    -- Deduplication counter — bumped each time a record_incident
    -- call lands a correlation-key match against an open incident
    -- for the same (tenant_id, category).
    occurrences           INTEGER NOT NULL DEFAULT 1 CHECK (occurrences >= 1),

    -- Audit envelope (matches cirisnode / cirisgraph shape).
    signature             TEXT,
    signing_key_id        TEXT,
    signature_verified    BOOLEAN NOT NULL DEFAULT FALSE,
    persist_row_hash      TEXT NOT NULL,

    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Hot path: open + investigating incidents per tenant, ranked by
-- recency. Partial index keeps it small even as resolved/closed
-- incidents accumulate.
CREATE INDEX IF NOT EXISTS incident_open_recent
    ON cirislens.incident_records (tenant_id, state, last_seen_at)
    WHERE state IN ('open', 'investigating');

-- Reverse-lookup path for `correlate` — find incidents whose
-- correlation_keys contain a given key.
CREATE INDEX IF NOT EXISTS incident_correlation_gin
    ON cirislens.incident_records USING GIN (correlation_keys);

-- Per-tenant timeline scans.
CREATE INDEX IF NOT EXISTS incident_first_seen
    ON cirislens.incident_records (tenant_id, first_seen_at);

COMMENT ON TABLE cirislens.incident_records IS
    'v0.8.3 (CIRISPersist#37) — incident records absorbed from CIRISAgent IncidentManagementService. Correlation-keyed dedup on record (bumps occurrences for matching open incident); open→investigating→resolved→closed state machine enforced server-side (AV-55).';

COMMIT;
