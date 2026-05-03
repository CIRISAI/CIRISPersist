-- V006 — Deployment-profile denormalization (sqlite, v0.3.4).
-- Postgres counterpart at migrations/postgres/lens/V006__deployment_profile.sql.
--
-- SQLite ALTER TABLE ADD COLUMN supports a single column per
-- statement (no multi-add comma form), so the 6 fields land as 6
-- separate ALTERs. Each column defaults to NULL — existing 2.7.0
-- rows stay NULL across all six.

ALTER TABLE trace_events ADD COLUMN agent_role            TEXT;
ALTER TABLE trace_events ADD COLUMN agent_template        TEXT;
ALTER TABLE trace_events ADD COLUMN deployment_domain     TEXT;
ALTER TABLE trace_events ADD COLUMN deployment_type       TEXT;
ALTER TABLE trace_events ADD COLUMN deployment_region     TEXT;
ALTER TABLE trace_events ADD COLUMN deployment_trust_mode TEXT;

-- Indexes (SQLite supports partial indexes via WHERE).
CREATE INDEX IF NOT EXISTS trace_events_deployment_domain
    ON trace_events (deployment_domain, ts DESC)
    WHERE deployment_domain IS NOT NULL;

CREATE INDEX IF NOT EXISTS trace_events_deployment_type
    ON trace_events (deployment_type, ts DESC)
    WHERE deployment_type IS NOT NULL;

CREATE INDEX IF NOT EXISTS trace_events_agent_role
    ON trace_events (agent_role, ts DESC)
    WHERE agent_role IS NOT NULL;

CREATE INDEX IF NOT EXISTS trace_events_deployment_trust_mode
    ON trace_events (deployment_trust_mode, ts DESC)
    WHERE deployment_trust_mode IS NOT NULL;
