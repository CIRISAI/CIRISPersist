-- V006 — Deployment-profile denormalization columns on trace_events
-- (v0.3.4, CIRISPersist#13).
--
-- Companion to CIRISAgent#718 (`431b0e0ae`). The 2.7.9 wire format
-- adds a 6-field `deployment_profile` block to every CompleteTrace
-- envelope; the block is part of the §8 signed canonical bytes and
-- carries the cohort-identity labels that lens analytical paths
-- (Coherence Ratchet, capacity scoring, manifold-conformity) cluster
-- on.
--
-- v0.3.4 denormalizes those 6 fields onto every event row of the
-- trace, same shape as the existing per-trace constants
-- (`agent_name`, `agent_id_hash`, `cognitive_state`). Lens queries
-- group/filter on these without JSONB extracts.
--
-- # Sourcing
--
-- Persist's decompose pass copies the wire-provided values onto
-- every TraceEventRow when `CompleteTrace.deployment_profile` is
-- `Some` — i.e., 2.7.9 traces (where the block is required-on-wire
-- per FSD §3.2). All NULL for 2.7.0 traces. Cross-shape rule:
-- 2.7.0 traces carrying the block are silently ignored at canonical
-- reconstruction (mirrors per-component agent_id_hash); the block
-- still rides in the wire JSON but doesn't enter signed bytes.
--
-- # Closed-enum constraint at the agent
--
-- The agent-side spec (FSD §3.2 + §3.3) closes the enums for
-- `deployment_domain`, `deployment_type`, `deployment_trust_mode`.
-- Persist accepts whatever the signed block declares — the
-- agent-side spec PR + bump to 2.X+1 is what governs adding new
-- values. Persist columns stay TEXT so new enum values land
-- without a persist migration.
--
-- # Lens-computed deployment_resourcing
--
-- A 7th column for the lens-computed `deployment_resourcing` tier
-- (`scarcity` / `constrained` / `standard` / `abundance`) is OUT OF
-- SCOPE for this migration — the computation lives in lens
-- (cost/tokens/model class observation), and lens manages its own
-- column on its own derived schema. Reserved here in comment only.

ALTER TABLE cirislens.trace_events
    ADD COLUMN IF NOT EXISTS agent_role            TEXT,
    ADD COLUMN IF NOT EXISTS agent_template        TEXT,
    ADD COLUMN IF NOT EXISTS deployment_domain     TEXT,
    ADD COLUMN IF NOT EXISTS deployment_type       TEXT,
    ADD COLUMN IF NOT EXISTS deployment_region     TEXT,
    ADD COLUMN IF NOT EXISTS deployment_trust_mode TEXT;

-- Indexes on the high-cardinality cohort axes that lens-side WHERE
-- clauses will hit. `deployment_domain` + `deployment_type` are the
-- primary filter keys; `agent_role` + `deployment_trust_mode` are
-- secondary. Composite (deployment_type, ts DESC) matches the
-- common "production traces last 24h" pattern.
--
-- `agent_template` and `deployment_region` are higher-cardinality
-- and less commonly filter-grouped, so no dedicated index — lens
-- queries that need them join against this table by trace_id and
-- pick up the columns via the dedup-tuple index hit.

CREATE INDEX IF NOT EXISTS trace_events_deployment_domain
    ON cirislens.trace_events (deployment_domain, ts DESC)
    WHERE deployment_domain IS NOT NULL;

CREATE INDEX IF NOT EXISTS trace_events_deployment_type
    ON cirislens.trace_events (deployment_type, ts DESC)
    WHERE deployment_type IS NOT NULL;

CREATE INDEX IF NOT EXISTS trace_events_agent_role
    ON cirislens.trace_events (agent_role, ts DESC)
    WHERE agent_role IS NOT NULL;

CREATE INDEX IF NOT EXISTS trace_events_deployment_trust_mode
    ON cirislens.trace_events (deployment_trust_mode, ts DESC)
    WHERE deployment_trust_mode IS NOT NULL;
