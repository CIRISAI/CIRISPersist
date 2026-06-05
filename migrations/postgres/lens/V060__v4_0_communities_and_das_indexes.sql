-- V060 — CIRISPersist v4.0 Data Access Surface (FSD §12).
--        Two concerns in one numbered cut, mirroring the V059
--        dual-substrate pattern:
--          Part A — the federation_communities substrate (§8.1.13.3).
--          Part B — scope-aware DAS covering indexes for the §4.3
--                   read-side cohort_scope predicate.
--
-- Refinery wraps this migration in its own transaction — no explicit
-- BEGIN/COMMIT (matches the V059 file convention).

-- ── Part A: federation_communities substrate (§8.1.13.3) ───────────
--
-- Symmetric to V059's federation_families shape. `members` JSONB
-- carries IDENTITY keys (not occurrence keys), matching the §5.6.8.9
-- worked example. `policy_blob` carries the cohort_scope membership
-- label consumed at CIRISEdge#48-A (V057 already indexed the
-- analogous shape on federation_peer_metadata).
--
-- Semantic difference from V059 family (§8.1.13.3): community content
-- is NOT structurally invisible —
-- `cohort_scope::suppresses_holds_bytes` returns FALSE for community.
-- Read paths federate community content normally (it emits holds_bytes
-- directory attestations); communities can be large and per-member
-- byte-level invisibility is infeasible, so the privacy property is
-- cohort-filtered visibility, not byte-level invisibility.
--
-- `consensus_protocol` is OPEN vocabulary per the spec (founder_only
-- / unanimous / majority / quorum:m/n / weighted:rubric / custom:id);
-- the CHECK constraint verifies the canonical form, mirroring the
-- Rust `check_consensus_protocol_form` admission gate.

CREATE TABLE cirislens.federation_communities (
    community_key_id      TEXT PRIMARY KEY,
    community_name        TEXT NOT NULL,
    members               JSONB NOT NULL,
    founded_at            TIMESTAMPTZ NOT NULL,
    consensus_protocol    TEXT NOT NULL,
    policy_blob           JSONB,
    persist_row_hash      TEXT NOT NULL,
    CONSTRAINT federation_communities_consensus_protocol_form
        CHECK (consensus_protocol ~ '^(founder_only|unanimous|majority|quorum:[0-9]+/[0-9]+|weighted:.+|custom:.+)$')
);

-- Membership fan-out index for list_communities_for_member — the `@>`
-- containment operator (members @> '[{"key_id": "X"}]') is the
-- matching shape.
CREATE INDEX idx_federation_communities_members_gin
    ON cirislens.federation_communities USING GIN (members);

-- ── Part B: DAS covering indexes ───────────────────────────────────
--
-- The scrub_key_id leading/INCLUDE column is what makes the §4.3
-- EXISTS-join inner indexable without a heap fetch.
--
-- NB — schema reconciliation vs FSD §12 draft DDL: the v3.x
-- `trace_events` table stores DMA/conscience/action/fragility scalars
-- inside the `payload` JSON (see V042 functional-index lineage), NOT
-- as physical columns, and carries no `cohort_scope` column;
-- `federation_attestations` exposes its subject as `attested_key_id`
-- (the singular `subject_key_id` / `asserter_key_id` /
-- `attestation_kind` names in the FSD draft do not exist on the
-- physical table — V055 added a plural `subject_key_ids` JSONB array).
-- These indexes therefore cover the §4.3 read-side predicate using the
-- columns that actually exist: `(ts, deployment_domain, scrub_key_id)`
-- on trace_events (the scope-predicate EXISTS join keys on scrub_key_id
-- and windows on ts) and the real `attested_key_id` / `cohort_scope` /
-- `scrub_key_id` columns on federation_attestations.

CREATE INDEX IF NOT EXISTS idx_trace_events_v060_repository_stats
ON cirislens.trace_events (ts, deployment_domain, scrub_key_id);

CREATE INDEX IF NOT EXISTS idx_federation_attestations_v060_by_target
ON cirislens.federation_attestations (attested_key_id, cohort_scope, asserted_at DESC);

CREATE INDEX IF NOT EXISTS idx_federation_attestations_v060_emitter_scope
ON cirislens.federation_attestations (scrub_key_id, cohort_scope);
-- Indexes the inner side of the §4.3 scope-predicate EXISTS join.
