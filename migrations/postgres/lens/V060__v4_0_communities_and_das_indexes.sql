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

-- ── Part B(i): trace_events cohort_scope + target ──────────────────
--
-- CIRISPersist#160 (FSD §12.0 item 1): the v3.x `trace_events` table
-- carried NO cohort_scope column, so the §9 community-lens flow had no
-- trace-read gate. Add TWO columns so the §4.3 predicate can gate at
-- trace-read time:
--   - cohort_scope     — the CEG visibility/routing axis the producer
--                        policy formed (CEG 0.4 wire / 0.10 §10.1.4
--                        admission). Closed-set CHECK mirroring V056's
--                        federation_attestations.cohort_scope discipline.
--   - cohort_target_id — the §4.3 scope TARGET (family_id / community_id
--                        the producer routed to; or, for `self`, the
--                        owner identity the substrate resolves from the
--                        verified signer at write). NULL for the broad
--                        belonging-tiers.
--
-- Default 'federation' + NULL target is backward-compat-safe: existing
-- rows predate any scope and are federation-visible today, so the
-- column DEFAULT preserves current behavior. The trace wire format
-- gains OPTIONAL cohort_scope + cohort_target_id envelope fields
-- (serde default / skip_serializing_if) so existing canonical bytes /
-- signatures are unchanged; producers that omit them ride the default.

ALTER TABLE cirislens.trace_events
    ADD COLUMN IF NOT EXISTS cohort_scope TEXT NOT NULL DEFAULT 'federation';
ALTER TABLE cirislens.trace_events
    ADD COLUMN IF NOT EXISTS cohort_target_id TEXT;

-- Closed-set enforcement — same discipline as V056's
-- federation_attestations_cohort_scope_closed_set (idempotent guard so
-- a re-run is a no-op).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
        WHERE conname = 'trace_events_cohort_scope_closed_set'
          AND conrelid = 'cirislens.trace_events'::regclass
    ) THEN
        ALTER TABLE cirislens.trace_events
            ADD CONSTRAINT trace_events_cohort_scope_closed_set
                CHECK (cohort_scope IN (
                    'self', 'family', 'community',
                    'affiliations', 'species', 'biosphere', 'federation'
                ));
    END IF;
END$$;

COMMENT ON COLUMN cirislens.trace_events.cohort_scope IS
    'v4.0 (CIRISPersist#160, CEG 0.4 §4.2.4 / 0.10 §10.1.4). Producer-formed visibility/routing axis. Closed-set; default ''federation'' (backward-compat). The §4.3 read-gate filters (cohort_scope, cohort_target_id) against the reader''s resolved admission.';
COMMENT ON COLUMN cirislens.trace_events.cohort_target_id IS
    'v4.0 (CIRISPersist#160, FSD §4.3). Scope target: family_id / community_id the producer routed to, or — for cohort_scope=''self'' — the owner identity the substrate resolved from the verified signer at write. NULL for the broad belonging-tiers.';

-- ── Part B(ii): DAS covering indexes ───────────────────────────────
--
-- The §4.3 predicate is now pure set-membership on (cohort_scope,
-- cohort_target_id) — no emitter join — so the covering index LEADS
-- with those two columns to make the scope filter index-only, then
-- windows on ts and groups on deployment_domain.
--
-- NB — schema reconciliation vs the FSD §12 first-draft DDL: the v3.x
-- `trace_events` table stores DMA/conscience/action/fragility scalars
-- inside the `payload` JSON (see V042 functional-index lineage), NOT as
-- physical columns, so the INCLUDE list carries only columns that
-- actually exist. `federation_attestations` exposes its subject as
-- `attested_key_id` (the singular `subject_key_id` / `asserter_key_id`
-- / `attestation_kind` names in the FSD draft do not exist — V055 added
-- a plural `subject_key_ids` JSONB array); its indexes use the real
-- `attested_key_id` / `cohort_scope` / `scrub_key_id` columns.

CREATE INDEX IF NOT EXISTS idx_trace_events_v060_repository_stats
ON cirislens.trace_events (cohort_scope, cohort_target_id, ts, deployment_domain)
INCLUDE (trace_id, agent_id_hash, scrub_key_id);

CREATE INDEX IF NOT EXISTS idx_federation_attestations_v060_by_target
ON cirislens.federation_attestations (attested_key_id, cohort_scope, asserted_at DESC);

CREATE INDEX IF NOT EXISTS idx_federation_attestations_v060_emitter_scope
ON cirislens.federation_attestations (scrub_key_id, cohort_scope);
-- Indexes the inner side of the §4.3 scope-predicate EXISTS join.
