-- V058 — Verify-coord R1+Q1 substrate (CIRISPersist#143, v3.11.0;
--        CIRISVerify FEDERATION_THREAT_MODEL §3.3.2, ratified v1.1,
--        audited v1.2 at 51da15f).
--
-- Closes the F-AV-FRONTRUN + F-AV-ROLLBACK substrate-tier gaps from
-- the federation threat model:
--
--  • R1 (τ_propagate)   — track *which region observed* each
--                          revocation so the τ_normal=60s / τ_partial
--                          =300s propagation deadlines are accountable
--                          per-row, and the F-AV-13 revocation-cache
--                          TTL ceiling (τ_normal/2 = 30s) consumers
--                          honor is rooted in the row's region tag.
--
--  • Q1 (quorum-write)  — track the per-revocation cross-region
--                          observation set + quorum-weight so the
--                          spec's deterministic 3-tier merge
--                          comparator (quorum_weight DESC →
--                          signed_timestamp DESC → canonical_bytes_hash
--                          ASC) has the inputs it needs in one indexed
--                          read. Anti-rollback monotonicity is
--                          enforced at admission BEFORE quorum is
--                          asked (in `put_revocation`); this table is
--                          the bookkeeping the comparator reads from.
--
-- Constants (immutable per v1.1; the Rust substrate pins them in
-- `crate::federation::verify_coord` as wire-format-normative values):
--
--   τ_normal              = 60s
--   τ_partial             = 300s
--   bounded_staleness     = τ_partial = 300s
--   N_regions             = 3        (us / eu / apac)
--   quorum_write_threshold= ⌈2N/3⌉=2
--   revocation_cache_ttl  = τ_normal/2 = 30s
--
-- The constants are *not* persisted as table data — they are spec
-- values consumers read from the Rust module. This migration only
-- adds the per-row state the merge + propagation accounting need.

-- ─── R1: observed_region column on federation_revocations ──────────
--
-- Closed-set CHECK matches the Rust `verify_coord::region` module;
-- producers asserting anything else are rejected at admission (the
-- same closed-set discipline V056 used for `cohort_scope`). DEFAULT
-- 'us' preserves the pre-v3.11 hash for legacy rows that did not
-- carry the field: the Rust struct's `#[serde(skip_serializing_if =
-- "is_default_observed_region")]` keeps 'us' out of canonical bytes,
-- so legacy rows AND new us-rows hash identically.

ALTER TABLE cirislens.federation_revocations
    ADD COLUMN IF NOT EXISTS observed_region TEXT NOT NULL DEFAULT 'us'
        CHECK (observed_region IN ('us', 'eu', 'apac'));

-- Read pattern: per-region propagation accounting + the quorum
-- comparator's per-region lookup. Partial index on the non-default
-- regions keeps the index small (the vast majority of pre-v3.11 rows
-- are 'us'-default backfilled and never queried by region).
CREATE INDEX IF NOT EXISTS federation_revocations_observed_region
    ON cirislens.federation_revocations (observed_region, revoked_key_id, scrub_timestamp DESC)
    WHERE observed_region != 'us';

-- ─── Q1: per-revocation cross-region quorum state ──────────────────
--
-- One row per `revocation_id`; each region's first-observation
-- timestamp lands in its own column (NULL = not yet observed in that
-- region). `quorum_reached_at` is set when the 2-of-3 threshold is
-- first crossed; the comparator's `quorum_weight` is derived as the
-- count of non-NULL region columns.
--
-- The table tracks state about a row in `federation_revocations` —
-- not the canonical revocation envelope itself, which already lives
-- in the parent table. Separating the quorum bookkeeping keeps the
-- parent table's persist_row_hash stable across region observations
-- (the row's signed canonical bytes don't change when a peer in
-- another region ACKs).

CREATE TABLE IF NOT EXISTS cirislens.federation_revocation_quorum_state (
    revocation_id     UUID PRIMARY KEY
        REFERENCES cirislens.federation_revocations(revocation_id) ON DELETE CASCADE,

    -- First-observation timestamp per region. NULL = not yet observed.
    us_observed_at    TIMESTAMPTZ,
    eu_observed_at    TIMESTAMPTZ,
    apac_observed_at  TIMESTAMPTZ,

    -- When 2-of-3 threshold was first crossed. NULL = pre-quorum.
    quorum_reached_at TIMESTAMPTZ,

    -- The Q1 tier-1 merge input. Derived as the count of non-NULL
    -- region columns; stored denormalized so the comparator reads it
    -- in one column-load instead of three NULL-checks.
    -- Always 1..=3 (the row exists because at least one region has
    -- observed; quorum_reached_at is derived from this hitting >=2).
    quorum_weight     SMALLINT NOT NULL DEFAULT 1
        CHECK (quorum_weight BETWEEN 1 AND 3),

    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Read pattern: "which revocations have reached quorum?" — used by
-- the F-AV-13 cache TTL gate to know which revocations are
-- consumer-visible. Partial index on the quorum-committed subset.
CREATE INDEX IF NOT EXISTS federation_revocation_quorum_state_committed
    ON cirislens.federation_revocation_quorum_state (quorum_reached_at DESC)
    WHERE quorum_reached_at IS NOT NULL;

-- Read pattern: "is this revocation pre-quorum?" — the admission
-- path checks this when deciding whether a new revocation against
-- the same `revoked_key_id` is a legitimate update or an
-- anti-rollback attempt. Index on the parent table's revoked_key_id
-- already covers most of the lookup; this index covers the join.
CREATE INDEX IF NOT EXISTS federation_revocation_quorum_state_pending
    ON cirislens.federation_revocation_quorum_state (revocation_id, quorum_weight);
