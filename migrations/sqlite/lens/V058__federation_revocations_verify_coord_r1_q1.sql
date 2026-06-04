-- V058 — Verify-coord R1+Q1 substrate — SQLite dialect
--        (CIRISPersist#143, v3.11.0; CIRISVerify FEDERATION_THREAT_MODEL
--        §3.3.2 v1.1 ratified, v1.2 audited).
--
-- Postgres parity: postgres/lens/V058. See that file for the full
-- design rationale (R1 τ_propagate region tagging + Q1 cross-region
-- quorum bookkeeping + F-AV-13 cache TTL anchoring + F-AV-ROLLBACK
-- anti-rollback admission). The Rust substrate pins the immutable
-- spec constants in `crate::federation::verify_coord`.

-- ─── R1: observed_region column on federation_revocations ──────────
--
-- Closed-set CHECK matches the Rust `verify_coord::region` module.
-- DEFAULT 'us' preserves the pre-v3.11 row hash for legacy rows: the
-- Rust struct's `skip_serializing_if = is_default_observed_region`
-- keeps 'us' out of canonical bytes, so legacy + new us-rows hash
-- identically.

ALTER TABLE federation_revocations
    ADD COLUMN observed_region TEXT NOT NULL DEFAULT 'us'
        CHECK (observed_region IN ('us', 'eu', 'apac'));

-- Read pattern: per-region propagation accounting + comparator
-- per-region lookup. SQLite partial-index discipline matches the
-- postgres V058 design (`WHERE observed_region != 'us'`).
CREATE INDEX IF NOT EXISTS federation_revocations_observed_region
    ON federation_revocations (observed_region, revoked_key_id, scrub_timestamp DESC)
    WHERE observed_region != 'us';

-- ─── Q1: per-revocation cross-region quorum state ──────────────────
--
-- One row per `revocation_id`. SQLite stores TIMESTAMPTZ as TEXT
-- ISO-8601 (the project's universal time encoding); the substrate
-- parses on read. quorum_weight stored as INTEGER 1..3.

CREATE TABLE IF NOT EXISTS federation_revocation_quorum_state (
    revocation_id     TEXT PRIMARY KEY
        REFERENCES federation_revocations(revocation_id) ON DELETE CASCADE,

    -- First-observation timestamp per region (ISO-8601 TEXT;
    -- NULL = not yet observed in that region).
    us_observed_at    TEXT,
    eu_observed_at    TEXT,
    apac_observed_at  TEXT,

    -- When 2-of-3 quorum was first crossed (ISO-8601 TEXT;
    -- NULL = pre-quorum).
    quorum_reached_at TEXT,

    -- Q1 tier-1 merge input. Always 1..=3 (denormalized count of
    -- non-NULL region columns; the comparator reads this in one
    -- column-load instead of three NULL-checks).
    quorum_weight     INTEGER NOT NULL DEFAULT 1
        CHECK (quorum_weight BETWEEN 1 AND 3),

    -- Always-current timestamp the substrate sets on every write
    -- (postgres parity: `DEFAULT NOW()`; sqlite uses CURRENT_TIMESTAMP).
    updated_at        TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Read pattern: "which revocations have reached quorum?" — F-AV-13
-- cache TTL gate uses this. Partial index on the committed subset.
CREATE INDEX IF NOT EXISTS federation_revocation_quorum_state_committed
    ON federation_revocation_quorum_state (quorum_reached_at DESC)
    WHERE quorum_reached_at IS NOT NULL;

-- Read pattern: anti-rollback admission lookup; pairs with the
-- parent table's revoked_key_id index for the join.
CREATE INDEX IF NOT EXISTS federation_revocation_quorum_state_pending
    ON federation_revocation_quorum_state (revocation_id, quorum_weight);
