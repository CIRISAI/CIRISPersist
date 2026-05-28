-- V050 — Typed `goals` table (v2.10.0, CIRISPersist#114).
--
-- Lands the typed `Goal` primitive's persistence shape. Every Goal
-- carries M-1 alignment as a structural construction-time invariant
-- in Rust (`federation::goal::Goal::new` takes `MetaGoalAlignment` by
-- value, not `Option`). This schema is the storage-layer mirror of
-- that invariant: `meta_dimension` + `meta_rationale` are both
-- `NOT NULL`. Cross-column CHECK constraints enforce the scope
-- discriminant (`scope_cohort_id IS NOT NULL ⇔ scope_kind = 'cohort'`)
-- and the seven-variant M-1 dimension vocabulary as defense-in-depth
-- behind the Rust type-system enforcement — a row that bypasses
-- `FederationDirectory::put_goal` (e.g., direct SQL) still cannot
-- land Goal-without-M-1.
--
-- # Why a dedicated table (vs. attestations)
--
-- A Goal is not an attestation about a key — it's the declarer's
-- stated intent, scoped to themselves / a cohort / the federation.
-- The F-3 detector family (CIRISLensCore#23 / #24 / #26) operates on
-- *the population the goal pertains to* (scope) crossed with *which
-- M-1 dimension the declarer claimed* (meta_dimension); a typed
-- table with native indexes on those columns is the right substrate.
--
-- # Why M-1 must be structural here too
--
-- See MISSION.md §1 + the `federation::goal` module doc-comment: the
-- framework's anti-attractor-capture posture needs M-1 to be where
-- any goal-declaring actor must engage. The Rust type system makes
-- it impossible to construct a Goal-without-M-1 in Rust; the schema
-- makes it impossible to land a Goal-without-M-1 in the database.
-- Belt and braces.

BEGIN;

CREATE TABLE IF NOT EXISTS cirislens.goals (
    -- Content-addressable identifier. Callers generate UUIDv7
    -- (creation-ordered) before INSERT.
    goal_id                UUID PRIMARY KEY,

    -- FK to federation_keys.key_id. ON DELETE RESTRICT — a declarer
    -- key cannot be deleted while it still has live goals; the
    -- federation has a record of who declared what.
    declared_by_key_id     TEXT NOT NULL
        REFERENCES cirislens.federation_keys(key_id) ON DELETE RESTRICT,

    -- Wall-clock at declaration (sealed into the signed envelope).
    declared_at            TIMESTAMPTZ NOT NULL,

    -- Free-text goal statement, sealed verbatim into the signed
    -- envelope. ≤ N chars per envelope budget; persist does not
    -- enforce a length cap here — the wire envelope budget is the
    -- gate.
    goal_text              TEXT NOT NULL,
    -- Canonicalized form (whitespace-normalized) for byte-stable
    -- equality comparison. NOT the signed form — goal_text is.
    goal_text_canonical    TEXT NOT NULL,

    -- Scope discriminant + payload. The Rust enum is sum-typed; in
    -- SQL we carry a discriminant column + a nullable payload column
    -- whose presence is gated by the discriminant via CHECK.
    scope_kind             TEXT NOT NULL
        CHECK (scope_kind IN ('cohort', 'federation', 'single_declarer')),
    scope_cohort_id        TEXT NULL,

    -- M-1 alignment payload (structural — NOT NULL).
    meta_dimension         TEXT NOT NULL
        CHECK (meta_dimension IN (
            'adaptivity', 'coherence', 'flourishing', 'justice',
            'plurality', 'sustainability', 'wonder'
        )),
    meta_rationale         TEXT NOT NULL,
    -- Optional deliberation pointer; JSONB shape is
    -- {artifact_type: TEXT, artifact_id: TEXT}.
    meta_deliberation      JSONB NULL,

    -- Lifecycle marker. NULL = live; non-NULL = retired at this
    -- wall-clock. `retire_goal` sets this; first-write idempotency
    -- and second-write idempotency both keep the FIRST retirement.
    retired_at             TIMESTAMPTZ NULL,

    -- Persist write-time wall-clock — separate from declared_at to
    -- track ingest latency.
    inserted_at            TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Server-computed canonical-bytes hash (the same AV-row-hash
    -- discipline V004+ uses for federation_keys / _attestations /
    -- _revocations). Excludes the persist_row_hash field itself.
    persist_row_hash       TEXT NOT NULL,

    -- Cross-column CHECK: scope_kind = 'cohort' iff scope_cohort_id
    -- IS NOT NULL. Defense-in-depth behind the typed Rust enum —
    -- direct-SQL bypass still cannot land a malformed scope shape.
    CONSTRAINT goals_scope_cohort_discriminant CHECK (
        (scope_kind = 'cohort' AND scope_cohort_id IS NOT NULL)
        OR (scope_kind <> 'cohort' AND scope_cohort_id IS NULL)
    )
);

-- ─── Indexes (F-3 hot paths) ───────────────────────────────────────

-- "What's THIS declarer's goal portfolio?" — F-3 §3.5.3 walks goals
-- by declarer to score cohort-aligned trajectory.
CREATE INDEX IF NOT EXISTS goals_declared_by_key_id
    ON cirislens.goals (declared_by_key_id);

-- "What dimension of M-1 is being claimed across the fleet?" — F-3
-- §3.5.4 aggregates by dimension to spot attractor-capture patterns
-- (e.g., everyone suddenly claiming "Adaptivity" while suppressing
-- "Justice").
CREATE INDEX IF NOT EXISTS goals_meta_dimension
    ON cirislens.goals (meta_dimension);

-- Partial index — F-3's hot path is "live goals only", so the
-- WHERE retired_at IS NULL gate stays in the index. Retired rows
-- still need to be queryable for observability paths (the full-table
-- scan they require is acceptable; the hot path stays fast).
CREATE INDEX IF NOT EXISTS goals_retired_at_live
    ON cirislens.goals (retired_at) WHERE retired_at IS NULL;

-- "What cohort-level goals exist for cohort C?" — F-3 §3.5.3 cohort
-- scoring. Partial index — only cohort rows have a non-NULL
-- scope_cohort_id.
CREATE INDEX IF NOT EXISTS goals_scope_cohort
    ON cirislens.goals (scope_kind, scope_cohort_id)
    WHERE scope_kind = 'cohort';

COMMENT ON TABLE cirislens.goals IS
    'v2.10.0 (CIRISPersist#114) — typed Goal primitive with M-1 alignment as a structural invariant. Every row carries meta_dimension + meta_rationale (NOT NULL). The Rust constructor (federation::goal::Goal::new) refuses to construct a Goal without MetaGoalAlignment; this schema is the storage-layer mirror so direct-SQL writes cannot bypass the invariant. F-3 detector family (LensCore#23 / #24 / #26) reads this table.';

COMMIT;
