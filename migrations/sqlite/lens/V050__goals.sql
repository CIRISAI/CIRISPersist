-- V050 — Typed `goals` table, SQLite dialect (v2.10.0, CIRISPersist#114).
--
-- Postgres parity (postgres/lens/V050): same column shapes, same
-- structural M-1 invariant + scope discriminant CHECK constraints.
-- Dialect translations:
--
--   PostgreSQL                     → SQLite
--   ──────────────────────────────────────────────────────────────────
--   UUID                           → TEXT (36-char hyphenated)
--   TIMESTAMPTZ                    → TEXT (RFC 3339)
--   JSONB meta_deliberation        → TEXT (json1 querying available)
--   REFERENCES cirislens.x         → REFERENCES x (no schema prefix)
--   now()                          → strftime('%Y-%m-%dT%H:%M:%fZ','now')
--   GIN-style index                → none needed (json_each at read time)
--
-- The scope_cohort_id ⇔ scope_kind = 'cohort' rule is enforced by an
-- inline table-level CHECK clause (SQLite supports CHECK inline at
-- CREATE TABLE time; ALTER TABLE ADD CHECK is not supported, so we
-- bake the constraint into the initial DDL).
--
-- See postgres/lens/V050 for the architectural rationale.

CREATE TABLE IF NOT EXISTS goals (
    goal_id                TEXT    PRIMARY KEY,
    declared_by_key_id     TEXT    NOT NULL
        REFERENCES federation_keys(key_id) ON DELETE RESTRICT,
    declared_at            TEXT    NOT NULL,
    goal_text              TEXT    NOT NULL,
    goal_text_canonical    TEXT    NOT NULL,
    scope_kind             TEXT    NOT NULL
        CHECK (scope_kind IN ('cohort', 'federation', 'single_declarer')),
    scope_cohort_id        TEXT,
    meta_dimension         TEXT    NOT NULL
        CHECK (meta_dimension IN (
            'adaptivity', 'coherence', 'flourishing', 'justice',
            'plurality', 'sustainability', 'wonder'
        )),
    meta_rationale         TEXT    NOT NULL,
    meta_deliberation      TEXT,
    retired_at             TEXT,
    inserted_at            TEXT    NOT NULL
        DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    persist_row_hash       TEXT    NOT NULL,

    -- Cross-column CHECK: scope_kind = 'cohort' iff scope_cohort_id
    -- IS NOT NULL. Defense-in-depth behind the typed Rust enum —
    -- direct-SQL bypass still cannot land a malformed scope shape.
    CONSTRAINT goals_scope_cohort_discriminant CHECK (
        (scope_kind = 'cohort' AND scope_cohort_id IS NOT NULL)
        OR (scope_kind <> 'cohort' AND scope_cohort_id IS NULL)
    )
);

-- ─── Indexes (F-3 hot paths) ───────────────────────────────────────

CREATE INDEX IF NOT EXISTS goals_declared_by_key_id
    ON goals (declared_by_key_id);

CREATE INDEX IF NOT EXISTS goals_meta_dimension
    ON goals (meta_dimension);

-- Partial index — F-3's hot path is "live goals only".
CREATE INDEX IF NOT EXISTS goals_retired_at_live
    ON goals (retired_at) WHERE retired_at IS NULL;

-- Partial index for cohort lookups.
CREATE INDEX IF NOT EXISTS goals_scope_cohort
    ON goals (scope_kind, scope_cohort_id)
    WHERE scope_kind = 'cohort';
