-- V030 — maintenance_locks substrate (v1.5.15, CIRISPersist#59 #7).
--
-- Seventh of 11 substrate absorptions ending CIRISAgent's direct
-- libsqlite access to `ciris_engine.db`. Absorbs CIRISAgent
-- 2.8.13 `consolidation_locks` table — generic multi-occurrence
-- coordination primitive used today by TSDB-consolidation workers
-- (one worker runs the consolidation pass at a time) but generalized
-- here to a `maintenance_locks` family per CIRISPersist#59 #7 spec
-- since the mechanism (named lock_key + caller-stamped owner +
-- timeout-driven steal-the-stale semantics) is not consolidation-
-- specific.
--
-- Distinct from the existing `cirisgraph.consolidation_locks`
-- (V015 — telemetry/TSDB substrate). That table is keyed on
-- `(period_start, tenant_id)` and is per-period-per-tenant. This
-- table is keyed on `lock_key` (TEXT) and is generic — any worker
-- can mint a key for any coordination scope. The two coexist.
--
-- Agent's 4-column shape (SQLite):
--   lock_key             TEXT PRIMARY KEY
--   locked_by            TEXT
--   locked_at            TEXT
--   lock_timeout_seconds INTEGER DEFAULT 300
--
-- PG-dialect translations + persist extensions:
--   TEXT timestamp           → TIMESTAMPTZ (locked_at)
--   INTEGER (no constraint)  → INTEGER NOT NULL DEFAULT 300
--                              + CHECK (lock_timeout_seconds > 0)
--                              (zero/negative timeouts make the
--                              steal-the-stale arithmetic meaningless)
--   +metadata JSONB          → optional payload for lock-holder
--                              context (worker id, occurrence id,
--                              etc). Nullable so back-compat with
--                              the agent's 4-column shape is
--                              preserved (rows lacking metadata
--                              decode as `metadata: None`).
--
-- Refinery wraps each migration in its own transaction; no
-- explicit BEGIN/COMMIT here (V019's fix established this rule).

CREATE TABLE cirislens.maintenance_locks (
    lock_key             TEXT PRIMARY KEY,
    locked_by            TEXT,
    locked_at            TIMESTAMPTZ,
    lock_timeout_seconds INTEGER NOT NULL DEFAULT 300
        CHECK (lock_timeout_seconds > 0),
    -- CIRISPersist#59 #7: substrate is generic. Optional payload
    -- for lock-holder context (worker id, occurrence id, etc).
    metadata             JSONB
);

-- Hot path: enumerate currently-held locks for operator visibility
-- ("who's holding what right now"). Partial — only rows with an
-- active holder carry an entry.
CREATE INDEX maintenance_locks_active
    ON cirislens.maintenance_locks (locked_at DESC)
    WHERE locked_by IS NOT NULL;

COMMENT ON TABLE cirislens.maintenance_locks IS
    'v1.5.15 (CIRISPersist#59 #7) — maintenance_locks substrate. Absorbs CIRISAgent ciris_engine.db.consolidation_locks; generalized to a generic lock_key-keyed family per the substrate spec since the steal-the-stale-via-timeout mechanism is not consolidation-specific. 5 columns (4 agent + 1 persist-only metadata JSONB). Coexists with the per-period cirisgraph.consolidation_locks (V015).';
