-- V032 — continuity_awareness substrate (v1.5.17, CIRISPersist#59 #9).
--
-- Ninth of 11 substrate absorptions ending CIRISAgent's direct
-- libsqlite access to `ciris_engine.db`. Absorbs the agent's
-- `continuity_awareness` table — the shutdown-event record an
-- agent leaves behind on each shutdown so that the next boot can
-- surface "where did I leave off?" continuity context.
--
-- # Cross-substrate FK
--
-- First substrate to ship a cross-substrate FK: the
-- (preservation_node_id, preservation_scope) pair references the
-- v0.8.0 cirisgraph substrate's `cirisgraph.nodes` table — the
-- composite PK (node_id, scope). The FK is DEFERRABLE so the
-- ceremony of a shutdown (graph-node write + continuity row write)
-- can land in one transaction without ordering constraints.
--
-- This requires the cirisgraph migrations (V013) to have run first.
-- The cargo feature `cirislens_continuity_awareness` declares a
-- transitive dependency on `cirisgraph` to enforce that ordering
-- at compile time.
--
-- # Agent's 14-column shape
--
--   id                          TEXT PRIMARY KEY
--   agent_id                    TEXT NOT NULL
--   shutdown_timestamp          TEXT NOT NULL
--   is_terminal                 BOOLEAN NOT NULL
--   shutdown_reason             TEXT NOT NULL
--   expected_reactivation       TEXT
--   initiated_by                TEXT NOT NULL
--   final_thoughts              TEXT NOT NULL
--   unfinished_tasks            TEXT          -- JSON-array-shaped string
--   reactivation_instructions   TEXT
--   deferred_goals              TEXT          -- JSON-array-shaped string
--   preservation_node_id        TEXT NOT NULL
--   preservation_scope          TEXT NOT NULL DEFAULT 'IDENTITY'
--   reactivation_count          INTEGER DEFAULT 0
--
-- PG-dialect translations:
--   TEXT (timestamps)               → TIMESTAMPTZ
--   TEXT (unfinished_tasks)         → JSONB (promote: agent stores
--                                     a JSON-array string; PG side
--                                     gets richer query semantics
--                                     for free).
--   TEXT (deferred_goals)           → JSONB (same as above)
--   preservation_scope vocabulary   → CHECK over the 4 cirisgraph
--                                     scope values (LOCAL / IDENTITY
--                                     / ENVIRONMENT / COMMUNITY).
--   reactivation_count              → NOT NULL with CHECK (>= 0).
--
-- Refinery wraps each migration in its own transaction; no explicit
-- BEGIN/COMMIT here (V019's fix established this rule).

CREATE TABLE cirislens.continuity_awareness (
    id                         TEXT PRIMARY KEY,
    agent_id                   TEXT NOT NULL,
    shutdown_timestamp         TIMESTAMPTZ NOT NULL,
    is_terminal                BOOLEAN NOT NULL,
    shutdown_reason            TEXT NOT NULL,
    expected_reactivation      TIMESTAMPTZ,
    initiated_by               TEXT NOT NULL,
    final_thoughts             TEXT NOT NULL,
    unfinished_tasks           JSONB,
    reactivation_instructions  TEXT,
    deferred_goals             JSONB,
    preservation_node_id       TEXT NOT NULL,
    preservation_scope         TEXT NOT NULL DEFAULT 'IDENTITY'
        CHECK (preservation_scope IN ('LOCAL', 'IDENTITY', 'ENVIRONMENT', 'COMMUNITY')),
    reactivation_count         INTEGER NOT NULL DEFAULT 0
        CHECK (reactivation_count >= 0),
    CONSTRAINT continuity_awareness_preservation_fk
        FOREIGN KEY (preservation_node_id, preservation_scope)
        REFERENCES cirisgraph.nodes (node_id, scope)
        DEFERRABLE INITIALLY DEFERRED
);

-- Hot path #1: per-agent recent shutdowns ("where did I leave off
-- on my last boot?"). Composite ordered index supports both the
-- newest-first `get_latest_shutdown` point read and any future
-- bounded-window history scans.
CREATE INDEX continuity_awareness_agent_recent
    ON cirislens.continuity_awareness (agent_id, shutdown_timestamp DESC);

-- Hot path #2: per-agent active (non-terminal) sessions. Partial
-- index — only carries the rows where the agent is expected to
-- reactivate. This is the index `record_reactivation` rides to
-- find the most-recent non-terminal shutdown for an incrementing
-- update.
CREATE INDEX continuity_awareness_active_session
    ON cirislens.continuity_awareness (agent_id, shutdown_timestamp DESC)
    WHERE is_terminal = FALSE;

COMMENT ON TABLE cirislens.continuity_awareness IS
    'v1.5.17 (CIRISPersist#59 #9) — continuity_awareness substrate. Absorbs CIRISAgent ciris_engine.db.continuity_awareness; per-shutdown record giving the next boot a "where did I leave off" surface. 14 columns matching the agent verbatim. First substrate with a cross-substrate FK: (preservation_node_id, preservation_scope) references cirisgraph.nodes(node_id, scope) DEFERRABLE so shutdown ceremony can land graph-node + continuity row in one tx. preservation_scope CHECK over LOCAL|IDENTITY|ENVIRONMENT|COMMUNITY (matches cirisgraph scope vocabulary). reactivation_count CHECK (>= 0).';
