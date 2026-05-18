-- V032 — continuity_awareness substrate (v1.5.17, CIRISPersist#59 #9).
--
-- SQLite mirror of V032 PG. Dialect translations:
--   TIMESTAMPTZ                → TEXT (RFC 3339)
--   BOOLEAN                    → INTEGER (0 / 1)
--   JSONB                      → TEXT (canonical JSON)
--   DEFERRABLE INITIALLY DEFERRED  → omitted (SQLite has only
--                                  immediate-mode FK enforcement
--                                  with PRAGMA foreign_keys=ON)
--
-- 14 columns matching the agent's source schema. First substrate
-- with a cross-substrate FK: (preservation_node_id, preservation_scope)
-- references the v0.8.4 cirisgraph_nodes table (composite PK
-- (node_id, scope)). The store layer always sets
-- PRAGMA foreign_keys = ON so the FK is enforced at insert time;
-- callers MUST ensure the referenced graph_nodes row exists first.
--
-- Refinery wraps each migration in its own transaction; no explicit
-- BEGIN/COMMIT here (V019's fix established this rule).

CREATE TABLE cirislens_continuity_awareness (
    id                         TEXT PRIMARY KEY,
    agent_id                   TEXT NOT NULL,
    shutdown_timestamp         TEXT NOT NULL,
    is_terminal                INTEGER NOT NULL,
    shutdown_reason            TEXT NOT NULL,
    expected_reactivation      TEXT,
    initiated_by               TEXT NOT NULL,
    final_thoughts             TEXT NOT NULL,
    unfinished_tasks           TEXT,
    reactivation_instructions  TEXT,
    deferred_goals             TEXT,
    preservation_node_id       TEXT NOT NULL,
    preservation_scope         TEXT NOT NULL DEFAULT 'IDENTITY'
        CHECK (preservation_scope IN ('LOCAL', 'IDENTITY', 'ENVIRONMENT', 'COMMUNITY')),
    reactivation_count         INTEGER NOT NULL DEFAULT 0
        CHECK (reactivation_count >= 0),
    FOREIGN KEY (preservation_node_id, preservation_scope)
        REFERENCES cirisgraph_nodes (node_id, scope)
);

CREATE INDEX continuity_awareness_agent_recent
    ON cirislens_continuity_awareness (agent_id, shutdown_timestamp DESC);

CREATE INDEX continuity_awareness_active_session
    ON cirislens_continuity_awareness (agent_id, shutdown_timestamp DESC)
    WHERE is_terminal = 0;
