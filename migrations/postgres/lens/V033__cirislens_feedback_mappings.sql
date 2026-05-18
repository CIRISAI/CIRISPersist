-- V033 — feedback_mappings substrate (v1.5.18, CIRISPersist#59 #10).
--
-- Tenth of 11 substrate absorptions ending CIRISAgent's direct
-- libsqlite access to `ciris_engine.db`. Absorbs the agent's
-- `feedback_mappings` table — the link between an inbound feedback
-- Discord message (or analogous wire-message id) and the agent
-- thought that resolved against it. The agent uses these rows to
-- chase "what feedback have we received about thought Y?" /
-- "which thought did message X end up routed to?" lookups.
--
-- # Design decision: dedicated substrate vs. folding into cirisgraph_edges
--
-- The agent's spec called out a design question: "may be foldable
-- into cirisgraph_edges if the relationship semantics fit." After
-- review we ship as a dedicated substrate:
--
--   * `target_thought_id` references `cirislens.thoughts(thought_id)`
--     — a typed-substrate FK, NOT a graph_nodes FK. cirisgraph_edges
--     expects (source_node_id, target_node_id) both pointing at
--     graph_nodes; this doesn't fit that shape.
--   * The agent's table semantics ("feedback X applies to thought Y")
--     are structurally different from "node A relates to node B in
--     graph G" — feedback rides on Discord-message-to-thought-
--     resolution pairs, which don't fit cleanly as graph edges.
--   * Folding into cirisgraph_edges would force us to also represent
--     the thought as a graph_node, doubling write surface.
--
-- A dedicated 5-column substrate is the right shape.
--
-- # Agent's 5-column shape (CIRISAgent v2.8.13)
--
--   feedback_id        TEXT PRIMARY KEY
--   source_message_id  TEXT
--   target_thought_id  TEXT
--   feedback_type      TEXT
--   created_at         TEXT NOT NULL
--
-- PG dialect: created_at promoted to TIMESTAMPTZ with NOW() default;
-- target_thought_id FK to `cirislens.thoughts(thought_id)` is
-- DEFERRABLE INITIALLY DEFERRED so a one-tx ceremony writing
-- (thought, feedback_mapping) in either order is supported.
--
-- The agent leaves target_thought_id nullable — feedback can arrive
-- before any thought has been resolved against it. PG's FK only
-- fires for non-NULL values natively; NULL FKs pass the constraint
-- check.
--
-- Refinery wraps each migration in its own transaction; no explicit
-- BEGIN/COMMIT here (V019's fix established this rule).

CREATE TABLE cirislens.feedback_mappings (
    feedback_id        TEXT PRIMARY KEY,
    source_message_id  TEXT,
    target_thought_id  TEXT,
    feedback_type      TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT feedback_mappings_target_thought_fk
        FOREIGN KEY (target_thought_id) REFERENCES cirislens.thoughts(thought_id)
        DEFERRABLE INITIALLY DEFERRED
);

-- Hot path #1: "what feedback applies to thought Y?". Partial index
-- — only carries rows where the FK is set (drops the unbound-yet
-- feedback rows that have no resolution).
CREATE INDEX feedback_mappings_thought ON cirislens.feedback_mappings (target_thought_id)
    WHERE target_thought_id IS NOT NULL;

-- Hot path #2: "which thought did message X resolve into?". Partial
-- index on the wire-message id — rows where the message id is
-- present (which is essentially all of them in practice but the
-- column is nullable in the agent's schema).
CREATE INDEX feedback_mappings_source_message ON cirislens.feedback_mappings (source_message_id)
    WHERE source_message_id IS NOT NULL;

-- Hot path #3: per-type recent listing (operator dashboards filtering
-- by approval / correction / clarification, time-windowed). Partial
-- index — only carries typed rows.
CREATE INDEX feedback_mappings_type_recent ON cirislens.feedback_mappings (feedback_type, created_at DESC)
    WHERE feedback_type IS NOT NULL;

COMMENT ON TABLE cirislens.feedback_mappings IS
    'v1.5.18 (CIRISPersist#59 #10) — feedback_mappings substrate. Absorbs CIRISAgent ciris_engine.db.feedback_mappings; the link between an inbound feedback Discord-message (or analogous wire-message id) and the agent thought it resolved against. 5 columns matching the agent. target_thought_id FK to cirislens.thoughts(thought_id), DEFERRABLE INITIALLY DEFERRED, only fires for non-NULL values (PG handles null FKs natively). Designed as a dedicated substrate rather than folded into cirisgraph_edges — feedback rides on typed-substrate FKs (thoughts), not graph-node FKs.';
