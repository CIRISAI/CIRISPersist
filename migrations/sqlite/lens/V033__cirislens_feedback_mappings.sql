-- V033 — feedback_mappings substrate (v1.5.18, CIRISPersist#59 #10).
--
-- SQLite mirror of V033 PG. Dialect translations:
--   TIMESTAMPTZ                          → TEXT (RFC 3339)
--   NOW() default                        → datetime('now', 'subsec')
--   DEFERRABLE INITIALLY DEFERRED        → omitted (SQLite has only
--                                          immediate-mode FK
--                                          enforcement with
--                                          PRAGMA foreign_keys=ON)
--
-- 5 columns matching the agent's source schema. The cross-substrate
-- FK to `cirislens_thoughts(thought_id)` only fires when
-- target_thought_id is non-NULL — SQLite handles nullable FKs
-- natively (NULL passes the constraint check without lookup).
--
-- The store layer always sets PRAGMA foreign_keys = ON so the FK is
-- enforced at insert time; non-NULL target_thought_id MUST reference
-- an existing thoughts row.
--
-- Refinery wraps each migration in its own transaction; no explicit
-- BEGIN/COMMIT here (V019's fix established this rule).

CREATE TABLE cirislens_feedback_mappings (
    feedback_id        TEXT PRIMARY KEY,
    source_message_id  TEXT,
    target_thought_id  TEXT,
    feedback_type      TEXT,
    created_at         TEXT NOT NULL DEFAULT (datetime('now', 'subsec')),
    FOREIGN KEY (target_thought_id) REFERENCES cirislens_thoughts(thought_id)
);

CREATE INDEX feedback_mappings_thought ON cirislens_feedback_mappings (target_thought_id)
    WHERE target_thought_id IS NOT NULL;

CREATE INDEX feedback_mappings_source_message ON cirislens_feedback_mappings (source_message_id)
    WHERE source_message_id IS NOT NULL;

CREATE INDEX feedback_mappings_type_recent ON cirislens_feedback_mappings (feedback_type, created_at DESC)
    WHERE feedback_type IS NOT NULL;
