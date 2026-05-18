-- V029 — deferral_reports substrate (v1.5.14, CIRISPersist#59 #6).
--
-- Sixth of 11 substrate absorptions ending CIRISAgent's direct
-- libsqlite access to `ciris_engine.db`. Absorbs CIRISAgent
-- 2.8.13 `deferral_reports` table — WA (Wise-Authority) deferrals
-- routed by message_id and pointing back into the agent's
-- (task, thought) reasoning chain.
--
-- Light shape — the agent's table is 5 columns; persist extends
-- with 2 nullable columns to support the `list_active_deferrals`
-- (WA deferrals awaiting resolution) hot path:
--
--   message_id        TEXT PRIMARY KEY
--   task_id           TEXT NOT NULL  → FK cirislens.tasks(task_id)
--   thought_id        TEXT NOT NULL  → FK cirislens.thoughts(thought_id)
--   package           JSONB           (agent's `package_json`,
--                                     renamed to drop _json suffix
--                                     on PG; JSONB is idiomatic)
--   created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
--   resolved_at       TIMESTAMPTZ     (persist-only — nullable,
--                                     marks WA resolution time)
--   resolution_notes  TEXT            (persist-only — nullable,
--                                     free-form WA notes)
--
-- The 2 persist-only columns are nullable so back-compat with the
-- agent's pre-extension 5-column shape is preserved. Agent rows
-- continue to deserialize cleanly with `resolved_at: None` +
-- `resolution_notes: None`.
--
-- PG-dialect translations from the agent's SQLite shape:
--
--   TEXT timestamps        → TIMESTAMPTZ (created_at)
--   TEXT JSON (package_json) → JSONB (package)
--
-- FK semantics: both FKs DEFERRABLE INITIALLY DEFERRED so the same
-- tx can write the (task, thought, deferral_report) chain in one
-- shot — same pattern as scheduled_tasks → thoughts (V027) and
-- thoughts → tasks (V025).
--
-- Refinery wraps each migration in its own transaction; no explicit
-- BEGIN/COMMIT here (V019's fix established this rule).

CREATE TABLE cirislens.deferral_reports (
    message_id        TEXT PRIMARY KEY,
    task_id           TEXT NOT NULL,
    thought_id        TEXT NOT NULL,
    package           JSONB,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at       TIMESTAMPTZ,
    resolution_notes  TEXT,
    CONSTRAINT deferral_reports_task_fk
        FOREIGN KEY (task_id) REFERENCES cirislens.tasks(task_id)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT deferral_reports_thought_fk
        FOREIGN KEY (thought_id) REFERENCES cirislens.thoughts(thought_id)
        DEFERRABLE INITIALLY DEFERRED
);

-- Hot path #1: per-task reverse lookup — "what deferrals did this
-- task produce?"
CREATE INDEX deferral_reports_task
    ON cirislens.deferral_reports (task_id);

-- Hot path #2: per-thought reverse lookup — "what deferrals did
-- this thought produce?"
CREATE INDEX deferral_reports_thought
    ON cirislens.deferral_reports (thought_id);

-- Hot path #3: `list_active_deferrals` — WA queue of deferrals
-- awaiting resolution, newest-first. Partial index — only
-- unresolved rows carry an entry.
CREATE INDEX deferral_reports_active
    ON cirislens.deferral_reports (created_at DESC)
    WHERE resolved_at IS NULL;

COMMENT ON TABLE cirislens.deferral_reports IS
    'v1.5.14 (CIRISPersist#59 #6) — deferral_reports substrate. Absorbs CIRISAgent ciris_engine.db.deferral_reports. Light 5-col agent shape + 2 persist-only nullable columns (resolved_at, resolution_notes) for the list_active hot path. FKs to cirislens.tasks + cirislens.thoughts both DEFERRABLE INITIALLY DEFERRED.';
