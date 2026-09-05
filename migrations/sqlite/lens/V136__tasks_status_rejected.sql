-- V136 — admit 'rejected' into cirislens_tasks.status, SQLite dialect
-- v41.2.0 (CIRISPersist#810, CIRISAgent#1077)
--
-- POSTGRES PARITY: migrations/postgres/lens/V136__tasks_status_rejected.sql
-- (same value admitted there; Postgres has DROP CONSTRAINT so its twin is
-- four lines and this one is a table rebuild. See that file for the FULL
-- rationale — why the vocabulary gains a value instead of becoming an open
-- string, and why folding `rejected` onto `failed` agent-side was the wrong
-- shape.)
--
-- THE SHORT VERSION
-- -----------------
-- V024's 6-value set is not a superset of the consumer enum it claimed to
-- mirror. `ciris_engine.schemas.runtime.enums.TaskStatus` writes
-- `rejected`; persist refuses it like a typo; the agent logs and continues;
-- the task stays `active` forever with nothing to retry it
-- (CIRISAgent#1077). Nothing is removed and no row changes.
--
-- HOW (the SQLite table-rebuild recipe — and this is the HARD case)
-- ----------------------------------------------------------------
-- SQLite bakes table-level CHECKs into CREATE TABLE and has no
-- `ALTER TABLE ... DROP CONSTRAINT`, so the table is rebuilt: the
-- V020 / V035 / V061 / V097 / V114 / V115 / V116 / V117 recipe.
--
-- V115's twin was the EASY case and said so — nothing referenced
-- `cirislens_tickets`. This one is worse than V117's. Three FKs point INTO
-- `cirislens_tasks(task_id)`, and two more point into the table that first
-- one cascades to:
--
--   cirislens_tasks(task_id)
--     <- cirislens_thoughts.source_task_id        ON DELETE CASCADE  (V035)
--     <- cirislens_deferral_reports.task_id       NO ACTION          (V029)
--     <- cirislens_tasks.parent_task_id           NO ACTION, self    (V024)
--   cirislens_thoughts(thought_id)
--     <- cirislens_deferral_reports.thought_id    NO ACTION          (V029)
--     <- cirislens_feedback_mappings.target_thought_id  NO ACTION    (V033)
--     <- cirislens_scheduled_tasks.origin_thought_id    NO ACTION    (V027)
--     <- cirislens_thoughts.parent_thought_id     NO ACTION, self    (V035)
--
-- With `PRAGMA foreign_keys = ON` (set by SqliteBackend at every connection
-- open) a `DROP TABLE` performs an implicit `DELETE FROM`, and that fires
-- foreign key ACTIONS. So a naive drop here would CASCADE-WIPE EVERY ROW IN
-- `cirislens_thoughts` — the agent's entire reasoning record — and the
-- migration would report success.
--
-- `PRAGMA defer_foreign_keys = ON` does NOT save this, and the two reasons
-- were both measured rather than reasoned about:
--
--   1. It defers when constraint VIOLATIONS are checked (to COMMIT). It
--      does not suppress a cascade ACTION, which fires immediately. V035
--      was safe with the pragma alone only because nothing points at
--      `cirislens_thoughts` with a CASCADE — every referrer above is NO
--      ACTION, so those were deferred violations, satisfied again by its
--      rename. Here there is a CASCADE, and the rows are simply gone.
--
--   2. Even with the cascade staged and restored — and even with every one
--      of the six referrers above emptied first, so the drop fires nothing
--      at all — **COMMIT still fails**. `PRAGMA foreign_key_check` reports
--      ZERO violations and `COMMIT` still raises `FOREIGN KEY constraint
--      failed`. Bisecting the migration statement by statement pins it to
--      `DROP TABLE cirislens_tasks`, and at that point the only thing left
--      referencing the table is the REBUILD ITSELF: in the usual
--      `CREATE cirislens_tasks_new / INSERT SELECT / DROP old / RENAME`
--      shape (V035's, V061's), `cirislens_tasks_new` holds rows whose
--      `parent_task_id` self-FK names `cirislens_tasks`, and the DROP pulls
--      that table out from under them. The rows are consistent — their
--      parent is right there in `_new` — but the referenced TABLE is gone
--      for the length of one statement. SQLite's deferred-FK ledger is a
--      COUNTER, not a re-check: it takes a +1 there that the later rename
--      never gives back, and the transaction is refused with the data
--      perfectly consistent.
--
-- So this migration does two things, and needs both:
--
--   * It makes the drop INERT. Every row that references `cirislens_tasks`,
--     or references `cirislens_thoughts` (which the cascade would empty),
--     is staged and DELETED first, leaf-first, and restored parent-first
--     afterwards. No cascade fires and no counter moves.
--
--   * It uses NO `_new` table and NO rename. `cirislens_tasks` is staged
--     like everything else, emptied, dropped, and re-created UNDER ITS
--     FINAL NAME, so the self-FK is correct from the moment it is declared
--     and there is no window in which a live row references a dropped
--     table. Child tables spell `cirislens_tasks` textually and bind to the
--     new one.
--
-- The pragma is kept as belt-and-braces for the two self-FKs, which resolve
-- at statement end regardless.
--
-- (V035 carries the same latent window and has never fired it: a rebuild
-- only meets it when some row's self-FK column is non-NULL, and no
-- deployment has yet rebuilt `cirislens_thoughts` with a populated
-- `parent_thought_id`. Noted here rather than fixed — V035 has been applied
-- everywhere it is going to be applied, and an already-run migration cannot
-- be edited.)
--
-- Every other CHECK, index, default and NULL-ability is reproduced VERBATIM
-- from V024 plus V036's partial unique expression index. A rebuild is the
-- one moment a constraint is silently lost or silently widened by
-- transcription, so they are copied, not restated. The whole intended diff
-- is the single added `'rejected'`.
--
-- The staged column lists are spelled out rather than `SELECT *`. A
-- migration only ever runs against one schema — the V135 shape, frozen —
-- so an explicit list is exact, and it is auditable in a way `*` is not.

PRAGMA defer_foreign_keys = ON;

-- ── 1. stage every row involved: the table being rebuilt, and everything
--       that references it or the table its cascade would empty ──────────
CREATE TABLE _v136_stage_tasks AS
    SELECT task_id, channel_id, description, status, priority, created_at,
           updated_at, parent_task_id, context_json, outcome_json,
           retry_count, signed_by, signature, signed_at,
           updated_info_available, updated_info_content, agent_occurrence_id,
           images_json
    FROM cirislens_tasks;

CREATE TABLE _v136_stage_thoughts AS
    SELECT thought_id, source_task_id, channel_id, thought_type, status,
           created_at, updated_at, round_number, content, context_json,
           thought_depth, ponder_notes_json, parent_thought_id,
           final_action_json, agent_occurrence_id
    FROM cirislens_thoughts;

CREATE TABLE _v136_stage_deferrals AS
    SELECT message_id, task_id, thought_id, package, created_at, resolved_at,
           resolution_notes
    FROM cirislens_deferral_reports;

CREATE TABLE _v136_stage_feedback AS
    SELECT feedback_id, source_message_id, target_thought_id, feedback_type,
           created_at
    FROM cirislens_feedback_mappings;

CREATE TABLE _v136_stage_scheduled AS
    SELECT id, name, goal_description, status, defer_until, schedule_cron,
           trigger_prompt, origin_thought_id, created_at, last_triggered_at,
           next_trigger_at, deferral_count, deferral_history, created_by_agent,
           agent_occurrence_id
    FROM cirislens_scheduled_tasks;

-- ── 2. empty them leaf-first, so the DROP below is inert ────────────────
-- Each self-FK (parent_thought_id, parent_task_id) is checked at STATEMENT
-- end, and each of these statements leaves its table empty, so no child
-- ever outlives its parent.
DELETE FROM cirislens_deferral_reports;
DELETE FROM cirislens_feedback_mappings;
DELETE FROM cirislens_scheduled_tasks;
DELETE FROM cirislens_thoughts;
DELETE FROM cirislens_tasks;

-- ── 3. rebuild the parent UNDER ITS FINAL NAME ──────────────────────────
DROP TABLE cirislens_tasks;

CREATE TABLE cirislens_tasks (
    task_id               TEXT PRIMARY KEY,
    channel_id            TEXT NOT NULL,
    description           TEXT NOT NULL,
    -- v41.2.0 (CIRISPersist#810) — 'rejected' joins the set.
    status                TEXT NOT NULL
        CHECK (status IN ('pending', 'active', 'completed',
                          'failed', 'cancelled', 'deferred',
                          'rejected')),
    priority              INTEGER NOT NULL DEFAULT 0,
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL,
    parent_task_id        TEXT,
    context_json          TEXT,
    outcome_json          TEXT,
    retry_count           INTEGER NOT NULL DEFAULT 0
        CHECK (retry_count >= 0),
    signed_by             TEXT,
    signature             TEXT,
    signed_at             TEXT,
    updated_info_available INTEGER NOT NULL DEFAULT 0,
    updated_info_content  TEXT,
    agent_occurrence_id   TEXT NOT NULL DEFAULT 'default',
    images_json           TEXT,
    FOREIGN KEY (parent_task_id) REFERENCES cirislens_tasks(task_id)
);

-- ── 4. restore, parent-first ────────────────────────────────────────────
INSERT INTO cirislens_tasks
SELECT task_id, channel_id, description, status, priority, created_at,
       updated_at, parent_task_id, context_json, outcome_json, retry_count,
       signed_by, signature, signed_at, updated_info_available,
       updated_info_content, agent_occurrence_id, images_json
FROM _v136_stage_tasks;

INSERT INTO cirislens_thoughts
SELECT thought_id, source_task_id, channel_id, thought_type, status,
       created_at, updated_at, round_number, content, context_json,
       thought_depth, ponder_notes_json, parent_thought_id,
       final_action_json, agent_occurrence_id
FROM _v136_stage_thoughts;

INSERT INTO cirislens_deferral_reports
SELECT message_id, task_id, thought_id, package, created_at, resolved_at,
       resolution_notes
FROM _v136_stage_deferrals;

INSERT INTO cirislens_feedback_mappings
SELECT feedback_id, source_message_id, target_thought_id, feedback_type,
       created_at
FROM _v136_stage_feedback;

INSERT INTO cirislens_scheduled_tasks
SELECT id, name, goal_description, status, defer_until, schedule_cron,
       trigger_prompt, origin_thought_id, created_at, last_triggered_at,
       next_trigger_at, deferral_count, deferral_history, created_by_agent,
       agent_occurrence_id
FROM _v136_stage_scheduled;

DROP TABLE _v136_stage_tasks;
DROP TABLE _v136_stage_thoughts;
DROP TABLE _v136_stage_deferrals;
DROP TABLE _v136_stage_feedback;
DROP TABLE _v136_stage_scheduled;

-- ── 5. recreate V024's three indexes and V036's, verbatim ──────────────
-- Hot path: list_tasks happy path (occurrence + status + recency).
CREATE INDEX tasks_status_occurrence
    ON cirislens_tasks (agent_occurrence_id, status, updated_at DESC);

-- Channel-scoped recency scan.
CREATE INDEX tasks_channel
    ON cirislens_tasks (channel_id, updated_at DESC);

-- Reverse-lookup: find a parent's children. NULL-skipping partial.
CREATE INDEX tasks_parent
    ON cirislens_tasks (parent_task_id)
    WHERE parent_task_id IS NOT NULL;

-- V036 — UNIQUE on (agent_occurrence_id, context.correlation_id).
CREATE UNIQUE INDEX tasks_correlation_id_unique
    ON cirislens_tasks (
        agent_occurrence_id,
        json_extract(context_json, '$.correlation_id')
    )
    WHERE context_json IS NOT NULL
      AND json_extract(context_json, '$.correlation_id') IS NOT NULL;
