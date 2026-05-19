-- V035 — cascade source_task_id FK on cirislens_thoughts (v1.5.20,
-- CIRISPersist#60).
--
-- The agent's `delete_tasks_by_ids` semantics expect parent task
-- deletion to take its thoughts with it. V025 declared the
-- `thoughts_task_fk` constraint as DEFERRABLE INITIALLY DEFERRED
-- but without an `ON DELETE` action, so the implicit NO ACTION
-- causes `task_delete` of a parent with children to reject with
-- FOREIGN_KEY_VIOLATION. This migration replaces the constraint
-- with `ON DELETE CASCADE` so `task_delete` cascades to thoughts
-- automatically.
--
-- The self-FK on `parent_thought_id` is left strict — `thought_delete`
-- is symmetric with `task_delete` (caller walks subtree before
-- deleting roots, or deletes leaves-first). This keeps thought-tree
-- semantics explicit and matches the task substrate's pattern.
--
-- Refinery wraps each migration in its own transaction; no explicit
-- BEGIN/COMMIT here (V019's fix established this rule).

ALTER TABLE cirislens.thoughts
    DROP CONSTRAINT thoughts_task_fk;

ALTER TABLE cirislens.thoughts
    ADD CONSTRAINT thoughts_task_fk
    FOREIGN KEY (source_task_id)
    REFERENCES cirislens.tasks(task_id)
    ON DELETE CASCADE
    DEFERRABLE INITIALLY DEFERRED;
