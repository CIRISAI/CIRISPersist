-- V036 — UNIQUE on (agent_occurrence_id, context.correlation_id)
-- for cirislens.tasks (v1.5.22, CIRISPersist#61).
--
-- Restores the legacy CIRISAgent migration 006 invariant lost when
-- v1.5.9 absorbed `ciris_engine.db.tasks` into the substrate. The
-- agent's `add_task` relied on this index to dedupe Reddit/Discord
-- comment-event tasks within the same occurrence: the second
-- INSERT for the same upstream-event correlation_id failed at the
-- DB layer and the caller gracefully returned the existing task_id
-- instead of duplicating.
--
-- Partial index (`WHERE … IS NOT NULL`) so rows without a
-- correlation_id (or without a context_json) skip the index — most
-- agent-internal tasks don't carry one.
--
-- Refinery wraps each migration in its own transaction; no explicit
-- BEGIN/COMMIT here.

CREATE UNIQUE INDEX tasks_correlation_id_unique
    ON cirislens.tasks (
        agent_occurrence_id,
        (context_json->>'correlation_id')
    )
    WHERE context_json IS NOT NULL
      AND context_json->>'correlation_id' IS NOT NULL;
