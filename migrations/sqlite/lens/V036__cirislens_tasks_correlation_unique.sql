-- V036 — UNIQUE on (agent_occurrence_id, context.correlation_id)
-- for cirislens_tasks, SQLite dialect (v1.5.22, CIRISPersist#61).
--
-- Postgres parity. SQLite expression indexes (3.9.0+) support
-- json_extract calls; the WHERE clause makes it a partial index so
-- correlation-id-less rows are skipped.
--
-- json_extract(...) returns NULL when the JSON path is absent;
-- the WHERE clause filters those rows out (`IS NOT NULL`) so the
-- index only carries correlation-bearing rows.

CREATE UNIQUE INDEX tasks_correlation_id_unique
    ON cirislens_tasks (
        agent_occurrence_id,
        json_extract(context_json, '$.correlation_id')
    )
    WHERE context_json IS NOT NULL
      AND json_extract(context_json, '$.correlation_id') IS NOT NULL;
