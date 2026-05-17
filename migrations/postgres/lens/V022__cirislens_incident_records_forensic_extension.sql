-- V022 — cirislens.incident_records D1-full forensic extension
-- (v1.5.5, CIRISPersist#56).
--
-- Absorbs CIRISAgent's IncidentNode D1-full fields (Lane D1-full).
-- All changes are additive + nullable; pre-V022 rows and
-- non-EXCEPTION incidents leave the new columns NULL. The
-- wire-format contract stays back-compatible (Rust struct gains
-- serde defaults for the 11 new fields).
--
-- # What this migration adds
--
-- 1. **11 forensic columns** carrying CIRISAgent's IncidentNode
--    fields (`incident_type`, `source_component`, `handler_name`,
--    `exception_type`, `stack_trace`, `filename`, `line_number`,
--    `function_name`, `impact`, `urgency`, `detection_method`).
--    All nullable, all free-form TEXT (except `line_number INTEGER`)
--    — no CHECK constraints, the agent owns the vocabulary.
--
-- 2. **Forensic-query indexes** on `(filename, line_number)` and
--    `source_component` (partial, NULL-skipping) so operator oncall
--    queries against the file:line and component dimensions hit an
--    index instead of a sequential scan.
--
-- 3. **Severity CHECK relaxed** to accept ITIL aliases
--    (`low`, `medium`, `high`) in addition to the syslog set
--    (`info`, `warning`, `error`, `critical`). The Rust enum
--    `IncidentSeverity` carries both vocabularies as distinct
--    variants for lossless round-trip; callers translate at the
--    type layer if they need a unified ladder.
--
-- 4. **State CHECK relaxed** to add `recurring` — per CIRISPersist#56
--    ask 3, this is "open with identified pattern" (parallel to
--    `open` in the AV-55 ladder, rank 0). Same-rank Open↔Recurring
--    transitions are NOT permitted at the type layer — callers
--    signal "recurring pattern" by recording a new Recurring-state
--    incident referencing the same problem_id via correlation_keys.
--
-- 5. **Partial-index predicate updated** for the hot-path active
--    index to include `recurring` alongside `open` and
--    `investigating`. Same index name preserved (`incident_open_recent`).
--
-- Refinery wraps each migration in its own transaction; no
-- explicit BEGIN/COMMIT here (V019's fix established this rule).

ALTER TABLE cirislens.incident_records
    ADD COLUMN incident_type    TEXT,
    ADD COLUMN source_component TEXT,
    ADD COLUMN handler_name     TEXT,
    ADD COLUMN exception_type   TEXT,
    ADD COLUMN stack_trace      TEXT,
    ADD COLUMN filename         TEXT,
    ADD COLUMN line_number      INTEGER,
    ADD COLUMN function_name    TEXT,
    ADD COLUMN impact           TEXT,
    ADD COLUMN urgency          TEXT,
    ADD COLUMN detection_method TEXT;

-- Forensic-query indexes (operator oncall — file:line and
-- source_component are the high-cardinality dimensions for
-- exception-class incidents).
CREATE INDEX incident_records_filename_line
    ON cirislens.incident_records (filename, line_number)
    WHERE filename IS NOT NULL;

CREATE INDEX incident_records_source_component
    ON cirislens.incident_records (source_component)
    WHERE source_component IS NOT NULL;

-- Relax severity CHECK to admit ITIL aliases. The V016 column-level
-- anonymous CHECK on `severity` is auto-named by PostgreSQL using
-- the canonical `<table>_<column>_check` pattern, i.e.
-- `incident_records_severity_check`.
ALTER TABLE cirislens.incident_records
    DROP CONSTRAINT incident_records_severity_check;
ALTER TABLE cirislens.incident_records
    ADD CONSTRAINT incident_records_severity_check
    CHECK (severity IN ('info', 'warning', 'error', 'critical',
                        'low', 'medium', 'high'));

-- Relax state CHECK to add 'recurring' (auto-named per same rule).
ALTER TABLE cirislens.incident_records
    DROP CONSTRAINT incident_records_state_check;
ALTER TABLE cirislens.incident_records
    ADD CONSTRAINT incident_records_state_check
    CHECK (state IN ('open', 'investigating', 'resolved', 'closed',
                     'recurring'));

-- Drop V016's partial active index (`incident_open_recent`) and
-- recreate with the updated predicate covering `recurring`. Same
-- name preserved.
DROP INDEX cirislens.incident_open_recent;
CREATE INDEX incident_open_recent
    ON cirislens.incident_records (tenant_id, state, last_seen_at)
    WHERE state IN ('open', 'investigating', 'recurring');

COMMENT ON COLUMN cirislens.incident_records.incident_type IS
    'v1.5.5 (CIRISPersist#56) — free-form incident type for agent forensics: ERROR | WARNING | EXCEPTION.';
COMMENT ON COLUMN cirislens.incident_records.source_component IS
    'v1.5.5 — component that raised the incident.';
COMMENT ON COLUMN cirislens.incident_records.handler_name IS
    'v1.5.5 — handler that processed the incident.';
COMMENT ON COLUMN cirislens.incident_records.exception_type IS
    'v1.5.5 — Python exception class name (EXCEPTION-type incidents).';
COMMENT ON COLUMN cirislens.incident_records.stack_trace IS
    'v1.5.5 — captured stack trace for EXCEPTION-type incidents.';
COMMENT ON COLUMN cirislens.incident_records.filename IS
    'v1.5.5 — source file the incident was raised from (forensics).';
COMMENT ON COLUMN cirislens.incident_records.line_number IS
    'v1.5.5 — source line number.';
COMMENT ON COLUMN cirislens.incident_records.function_name IS
    'v1.5.5 — source function name.';
COMMENT ON COLUMN cirislens.incident_records.impact IS
    'v1.5.5 — ITIL impact dimension (free-form).';
COMMENT ON COLUMN cirislens.incident_records.urgency IS
    'v1.5.5 — ITIL urgency dimension (free-form).';
COMMENT ON COLUMN cirislens.incident_records.detection_method IS
    'v1.5.5 — how the incident was detected.';
