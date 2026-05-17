-- V022 — cirislens_incident_records D1-full forensic extension,
-- SQLite dialect (v1.5.5, CIRISPersist#56).
--
-- Postgres parity (postgres/lens/V022): adds 11 nullable forensic
-- columns + relaxes severity and state CHECKs (severity gains ITIL
-- aliases `low`/`medium`/`high`; state gains `recurring`).
--
-- SQLite ALTER TABLE does not support DROP CONSTRAINT, so the
-- CHECK relaxations require the recreate-table dance: build the
-- new shape side-by-side, copy rows, drop the old table, rename.
-- All V016 columns are preserved (signature / signing_key_id /
-- signature_verified / persist_row_hash / created_at included)
-- + the 11 new forensic columns appended at the end. V016 indexes
-- are re-created with the predicate of the partial active index
-- updated to include `recurring`.
--
-- Refinery wraps each migration in its own transaction, so no
-- explicit BEGIN/COMMIT here — nesting would fail at the driver
-- with "cannot start a transaction within a transaction" (same
-- failure mode V019's fix solved on PG).

CREATE TABLE cirislens_incident_records_v22 (
    incident_id           TEXT PRIMARY KEY,
    tenant_id             TEXT NOT NULL,
    severity              TEXT NOT NULL
        CHECK (severity IN ('info', 'warning', 'error', 'critical',
                            'low', 'medium', 'high')),
    category              TEXT NOT NULL,
    title                 TEXT NOT NULL,
    description           TEXT,
    correlation_keys      TEXT NOT NULL DEFAULT '[]',
    state                 TEXT NOT NULL
        CHECK (state IN ('open', 'investigating', 'resolved', 'closed',
                         'recurring')),
    first_seen_at         TEXT NOT NULL,
    last_seen_at          TEXT NOT NULL,
    resolved_at           TEXT,
    resolution_notes      TEXT,
    occurrences           INTEGER NOT NULL DEFAULT 1
        CHECK (occurrences >= 1),

    -- Audit envelope (preserved verbatim from V016).
    signature             TEXT,
    signing_key_id        TEXT,
    signature_verified    INTEGER NOT NULL DEFAULT 0,
    persist_row_hash      TEXT NOT NULL,
    created_at            TEXT NOT NULL DEFAULT (datetime('now', 'subsec')),

    -- v1.5.5 forensic fields (CIRISPersist#56). All nullable.
    incident_type         TEXT,
    source_component      TEXT,
    handler_name          TEXT,
    exception_type        TEXT,
    stack_trace           TEXT,
    filename              TEXT,
    line_number           INTEGER,
    function_name         TEXT,
    impact                TEXT,
    urgency               TEXT,
    detection_method      TEXT
);

INSERT INTO cirislens_incident_records_v22 (
    incident_id, tenant_id, severity, category, title, description,
    correlation_keys, state, first_seen_at, last_seen_at, resolved_at,
    resolution_notes, occurrences, signature, signing_key_id,
    signature_verified, persist_row_hash, created_at
) SELECT
    incident_id, tenant_id, severity, category, title, description,
    correlation_keys, state, first_seen_at, last_seen_at, resolved_at,
    resolution_notes, occurrences, signature, signing_key_id,
    signature_verified, persist_row_hash, created_at
FROM cirislens_incident_records;

DROP TABLE cirislens_incident_records;
ALTER TABLE cirislens_incident_records_v22 RENAME TO cirislens_incident_records;

-- Re-create V016 indexes (with `recurring` added to the partial
-- predicate) + add v1.5.5 forensic indexes.
CREATE INDEX incident_open_recent
    ON cirislens_incident_records (tenant_id, state, last_seen_at)
    WHERE state IN ('open', 'investigating', 'recurring');

CREATE INDEX incident_first_seen
    ON cirislens_incident_records (tenant_id, first_seen_at);

CREATE INDEX incident_records_filename_line
    ON cirislens_incident_records (filename, line_number)
    WHERE filename IS NOT NULL;

CREATE INDEX incident_records_source_component
    ON cirislens_incident_records (source_component)
    WHERE source_component IS NOT NULL;
