-- V187 — the steward purge plane: execution headers and tombstones, Postgres dialect
-- v54.1.0 (CIRISPersist#1046, CIRISConstitution#165, CSD-108)
--
-- SQLITE PARITY: migrations/sqlite/lens/V187__steward_purge.sql
-- See that file's header for the rationale.

CREATE TABLE IF NOT EXISTS cirislens.purge_executions (
    notice_id          TEXT PRIMARY KEY CHECK (notice_id ~ '^[0-9a-f]{64}$'),
    selection_digest   TEXT NOT NULL CHECK (selection_digest ~ '^[0-9a-f]{64}$'),
    claimant_key_id    TEXT NOT NULL CHECK (claimant_key_id <> ''),
    record_count       BIGINT NOT NULL CHECK (record_count >= 0),
    notice_jcs         TEXT NOT NULL,
    cosignatures_json  TEXT NOT NULL,
    executed_by        TEXT NOT NULL,
    origin             TEXT NOT NULL CHECK (origin IN ('local', 'replicated')),
    executed_at        TIMESTAMPTZ NOT NULL,
    admitted_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finalized_at       TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS purge_executions_serve
    ON cirislens.purge_executions (admitted_at, notice_id);

CREATE TABLE IF NOT EXISTS cirislens.purge_tombstones (
    notice_id     TEXT NOT NULL REFERENCES cirislens.purge_executions (notice_id),
    plane         TEXT NOT NULL CHECK (plane IN ('attestation', 'trace', 'key', 'blob')),
    record_ref    TEXT NOT NULL CHECK (record_ref <> ''),
    ordinal       BIGINT NOT NULL CHECK (ordinal >= 0),
    derived_from  TEXT NULL,
    PRIMARY KEY (notice_id, plane, record_ref)
);

CREATE INDEX IF NOT EXISTS purge_tombstones_record
    ON cirislens.purge_tombstones (plane, record_ref);
CREATE INDEX IF NOT EXISTS purge_tombstones_ordinal
    ON cirislens.purge_tombstones (notice_id, ordinal);
