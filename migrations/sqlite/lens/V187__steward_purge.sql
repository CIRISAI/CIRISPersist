-- V187 — the steward purge plane: execution headers and tombstones
-- v54.1.0 (CIRISPersist#1046, CIRISConstitution#165, CSD-108)
--
-- POSTGRES PARITY: migrations/postgres/lens/V187__steward_purge.sql
--
-- A steward purge removes rows the purger did not author, under the trust
-- root's cosigned `takedown_notice` (basis `steward_purge`) naming the
-- SHA-256 of the JCS-sorted record id list. Execution writes one header per
-- notice and one tombstone per record; nothing is deleted until the explicit
-- `purge_finalize` after the retraction round settles. Both tables OUTLIVE
-- the rows they name: a tombstone is what refuses a replica's copy of a
-- purged row at admission, and it is what replicates (notice + ids, never
-- content).
--
-- `purge_executions` carries every preimage the ledger claims: the notice's
-- JCS bytes (whose SHA-256 is `notice_id`), its whole cosignature set, the
-- digest, the count, the recording node and its instant. `admitted_at` is the
-- serve position. `purge_tombstones` is keyed per notice, so every notice's
-- id list is complete and its digest re-derives from its own rows; the
-- `(plane, record_ref)` index is the admission gates' lookup.
--
-- ONE tombstone row for takedown and purge (CC 4.5.3, CIRISConstitution
-- rc8@af6b436): `legal_basis` is the authorising notice's basis, so the same
-- tables hold a duty-holder takedown (bytes plane only; an immediate-removal
-- basis destroys on receipt, so `finalized_at` is simply set at once) beside
-- a `steward_purge` (any plane; hard delete after the round settles). No
-- column assumes `steward_purge`; v54.1.0 writes only that basis.

CREATE TABLE IF NOT EXISTS purge_executions (
    notice_id          TEXT PRIMARY KEY CHECK (length(notice_id) = 64 AND notice_id NOT GLOB '*[^0-9a-f]*'),
    selection_digest   TEXT NOT NULL CHECK (length(selection_digest) = 64 AND selection_digest NOT GLOB '*[^0-9a-f]*'),
    claimant_key_id    TEXT NOT NULL CHECK (claimant_key_id <> ''),
    record_count       INTEGER NOT NULL CHECK (record_count >= 0),
    notice_jcs         TEXT NOT NULL,
    cosignatures_json  TEXT NOT NULL,
    executed_by        TEXT NOT NULL,
    origin             TEXT NOT NULL CHECK (origin IN ('local', 'replicated')),
    executed_at        TEXT NOT NULL,
    admitted_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    finalized_at       TEXT NULL,
    legal_basis        TEXT NOT NULL CHECK (legal_basis <> '')
);

CREATE INDEX IF NOT EXISTS purge_executions_serve
    ON purge_executions (admitted_at, notice_id);

CREATE TABLE IF NOT EXISTS purge_tombstones (
    notice_id     TEXT NOT NULL REFERENCES purge_executions (notice_id),
    plane         TEXT NOT NULL CHECK (plane IN ('attestation', 'trace', 'blob')),
    record_ref    TEXT NOT NULL CHECK (record_ref <> ''),
    ordinal       INTEGER NOT NULL CHECK (ordinal >= 0),
    derived_from  TEXT NULL,
    PRIMARY KEY (notice_id, plane, record_ref)
);

CREATE INDEX IF NOT EXISTS purge_tombstones_record
    ON purge_tombstones (plane, record_ref);
CREATE INDEX IF NOT EXISTS purge_tombstones_ordinal
    ON purge_tombstones (notice_id, ordinal);
