-- V195 — detection_events becomes a projection of detection:{detector}:v1
-- rows. Postgres dialect. v57.0.0 (CIRISPersist#988 item 3; CC 3.4.8, CC 2.4.2).
--
-- SQLITE PARITY: migrations/sqlite/lens/V195__detection_events_projection.sql
--
-- WHY
-- ---
-- V008 made cirislens_derived.detection_events LensCore's detection store:
-- hybrid-signed by the detector, but written directly and never replicated.
-- CC 3.4.8 registers detection:* as the detector-only reserved family, so
-- every detection is now a `scores` row on the plane (attester = the
-- detector's key; `attestation_admit::plan_detection_row`), and this table is
-- the projection of those rows, written by the row's executor in the same
-- transaction and rebuildable from the rows alone
-- (CLM-silo-projection-rebuildable). The V080 Art. 17 tombstone is the
-- projection of the redacted row.
--
-- HOW
-- ---
-- `attestation_id` names the row each projection row comes from, ON DELETE
-- CASCADE (as V194). A pre-v57 row carries NULL until the next
-- put_detection_event rehomes it (`rehome_legacy_detection_events`); the
-- partial index makes that probe free.

ALTER TABLE cirislens_derived.detection_events
    ADD COLUMN IF NOT EXISTS attestation_id TEXT
        REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE CASCADE;

CREATE UNIQUE INDEX IF NOT EXISTS detection_events_by_attestation
    ON cirislens_derived.detection_events (attestation_id);

CREATE INDEX IF NOT EXISTS detection_events_legacy
    ON cirislens_derived.detection_events (detection_id) WHERE attestation_id IS NULL;
