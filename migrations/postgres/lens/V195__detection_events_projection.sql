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
-- the projection of rows, written by the row's executor in the same
-- transaction and rebuildable from the rows alone
-- (CLM-silo-projection-rebuildable). A row is projected by:
--   * a live `detection:*` row (its detection);
--   * the same row under a steward-purge tombstone (the V080 tombstone);
--   * a `hard_case:trace_erasure:v1` row, for each detection the DSAR
--     erasure hard-deleted (the V080 tombstone, rebuilt from the erasure
--     row's detail: the analytics columns, no linkage, no signatures).
--
-- HOW
-- ---
-- `attestation_id` names the row each projection row comes from, ON DELETE
-- CASCADE. It is NOT unique: one erasure row projects every detection it
-- erased. The two signature columns become NULLABLE: an erasure-derived
-- tombstone carries no signature (the bytes it covered are gone); their
-- length CHECKs pass on NULL. A pre-v57 row carries NULL `attestation_id`
-- until the next put_detection_event rehomes it; the partial index makes
-- that probe free.

ALTER TABLE cirislens_derived.detection_events
    ADD COLUMN IF NOT EXISTS attestation_id TEXT
        REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE CASCADE;

ALTER TABLE cirislens_derived.detection_events
    ALTER COLUMN ed25519_sig DROP NOT NULL,
    ALTER COLUMN ml_dsa_65_sig DROP NOT NULL;

CREATE INDEX IF NOT EXISTS detection_events_by_attestation
    ON cirislens_derived.detection_events (attestation_id);

CREATE INDEX IF NOT EXISTS detection_events_legacy
    ON cirislens_derived.detection_events (detection_id) WHERE attestation_id IS NULL;
