-- V195 — detection_events becomes a projection of detection:{detector}:v1
-- rows. SQLite dialect. v57.0.0 (CIRISPersist#988 item 3; CC 3.4.8, CC 2.4.2).
--
-- POSTGRES PARITY: migrations/postgres/lens/V195__detection_events_projection.sql
--
-- WHY
-- ---
-- V008/V040 made cirislens_derived_detection_events LensCore's detection
-- store: hybrid-signed by the detector, but written directly and never
-- replicated. CC 3.4.8 registers detection:* as the detector-only reserved
-- family, so every detection is now a `scores` row on the plane (attester =
-- the detector's key; `attestation_admit::plan_detection_row`), and this
-- table is the projection of rows, written by the row's executor in the
-- same transaction and rebuildable from the rows alone
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
-- tombstone carries no signature (the bytes it covered are gone). SQLite
-- cannot drop NOT NULL in place, so the table is rebuilt (the V080 dance);
-- every CHECK is kept verbatim (a CHECK on a NULL column passes). A pre-v57
-- row carries NULL `attestation_id` until the next put_detection_event
-- rehomes it; the partial index makes that probe free.

PRAGMA defer_foreign_keys = ON;

CREATE TABLE cirislens_derived_detection_events_new (
    detection_id                 TEXT PRIMARY KEY,
    trace_id                     TEXT,
    body_sha256                  BLOB,
    detector                     TEXT NOT NULL,
    severity                     TEXT NOT NULL,
    cohort_cell                  TEXT NOT NULL,
    conformity_variant           TEXT NOT NULL,
    conformity_payload           TEXT NOT NULL,
    lens_core_version            TEXT NOT NULL,
    ratchet_calibration_version  INTEGER NOT NULL,
    canonical_bytes              BLOB,
    -- V195: NULLABLE (an erasure-derived tombstone carries no signature).
    ed25519_sig                  BLOB,
    ml_dsa_65_sig                BLOB,
    signing_key_id               TEXT NOT NULL,
    ts                           TEXT NOT NULL,
    erased_at                    TEXT,
    -- V195: the row this projection row comes from.
    attestation_id               TEXT
        REFERENCES federation_attestations(attestation_id) ON DELETE CASCADE,

    CONSTRAINT detection_events_severity_known
        CHECK (severity IN ('info', 'warning', 'critical')),
    CONSTRAINT detection_events_conformity_variant_known
        CHECK (conformity_variant IN ('numeric', 'indeterminate', 'unavailable')),
    CONSTRAINT detection_events_body_sha256_correct_length
        CHECK (length(body_sha256) = 32),
    CONSTRAINT detection_events_ed25519_sig_correct_length
        CHECK (length(ed25519_sig) = 64),
    CONSTRAINT detection_events_ml_dsa_65_sig_correct_length
        CHECK (length(ml_dsa_65_sig) = 3309),
    CONSTRAINT detection_events_canonical_bytes_bounded
        CHECK (length(canonical_bytes) BETWEEN 1 AND 1048576)
);

INSERT INTO cirislens_derived_detection_events_new (
    detection_id, trace_id, body_sha256, detector, severity,
    cohort_cell, conformity_variant, conformity_payload,
    lens_core_version, ratchet_calibration_version,
    canonical_bytes, ed25519_sig, ml_dsa_65_sig, signing_key_id, ts,
    erased_at, attestation_id
)
SELECT
    detection_id, trace_id, body_sha256, detector, severity,
    cohort_cell, conformity_variant, conformity_payload,
    lens_core_version, ratchet_calibration_version,
    canonical_bytes, ed25519_sig, ml_dsa_65_sig, signing_key_id, ts,
    erased_at, NULL
FROM cirislens_derived_detection_events;

DROP TABLE cirislens_derived_detection_events;

ALTER TABLE cirislens_derived_detection_events_new
    RENAME TO cirislens_derived_detection_events;

CREATE INDEX detection_events_trace_id
    ON cirislens_derived_detection_events (trace_id);
CREATE INDEX detection_events_body_sha256
    ON cirislens_derived_detection_events (body_sha256);
CREATE INDEX detection_events_detector_ts
    ON cirislens_derived_detection_events (detector, ts DESC);
CREATE INDEX detection_events_erased_at
    ON cirislens_derived_detection_events (erased_at)
    WHERE erased_at IS NOT NULL;
CREATE INDEX detection_events_by_attestation
    ON cirislens_derived_detection_events (attestation_id);
CREATE INDEX detection_events_legacy
    ON cirislens_derived_detection_events (detection_id) WHERE attestation_id IS NULL;
