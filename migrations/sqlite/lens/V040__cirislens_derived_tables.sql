-- V040 — lens-derived tables, SQLite dialect (CIRISPersist#82 review:
-- SQLite/PG ReadEngine + DerivedSchema parity).
--
-- Postgres parity with V008 (cirislens_derived.detection_events +
-- cirislens_derived.calibration_bundles). SQLite has no schemas, so
-- the schema-qualified names collapse to a `cirislens_derived_` table
-- prefix. TIMESTAMPTZ → TEXT (RFC 3339); JSONB → TEXT; BYTEA → BLOB;
-- BOOLEAN → INTEGER 0/1. octet_length() → length() (byte count for
-- BLOBs in SQLite).

CREATE TABLE cirislens_derived_detection_events (
    detection_id                 TEXT PRIMARY KEY,

    trace_id                     TEXT NOT NULL,
    body_sha256                  BLOB NOT NULL,

    detector                     TEXT NOT NULL,
    severity                     TEXT NOT NULL,

    cohort_cell                  TEXT NOT NULL,
    conformity_variant           TEXT NOT NULL,
    conformity_payload           TEXT NOT NULL,

    lens_core_version            TEXT NOT NULL,
    ratchet_calibration_version  INTEGER NOT NULL,

    canonical_bytes              BLOB NOT NULL,
    ed25519_sig                  BLOB NOT NULL,
    ml_dsa_65_sig                BLOB NOT NULL,
    signing_key_id               TEXT NOT NULL,

    ts                           TEXT NOT NULL,

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

CREATE INDEX detection_events_trace_id
    ON cirislens_derived_detection_events (trace_id);

CREATE INDEX detection_events_body_sha256
    ON cirislens_derived_detection_events (body_sha256);

CREATE INDEX detection_events_detector_ts
    ON cirislens_derived_detection_events (detector, ts DESC);


CREATE TABLE cirislens_derived_calibration_bundles (
    ratchet_calibration_version  INTEGER PRIMARY KEY,

    projection_version           TEXT NOT NULL,

    calibrated_at                TEXT NOT NULL,

    calibration_corpus_sha256    TEXT NOT NULL,
    calibration_corpus_n         INTEGER NOT NULL,

    sample_size_gate             INTEGER NOT NULL,
    manifold_threshold_global    REAL NOT NULL,

    projection_metadata          TEXT NOT NULL,
    cohort_centroids             TEXT NOT NULL,

    is_current                   INTEGER NOT NULL DEFAULT 0,

    canonical_bytes              BLOB NOT NULL,
    ed25519_sig                  BLOB NOT NULL,
    ml_dsa_65_sig                BLOB NOT NULL,
    signing_key_id               TEXT NOT NULL,

    inserted_at                  TEXT NOT NULL,

    CONSTRAINT calibration_bundles_corpus_n_positive
        CHECK (calibration_corpus_n > 0),
    CONSTRAINT calibration_bundles_sample_size_gate_positive
        CHECK (sample_size_gate > 0),
    CONSTRAINT calibration_bundles_manifold_threshold_positive
        CHECK (manifold_threshold_global > 0.0),
    CONSTRAINT calibration_bundles_ed25519_sig_correct_length
        CHECK (length(ed25519_sig) = 64),
    CONSTRAINT calibration_bundles_ml_dsa_65_sig_correct_length
        CHECK (length(ml_dsa_65_sig) = 3309),
    CONSTRAINT calibration_bundles_canonical_bytes_bounded
        CHECK (length(canonical_bytes) BETWEEN 1 AND 8388608),
    CONSTRAINT calibration_bundles_is_current_bool
        CHECK (is_current IN (0, 1))
);

-- Partial-unique: at most one is_current = 1 row across the table.
CREATE UNIQUE INDEX calibration_bundles_one_current
    ON cirislens_derived_calibration_bundles (is_current)
    WHERE is_current = 1;

CREATE INDEX calibration_bundles_projection_version
    ON cirislens_derived_calibration_bundles
       (projection_version, ratchet_calibration_version DESC);
