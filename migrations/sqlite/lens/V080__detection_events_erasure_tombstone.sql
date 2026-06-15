-- V080 — detection_events Art. 17 erasure tombstone, SQLite dialect
--        (CIRISPersist#222). Postgres parity: postgres/lens/V080.
--
-- See the postgres/lens/V080 header for the full rationale. Summary:
-- `Engine::delete_traces_for_agent_id_hash` (GDPR Art. 17 / DSAR) hard-
-- deletes the subject's traces but TOMBSTONES the derived
-- `cirislens_derived_detection_events` rows — NULLs the PII-linkage
-- columns (`trace_id`, `body_sha256`, `canonical_bytes`) and stamps
-- `erased_at`, keeping the substrate-derived analytics (detector,
-- severity, cohort_cell, reproducibility anchors).
--
-- SQLite does NOT support `ALTER TABLE ... ALTER COLUMN ... DROP NOT
-- NULL`, so we do the standard 12-step rebuild dance (cf. V035) to relax
-- the three NOT NULL columns to NULLABLE, and add `erased_at` in the
-- rebuilt shape. The length CHECK constraints (length(...) = N) are
-- retained verbatim: a CHECK evaluates to true/UNKNOWN (= passes) when
-- its column is NULL, so a tombstoned NULL row satisfies every CHECK.
--
-- Refinery wraps each migration in its own transaction; the
-- defer_foreign_keys pragma is local to it and resets at COMMIT.

PRAGMA defer_foreign_keys = ON;

CREATE TABLE cirislens_derived_detection_events_new (
    detection_id                 TEXT PRIMARY KEY,

    -- V080: PII-linkage columns relaxed to NULLABLE so the Art. 17
    -- tombstone can NULL them (were NOT NULL in V040).
    trace_id                     TEXT,
    body_sha256                  BLOB,

    detector                     TEXT NOT NULL,
    severity                     TEXT NOT NULL,

    cohort_cell                  TEXT NOT NULL,
    conformity_variant           TEXT NOT NULL,
    conformity_payload           TEXT NOT NULL,

    lens_core_version            TEXT NOT NULL,
    ratchet_calibration_version  INTEGER NOT NULL,

    -- V080: relaxed to NULLABLE (tombstone NULLs it).
    canonical_bytes              BLOB,
    ed25519_sig                  BLOB NOT NULL,
    ml_dsa_65_sig                BLOB NOT NULL,
    signing_key_id               TEXT NOT NULL,

    ts                           TEXT NOT NULL,

    -- V080 (CIRISPersist#222) — Art. 17 tombstone marker.
    erased_at                    TEXT,

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
    erased_at
)
SELECT
    detection_id, trace_id, body_sha256, detector, severity,
    cohort_cell, conformity_variant, conformity_payload,
    lens_core_version, ratchet_calibration_version,
    canonical_bytes, ed25519_sig, ml_dsa_65_sig, signing_key_id, ts,
    NULL
FROM cirislens_derived_detection_events;

DROP TABLE cirislens_derived_detection_events;

ALTER TABLE cirislens_derived_detection_events_new
    RENAME TO cirislens_derived_detection_events;

-- Recreate the three V040 indexes.
CREATE INDEX detection_events_trace_id
    ON cirislens_derived_detection_events (trace_id);

CREATE INDEX detection_events_body_sha256
    ON cirislens_derived_detection_events (body_sha256);

CREATE INDEX detection_events_detector_ts
    ON cirislens_derived_detection_events (detector, ts DESC);

-- Tombstone-set partial index (parity with postgres V080).
CREATE INDEX detection_events_erased_at
    ON cirislens_derived_detection_events (erased_at)
    WHERE erased_at IS NOT NULL;
