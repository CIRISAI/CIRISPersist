-- V008 — Lens-derived schemas (v0.4.3, CIRISPersist#18).
--
-- Closes the substrate-side of CIRISLensCore Phase 1 P0 ASKs:
--
--   1. detection_events  — signed records lens-core produces on every
--                          detector flag (LC-AV-2 cohort/declared-
--                          inferred mismatch P0; LC-AV-11 manifold-
--                          conformity outlier; LC-AV-18 reasoning-
--                          collapse; future ratchet detectors).
--
--   2. calibration_bundles — RATCHET-signed projection metadata +
--                          cohort centroids + thresholds + sample-size
--                          gate that lens-core's manifold scoring
--                          consumes per CIRISLensCore#3.
--
-- Both belong on cirislens_derived (separate from cirislens, which
-- is wire-ingest-shaped). Both are signed federation evidence with
-- the same trust shape: hybrid Ed25519 + ML-DSA-65 mandatory, verified
-- via verify_hybrid_via_directory under HybridPolicy::Strict on the
-- put paths (Engine.put_*; cf. CIRISPersist#14).
--
-- # Why a separate schema
--
-- cirislens.* holds rows derived directly from agent-emitted wire bytes
-- (trace_events, trace_llm_calls, accord_public_keys / federation_keys).
-- cirislens_derived.* holds rows produced by federation peers AFTER
-- trace ingest — lens-core scores traces, RATCHET calibrates against
-- corpora. Different write authority, different access surface, different
-- retention policy. Schema separation lets readonly_role grants stay
-- crisp (cirislens_reader for raw, cirislens_derived_reader for scored).
--
-- # Schema lifecycle
--
-- Experimental during v0.4.x per the same v0.4.0-stabilization contract
-- federation_keys uses. Stabilizes at v0.5.0 once lens-core +
-- RATCHET cutover settle.

CREATE SCHEMA IF NOT EXISTS cirislens_derived;


-- ─── detection_events ─────────────────────────────────────────────
--
-- Lens-core writes one row per detector flag. Forensic join key is
-- body_sha256 (matches edge::VerifiedTrace.body_sha256, used in
-- federation_attestations.scrub_signature, etc.). detector is a
-- free-form string scoped by lens-core's detector taxonomy; severity
-- is the federation-stable triage bucket.
--
-- cohort_cell is the RATCHET-confirmed 6-tuple per CIRISLensCore
-- OQ-10 (2026-05-04): agent_role, agent_template, deployment_domain,
-- deployment_type, deployment_region, deployment_trust_mode.
--
-- conformity_variant + conformity_payload split the
-- ManifoldConformity enum across two columns: variant tags which of
-- {numeric, indeterminate, unavailable}; payload carries variant-
-- specific data (score f64, IndeterminateReason discriminant,
-- UnavailableReason discriminant). lens-core's
-- src/scoring/result.rs is authoritative on the payload shapes.
--
-- ratchet_calibration_version stamps WHICH calibration_bundles row
-- was current at score time. Fundamental for LC-AV-19 reproducibility:
-- old detection events score against old centroids, never re-scored
-- silently when calibration rotates.

CREATE TABLE IF NOT EXISTS cirislens_derived.detection_events (
    detection_id                 UUID PRIMARY KEY,

    -- Forensic join keys.
    trace_id                     TEXT NOT NULL,
    body_sha256                  BYTEA NOT NULL,

    -- Detector taxonomy + triage.
    detector                     TEXT NOT NULL,
    severity                     TEXT NOT NULL,

    -- Cohort + conformity.
    cohort_cell                  JSONB NOT NULL,
    conformity_variant           TEXT NOT NULL,
    conformity_payload           JSONB NOT NULL,

    -- Reproducibility (LC-AV-19).
    lens_core_version            TEXT NOT NULL,
    ratchet_calibration_version  INTEGER NOT NULL,

    -- Hybrid signature payload. canonical_bytes is the input to
    -- verify_hybrid (canonical JSON via persist::prelude::
    -- canonicalize_envelope_for_signing — same canonicalizer edge
    -- and every other federation primitive use; CIRISPersist#7
    -- single-source-of-truth).
    canonical_bytes              BYTEA NOT NULL,
    ed25519_sig                  BYTEA NOT NULL,
    ml_dsa_65_sig                BYTEA NOT NULL,
    signing_key_id               TEXT NOT NULL,

    ts                           TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- ── Invariants ──
    CONSTRAINT detection_events_severity_known
        CHECK (severity IN ('info', 'warning', 'critical')),
    CONSTRAINT detection_events_conformity_variant_known
        CHECK (conformity_variant IN ('numeric', 'indeterminate', 'unavailable')),
    -- SHA-256 is exactly 32 bytes.
    CONSTRAINT detection_events_body_sha256_correct_length
        CHECK (octet_length(body_sha256) = 32),
    -- Ed25519 signatures are 64 bytes.
    CONSTRAINT detection_events_ed25519_sig_correct_length
        CHECK (octet_length(ed25519_sig) = 64),
    -- FIPS 204 final ML-DSA-65 signatures are 3309 bytes
    -- (CIRISVerify#4 / CIRISPersist#8 constant). Persist ships
    -- with ciris-keyring v1.9.0 which writes the corrected size;
    -- old draft-spec sigs (3293 bytes) would be rejected here.
    CONSTRAINT detection_events_ml_dsa_65_sig_correct_length
        CHECK (octet_length(ml_dsa_65_sig) = 3309),
    -- AV-13: bound canonical_bytes against runaway evidence rows.
    -- 1 MiB is well above any realistic detection envelope size;
    -- typical rows are ~1-5 KiB.
    CONSTRAINT detection_events_canonical_bytes_bounded
        CHECK (octet_length(canonical_bytes) BETWEEN 1 AND 1048576)
);

-- Trace-id lookup: "what flagged on this trace?". Hot path for
-- CIRISLens UI + operator triage.
CREATE INDEX IF NOT EXISTS detection_events_trace_id
    ON cirislens_derived.detection_events (trace_id);

-- Forensic join: "who flagged this body_sha256?". Cross-references
-- federation_attestations + outbound queue acks.
CREATE INDEX IF NOT EXISTS detection_events_body_sha256
    ON cirislens_derived.detection_events (body_sha256);

-- Detector dashboards: "what's the rate of <detector> over time?".
-- (detector, ts DESC) is the operator-time-series shape.
CREATE INDEX IF NOT EXISTS detection_events_detector_ts
    ON cirislens_derived.detection_events (detector, ts DESC);


-- ─── calibration_bundles ─────────────────────────────────────────
--
-- RATCHET writes one row per calibration. is_current flips atomically
-- on each new bundle; the partial-unique index enforces "at most one
-- current bundle". Old bundles retained for re-scoring + audit
-- (LC-AV-19).
--
-- projection_metadata + cohort_centroids carry the parameters
-- lens-core needs at scoring time. The JSONB shapes are documented
-- in CIRISPersist#18 issue body and the type docs on
-- crate::derived::types::{ProjectionMetadata, CohortCentroid}.

CREATE TABLE IF NOT EXISTS cirislens_derived.calibration_bundles (
    -- Monotonic version. Detection events stamp this so old detections
    -- can always be re-scored against the bundle that was current at
    -- score time.
    ratchet_calibration_version  INTEGER PRIMARY KEY,

    -- Pins the field-order + retention-mask contract. e.g. "crc-v1".
    projection_version           TEXT NOT NULL,

    calibrated_at                TIMESTAMPTZ NOT NULL,

    -- Calibration corpus provenance.
    calibration_corpus_sha256    TEXT NOT NULL,
    calibration_corpus_n         INTEGER NOT NULL,

    -- Score-time gates / thresholds.
    sample_size_gate             INTEGER NOT NULL,
    manifold_threshold_global    REAL NOT NULL,

    -- Score-time parameters (typed shapes; see crate::derived::types).
    projection_metadata          JSONB NOT NULL,
    cohort_centroids             JSONB NOT NULL,

    -- "Is this bundle the one lens-core is currently using?"
    is_current                   BOOLEAN NOT NULL DEFAULT FALSE,

    -- Hybrid signature payload — same shape as detection_events.
    canonical_bytes              BYTEA NOT NULL,
    ed25519_sig                  BYTEA NOT NULL,
    ml_dsa_65_sig                BYTEA NOT NULL,
    signing_key_id               TEXT NOT NULL,

    inserted_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- ── Invariants ──
    CONSTRAINT calibration_bundles_corpus_n_positive
        CHECK (calibration_corpus_n > 0),
    CONSTRAINT calibration_bundles_sample_size_gate_positive
        CHECK (sample_size_gate > 0),
    CONSTRAINT calibration_bundles_manifold_threshold_positive
        CHECK (manifold_threshold_global > 0.0),
    CONSTRAINT calibration_bundles_ed25519_sig_correct_length
        CHECK (octet_length(ed25519_sig) = 64),
    CONSTRAINT calibration_bundles_ml_dsa_65_sig_correct_length
        CHECK (octet_length(ml_dsa_65_sig) = 3309),
    -- 8 MiB matches the persist ingest body limit. Cohort centroids
    -- for thousands of cohorts at D=16 features fits comfortably.
    CONSTRAINT calibration_bundles_canonical_bytes_bounded
        CHECK (octet_length(canonical_bytes) BETWEEN 1 AND 8388608)
);

-- Partial-unique: at most one is_current=TRUE row across the table.
-- put_calibration_bundle clears the prior current row and sets the
-- new one in a single transaction; this index makes the invariant
-- DB-enforced rather than application-policy.
CREATE UNIQUE INDEX IF NOT EXISTS calibration_bundles_one_current
    ON cirislens_derived.calibration_bundles (is_current)
    WHERE is_current = TRUE;

-- Bundle-by-version lookup is PRIMARY KEY (no extra index needed).
-- "All bundles for projection_version X" — for migration from old
-- projection to new, audit reads, etc.
CREATE INDEX IF NOT EXISTS calibration_bundles_projection_version
    ON cirislens_derived.calibration_bundles (projection_version, ratchet_calibration_version DESC);
