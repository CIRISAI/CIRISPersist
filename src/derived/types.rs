//! Wire types for the `cirislens_derived` schema.
//!
//! Two record kinds — [`DetectionEvent`] (one per detector flag) and
//! [`CalibrationBundle`] (one per RATCHET calibration) — plus the
//! filter struct callers pass into the page-style getter for
//! detections.
//!
//! All fields are public; serde shapes match the SQL columns
//! field-for-field.
//!
//! # Hybrid signatures
//!
//! Both record types carry a hybrid (Ed25519 + ML-DSA-65) signature
//! over `canonical_bytes`. `canonical_bytes` is the canonical-JSON
//! representation produced by
//! [`crate::prelude::canonicalize_envelope_for_signing`] — the same
//! canonicalizer edge and every other federation primitive use
//! (CIRISPersist#7 single-source-of-truth).
//!
//! Persist's [`crate::derived::DerivedSchema::put_detection_event`]
//! and [`crate::derived::DerivedSchema::put_calibration_bundle`] back
//! ends do **not** verify these signatures themselves — that is the
//! [`Engine`] surface's responsibility, which calls
//! [`crate::verify::verify_hybrid_via_directory`] under
//! [`crate::verify::HybridPolicy::Strict`] before the backend write
//! (cf. CIRISPersist#14).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Severity bucket on a detection event. Federation-stable string
/// tokens: `"info"`, `"warning"`, `"critical"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DetectionSeverity {
    /// Diagnostic / observational. No alert action implied.
    Info,
    /// Notable; consumer policy may surface to operators.
    Warning,
    /// Federation-level evidence; consumers SHOULD react.
    Critical,
}

impl DetectionSeverity {
    /// Render as the canonical SQL `TEXT` value.
    pub fn as_db_str(&self) -> &'static str {
        match self {
            DetectionSeverity::Info => "info",
            DetectionSeverity::Warning => "warning",
            DetectionSeverity::Critical => "critical",
        }
    }

    /// Parse from the SQL `TEXT` value.
    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "info" => Some(DetectionSeverity::Info),
            "warning" => Some(DetectionSeverity::Warning),
            "critical" => Some(DetectionSeverity::Critical),
            _ => None,
        }
    }
}

/// Discriminant on a manifold-conformity score variant. Mirrors
/// lens-core's `src/scoring/result.rs::ManifoldConformity` enum
/// without dragging the full payload shape into persist (consumers
/// own the variant-specific JSONB shape; persist stores it
/// opaquely).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConformityVariant {
    /// Numeric Mahalanobis-σ score available;
    /// `conformity_payload = {"score": <f64>}`.
    Numeric,
    /// Score not computable (missing inputs, etc.);
    /// `conformity_payload = {"reason": "<IndeterminateReason>"}`.
    Indeterminate,
    /// Score machinery unavailable at scoring time;
    /// `conformity_payload = {"reason": "<UnavailableReason>"}`.
    Unavailable,
}

impl ConformityVariant {
    /// Render as the canonical SQL `TEXT` value.
    pub fn as_db_str(&self) -> &'static str {
        match self {
            ConformityVariant::Numeric => "numeric",
            ConformityVariant::Indeterminate => "indeterminate",
            ConformityVariant::Unavailable => "unavailable",
        }
    }

    /// Parse from the SQL `TEXT` value.
    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "numeric" => Some(ConformityVariant::Numeric),
            "indeterminate" => Some(ConformityVariant::Indeterminate),
            "unavailable" => Some(ConformityVariant::Unavailable),
            _ => None,
        }
    }
}

/// One row of `cirislens_derived.detection_events`.
///
/// Lens-core writes one of these per detector flag. Forensic join key
/// is `body_sha256`; reproducibility anchor is
/// `(lens_core_version, ratchet_calibration_version)`.
///
/// `cohort_cell` is the RATCHET-confirmed 6-tuple per CIRISLensCore
/// OQ-10 (2026-05-04): `agent_role`, `agent_template`,
/// `deployment_domain`, `deployment_type`, `deployment_region`,
/// `deployment_trust_mode`. Persist stores the JSONB opaquely;
/// schema enforcement is consumer-side.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectionEvent {
    /// Detection identifier (UUID v4).
    pub detection_id: uuid::Uuid,
    /// Trace this detection fired against.
    pub trace_id: String,
    /// SHA-256 of the original wire body. 32 bytes.
    pub body_sha256: Vec<u8>,
    /// Detector token (`"cohort_declared_inferred_mismatch"`,
    /// `"manifold_conformity_outlier"`, etc.).
    pub detector: String,
    /// Triage bucket.
    pub severity: DetectionSeverity,
    /// 6-tuple cohort cell; consumer-typed JSONB.
    pub cohort_cell: serde_json::Value,
    /// Manifold-conformity variant discriminant.
    pub conformity_variant: ConformityVariant,
    /// Variant-specific payload (consumer-typed JSONB).
    pub conformity_payload: serde_json::Value,
    /// Lens-core version that ran the scoring (LC-AV-19
    /// reproducibility).
    pub lens_core_version: String,
    /// Which `calibration_bundles.ratchet_calibration_version` was
    /// `is_current = TRUE` at score time.
    pub ratchet_calibration_version: i32,
    /// Canonical-JSON bytes that were signed.
    pub canonical_bytes: Vec<u8>,
    /// Ed25519 signature over `canonical_bytes`. 64 bytes.
    pub ed25519_sig: Vec<u8>,
    /// ML-DSA-65 signature over `canonical_bytes`. 3309 bytes
    /// (FIPS 204 final size; CIRISVerify#4 / CIRISPersist#8).
    pub ml_dsa_65_sig: Vec<u8>,
    /// Signing key id (resolves through `federation_keys`).
    pub signing_key_id: String,
    /// Wall-clock when persist accepted the row.
    pub ts: DateTime<Utc>,
}

/// Filter struct for [`crate::derived::DerivedSchema::get_detection_events`].
///
/// All fields are optional; an empty filter returns the full table
/// (subject to whatever default LIMIT the backend applies).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EventFilter {
    /// Filter by `trace_id`. `None` returns all traces.
    pub trace_id: Option<String>,
    /// Filter by `detector` token. `None` returns all detectors.
    pub detector: Option<String>,
    /// Filter to `ts >= since`. `None` returns all timestamps.
    pub since: Option<DateTime<Utc>>,
}

/// Projection metadata captured at calibration time. Lens-core needs
/// these three things to deterministically reproduce RATCHET's
/// transformation at score time:
///
/// 1. `imputation` — fill-in values for null fields (5/16 corpus
///    fields are >40% null because they're conscience-gated).
/// 2. `standardization.{means,stds}` — per-feature mean/std for the
///    Mahalanobis-σ math.
/// 3. `retention_mask` — which fields to keep (`std < 1e-9` → drop).
///
/// `field_order` is verification-redundant with `projection_version`
/// (the version pins the canonical order); persist treats version as
/// authoritative on disagreement, but lens-core's startup load runs
/// the redundancy check.
///
/// Persist stores this as opaque JSONB; the type below is provided
/// for callers who want strict deserialization. The wire shape is
/// documented in CIRISPersist#18.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProjectionMetadata {
    /// Field-order pinned by `projection_version` (verification-
    /// redundant; lens-core checks at startup).
    pub field_order: Vec<String>,
    /// Per-field corpus-mean fill-in for nulls. Keyed by field name.
    pub imputation: std::collections::BTreeMap<String, f64>,
    /// Per-feature mean + std for Mahalanobis math.
    pub standardization: Standardization,
    /// Per-feature retention flag; `std < 1e-9` → false. Length =
    /// `field_order.len()`.
    pub retention_mask: Vec<bool>,
}

/// Per-feature mean + std vectors, in `field_order` order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Standardization {
    /// Per-feature corpus mean.
    pub means: Vec<f64>,
    /// Per-feature corpus std.
    pub stds: Vec<f64>,
}

/// One cohort centroid in a calibration bundle.
///
/// `centroid` and `variance` are length D = `count(retention_mask ==
/// true)`. `variance` is per-feature scalar (length D), not full N×N
/// covariance — sufficient for σ-distance scoring at v0.1.0.
///
/// Cohort key is the 6-tuple per CIRISLensCore OQ-10
/// (RATCHET-confirmed 2026-05-04). `deployment_resourcing` is
/// lens-computed and lives outside the cohort key (resourcing handling
/// is lens-core-internal).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CohortCentroid {
    /// 6-tuple cohort key (same shape as
    /// [`DetectionEvent::cohort_cell`]).
    pub cohort: serde_json::Value,
    /// Per-feature centroid; length D.
    pub centroid: Vec<f64>,
    /// Per-feature variance; length D.
    pub variance: Vec<f64>,
    /// Number of corpus samples that fell in this cohort.
    pub sample_count: u64,
}

/// One row of `cirislens_derived.calibration_bundles`.
///
/// RATCHET writes one per calibration. `is_current = TRUE` denotes
/// the bundle lens-core is currently scoring against; the partial-
/// unique index `calibration_bundles_one_current` enforces "at most
/// one current bundle" at the DB level. The
/// [`crate::derived::DerivedSchema::put_calibration_bundle`] write path
/// flips `is_current` atomically (clear previous + insert new in a
/// single transaction).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CalibrationBundle {
    /// Monotonic version. Detection events stamp this.
    pub ratchet_calibration_version: i32,
    /// Pins the field-order + retention-mask contract (`"crc-v1"`).
    pub projection_version: String,
    /// Wall-clock at which RATCHET produced the bundle.
    pub calibrated_at: DateTime<Utc>,
    /// SHA-256 hex of the calibration corpus.
    pub calibration_corpus_sha256: String,
    /// Corpus row count.
    pub calibration_corpus_n: i32,
    /// Per-cohort sample-count gate at score time.
    pub sample_size_gate: i32,
    /// Mahalanobis-σ outlier threshold.
    pub manifold_threshold_global: f32,
    /// Projection metadata (see [`ProjectionMetadata`]).
    pub projection_metadata: serde_json::Value,
    /// Cohort centroids (see [`CohortCentroid`]).
    pub cohort_centroids: serde_json::Value,
    /// `TRUE` iff this bundle is the one lens-core currently scores
    /// against.
    pub is_current: bool,
    /// Canonical-JSON bytes that were signed.
    pub canonical_bytes: Vec<u8>,
    /// Ed25519 signature over `canonical_bytes`. 64 bytes.
    pub ed25519_sig: Vec<u8>,
    /// ML-DSA-65 signature over `canonical_bytes`. 3309 bytes.
    pub ml_dsa_65_sig: Vec<u8>,
    /// RATCHET steward identity in `federation_keys`.
    pub signing_key_id: String,
    /// Wall-clock when persist accepted the row.
    pub inserted_at: DateTime<Utc>,
}
