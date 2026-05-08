//! Lens-derived schemas — substrate side of CIRISLensCore Phase 1
//! (v0.4.3, CIRISPersist#18).
//!
//! # Mission alignment (MISSION.md §2 — `derived/`)
//!
//! Persist holds the substrate; consumers compose policy. This module
//! defines the [`DerivedSchema`] trait — CRUD over two tables in the
//! `cirislens_derived` schema:
//!
//! - `cirislens_derived.detection_events` — one row per lens-core
//!   detector flag (LC-AV-2 cohort/declared-inferred mismatch P0;
//!   LC-AV-11 manifold-conformity outlier; LC-AV-18 reasoning-collapse;
//!   future ratchet detectors).
//! - `cirislens_derived.calibration_bundles` — one row per RATCHET
//!   calibration; lens-core reads `is_current = TRUE` at startup +
//!   on a config-driven refresh interval.
//!
//! Both record kinds are **federation evidence** carrying hybrid
//! (Ed25519 + ML-DSA-65) signatures. The trait does NOT verify
//! signatures itself — that responsibility belongs to the
//! [`Engine`] PyO3 surface, which calls
//! [`crate::verify::verify_hybrid_via_directory`] under
//! [`crate::verify::HybridPolicy::Strict`] before invoking the
//! backend put. (CIRISPersist#14 closure-pattern; the trait is the
//! storage primitive, the verify call is the policy layer.)
//!
//! Backends (postgres, sqlite, memory) implement the trait in
//! [`crate::store`]. Phase-1 sqlite + memory backends return
//! [`Error::NotImplemented`] for the put paths — sovereign-mode
//! deployments without lens-core / RATCHET don't need the substrate.
//!
//! ## Why a separate schema (vs `cirislens.*`)
//!
//! `cirislens.*` holds rows derived directly from agent-emitted wire
//! bytes (`trace_events`, `trace_llm_calls`, `accord_public_keys` /
//! `federation_keys`). `cirislens_derived.*` holds rows produced by
//! federation peers AFTER trace ingest — lens-core scores traces,
//! RATCHET calibrates against corpora. Different write authority,
//! different access surface, different retention policy. Schema
//! separation lets `cirislens_reader` grants stay crisp
//! (`cirislens_reader` for raw, `cirislens_derived_reader` for
//! scored).

use std::future::Future;

pub mod types;

pub use types::{
    CalibrationBundle, CohortCentroid, ConformityVariant, DetectionEvent, DetectionSeverity,
    EventFilter, ProjectionMetadata, Standardization,
};

/// Lens-derived schema CRUD trait — substrate-layer storage for
/// detection events + calibration bundles.
///
/// Async surface uses Rust 1.75+ `async fn in trait` directly with
/// `Send` futures (matches [`crate::store::Backend`] convention).
///
/// # Verify boundary
///
/// The put paths (`put_detection_event`, `put_calibration_bundle`)
/// expect canonical bytes + hybrid signature already verified by the
/// caller. The [`Engine`] PyO3 surface does the verify;
/// implementations of this trait are storage-only. A backend that
/// receives a tampered or unverified row is allowed to assume the
/// caller has already failed the verify boundary, BUT the DB-level
/// CHECK constraints (signature length, body_sha256 length, etc.)
/// catch shape-violations independently.
pub trait DerivedSchema: Send + Sync {
    // ── detection_events ──────────────────────────────────────────

    /// Insert a [`DetectionEvent`]. Idempotent on `detection_id`
    /// collision with matching content (no-op); errors on collision
    /// with differing content.
    ///
    /// Caller MUST have already verified the hybrid signature. The
    /// [`Engine`] PyO3 surface enforces this; the storage trait does
    /// not re-verify.
    fn put_detection_event(
        &self,
        event: DetectionEvent,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Page-style lookup over `detection_events`. Filter is `AND`-ed
    /// across set fields; an empty filter returns up to the backend's
    /// default LIMIT.
    fn get_detection_events(
        &self,
        filter: EventFilter,
    ) -> impl Future<Output = Result<Vec<DetectionEvent>, Error>> + Send;

    // ── calibration_bundles ──────────────────────────────────────

    /// Insert a [`CalibrationBundle`]. If `is_current = TRUE`, the
    /// backend MUST atomically clear `is_current` on the previous
    /// row and insert the new row in a single transaction (the
    /// partial-unique index `calibration_bundles_one_current`
    /// enforces "at most one current bundle"; concurrent writers
    /// without transactional flip would race).
    ///
    /// Caller MUST have already verified the hybrid signature under
    /// [`crate::verify::HybridPolicy::Strict`].
    fn put_calibration_bundle(
        &self,
        bundle: CalibrationBundle,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Return the bundle with `is_current = TRUE`, if any. Lens-core
    /// reads this at startup + on the config-driven refresh interval.
    fn get_current_calibration_bundle(
        &self,
    ) -> impl Future<Output = Result<Option<CalibrationBundle>, Error>> + Send;

    /// Return the bundle for a specific `ratchet_calibration_version`.
    /// Used for re-scoring detection events against the bundle that
    /// was current at score time (LC-AV-19 reproducibility).
    fn get_calibration_bundle_by_version(
        &self,
        version: i32,
    ) -> impl Future<Output = Result<Option<CalibrationBundle>, Error>> + Send;
}

/// Lens-derived schema errors. Distinct from [`crate::store::Error`]
/// (which covers trace ingest / lens schema concerns) and from
/// [`crate::federation::Error`] (which covers the public-key /
/// attestation surface) — the derived schemas have their own
/// failure surface for write validation.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Caller passed invalid arguments (bad UUID, malformed cohort
    /// cell JSON, signature length wrong on the wire, etc.).
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Row would conflict with an existing row whose content differs.
    /// Idempotent re-submission of the same content is OK; this
    /// fires only when the caller is overwriting.
    #[error("conflicts with existing row: {0}")]
    Conflict(String),

    /// `ratchet_calibration_version` foreign-key from
    /// `detection_events` does not match any
    /// `calibration_bundles` row. The detector tried to record a
    /// flag scored against a calibration that doesn't exist in the
    /// substrate.
    #[error("calibration version not found: {0}")]
    CalibrationVersionNotFound(i32),

    /// Backend-level error (DB connection, serialization, etc.).
    /// String-typed because each backend has its own error tree.
    #[error("backend: {0}")]
    Backend(String),

    /// Surface declared on the trait but the backend doesn't yet
    /// implement it. Memory and (Phase 1) sqlite backends return
    /// this for the put paths; sovereign-mode deployments without
    /// lens-core / RATCHET don't need the substrate.
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
}

impl Error {
    /// Stable string-token for telemetry / structured logging.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::InvalidArgument(_) => "derived_invalid_argument",
            Error::Conflict(_) => "derived_conflict",
            Error::CalibrationVersionNotFound(_) => "derived_calibration_version_not_found",
            Error::Backend(_) => "derived_backend",
            Error::NotImplemented(_) => "derived_not_implemented",
        }
    }
}
