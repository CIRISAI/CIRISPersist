//! Curated re-exports for federation peers integrating with persist
//! at the Rust API layer (CIRISEdge, registry, partner sites).
//!
//! v0.4.1 (CIRISEdge ask): `use ciris_persist::prelude::*` covers
//! the common imports edge's verify + outbound pipelines need
//! without forcing the caller to know which sub-module each type
//! lives in.
//!
//! Curated, not exhaustive — only the substrate surface
//! consumers actually compose against. Internal types (e.g.,
//! `IngestPipeline`, `BatchSummary`) stay sub-module-imported by
//! the smaller set of consumers that need them.
//!
//! # Example
//!
//! ```ignore
//! use ciris_persist::prelude::*;
//!
//! async fn verify_inbound<F: FederationDirectory>(
//!     directory: &F,
//!     envelope: &serde_json::Value,
//!     signing_key_id: &str,
//!     ed25519_sig_b64: &str,
//!     ml_dsa_65_sig_b64: Option<&str>,
//! ) -> Result<VerifyOutcome, HybridVerifyError> {
//!     let canonical = canonicalize_envelope_for_signing(envelope)
//!         .map_err(|e| HybridVerifyError::Crypto(format!("{e}")))?;
//!     verify_hybrid_via_directory(
//!         directory,
//!         &canonical,
//!         signing_key_id,
//!         ed25519_sig_b64,
//!         ml_dsa_65_sig_b64,
//!         HybridPolicy::Strict,
//!         None,
//!     )
//!     .await
//! }
//! ```

// Trait surfaces consumers compose against. Federation peers
// implement against these, not concrete backend types.
pub use crate::derived::DerivedSchema;
pub use crate::federation::FederationDirectory;
pub use crate::outbound::OutboundQueue;
pub use crate::read::ReadEngine;
pub use crate::store::Backend;

// v4.0 CallerScope substrate (CIRISPersist#150, FSD §4). The read-side
// cohort_scope admission primitive: scope variant, substrate-built
// admission set + its sole builder, the §4.3 SQL predicate emitter, and
// the structured refusal reason Commit E folds into the read `Error`.
pub use crate::scope::{build_caller_admission, CallerAdmission, CallerScope, ScopeRefusalReason};

// Federation read primitive types (v0.5.0, CIRISPersist#23).
// Sections A/B/F/E ship in v0.5.0 — trace listing, trace detail,
// Coherence Ratchet inputs, scoring factor aggregates. Sections
// C/D/G/H/I land in v0.5.1 after lens validates the v0.5.0 batch.
pub use crate::read::{
    AuditChainAggregate, CoherencePoint, DeviationMetric, DivergenceRow, HashChainGap,
    OverrideRateRow, RecoveryEvent, ScoringFactorAggregate, TemporalDriftRow, TimeWindow,
    TraceComponentRow, TraceCursor, TraceDetail, TraceEnvelopeRefs, TraceFilter, TraceListPage,
    TraceSummary,
};

// Lens-derived schema types (v0.4.3, CIRISPersist#18). Lens-core
// writes detection events; RATCHET writes calibration bundles; both
// flow through Engine.put_* (PyO3) or DerivedSchema impls (rlib).
pub use crate::derived::{
    CalibrationBundle, CohortCentroid, ConformityVariant, DetectionEvent, DetectionSeverity,
    EventFilter, ProjectionMetadata, Standardization,
};

// Local signing surface (v0.4.2, CIRISPersist#17). Federation
// peers signing as their deployment's local identity construct
// `LocalSigner` from filesystem seeds and call `sign_ed25519` /
// `sign_ml_dsa_65` / `sign_hybrid`.
pub use crate::signing::{LocalSigner, LocalSignerConfig, LocalSignerError};

// Verify primitives. The full surface edge needs to compose a
// verify pipeline against persist instead of rebuilding it.
pub use crate::verify::{
    body_sha256, canonical_payload_value, canonicalize_envelope_for_signing, verify_hybrid,
    verify_hybrid_via_directory, verify_trace, verify_trace_via_directory, Canonicalizer,
    HybridPolicy, HybridVerifyError, PublicKeyDirectory, PythonJsonDumpsCanonicalizer,
    VerifyOutcome,
};

// Outbound queue types — federation peers building dispatcher
// loops compose against these.
pub use crate::outbound::{
    AbandonedReason, OutboundFailureOutcome, OutboundFilter, OutboundRow, OutboundStatus, QueueId,
};

// Federation directory types — consumers verifying SignedKeyRecord /
// SignedAttestation / SignedRevocation envelopes need the wire
// shapes.
pub use crate::federation::{
    Attestation, HybridPendingRow, KeyRecord, Revocation, SignedAttestation, SignedKeyRecord,
    SignedRevocation,
};

// Atomic-claim primitive (v1.0.0; CIRISAgent#756 concern #2). Returned
// by SecretsService::try_claim_secret + AuditService::try_claim_event;
// federation peers calling either path need the typed outcome enum.
pub use crate::ClaimResult;

// v1.1.0 (CIRISPersist#33 part 4b) — federated HTTP client for the
// secrets API. Mirrors the SecretsService trait surface so consumer
// code can swap in-process ↔ federated transparently.
#[cfg(feature = "secrets-client")]
pub use crate::secrets::FederatedSecretsClient;

// v1.1.0 (CIRISPersist#33) — generic pipeline substrate trait +
// inline-text envelope + match address. Consumers wiring outbound
// SPEAK / LLM-prompt / WBD / DSAR pipelines compose against these.
pub use crate::pipeline::{InlineTextEnvelope, MatchAddress, WireEnvelope};

// v1.1.0 (CIRISPersist#43) — Rust-side substrate composition handle
// + SQLite-only direct constructors for sovereign-mode Reticulum
// agents and in-process lens-core consumers.
pub use crate::engine::{BackendDispatch, Engine, EngineError};
#[cfg(feature = "sqlite")]
pub use crate::federation::FederationDirectorySqlite;
#[cfg(feature = "sqlite")]
pub use crate::outbound::EdgeOutboundQueueSqlite;
