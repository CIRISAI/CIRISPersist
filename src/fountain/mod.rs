//! Fountain-coded content primitive — the store-and-evict half
//! (CIRISPersist#227, v8.0.0).
//!
//! The `FountainContentV1` contract (RATIFIED + LOCKED on
//! CIRISPersist#227 / CIRISEdge#133) promotes the **envelope / payload
//! split** to a substrate boundary: any corpus (traces, blobs, AV
//! chunks, attestation evidence, …) can opt in by handing persist a
//! small, signed, always-retained **manifest** plus N+K opaque fountain
//! **symbols**. persist owns store/evict/read; the edge/consumer codec
//! owns reconstruction. **persist links ZERO codec crates** (no
//! raptorq/rav1e/dav1d/opus) — the symbol bytes are opaque.
//!
//! # The law: any *payload*, never the *envelope*
//! The manifest (`content_manifest`) is NEVER evicted — it carries the
//! #225 hybrid signature that is the always-retained Layer-1 provenance
//! ("existed with signature X"). Only the `content_symbols` rows
//! disk-pressure / consent-decay evict. Graceful degradation must never
//! become graceful *corruption* of state a decision depends on.
//!
//! # Two orthogonal eviction triggers
//! 1. **DiskPressure** (#149) — [`FountainTier::from_pressure`] maps the
//!    free-bytes tier to a keep-count.
//! 2. **Consent decay** — the per-`content_id` consent clock in [`decay`]
//!    drives the tier down as content ages past its consent stream's
//!    window (TEMPORARY 14-day, pattern 90-day), **independent of disk**.
//!    It reuses the SAME eviction MECHANISM
//!    ([`crate::store::Backend::evict_fountain_content_to_tier`]); the
//!    scheduling is driven by
//!    [`crate::Engine::sweep_consent_decay_once`]. See [`decay`] for the
//!    spec-pinned-vs-default schedule breakdown.
//!
//! # Modules
//! - [`types`] — the LOCKED `FountainContentV1` structs + the typed
//!   degraded-read enum + the read-class boundary.
//! - [`admit`] — the verify-before-mutation admission gate (#225 hybrid
//!   verify on the manifest + per-symbol SHA-256 auth).
//! - [`eviction`] — the tier × keep-count policy + the #149 mapping.
//! - [`aggregation`] — §19.7 inter-object aggregation (operator 2): the
//!   forever-memory pyramid metadata persist records for a composite
//!   (opaque `aggregation_meta` + navigation scalars) + the internal
//!   noise-floor `EjectionVerdict` framing. v8.3.0 (CIRISPersist#230).

pub mod admit;
pub mod aggregation;
pub mod decay;
pub mod eviction;
pub mod retention;
pub mod storage_contention;
pub mod types;

pub use admit::{
    check_admission, check_admission_via_envelope, symbol_sha256_hex, FountainAdmitError,
};
pub use aggregation::{
    aggregate_corpus_kind, aggregation_member_commitment_from_hex,
    descend_aggregated_sources_on_backend, descend_order, ejection_verdict,
    evict_aggregated_tier_on_backend, member_commitment, verify_aggregation_meta,
    verify_member_commitment, AggregationMetaError, AggregationMetaV1, AggregationMetaVerification,
    AggregationMetaVerifyInputsV1, AggregationRecordV1, EjectionAction, EjectionVerdict,
    AGGREGATE_CORPUS_PREFIX,
};
pub use decay::{
    consent_decay_class_from_envelope, consent_decay_target_tier, ConsentDecayClass,
    ConsentDecaySweepReport, FountainDecayCandidate, DECAY_FRACTION_T2, DECAY_FRACTION_T3,
    DECAY_FRACTION_T4, DECAY_FRACTION_T5, PATTERN_DECAY_DAYS, TEMPORARY_DECAY_DAYS,
};
pub use eviction::FountainTier;
pub use retention::{
    holding_claim_counts, map_consent_state, resolve_retention_action, RetentionAction,
};
pub use types::{
    cohort_scope_from_envelope, FountainContent, FountainHeldMeta, FountainManifestV1,
    FountainReadClass, FountainSymbolV1, MANIFEST_VERSION_V1,
};
