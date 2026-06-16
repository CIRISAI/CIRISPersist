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
//! 2. **Consent decay** — the eviction MECHANISM is exposed as a
//!    callable ([`crate::store::Backend::evict_fountain_content_to_tier`]);
//!    the FULL Consensual-Evolution stream scheduling integration is an
//!    explicit **documented follow-on** (see CHANGELOG [8.0.0]) and is
//!    intentionally NOT built in this cut.
//!
//! # Modules
//! - [`types`] — the LOCKED `FountainContentV1` structs + the typed
//!   degraded-read enum + the read-class boundary.
//! - [`admit`] — the verify-before-mutation admission gate (#225 hybrid
//!   verify on the manifest + per-symbol SHA-256 auth).
//! - [`eviction`] — the tier × keep-count policy + the #149 mapping.

pub mod admit;
pub mod eviction;
pub mod retention;
pub mod types;

pub use admit::{
    check_admission, check_admission_via_envelope, symbol_sha256_hex, FountainAdmitError,
};
pub use eviction::FountainTier;
pub use retention::{
    holding_claim_counts, map_consent_state, resolve_retention_action, RetentionAction,
};
pub use types::{
    FountainContent, FountainManifestV1, FountainReadClass, FountainSymbolV1, MANIFEST_VERSION_V1,
};
