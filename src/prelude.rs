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
pub use crate::federation::FederationDirectory;
pub use crate::outbound::OutboundQueue;
pub use crate::store::Backend;

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
