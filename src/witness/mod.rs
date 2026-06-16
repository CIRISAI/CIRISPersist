//! §19.1 WholenessWitness corpus + verify-before-persist gate +
//! WW→quorum-merge subordination (CEG 1.0-RC11 §19; CIRISPersist#228
//! items 1–2 / #229 item 1).
//!
//! persist is the §19 **store + the WW-2 leaf-walk owner + the
//! divergence→§10.1.6 router**. The holonomic verifiers themselves
//! (Merkle construction, the PQC bound-hybrid gate, the equivocation
//! classifier) are frozen + cross-impl-proven in
//! `ciris_verify_core::holonomic` (CIRISVerify v5.9.0); persist CALLS
//! them and never re-rolls Merkle / preimage / signature logic.
//!
//! # The three persist-owned guards
//! 1. **Verify-before-persist (N3 / RC8).** A witness is hybrid-PQC
//!    verified at the ingest gate BEFORE any row is durable
//!    ([`admit`]). A missing/invalid ML-DSA-65 half is a hard cut
//!    ([`WitnessAdmitError::HybridRequired`]); store-then-quarantine is
//!    non-conformant.
//! 2. **WW-2 leaf filter.** persist owns "gather all CEG envelopes a
//!    peer holds" → it filters out anonymous-tier + `cohort_scope: self`
//!    rows BEFORE computing the root ([`build_local_witness`]). A naive
//!    sweep would re-attribute deniable/self-private content to a stable
//!    peer_id.
//! 3. **WW→quorum-merge subordination + anti-rollback** ([`compare`]).
//!    A `Divergent` verdict TRIGGERS the EXISTING V058 §10.1.6
//!    quorum-merge; the witness never decides it (no "reconstitute from
//!    any fragment" → no revoked-key resurrection). An `Equivocation` is
//!    retained + surfaced as a `hard_case:*`, never reconciled. A stale
//!    per-peer `epoch_id` is rejected (eclipse guard).
//!
//! The corpus storage surface (last-K per peer, V085) lives on
//! [`FederationDirectory`](crate::federation::FederationDirectory) —
//! a federation-tier object, alongside `record_hard_case`.
//!
//! NOTE (out of persist's scope, edge-owned — CIRISEdge#144):
//! `SignedRelayCapacity` / `verify_relay_capacity` (N8) and the
//! recursive-bootstrap `SignedClaim` / `recursive_trust_bootstrap` gates
//! are EDGE topology-scoring / admission surfaces, NOT persist ingest —
//! deliberately not wired here. The §19.7 inter-object aggregation
//! pyramid is a follow-on (CIRISPersist#230).

pub mod admit;
pub mod compare;
pub mod types;

pub use admit::{
    admit_witness, build_local_witness, filter_witness_leaves, surviving_namespaces,
    WitnessAdmitError,
};
pub use compare::{
    accept_if_monotonic, classify, classify_stored, equivocation_hard_case, WitnessReconcileAction,
    QUORUM_MERGE_SUBJECT_KINDS, WITNESS_EQUIVOCATION,
};
pub use types::{
    decode_root_hex, encode_root_hex, StoredWitness, WitnessLeaf, WITNESS_CORPUS_K,
    WITNESS_VERSION_V1,
};
