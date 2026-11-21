//! v62.0.0 (JSON-cut slice F, F0-cp7; RULINGS "composite signatures only,
//! no standalone component signers") — **the bound-hybrid verify family is
//! DELETED.** `verify_hybrid`, `verify_hybrid_via_directory`,
//! `verify_hybrid_with_policy`, `require_strict_policy` and the
//! `VerifyError` / `VERIFY_POLICY_VIOLATION` vocabulary went with it: each
//! checked an Ed25519 half and an ML-DSA-65 half (the ML-DSA half over
//! `msg ‖ ed25519_sig`) against a key's registered component halves, which a
//! v62 node never does. A signature is ONE composite under a live edition-2
//! key (`federation::edition2::composite_verify`), or a CC 6.1 composite over
//! its own preimage (`verify::sig19`). A door that still receives the earlier
//! pair refuses it by name (`federation::edition2::door::earlier_form_signature`).
//!
//! What remains is the one data type the retired capsule result
//! (`DirectoryOpResult::HybridVerify`) still names in its append-only wire
//! shape, [`VerifyOutcome`]. Nothing verifies with it. The earlier
//! `HybridPolicy` type is deleted (v62.0.0, CL-fix1); the name below is only
//! an alias of the capsule's wire-only stand-in, so the retired op's `policy`
//! member keeps its exact ABI-14 shape.
//! `scripts/earlier_form_doors.py` fails if a bound-hybrid verifier returns.

use std::time::Duration;

/// v62.0.0 (CL-fix1) — wire shape of a retired op; never evaluated. An alias
/// of [`crate::ffi::directory_capsule::RetiredHybridPolicy`], kept at this
/// path so `DirectoryOp::VerifyHybridViaDirectory`'s pinned field text is
/// unchanged. No verify reads it.
pub use crate::ffi::directory_capsule::RetiredHybridPolicy as HybridPolicy;

/// Outcome of a successful `verify_hybrid` call. Distinguishes
/// hybrid-verified (both signatures passed) from Ed25519-only
/// (PQC absent, accepted by policy).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum VerifyOutcome {
    /// Both Ed25519 and ML-DSA-65 signatures verified.
    HybridVerified,
    /// Only Ed25519 verified — `ml_dsa_65_sig` was `None` and policy
    /// is `SoftFreshness` with `row_age < window`. The `row_age` is
    /// echoed back so the caller can log/audit which window matched.
    Ed25519VerifiedHybridPending {
        /// Age of the row at the time of verification, as passed by
        /// the caller. `None` if the caller didn't supply row_age.
        row_age: Option<Duration>,
    },
    /// Only Ed25519 verified — `ml_dsa_65_sig` was `None` and policy
    /// is `Ed25519Fallback`. Distinct from
    /// `Ed25519VerifiedHybridPending` so audit logs can tell whether
    /// the acceptance was bounded-soft or always-soft.
    Ed25519VerifiedFallback,
}
