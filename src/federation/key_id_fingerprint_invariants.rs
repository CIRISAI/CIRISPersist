//! v62.0.0 (JSON-cut slice E4) — **I1153 retired.** The earlier form's rule
//! that a key id ends in `-<fp>` of its own Ed25519 key (CC 2.6.8 rc9,
//! `key_id_fingerprint_mismatch`) has no edition-2 counterpart: an edition-2
//! key is named by its identity-ref, which the door computes from the key
//! itself (`edition2::kid`), so there is no chosen id left to check. Its
//! witnesses asserted earlier-form behaviour and were deleted, not rewritten
//! (the contract's rule for fingerprint tests). The module stays empty so the
//! `mod` line in `federation/mod.rs` needs no foreign hunk; the F slice
//! removes both.
