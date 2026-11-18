//! v62.0.0 (JSON-cut slice E4) — **I616–I621 retired.** The `InvalidReplaced`
//! arm (CIRISPersist#1044) repaired an earlier-form key row that was stored
//! without passing `verify_key_registration` (its hybrid scrub signatures
//! over other bytes) by an incoming record with the same pubkeys and claim,
//! and the #864 `rebind_key_record` door that ran the same plan. Both exist
//! only for the earlier form: an edition-2 key is live only through a
//! `key:record` statement that the door verifies before it is held, so no
//! unverified key row can be stored for the arm to replace. The witnesses
//! asserted earlier-form behaviour and were deleted, not rewritten. The
//! module stays empty so the `mod` line in `federation/mod.rs` needs no
//! foreign hunk; the F slice removes both.
