//! v62.0.0 (slice E2a, CIRISPersist#1274; CC rc20 `0c9e17c`, "nothing
//! carries, clean mesh") — **the edition-2 wire.**
//!
//! A row of this edition is one or more `COSE_Sign1` statements over one
//! deterministically encoded payload, signed with the composite ML-DSA-65 +
//! Ed25519 (CC 2.6.1, 2.6.1.7). Persist reads it with CIRISVerify 23.3.0's
//! edition-2 reader and family matcher ([`ciris_verify_core::edition2`]); it
//! does not re-implement either. What persist adds is the door around them:
//!
//! | piece | module |
//! |---|---|
//! | the door: input form, Verify's verdict, family rules, edition-1 row-refs, the node-computed row id | [`door`] |
//! | the row id and what a row names, for the kernel adapter (`Row::names()`) | [`names`] |
//! | key liveness, only from edition-2 `key:record`s, ended only by the three revokers | [`liveness`] |
//! | the genesis bundle's generic parts (object verify, object id, version / prev, every holder) | [`genesis`] |
//! | the statement store's shape (the E2b baseline's `ceg_statements`, `ceg_row_names`) | [`store`] |
//! | one rule set, two codecs: the statement mapped onto persist's typed row and its gates | [`ingest`] |
//! | the read models: an edition-2 key and its honoured revocations projected into `federation_keys` / `federation_revocations`; the cross-form refusal | [`projection`] |
//! | producing: an edition-2 row or object signed with persist's own composite signer | [`produce`] |
//! | the accord's halt and invocation door over Verify's halt reader (one holder's statement latches; dedup by invocation_id / nonce) | [`halt`] |
//! | the payload members of each mapped family (the source of `docs/EDITION2_PAYLOADS.md`) | [`payloads`] |
//! | the group planes: a `group:roster` version and a counted membership change judged by the typed group doors, counted over every voice (v62.0.0, wave T1) | [`group`] |
//! | a recovery key refused as a signer by its key material (CC 4.2.6) | [`recovery_signer`] |
//! | the `identity:occurrence` bind (two voices, the typed occurrence table) and the key-of-issuer check's occurrence arm | [`occurrence`] |
//! | the remaining families with a typed table (occurrence revocation, revocation, takedown notice, custody report, key grant, delivery receipt, cosign state) landed through the JSON form's own door, counted voices included (v62.0.0, wave T2) | [`typed`] |
//! | a seat's transit key moved only by a counted `transport:canonical_rebind` of the bundle's holders (v62.0.0, wave W1) | [`transport_rebind`] |
//! | a trust-root community counted over the genesis bundle in force: holders as founders, the birth's count, a founders' link's voices (v62.0.0, wave W1) | [`trust_root_group`] |
//!
//! **The rule this module keeps (CC 2.6.1.12).** A node of this form reads and
//! writes this form only. An object of the earlier form (CC 8.11, a JSON object
//! signed over its JCS image) offered at an edition-2 door is refused by name
//! ([`token::EARLIER_FORM_OBJECT`]), never parsed for standing; a `row-ref` of
//! edition 1 is refused by name ([`token::ROW_REF_EDITION_1`]). A row is
//! stored under the row id THIS node computes from the bytes, never under an
//! id a peer offers ([`token::ROW_ID_MISMATCH`]).

// v62.0.0 (F0-cp5) — the one directory-backed composite verifier.
/// v62.0.0 (C5-fix3) — the one composite key / signature half split.
pub mod composite;
pub mod composite_verify;
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod composite_verify_invariants;
pub mod door;
pub mod emit;
#[cfg(any(test, feature = "test-anchor"))]
pub mod fixture_genesis;
#[cfg(any(test, feature = "test-anchor"))]
pub mod fixture_genesis_custody;
// v62.0.0 (C4-fix, ceremony gap 3) — the REAL July holders' YubiKey PIV
// custody evidence (public certificates and keys), for I2390–I2393.
#[cfg(test)]
pub(crate) mod fixture_genesis_real_custody;
#[cfg(any(test, feature = "test-anchor"))]
pub mod fixture_occurrence;
#[cfg(any(test, feature = "test-anchor"))]
pub mod fixture_switch;
pub mod fold;
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod fold_invariants;
// v62.0.0 (wave GC3; CC 2.7.3) — witnesses of GC3's fold conversions.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod gc3_fold_invariants;
// v62.0.0 (wave GC4) — the GC4 conversions' witnesses (I3792–I3795).
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod fold_gc4_invariants;
// v62.0.0 (wave GC1; CC 2.7.3) — the admission.rs gates' folds (I3670-I3675).
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod admission_fold_invariants;
// v62.0.0 (wave GC8) — the CC 2.7 conversion's witnesses (I3950–I3960).
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod fold_gc8_invariants;
// v62.0.0 (wave W1b) — a ROOTED edition-2 trust root, for any test.
#[cfg(any(test, feature = "test-anchor"))]
pub mod fixture_trust_root;
pub mod genesis;
pub mod group;
#[cfg(any(test, feature = "test-anchor"))]
pub mod group_fixtures;
pub mod group_serve;
pub mod halt;
pub mod ingest;
pub mod liveness;
pub mod names;
pub mod occurrence;
pub mod payloads;
pub mod produce;
pub mod projection;
pub mod recovery_signer;
// v62.0.0 (P10; CC rc21 2.7.11) — SCITT receipts (RFC 9942, label 394) held
// with their statements; the receipt leg of running admitted code.
pub mod receipts;
// v62.0.0 (v62 P8-fix5; CC 2.6.1.9, 2.7.3, 4.4.3.19) — a second signer's
// voice over a held row, in any role K2's resolver names: list (by the
// awaited key), draft, voice, submit, outcome.
pub mod second_signer_voice;
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod second_signer_voice_invariants;
pub mod serve;
pub mod standing;
pub mod store;
// v62.0.0 (F0-cp6) — the CC 6.1.3 substrate planes and their one predicate.
pub mod substrate;
pub mod transport_rebind;
pub mod trust_root_group;
pub mod typed;
#[cfg(any(test, feature = "test-anchor"))]
pub mod typed_fixtures;
pub mod voices;
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod voices_invariants;

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod composer_invariants;
#[cfg(test)]
mod door_invariants;
// v62.0.0 (wave P1e) — I2925: the emit side states every family digest
// member (needs edition2::payloads, so it lands at syn1 with P1e.patch).
#[cfg(test)]
mod doors_shut_invariants;
#[cfg(test)]
mod earlier_form_refusal_invariants;
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod emit_digest_invariants;
#[cfg(test)]
mod fixture_genesis_invariants;
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod gc5_fold_invariants;
#[cfg(test)]
mod genesis_invariants;
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod genesis_store_invariants;
#[cfg(test)]
mod group_codec_invariants;
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod group_invariants;
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod group_serve_invariants;
#[cfg(test)]
mod halt_invariants;
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod halt_lifecycle_invariants;
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod ingest_invariants;
#[cfg(test)]
mod open_legacy_invariants;
// v62.0.0 (CC 2.7, wave P9) — I3600, I3601, I3603: a wait is a wait on every
// surface.
#[cfg(test)]
mod key_chain_invariants;
#[cfg(test)]
mod liveness_invariants;
#[cfg(test)]
mod occurrence_invariants;
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod occurrence_node_bearing_invariants;
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod occurrence_roster_invariants;
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod occurrence_route_invariants;
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod occurrence_tx_invariants;
#[cfg(test)]
mod payloads_invariants;
#[cfg(test)]
mod produce_invariants;
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod wait_invariants;
// v62.0.0 (K2-fix4) — I2845–I2846: the generic second-signer hold (CC 2.7.3).
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod second_signer_invariants;
// v62.0.0 (wave P1c) — I2914: the door's pure gates precede its first
// directory read (AV-76), on sqlite and postgres.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod pure_gates_invariants;
// v62.0.0 (wave P1c) — I2915: the mapping fills the typed `weight` column.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod producer_invariants;
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod weight_column_invariants;
// v62.0.0 (v62 P3) — I3055/I3056: the hard_case producer, two nodes.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod hard_case_producer_invariants;
// v62.0.0 (v62 P8) — I3520–I3532: the crossing, the widening and the
// occurrence producer state edition 2; a second node admits it.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod crossing_producer_invariants;
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod projection_invariants;
// v62.0.0 (ceremony gap 2, C3) — I2368–I2372: the edition-2 re-bind read,
// its capsule op and the X-Wing transit pair, on sqlite and postgres.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod rebind_held_invariants;
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod recovery_signer_invariants;
// v62.0.0 (JSON-cut slice F) — I2874–I2876: an edition-2 holder recovery,
// the old key's halt it voids, and the earlier-form recovery refused.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod recovery_halt_invariants;
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod standing_invariants;
#[cfg(test)]
mod verify_vectors_replay;
// v62.0.0 (wave T2) — I3140–I3149: the typed planes' mapping, pure.
#[cfg(test)]
mod typed_codec_invariants;
// v62.0.0 (wave T2) — I3150–I3169: the typed planes at the door, on sqlite
// and postgres.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod typed_invariants;
// v62.0.0 (wave T2, on W1b's rooted trust root) — I3182–I3184: a steward
// purge executed from its founders' voices and replicated to a second node.
// Needs `fixture_trust_root` (W1b).
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod typed_purge_rooted_invariants;
// v62.0.0 (v62 P8) — I3530: an external edition-2 holding claim (the door
// Python's `put_blob` calls) admitted on a second node.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod external_claim_invariants;
// v62.0.0 (v62 P8) — I3535–I3537: the detection producer on edition 2.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod detection_producer_invariants;
// v62.0.0 (v62 P8) — I3546–I3547: the erasure withdraws as the producer's
// edition-2 statement; the CC 2.4.1.1 carve-out kept.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod erasure_producer_invariants;
// v62.0.0 (kernel pass 2, K1) — I2819–I2820: the half-open window and
// `valid_until_not_after_asserted_at`, on sqlite and postgres.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod window_invariants;
// v62.0.0 (P10; CC rc21 2.7.11) — I4040–I4057: receipts outside the row id,
// merged and served, and the receipt leg, on sqlite and postgres.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod receipts_invariants;

pub use ciris_verify_core::edition2::Digest32;

/// The refusal tokens of the edition-2 door. Each is a
/// [`super::malformed_row`] reason, so a refusal is the typed, terminal
/// `federation_malformed_row` (Python `ValueError`) with this reason; a
/// statement that waits on a key is the retryable
/// `federation_attester_key_unknown` instead.
pub mod token {
    pub use super::super::malformed_row::{
        EDITION2_EARLIER_FORM_OBJECT as EARLIER_FORM_OBJECT,
        EDITION2_FAMILY_INVALID as FAMILY_INVALID, EDITION2_NOT_A_ROW as NOT_A_ROW,
        EDITION2_ROW_ID_MISMATCH as ROW_ID_MISMATCH,
        EDITION2_ROW_REF_EDITION_1 as ROW_REF_EDITION_1,
        EDITION2_STATEMENT_INVALID as STATEMENT_INVALID, KEY_RECORD_OUT_OF_WINDOW, KID_NOT_OF_ISS,
    };
}
