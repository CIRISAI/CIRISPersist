//! v62.0.0 (slice E2a, CIRISPersist#1274; CC rc20 `0c9e17c`, "nothing
//! carries, clean mesh") — **the edition-2 wire.**
//!
//! A row of this edition is one or more `COSE_Sign1` statements over one
//! deterministically encoded payload, signed with the composite ML-DSA-65 +
//! Ed25519 (CC 2.6.1, 2.6.1.7). Persist reads it with CIRISVerify 23.1.3's
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
//!
//! **The rule this module keeps (CC 2.6.1.12).** A node of this form reads and
//! writes this form only. An object of the earlier form (CC 8.11, a JSON object
//! signed over its JCS image) offered at an edition-2 door is refused by name
//! ([`token::EARLIER_FORM_OBJECT`]), never parsed for standing; a `row-ref` of
//! edition 1 is refused by name ([`token::ROW_REF_EDITION_1`]). A row is
//! stored under the row id THIS node computes from the bytes, never under an
//! id a peer offers ([`token::ROW_ID_MISMATCH`]).

pub mod door;
pub mod emit;
#[cfg(any(test, feature = "test-anchor"))]
pub mod fixture_switch;
pub mod genesis;
pub mod ingest;
pub mod liveness;
pub mod names;
pub mod produce;
pub mod projection;
pub mod store;

#[cfg(test)]
pub(crate) mod codec;
#[cfg(test)]
mod door_invariants;
#[cfg(test)]
mod genesis_invariants;
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod genesis_store_invariants;
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod ingest_invariants;
#[cfg(test)]
mod liveness_invariants;
#[cfg(test)]
mod produce_invariants;
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod producer_invariants;
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod projection_invariants;
#[cfg(test)]
mod verify_vectors_replay;

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
        EDITION2_STATEMENT_INVALID as STATEMENT_INVALID, KEY_RECORD_OUT_OF_WINDOW,
    };
}
