//! The test-fixture codec switch and the test codec (slice E2a's switch, J0's
//! codec, made the suite's one fixture surface by the v62 fixture flip, E0).
//!
//! The JSON cut flips the suite's fixtures onto edition 2. This module is the
//! one place a fixture signs an edition-2 row:
//!
//! - **the switch** ([`emit_edition2`], default ON): the typed-row builders
//!   (`tier_ingest::test_support::seal_row` and every builder that seals
//!   through it, the key-record builders) read it. ON, a builder returns the
//!   edition-2 shape: the statement through the door
//!   ([`admit_row`](super::door::admit_row)) and the mapping
//!   ([`attestation_of`](super::ingest::attestation_of)). [`with_earlier_form`]
//!   turns it off on this thread until slice F deletes the earlier form.
//! - **keys and ids** ([`signing_key`], [`kid`], [`rid`]): the composite key a
//!   test seed names (the seed is the text's first 32 bytes over a `0x11`
//!   fill, both halves: the keys `tier_ingest::test_support::local_signer`
//!   signs with), its identity-ref, and a row's node-computed id.
//! - **the codec** ([`statement_of`], [`row_of`]): an earlier-form-shaped
//!   [`Attestation`] as an edition-2 statement and back. The inverse of
//!   `ingest::json_of` / `attestation_of`.
//! - **the key plane** ([`key_record`], [`key_row`]): a `key:record` that
//!   makes a key live, and its `federation_keys` read model.
//! - **store helpers** ([`put_key`], [`put_row`], [`put_signed`]): through the
//!   one statement entry, `ingest::put_statement`, so on every backend.
//!
//! [`FLIP`] lists every typed-row builder on disk (I1912 re-derives it); I2541
//! checks from disk that each one not in [`NOT_FLIPPED`] reaches the switch.
//!
//! This is test-only surface (`cfg(any(test, feature = "test-anchor"))`): it
//! signs with deterministic test keys and panics on a fixture mistake.

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::{self, Value};
use ciris_verify_core::edition2::family::{
    select::Act, FamilyModel as _, RuleAnswer, SelectContext, VendoredFamilyModel,
};
use ciris_verify_core::edition2::{
    cose_key, identity_ref, is_identity_ref, sign_row_statement, thumbprint, Digest32,
};
use ciris_verify_core::namespace_match;

use super::door::{admit_row, AdmittedRow};
use super::ingest::{
    attestation_of, StatementOutcome, COMPOSER_ROW_TYPES, INGEST_TIER, INSTANT_MEMBERS,
    REFERENCES_MEMBER, SCALED_MEMBERS, STATEMENT_MEMBER,
};
use super::liveness::{statement_parts, HeldKeys};
use super::names::RowId;
use super::payloads::{self, Ty};
use crate::federation::types::{attestation_type, Attestation, KeyRecord, SignedAttestation};
use crate::federation::{Error, FederationDirectory};

// ---------------------------------------------------------------------------
// 1. The switch
// ---------------------------------------------------------------------------

thread_local! {
    // v62.0.0 (E0) — default ON: the suite's fixtures emit edition 2.
    static EDITION2: Cell<bool> = const { Cell::new(true) };
}

tokio::task_local! {
    // v62.0.0 (E0) — the switch for one future and everything it polls
    // ([`with_earlier_form_async`] / [`with_edition2_async`]), on whichever
    // worker thread polls it. Read before the thread-local.
    static EDITION2_TASK: bool;
}

/// Should a fixture builder emit an edition-2 statement here? The scoped
/// task's switch when inside [`with_earlier_form_async`] /
/// [`with_edition2_async`], else this thread's. Default ON.
#[must_use]
pub fn emit_edition2() -> bool {
    if let Ok(on) = EDITION2_TASK.try_with(|v| *v) {
        return on;
    }
    EDITION2.with(Cell::get)
}

/// Run the future `f` with every builder and every flipped store helper it
/// polls emitting the EARLIER form (a task-local, so a multi-thread
/// runtime's workers are covered). A task `f` SPAWNS does not inherit it
/// (tokio task-locals do not cross `spawn`): wrap the spawned future too.
pub async fn with_earlier_form_async<F: std::future::Future>(f: F) -> F::Output {
    EDITION2_TASK.scope(false, f).await
}

/// [`with_earlier_form_async`]'s twin: the future emits edition 2 (inside an
/// earlier-form scope).
pub async fn with_edition2_async<F: std::future::Future>(f: F) -> F::Output {
    EDITION2_TASK.scope(true, f).await
}

fn with_switch<R>(on: bool, f: impl FnOnce() -> R) -> R {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            EDITION2.with(|c| c.set(self.0));
        }
    }
    let _restore = Restore(EDITION2.with(|c| c.replace(on)));
    f()
}

/// Run `f` with the fixture builders emitting edition 2 on this thread.
pub fn with_edition2<R>(f: impl FnOnce() -> R) -> R {
    with_switch(true, f)
}

/// Run `f` with the fixture builders emitting the EARLIER form on this
/// thread. For the witnesses that still drive an earlier-form door until
/// slice F shuts it (each one is a deletion candidate then).
pub fn with_earlier_form<R>(f: impl FnOnce() -> R) -> R {
    with_switch(false, f)
}

/// The typed-row builders on disk, as `file::function`: every `test_support`
/// function returning a typed row (`Attestation`, `SignedAttestation`,
/// `KeyRecord`, `SignedKeyRecord`, `SignedFamily`, `SignedCommunity`).
/// I1912 re-derives the list from disk, so a new builder that is not listed
/// is red. v62.0.0 (E0): the two zero-caller `*_widening_by_consensus`
/// builders are deleted (37 → 35).
pub const FLIP: &[&str] = &[
    "src/federation/bootstrap_admission.rs::consent_scope_row",
    "src/federation/bootstrap_admission.rs::consent_scope_row_superseding",
    "src/federation/bootstrap_admission.rs::consent_withdraws_row",
    "src/federation/bootstrap_admission.rs::scores_row",
    "src/federation/bootstrap_admission.rs::typed_family_row",
    "src/federation/consent_peer_set.rs::grant",
    "src/federation/membership_acceptance.rs::acceptance_row",
    "src/federation/membership_acceptance.rs::proposal_row",
    "src/federation/operational.rs::accord_conferred",
    "src/federation/operational.rs::co_signed_trust_attestation",
    "src/federation/operational.rs::signed_canonical_record",
    "src/federation/operational.rs::signed_canonical_record_with_roles",
    "src/federation/operational.rs::signed_trust_attestation",
    "src/federation/operational.rs::steward_key_record",
    "src/federation/register.rs::authority_signed_record",
    "src/federation/register.rs::self_scrubbed_record_signed_at",
    "src/federation/reverse_quorum.rs::signed_row",
    "src/federation/tier_ingest.rs::bare_attestation",
    "src/federation/tier_ingest.rs::community_naming_held",
    "src/federation/tier_ingest.rs::expired_key_record",
    "src/federation/tier_ingest.rs::family_naming_held",
    "src/federation/tier_ingest.rs::moderate_delegation_attestation",
    "src/federation/tier_ingest.rs::occurrence_withdrawal",
    "src/federation/tier_ingest.rs::owner_binding_attestation",
    "src/federation/tier_ingest.rs::replicated_key_record",
    "src/federation/tier_ingest.rs::replicated_key_record_with_expiry",
    "src/federation/tier_ingest.rs::seal_row",
    "src/federation/tier_ingest.rs::sign_community",
    "src/federation/tier_ingest.rs::sign_community_membership_revocation",
    "src/federation/tier_ingest.rs::sign_community_membership_widening",
    "src/federation/tier_ingest.rs::sign_family",
    "src/federation/tier_ingest.rs::sign_family_membership_revocation",
    "src/federation/tier_ingest.rs::sign_family_membership_widening",
    "src/federation/tier_ingest.rs::sign_family_revocation_by_consensus",
    "src/federation/tier_ingest.rs::sign_revocation_by_consensus",
];

/// The builders of [`FLIP`] that do NOT read the switch, each with why.
/// - the typed planes: no edition-2 projection onto `SignedFamily` /
///   `SignedCommunity` / the membership structs exists; their statements are
///   [`roster_statement`] / [`membership_statement`];
/// - `bare_attestation`: an unsigned skeleton, sealed (and so flipped) by its
///   caller.
pub const NOT_FLIPPED: &[&str] = &[
    "src/federation/tier_ingest.rs::bare_attestation",
    "src/federation/tier_ingest.rs::community_naming_held",
    "src/federation/tier_ingest.rs::family_naming_held",
    "src/federation/tier_ingest.rs::sign_community",
    "src/federation/tier_ingest.rs::sign_community_membership_revocation",
    "src/federation/tier_ingest.rs::sign_community_membership_widening",
    "src/federation/tier_ingest.rs::sign_family",
    "src/federation/tier_ingest.rs::sign_family_membership_revocation",
    "src/federation/tier_ingest.rs::sign_family_membership_widening",
    "src/federation/tier_ingest.rs::sign_family_revocation_by_consensus",
    "src/federation/tier_ingest.rs::sign_revocation_by_consensus",
];

// ---------------------------------------------------------------------------
// 2. Keys and ids
// ---------------------------------------------------------------------------

/// identity-ref → the seed text it was derived from (so a row whose
/// `attesting_key_id` is already a kid re-seals under the same key).
fn seeds() -> &'static Mutex<HashMap<String, String>> {
    static SEEDS: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    SEEDS.get_or_init(Default::default)
}

/// row id (hex) → its family: a composer names its target by id and carries
/// the target's family, so the codec remembers each row it minted.
fn row_families() -> &'static Mutex<HashMap<String, String>> {
    static FAMILIES: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    FAMILIES.get_or_init(Default::default)
}

fn key_of_seed_text(seed: &str) -> CompositeSigningKey {
    // Every identity-ref shares its first 32 bytes
    // (`urn:ietf:params:oauth:ckt:sha-25…`), and a test signer seeds from the
    // first 32 bytes: seeding from a kid would give EVERY key one keypair.
    assert!(
        !seed.starts_with("urn:"),
        "fixture_switch: seed a signer from the seed name, never from kid() ({seed})"
    );
    let s = crate::federation::tier_ingest::test_support::seed_for(seed);
    CompositeSigningKey::from_seeds(&s, &s)
}

/// The composite key a test seed names. An identity-ref this module derived
/// before resolves to the seed it came from.
///
/// # Panics
/// An identity-ref this process never derived (sign with the seed).
#[must_use]
pub fn signing_key(seed: &str) -> CompositeSigningKey {
    if is_identity_ref(seed) {
        let known = seeds().lock().expect("seed map").get(seed).cloned();
        let Some(text) = known else {
            assert!(
                !is_foreign_kid(seed),
                "fixture_switch: {seed} is a key no seed names (put_key_for_composite / \
                 put_key_for_signer): sign its rows with statement_of_with_key or its signer"
            );
            panic!(
                "fixture_switch: {seed} is an identity-ref no fixture derived; sign with the seed \
                 text it was derived from"
            )
        };
        return key_of_seed_text(&text);
    }
    let k = key_of_seed_text(seed);
    let iref = identity_ref(&thumbprint(k.public_key()));
    seeds()
        .lock()
        .expect("seed map")
        .entry(iref)
        .or_insert_with(|| seed.to_owned());
    k
}

/// The identity-ref of [`signing_key`]`(seed)`: what persist stores and
/// compares as an edition-2 key id. An identity-ref is returned unchanged.
#[must_use]
pub fn kid(seed: &str) -> String {
    if is_identity_ref(seed) {
        return seed.to_owned();
    }
    // Cached: a kid is asked for far more often than a key signs, and an
    // ML-DSA-65 key generation per call is the cost.
    static KIDS: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    let kids = KIDS.get_or_init(Default::default);
    let cached = kids.lock().expect("kid cache").get(seed).cloned();
    if let Some(k) = cached {
        return k;
    }
    let k = identity_ref(&thumbprint(signing_key(seed).public_key()));
    kids.lock()
        .expect("kid cache")
        .insert(seed.to_owned(), k.clone());
    k
}

/// The thumbprint (the COSE `kid`) of [`signing_key`]`(seed)`.
#[must_use]
pub fn kid_digest(seed: &str) -> Digest32 {
    thumbprint(signing_key(seed).public_key())
}

/// Is `s` already an identity-ref?
#[must_use]
pub fn is_kid(s: &str) -> bool {
    is_identity_ref(s)
}

/// Text that names no key and is kept as it is by [`kid_or_keep`]: a 64-hex
/// row id or digest, and a canonical-hash subject (`sha256:<hex>`,
/// `canonical:sha256:<hex>`; CC 4.2.2).
fn is_not_a_key(s: &str) -> bool {
    is_hex64(s) || s.starts_with("sha256:") || s.starts_with("canonical:")
}

/// An identity-ref unchanged; a subject that names no key (a 64-hex id or
/// digest, `sha256:…`, `canonical:…`) unchanged; any other text is a seed,
/// and its [`kid`]. What the codec applies to `attested_key_id`,
/// `subject_key_ids` and identity-ref members.
#[must_use]
pub fn kid_or_keep(s: &str) -> String {
    if is_not_a_key(s) {
        s.to_owned()
    } else {
        kid(s)
    }
}

/// The seed text a minted identity-ref was derived from; any other text is
/// returned unchanged (it is a seed already). `seed_of(&kid(x)) == x` for
/// every `x` this process derived a kid from.
#[must_use]
pub fn seed_of(s: &str) -> String {
    if is_identity_ref(s) {
        if let Some(seed) = seeds().lock().expect("seed map").get(s) {
            return seed.clone();
        }
    }
    s.to_owned()
}

/// The bare thumbprint of [`kid`]`(seed)`: the 43 base64url characters after
/// `urn:ietf:params:oauth:ckt:sha-256:`, the form a key takes inside a family
/// name / dimension (CC rc21: `licensure:{kid_thumb}:v1`). By the ruling this
/// equals `namespace::key_segment::segment_of(&kid(seed))`.
#[must_use]
pub fn kid_thumb(seed: &str) -> String {
    let k = kid(seed);
    k.strip_prefix(ciris_verify_core::edition2::IDENTITY_REF_PREFIX)
        .unwrap_or_else(|| panic!("fixture_switch: {k} is not an identity-ref"))
        .to_owned()
}

/// An earlier comma-joined `identity_type` as a set (trimmed, sorted, unique).
#[must_use]
pub fn identity_types_of(identity_type: &str) -> Vec<&str> {
    let mut types: Vec<&str> = identity_type
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .collect();
    types.sort_unstable();
    types.dedup();
    types
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A row's subject as the header carries it ([`kid_or_keep`]).
fn subject_of(s: &str) -> String {
    kid_or_keep(s)
}

/// A row's id as stored (lowercase hex). A row carrying its statement: the
/// id this node computes from the statement; else its `attestation_id`.
#[must_use]
pub fn rid(row: &Attestation) -> String {
    carried_statement(row)
        .and_then(|st| RowId::of_statement(&st))
        .map_or_else(|| row.attestation_id.clone(), |id| id.hex())
}

/// [`rid`] as bytes.
///
/// # Panics
/// A row whose id is not 64 hex.
#[must_use]
pub fn rid_digest(row: &Attestation) -> Digest32 {
    let id = rid(row);
    <[u8; 32]>::try_from(hex::decode(&id).unwrap_or_default().as_slice())
        .unwrap_or_else(|_| panic!("fixture_switch: row id {id:?} is not 64 hex"))
}

/// `[2, [-16, rid]]`: an edition-2 row-ref to `row`, for a payload's `refs`.
#[must_use]
pub fn row_ref(row: &Attestation) -> Value {
    ciris_verify_core::edition2::row_ref(&rid_digest(row))
}

// ---------------------------------------------------------------------------
// 3. The codec
// ---------------------------------------------------------------------------

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

/// A deterministic map: entries sorted by their keys' encodings.
fn det_map(mut m: Vec<(Value, Value)>) -> Value {
    m.sort_by_key(|(k, _)| cde::encode(k));
    Value::Map(m)
}

/// A sorted, de-duplicated CBOR set.
fn det_set(mut a: Vec<Value>) -> Value {
    a.sort_by_key(cde::encode);
    a.dedup_by(|x, y| cde::encode(x) == cde::encode(y));
    Value::Array(a)
}

fn int_value(i: i64) -> Value {
    if i >= 0 {
        Value::Uint(i.unsigned_abs())
    } else {
        Value::Nint(i.unsigned_abs() - 1)
    }
}

fn ms_of_text(s: &str) -> u64 {
    u64::try_from(
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap_or_else(|e| panic!("fixture_switch: instant {s:?}: {e}"))
            .timestamp_millis(),
    )
    .expect("fixture_switch: an instant before the epoch")
}

/// POSIX ms of an instant.
///
/// # Panics
/// An instant before the epoch.
#[must_use]
pub fn ms(at: chrono::DateTime<chrono::Utc>) -> u64 {
    u64::try_from(at.timestamp_millis()).expect("fixture_switch: an instant before the epoch")
}

fn ms_value(v: &serde_json::Value, member: &str) -> Value {
    match v {
        serde_json::Value::String(s) => Value::Uint(ms_of_text(s)),
        serde_json::Value::Number(n) => Value::Uint(
            n.as_u64()
                .unwrap_or_else(|| panic!("fixture_switch: `{member}` is not ms")),
        ),
        other => panic!("fixture_switch: `{member}` is not an instant: {other}"),
    }
}

fn hex_bytes(v: &serde_json::Value, member: &str) -> Vec<u8> {
    v.as_str()
        .and_then(|s| hex::decode(s).ok())
        .unwrap_or_else(|| panic!("fixture_switch: `{member}` is not hex: {v}"))
}

/// A digest member: 64 hex, or the mapping's own `[-16, "hex"]`.
fn digest_value(v: &serde_json::Value, member: &str) -> Value {
    let bytes = match v {
        serde_json::Value::Array(a) if a.len() == 2 && a[0].as_i64() == Some(-16) => {
            hex_bytes(&a[1], member)
        }
        _ => hex_bytes(v, member),
    };
    assert_eq!(
        bytes.len(),
        32,
        "fixture_switch: `{member}` is not 32 bytes"
    );
    Value::Array(vec![int_value(-16), Value::Bytes(bytes)])
}

/// A `[+ hash-digest]` sequence: non-empty, in the order given (signed
/// order; P1: not sorted, not de-duplicated).
fn digests_value(v: &serde_json::Value, member: &str) -> Value {
    let a = v
        .as_array()
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| panic!("fixture_switch: `{member}` is not a non-empty array"));
    Value::Array(a.iter().map(|x| digest_value(x, member)).collect())
}

fn identity_value(v: &serde_json::Value, member: &str) -> Value {
    text(&kid_or_keep(v.as_str().unwrap_or_else(|| {
        panic!("fixture_switch: `{member}` is not text")
    })))
}

fn identities_value(v: &serde_json::Value, member: &str) -> Value {
    let a = v
        .as_array()
        .unwrap_or_else(|| panic!("fixture_switch: `{member}` is not an array"));
    det_set(a.iter().map(|x| identity_value(x, member)).collect())
}

fn roster_members_value(v: &serde_json::Value) -> Value {
    let a = v
        .as_array()
        .expect("fixture_switch: `members` is not an array");
    let mut out: Vec<Value> = a
        .iter()
        .map(|m| {
            let o = m
                .as_object()
                .expect("fixture_switch: a roster member is a map");
            let mut e = Vec::new();
            for (k, x) in o {
                let c = match k.as_str() {
                    "key" | "key_id" => ("key".to_owned(), identity_value(x, "members.key")),
                    "joined_at" => ("joined_at".to_owned(), ms_value(x, "members.joined_at")),
                    _ => (k.clone(), cbor_of(x, Some(k))),
                };
                e.push((text(&c.0), c.1));
            }
            det_map(e)
        })
        .collect();
    // P1's set rule: a roster is sorted by each member entry's FULL
    // deterministic encoding (an entry with a `role` sorts by its bytes).
    out.sort_by_key(cde::encode);
    Value::Array(out)
}

/// A JSON value as CBOR, maps in the deterministic order.
fn cbor_of(v: &serde_json::Value, member: Option<&str>) -> Value {
    use serde_json::Value as J;
    match v {
        J::Null => Value::Null,
        J::Bool(b) => Value::Bool(*b),
        J::Number(n) => {
            if let Some(u) = n.as_u64() {
                Value::Uint(u)
            } else if let Some(i) = n.as_i64() {
                int_value(i)
            } else {
                panic!("fixture_switch: a real outside the fixed-scale members ({member:?}: {n})")
            }
        }
        J::String(s) => Value::Text(s.clone()),
        J::Array(a) => Value::Array(a.iter().map(|x| cbor_of(x, member)).collect()),
        J::Object(o) => det_map(
            o.iter()
                .map(|(k, x)| (text(k), cbor_of(x, Some(k))))
                .collect(),
        ),
    }
}

/// `refs` as the mapping renders it (`json_of`): every `[-16, "hex"]` is a
/// digest again, and a row-ref `[n, [-16, "hex"]]` is a row-ref.
fn refs_value(v: &serde_json::Value) -> Value {
    use serde_json::Value as J;
    match v {
        J::Array(a) if a.len() == 2 && a[0].as_i64() == Some(-16) && a[1].is_string() => {
            digest_value(v, "refs")
        }
        J::Array(a) => Value::Array(a.iter().map(refs_value).collect()),
        J::Object(o) => det_map(o.iter().map(|(k, x)| (text(k), refs_value(x))).collect()),
        other => cbor_of(other, Some("refs")),
    }
}

/// The payload member types of the family id `family`
/// ([`payloads::FAMILIES`], keyed by pattern).
fn member_types(family: &str) -> Vec<(&'static str, Ty)> {
    payloads::FAMILIES
        .iter()
        .filter(|f| namespace_match::family_id(f.family) == family)
        .flat_map(|f| f.members.iter().map(|m| (m.name, m.ty)))
        .collect()
}

fn typed_value(v: &serde_json::Value, member: &str, ty: Ty) -> Value {
    match ty {
        Ty::Ms => ms_value(v, member),
        Ty::Bstr => Value::Bytes(hex_bytes(v, member)),
        Ty::Digest => digest_value(v, member),
        Ty::Digests => digests_value(v, member),
        Ty::IdentityRef => identity_value(v, member),
        Ty::IdentityRefs => identities_value(v, member),
        Ty::RosterMembers => roster_members_value(v),
        Ty::Uint | Ty::Tstr | Ty::Bool | Ty::Map => cbor_of(v, Some(member)),
        // P1 adds `Ty::Any` (a ceg-value, carried as is) and `Ty::Tstrs` (a
        // SET of text: sorted by encoding, unique). Neither is named here, so
        // this arm keeps the match whole on either side of that merge: an
        // array of text is written as the set, anything else as is.
        #[allow(unreachable_patterns)]
        _ => match v.as_array() {
            Some(a) if a.iter().all(serde_json::Value::is_string) => det_set(
                a.iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(text)
                    .collect(),
            ),
            _ => cbor_of(v, Some(member)),
        },
    }
}

/// v62.0.0 (E0 fix 2) — **the earlier-form row in its edition-2 shape**,
/// before anything is read from it:
/// - a TYPE-keyed row (an `attestation_type` outside the five row types,
///   e.g. `age_self_declared:band:adult`) with no dimension is a `scores`
///   row whose dimension is that type: edition 2 has no type-keyed shape
///   (the row type is one of five, CC 2.6.1);
/// - a dimension Verify's matcher refuses ONLY for its missing trailing
///   version segment (`capacity:integrity`, `cert_validity:probe`) carries
///   `:v1` when that resolves to a registered family (the rc21 R3 rule).
///   Any other refusal, and open vocabulary, are left for the door to
///   refuse.
fn edition2_shape(a: &Attestation) -> std::borrow::Cow<'_, Attestation> {
    let mut out = std::borrow::Cow::Borrowed(a);
    let has_dimension = a.attestation_envelope.get("dimension").is_some();
    if !has_dimension && !attestation_type::ALL.contains(&a.attestation_type.as_str()) {
        let row = out.to_mut();
        let ty = std::mem::replace(
            &mut row.attestation_type,
            attestation_type::SCORES.to_owned(),
        );
        if let Some(o) = row.attestation_envelope.as_object_mut() {
            o.insert("dimension".to_owned(), serde_json::Value::String(ty));
        }
    }
    let dim = out
        .attestation_envelope
        .get("dimension")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    if let Some(d) = dim {
        if matches!(namespace_match::resolve(&d), Err(r) if r.token == "missing_version_segment") {
            let versioned = format!("{d}:v1");
            if matches!(
                namespace_match::resolve(&versioned),
                Ok(namespace_match::Resolved::Family { .. })
            ) {
                out.to_mut().attestation_envelope["dimension"] =
                    serde_json::Value::String(versioned);
            }
        }
    }
    out
}

fn try_family_of(row: &Attestation) -> Result<String, String> {
    let row = &*edition2_shape(row);
    let env = &row.attestation_envelope;
    if let Some(d) = env.get("dimension").and_then(serde_json::Value::as_str) {
        return match namespace_match::resolve(d) {
            Ok(namespace_match::Resolved::Family { family_id, .. }) => Ok(family_id),
            Ok(_) => Err(format!(
                "dimension {d:?} is open vocabulary: no registered family claims it, and the \
                 edition-2 door refuses it (move the fixture to a registered dimension)"
            )),
            Err(r) => Err(format!(
                "dimension {d:?} is refused by Verify's matcher ({})",
                r.token
            )),
        };
    }
    let ty = row.attestation_type.as_str();
    if COMPOSER_ROW_TYPES.contains(&ty) {
        let target = env
            .get(REFERENCES_MEMBER)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        return row_families()
            .lock()
            .expect("family map")
            .get(target)
            .cloned()
            .ok_or_else(|| {
                format!(
                    "the {ty} row names target {target:?}, a row no fixture minted: a composer \
                     carries its target's family (use composer_of / statement_of_family)"
                )
            });
    }
    if ty == attestation_type::DELEGATES_TO {
        return Ok("self:delegates_to".to_owned());
    }
    if let Ok(namespace_match::Resolved::Family { family_id, .. }) = namespace_match::resolve(ty) {
        return Ok(family_id);
    }
    Err(format!(
        "a `{ty}` row with no dimension names no family: use statement_of_family"
    ))
}

/// The family (header -70002) an earlier-form-shaped row is a row of: the
/// family its `dimension` resolves to under Verify's matcher; a composer's
/// target's; `self:delegates_to` for a `delegates_to` with no dimension.
///
/// # Panics
/// A row that names no family (module docs of E0.api.md).
#[must_use]
pub fn family_of(row: &Attestation) -> String {
    try_family_of(row).unwrap_or_else(|e| panic!("fixture_switch: {e}"))
}

/// Is `family` counted (no `author`) for a row with this `dimension`, signed
/// as one signer's own row?
fn counted(family: &str, dimension: Option<&str>) -> bool {
    let leaf = dimension.and_then(|d| {
        let prefix = namespace_match::prefix_of_family_id(family)?;
        namespace_match::bind_leaf(prefix, d).ok().map(|b| b.leaf)
    });
    let ctx = SelectContext {
        act: Some(Act::Own),
        ..SelectContext::default()
    };
    matches!(
        VendoredFamilyModel.rule_for(family, leaf.as_deref(), &ctx),
        RuleAnswer::Rule(r) if !r.authored
    )
}

/// The payload a row's envelope projects from (the inverse of the mapping).
fn payload_of(row: &Attestation, family: &str, signer_iref: &str) -> Value {
    let mut env = row.attestation_envelope.clone();
    let o = env
        .as_object_mut()
        .expect("fixture_switch: the envelope is a JSON object");
    // v62.0.0 (E13 fix1) — a RE-SEAL of a mapped row (its envelope carries
    // the statement it was sealed from) re-derives the statement from the
    // MUTATED struct (E0.api v1.2): the row's `subject_key_ids` column wins
    // over the projection the earlier seal left in the envelope. Else a
    // fixture that clears the subjects and reseals (a standing proposal)
    // still signs the old subjects.
    if o.remove(STATEMENT_MEMBER).is_some() {
        o.remove("subject_key_ids");
    }
    o.remove("row");
    // The row's columns are the signed instants (as `stamp_signed_instants`
    // stamps them on the earlier form).
    o.remove("asserted_at");
    o.remove("expires_at");
    let has_refs = o.contains_key("refs");
    let target = o.remove(REFERENCES_MEMBER);
    let dimension = o
        .get("dimension")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let typed = member_types(family);
    let mut m: Vec<(Value, Value)> = Vec::new();
    for (k, v) in o.iter() {
        let c = if let Some((_, ty)) = typed.iter().find(|(n, _)| *n == k.as_str()) {
            typed_value(v, k, *ty)
        } else if INSTANT_MEMBERS.contains(&k.as_str()) {
            ms_value(v, k)
        } else if SCALED_MEMBERS.contains(&k.as_str()) {
            let real = v
                .as_f64()
                .unwrap_or_else(|| panic!("fixture_switch: `{k}` is not a number"));
            #[allow(clippy::cast_possible_truncation)]
            let scaled = (real * 1_000_000.0).round() as i64;
            int_value(scaled)
        } else if k == "evidence_refs" {
            digests_value(v, k)
        } else if matches!(
            k.as_str(),
            "carried" | "seat_commitment" | "amendment_digest" | "call_fingerprint"
        ) {
            digest_value(v, k)
        } else if k == "refs" {
            refs_value(v)
        } else if k == "author" {
            // A re-seal under another signer: the earlier author was the
            // earlier signer.
            if v.as_str() == Some(row.attesting_key_id.as_str()) {
                continue;
            }
            identity_value(v, k)
        } else {
            cbor_of(v, Some(k))
        };
        m.push((text(k), c));
    }
    // `references_attestation_id` is the mapping's projection of
    // `refs.target`: a literal's names its target here.
    if !has_refs {
        if let Some(t) = target.as_ref().and_then(serde_json::Value::as_str) {
            if is_hex64(t) {
                let d = <[u8; 32]>::try_from(hex::decode(t).expect("hex").as_slice())
                    .expect("32 bytes");
                m.push((
                    text("refs"),
                    det_map(vec![(
                        text("target"),
                        ciris_verify_core::edition2::row_ref(&d),
                    )]),
                ));
            } else {
                panic!(
                    "fixture_switch: `{REFERENCES_MEMBER}` {t:?} is not a row id: name the target \
                     by rid(&target)"
                );
            }
        }
    }
    // The typed `weight` column, when the envelope states none: the payload's
    // fixed-scale `weight` (CC 2.6.1.5, round(w × 10⁶)); the store binds the
    // column to it (P1).
    if !o.contains_key("weight") {
        if let Some(w) = row.weight {
            #[allow(clippy::cast_possible_truncation)]
            let scaled = (w * 1_000_000.0).round() as i64;
            m.push((text("weight"), int_value(scaled)));
        }
    }
    m.push((text("asserted_at"), Value::Uint(ms(row.asserted_at))));
    if let Some(e) = row.expires_at {
        m.push((text("expires_at"), Value::Uint(ms(e))));
    }
    if !o.contains_key("cohort_scope")
        && !row.cohort_scope.is_empty()
        && row.cohort_scope != crate::federation::types::cohort_scope::FEDERATION
    {
        m.push((text("cohort_scope"), text(&row.cohort_scope)));
    }
    if !o.contains_key("subject_key_ids") && !row.subject_key_ids.is_empty() {
        m.push((
            text("subject_key_ids"),
            Value::Array(
                row.subject_key_ids
                    .iter()
                    .map(|s| text(&kid_or_keep(s)))
                    .collect(),
            ),
        ));
    }
    let authored_here = m.iter().any(|(k, _)| k.as_text() == Some("author"));
    if !authored_here && !counted(family, dimension.as_deref()) {
        m.push((text("author"), text(signer_iref)));
    }
    det_map(m)
}

/// **An earlier-form-shaped row as an edition-2 statement**, of
/// [`family_of`]`(a)`, signed by `seed`'s key.
#[must_use]
pub fn statement_of(a: &Attestation, seed: &str) -> Vec<u8> {
    statement_of_family(a, seed, &family_of(a))
}

/// v62.0.0 (wave V1b, CC 2.6.1.9) — **a COUNTED row's first voice**: as
/// [`statement_of`], but the payload carries no `author`, so the door reads
/// the act as `group` and a family whose card is counted under `act=group`
/// (`licensure:{authority_id}`, `trust:{job}:{version}`, `key:record`,
/// `collection:{kind}`, ...) admits any signer's voice over it. Further
/// voices: [`voices_of`] / [`voice_of`] over its statement (same row id).
/// [`statement_of`] signs such a row as one signer's OWN (authored) row, over
/// which a second signer is refused `iss_not_in_role`.
///
/// # Panics
/// As [`statement_of_family`].
#[must_use]
pub fn counted_statement_of(a: &Attestation, seed: &str) -> Vec<u8> {
    counted_statement_of_family(a, seed, &family_of(a))
}

/// [`counted_statement_of`] under an explicit `family` id (a composer of a
/// counted row carries its target's family: a counted `withdraws`).
///
/// # Panics
/// As [`statement_of_family`].
#[must_use]
pub fn counted_statement_of_family(a: &Attestation, seed: &str, family: &str) -> Vec<u8> {
    let family = family.to_owned();
    let key = signing_key(seed);
    let iref = identity_ref(&thumbprint(key.public_key()));
    let payload = match payload_of(a, &family, &iref) {
        Value::Map(m) => det_map(
            m.into_iter()
                .filter(|(k, _)| k.as_text() != Some("author"))
                .collect(),
        ),
        other => other,
    };
    let st = sign_row_statement(
        &key,
        &iref,
        &subject_of(&a.attested_key_id),
        &a.attestation_type,
        &family,
        &payload,
        vec![],
    )
    .expect("fixture_switch: sign a counted row");
    if let Some(id) = RowId::of_statement(&st) {
        row_families()
            .lock()
            .expect("family map")
            .insert(id.hex(), family.clone());
    }
    st
}

/// [`counted_statement_of`] as the typed row the gates read (its first
/// voice's projection), for [`put_signed`] and [`voices_of`].
///
/// # Panics
/// The door refuses it.
#[must_use]
pub fn counted_row_of(a: &Attestation, seed: &str) -> Attestation {
    row_of_statement(&counted_statement_of(a, seed), tier_of(a))
}

/// [`statement_of`], or why the row names no family.
///
/// # Errors
/// The row names no family.
pub fn try_statement_of(a: &Attestation, seed: &str) -> Result<Vec<u8>, String> {
    let family = try_family_of(a)?;
    Ok(statement_of_family(a, seed, &family))
}

/// [`statement_of`] under an explicit `family` id.
///
/// # Panics
/// A payload member the codec cannot carry; a signing failure.
#[must_use]
pub fn statement_of_family(a: &Attestation, seed: &str, family: &str) -> Vec<u8> {
    let a = &*edition2_shape(a);
    let key = signing_key(seed);
    let iref = identity_ref(&thumbprint(key.public_key()));
    let payload = payload_of(a, family, &iref);
    let st = sign_row_statement(
        &key,
        &iref,
        &subject_of(&a.attested_key_id),
        &a.attestation_type,
        family,
        &payload,
        vec![],
    )
    .expect("fixture_switch: sign");
    if let Some(id) = RowId::of_statement(&st) {
        row_families()
            .lock()
            .expect("family map")
            .insert(id.hex(), family.to_owned());
    }
    st
}

/// The `iss` (CWT claim 1) a statement names.
fn statement_iss(statement: &[u8]) -> Option<String> {
    let (protected, _) = statement_parts(statement)?;
    protected
        .get_int(15)?
        .get_int(1)?
        .as_text()
        .map(str::to_owned)
}

/// The signer's own `key:record` (a `user` record from 0, no end): enough
/// for the door's key-of-issuer check and liveness at any instant.
fn signer_held(statement: &[u8]) -> HeldKeys {
    let mut keys = HeldKeys::new();
    if let Some(iss) = statement_iss(statement) {
        if seeds().lock().expect("seed map").contains_key(&iss) {
            keys.insert_record(key_record_with(
                &iss,
                &["user"],
                &KeyRecordOptions {
                    asserted_at_ms: Some(0),
                    ..KeyRecordOptions::default()
                },
            ));
        } else if let Some(rec) = foreign_records().lock().expect("foreign map").get(&iss) {
            keys.insert_record(rec.clone());
        }
    }
    keys
}

/// A statement through the door with `keys` held.
///
/// # Errors
/// The door's refusals.
pub fn try_admit(statement: &[u8], keys: &HeldKeys) -> Result<AdmittedRow, Error> {
    admit_row(statement, keys, None, SelectContext::default())
}

/// A statement through the door, its signer's own record held.
///
/// # Panics
/// The door refuses it.
#[must_use]
pub fn admit(statement: &[u8]) -> AdmittedRow {
    try_admit(statement, &signer_held(statement))
        .unwrap_or_else(|e| panic!("fixture_switch: the door refuses the statement: {e}"))
}

/// **A statement as the typed row** the gates read, mapped at `tier`.
///
/// # Errors
/// The door's refusals; the mapping's.
pub fn try_row_of_statement(statement: &[u8], tier: &str) -> Result<Attestation, Error> {
    let admitted = try_admit(statement, &signer_held(statement))?;
    attestation_of(&admitted, tier)
}

/// [`try_row_of_statement`], panicking on a refusal.
#[must_use]
pub fn row_of_statement(statement: &[u8], tier: &str) -> Attestation {
    try_row_of_statement(statement, tier)
        .unwrap_or_else(|e| panic!("fixture_switch: row_of_statement: {e}"))
}

fn tier_of(a: &Attestation) -> &str {
    if a.tier.is_empty() {
        INGEST_TIER
    } else {
        a.tier.as_str()
    }
}

/// **An earlier-form-shaped row, edition 2**: `statement_of(a, seed)`
/// through the door, mapped at the row's tier.
///
/// # Errors
/// The door's refusals.
pub fn try_row_of(a: &Attestation, seed: &str) -> Result<Attestation, Error> {
    try_row_of_statement(&try_statement_of_door(a, seed)?, tier_of(a))
}

/// [`try_statement_of`] with a row that names no family (a dimension
/// Verify's matcher refuses or does not register) as the door's refusal:
/// `federation_malformed_row` / `edition2_statement_invalid`, its message
/// naming the matcher's token. Never a panic, so a witness that expects
/// the refusal reads it as an `Err`.
fn try_statement_of_door(a: &Attestation, seed: &str) -> Result<Vec<u8>, Error> {
    try_statement_of(a, seed).map_err(|why| {
        Error::malformed_row(
            super::door::PLANE,
            super::token::STATEMENT_INVALID,
            format!("the statement door refuses the row: {why}"),
        )
    })
}

/// [`try_row_of`], panicking on a refusal.
#[must_use]
pub fn row_of(a: &Attestation, seed: &str) -> Attestation {
    try_row_of(a, seed).unwrap_or_else(|e| {
        panic!(
            "fixture_switch: row_of({} `{}`): the door refuses it: {e}",
            a.attestation_type,
            a.attestation_envelope
                .get("dimension")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("-")
        )
    })
}

/// [`row_of`] wrapped for `put_attestation`.
#[must_use]
pub fn signed_row_of(a: &Attestation, seed: &str) -> SignedAttestation {
    SignedAttestation {
        attestation: row_of(a, seed),
    }
}

/// The statement a mapped row carries (its envelope's `ceg_statement`).
#[must_use]
pub fn carried_statement(row: &Attestation) -> Option<Vec<u8>> {
    row.attestation_envelope
        .get(STATEMENT_MEMBER)
        .and_then(serde_json::Value::as_str)
        .and_then(|h| hex::decode(h).ok())
}

/// **A further voice** of the row `statement` is a voice of: the same row
/// type, family, subject and payload bytes, signed by `seed`. A counted row
/// (no `author`) has one row id for every voice.
///
/// # Panics
/// Not a row statement.
#[must_use]
pub fn voice_of(statement: &[u8], seed: &str) -> Vec<u8> {
    let (protected, payload) =
        statement_parts(statement).expect("fixture_switch: voice_of: not a statement");
    let row_type = protected
        .get_int(-70001)
        .and_then(Value::as_text)
        .expect("row type");
    let family = protected
        .get_int(-70002)
        .and_then(Value::as_text)
        .expect("family");
    let sub = protected
        .get_int(15)
        .and_then(|c| c.get_int(2))
        .and_then(Value::as_text)
        .expect("sub");
    let key = signing_key(seed);
    let iref = identity_ref(&thumbprint(key.public_key()));
    sign_row_statement(&key, &iref, sub, row_type, family, &payload, vec![])
        .expect("fixture_switch: sign a voice")
}

/// Each of `seeds`' voices over the statement `row` carries.
///
/// # Panics
/// A row that carries no statement.
#[must_use]
pub fn voices_of(row: &Attestation, seeds_: &[&str]) -> Vec<Vec<u8>> {
    let st = carried_statement(row).expect("fixture_switch: the row carries no statement");
    seeds_.iter().map(|s| voice_of(&st, s)).collect()
}

/// **A composer** (`withdraws` / `recants` / `supersedes`) of `target`,
/// signed by `seed`: `refs.target` names the target's row id and the row
/// carries the target's family (CC 2.4.1.1), about the target's subject.
///
/// # Panics
/// `kind` is not a composer; the door refuses it.
#[must_use]
pub fn composer_of(kind: &str, target: &Attestation, seed: &str) -> Attestation {
    assert!(
        COMPOSER_ROW_TYPES.contains(&kind),
        "fixture_switch: {kind} is not a composer"
    );
    let family = carried_statement(target)
        .and_then(|st| statement_parts(&st))
        .and_then(|(p, _)| {
            p.get_int(-70002)
                .and_then(Value::as_text)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| family_of(target));
    let mut row = target.clone();
    row.attestation_type = kind.to_owned();
    row.asserted_at = crate::host::clock::now();
    row.expires_at = None;
    row.subject_key_ids = Vec::new();
    let mut envelope = serde_json::Map::new();
    if let Some(d) = target.attestation_envelope.get("dimension") {
        envelope.insert("dimension".to_owned(), d.clone());
    }
    envelope.insert(
        REFERENCES_MEMBER.to_owned(),
        serde_json::Value::String(rid(target)),
    );
    row.attestation_envelope = serde_json::Value::Object(envelope);
    row.attesting_key_id = kid(seed);
    row_of_statement(&statement_of_family(&row, seed, &family), tier_of(target))
}

// ---------------------------------------------------------------------------
// 4. The key plane
// ---------------------------------------------------------------------------

/// The longest a node or agent record may run: 365 days, in ms (Verify's
/// `KEY_RECORD_MAX_SECS`).
pub const NODE_KEY_MAX_MS: u64 = ciris_verify_core::edition2::keys::KEY_RECORD_MAX_SECS * 1000;

const DAY_MS: u64 = 86_400_000;

/// How far before today 00:00 UTC a default node / agent record starts: 180
/// days (live until today + 185 days). **Rows signed by a node / agent key
/// must be NOW-RELATIVE** (today minus N days): such a key ends by its own
/// record and its rows lapse by that end (CC 2.4.1.1), at most 365 days, so a
/// FIXED calendar date stops verifying within a year of it whatever start the
/// key is given. Fixed dates are for keys with no end (`user`,
/// `accord_holder`). A default key signing outside its window panics at the
/// put, naming that rule ([`put_signed`], [`put_row`]).
pub const NODE_DEFAULT_BACK_DAYS: u64 = 180;

/// identity-ref → the window `[from, until]` (ms) of the DEFAULT node /
/// agent record a fixture put for it.
fn default_windows() -> &'static Mutex<HashMap<String, (u64, u64)>> {
    static W: OnceLock<Mutex<HashMap<String, (u64, u64)>>> = OnceLock::new();
    W.get_or_init(Default::default)
}

/// Remember (`Some`) or forget (`None`: an explicit record) the default
/// window of `seed`'s key.
fn note_window(seed: &str, window: Option<(u64, u64)>) {
    let k = kid(seed);
    let mut w = default_windows().lock().expect("window map");
    match window {
        Some(x) => {
            w.insert(k, x);
        }
        None => {
            w.remove(&k);
        }
    }
}

/// v62.0.0 (K2, red round 3) — **where `seed`'s key record starts**, POSIX ms:
/// the start of the default node / agent window [`put_key`] noted for it, or,
/// when none is noted (the key is not put yet, or was put with explicit
/// options), the start a DEFAULT node record gets ([`NODE_DEFAULT_BACK_DAYS`]
/// before today 00:00 UTC). A fixture that signs a row a node key must voice
/// dates it from here plus a fixed offset, so the row sits at a fixed place
/// inside the key's own window rather than at a calendar date the window
/// moves past. There is no pinned fixture clock: the default window is itself
/// derived from the day the suite runs, and this reads that one derivation.
#[must_use]
pub fn key_window_start_ms(seed: &str) -> u64 {
    default_windows()
        .lock()
        .expect("window map")
        .get(&kid(seed))
        .map_or_else(|| default_asserted_at(&["node"]), |(from, _)| *from)
}

/// The default window a node / agent key gets with no options.
fn default_window(identity_types: &[&str]) -> Option<(u64, u64)> {
    must_end(identity_types).then(|| {
        let from = default_asserted_at(identity_types);
        (from, from.saturating_add(NODE_KEY_MAX_MS))
    })
}

/// **The fixed-instant guard**: a statement signed by a key whose record is
/// a DEFAULT node / agent window, asserted outside that window, panics with
/// the fix instead of the store's waiting / not-covered refusal.
///
/// # Panics
/// As above.
fn check_default_window(statement: &[u8]) {
    let Some(iss) = statement_iss(statement) else {
        return;
    };
    let Some(at) = statement_parts(statement)
        .and_then(|(_, p)| p.get_text("asserted_at").and_then(Value::as_u64))
    else {
        return;
    };
    let window = default_windows()
        .lock()
        .expect("window map")
        .get(&iss)
        .copied();
    if let Some((from, until)) = window {
        assert!(
            from <= at && at <= until,
            "fixed-instant fixture: a node/agent key's rows lapse with its own record (CC \
             2.4.1.1, at most 365 days), so make the rows NOW-RELATIVE (today minus N days), or \
             sign fixed calendar dates with a key that has no end (user / accord_holder); \
             put_key_with with a fixed start is not a fix. {} signed at {at} ms, outside its \
             node/agent window [{from}, {until}]",
            seed_of(&iss)
        );
    }
}

/// How a fixture's `key:record` is shaped. Every field defaults (module docs
/// of E0.api.md).
#[derive(Clone, Debug, Default)]
pub struct KeyRecordOptions {
    /// The record's `asserted_at`. Default: a `user` / `accord_holder` (or any
    /// set with no `node` / `agent`) 0; a `node` / `agent` today 00:00 UTC
    /// less [`NODE_DEFAULT_BACK_DAYS`] (180 days): for now-relative rows only.
    pub asserted_at_ms: Option<u64>,
    /// The record's end. Default: a `node` / `agent` `asserted_at` +
    /// [`NODE_KEY_MAX_MS`]; others none.
    pub valid_until_ms: Option<u64>,
    /// No `valid_until` even for a `node` / `agent` (a witness of the
    /// end-rule refusal).
    pub no_end: bool,
    /// The record's `valid_from`, if any.
    pub valid_from_ms: Option<u64>,
    /// A record signed by another key (a seed). Default: the key itself.
    pub signer: Option<String>,
    /// `refs.target`: the predecessor record's row id (a rotation).
    pub prev: Option<Digest32>,
    /// Further payload members.
    pub extra: Vec<(String, Value)>,
}

fn must_end(identity_types: &[&str]) -> bool {
    identity_types
        .iter()
        .any(|t| matches!(*t, "node" | "agent"))
}

fn default_asserted_at(identity_types: &[&str]) -> u64 {
    if must_end(identity_types) {
        let now = ms(crate::host::clock::now());
        (now / DAY_MS * DAY_MS).saturating_sub(NODE_DEFAULT_BACK_DAYS * DAY_MS)
    } else {
        0
    }
}

/// A self-signed `key:record` of `seed`'s key with these identity types.
#[must_use]
pub fn key_record(seed: &str, identity_types: &[&str]) -> Vec<u8> {
    key_record_with(seed, identity_types, &KeyRecordOptions::default())
}

/// A `key:record` of `seed`'s key, shaped by `opts`.
///
/// # Panics
/// A signing failure.
#[must_use]
pub fn key_record_with(seed: &str, identity_types: &[&str], opts: &KeyRecordOptions) -> Vec<u8> {
    let subject = signing_key(seed);
    let signer = opts
        .signer
        .as_deref()
        .map_or_else(|| signing_key(seed), signing_key);
    let iss = identity_ref(&thumbprint(signer.public_key()));
    let payload = key_record_payload(subject.public_key(), &iss, identity_types, opts);
    sign_row_statement(
        &signer,
        &iss,
        &identity_ref(&thumbprint(subject.public_key())),
        "scores",
        ciris_verify_core::edition2::keys::KEY_RECORD_FAMILY,
        &payload,
        vec![],
    )
    .expect("fixture_switch: sign a key record")
}

/// The payload of a `key:record` of `subject`, authored by `iss`.
fn key_record_payload(
    subject: &ciris_crypto::composite::CompositePublicKey,
    iss: &str,
    identity_types: &[&str],
    opts: &KeyRecordOptions,
) -> Value {
    let at = opts
        .asserted_at_ms
        .unwrap_or_else(|| default_asserted_at(identity_types));
    let until = if opts.no_end {
        None
    } else {
        opts.valid_until_ms
            .or_else(|| must_end(identity_types).then(|| at.saturating_add(NODE_KEY_MAX_MS)))
    };
    let mut m = vec![
        (text("key"), cose_key(subject)),
        (
            text("identity_type"),
            det_set(identity_types.iter().map(|t| text(t)).collect()),
        ),
        (text("asserted_at"), Value::Uint(at)),
        (text("author"), text(iss)),
    ];
    if let Some(u) = until {
        m.push((text("valid_until"), Value::Uint(u)));
    }
    if let Some(f) = opts.valid_from_ms {
        m.push((text("valid_from"), Value::Uint(f)));
    }
    if let Some(p) = opts.prev {
        m.push((
            text("refs"),
            det_map(vec![(
                text("target"),
                ciris_verify_core::edition2::row_ref(&p),
            )]),
        ));
    }
    for (k, v) in &opts.extra {
        m.push((text(k), v.clone()));
    }
    det_map(m)
}

/// identity-ref → a `user` record (from 0) of a key NOT derived from a seed
/// (an engine's signer, an STH producer), signed by that key: what the
/// in-memory door holds for it ([`signer_held`]).
fn foreign_records() -> &'static Mutex<HashMap<String, Vec<u8>>> {
    static F: OnceLock<Mutex<HashMap<String, Vec<u8>>>> = OnceLock::new();
    F.get_or_init(Default::default)
}

/// Is `s` the kid of a key registered by [`put_key_for_composite`] /
/// [`put_key_for_signer`] that no seed names?
#[must_use]
pub fn is_foreign_kid(s: &str) -> bool {
    foreign_records()
        .lock()
        .expect("foreign map")
        .contains_key(s)
}

/// A self-signed `key:record` of a composite key NOT derived from a seed.
///
/// # Panics
/// A signing failure.
#[must_use]
pub fn key_record_for_composite(
    key: &CompositeSigningKey,
    identity_types: &[&str],
    opts: &KeyRecordOptions,
) -> Vec<u8> {
    let iss = identity_ref(&thumbprint(key.public_key()));
    sign_row_statement(
        key,
        &iss,
        &iss,
        "scores",
        ciris_verify_core::edition2::keys::KEY_RECORD_FAMILY,
        &key_record_payload(key.public_key(), &iss, identity_types, opts),
        vec![],
    )
    .expect("fixture_switch: sign a key record")
}

/// **Make a key that no seed names live** (an STH producer, a hand-built
/// composite): its self-signed `key:record` through the store; its kid.
/// The kid is registered, so the codec's `*_with_key` forms and the
/// in-memory door ([`row_of_statement`]) hold it. A seed cannot be
/// recovered from it: `seed_of(kid)` returns the kid and `seed_for` panics
/// naming this function; sign its rows with [`statement_of_with_key`].
///
/// # Panics
/// The store refuses the record.
pub async fn put_key_for_composite<D: FederationDirectory + ?Sized>(
    dir: &D,
    key: &CompositeSigningKey,
    identity_types: &[&str],
) -> String {
    let k = identity_ref(&thumbprint(key.public_key()));
    foreign_records().lock().expect("foreign map").insert(
        k.clone(),
        key_record_for_composite(
            key,
            &["user"],
            &KeyRecordOptions {
                asserted_at_ms: Some(0),
                ..KeyRecordOptions::default()
            },
        ),
    );
    put_statement(
        dir,
        &key_record_for_composite(key, identity_types, &KeyRecordOptions::default()),
    )
    .await
    .unwrap_or_else(|e| panic!("fixture_switch: put_key_for_composite({k}): {e}"));
    k
}

/// **Make a `LocalSigner`'s key live** (an engine's signer): its
/// self-signed `key:record`, signed through `LocalSigner::sign_composite`
/// (`edition2::produce::sign_row`); its kid. When the signer's `key_id` is a
/// seed whose [`kid`] is this kid (a `tier_ingest::test_support::local_signer`),
/// the kid resolves to that seed like any other ([`seed_of`]); otherwise it
/// is a foreign kid ([`is_foreign_kid`]).
///
/// # Panics
/// The signer has no PQC half; the store refuses the record.
pub async fn put_key_for_signer<D: FederationDirectory + ?Sized>(
    dir: &D,
    signer: &crate::signing::LocalSigner,
    identity_types: &[&str],
) -> String {
    let pk = super::produce::composite_public_key(signer)
        .await
        .unwrap_or_else(|e| panic!("fixture_switch: put_key_for_signer: {e}"));
    let k = identity_ref(&thumbprint(&pk));
    let sign = |types: &[&str], opts: &KeyRecordOptions| {
        let payload = key_record_payload(&pk, &k, types, opts);
        let k = k.clone();
        async move {
            super::produce::sign_row(
                signer,
                &k,
                "scores",
                ciris_verify_core::edition2::keys::KEY_RECORD_FAMILY,
                &payload,
            )
            .await
            .unwrap_or_else(|e| panic!("fixture_switch: put_key_for_signer({k}): {e}"))
        }
    };
    let alias = signer.key_id();
    if !alias.starts_with("urn:") && kid(alias) == k {
        // A seeded signer: `kid(alias)` already registered it in the seed map.
    } else {
        let user = sign(
            &["user"],
            &KeyRecordOptions {
                asserted_at_ms: Some(0),
                ..KeyRecordOptions::default()
            },
        )
        .await;
        foreign_records()
            .lock()
            .expect("foreign map")
            .insert(k.clone(), user);
    }
    let record = sign(identity_types, &KeyRecordOptions::default()).await;
    put_statement(dir, &record)
        .await
        .unwrap_or_else(|e| panic!("fixture_switch: put_key_for_signer({k}): {e}"));
    k
}

/// [`statement_of_family`] signed by an explicit composite key (a key no
/// seed names, e.g. registered by [`put_key_for_composite`]).
///
/// # Panics
/// As [`statement_of_family`].
#[must_use]
pub fn statement_of_with_key(a: &Attestation, key: &CompositeSigningKey, family: &str) -> Vec<u8> {
    let a = &*edition2_shape(a);
    let iref = identity_ref(&thumbprint(key.public_key()));
    let payload = payload_of(a, family, &iref);
    let st = sign_row_statement(
        key,
        &iref,
        &subject_of(&a.attested_key_id),
        &a.attestation_type,
        family,
        &payload,
        vec![],
    )
    .expect("fixture_switch: sign");
    if let Some(id) = RowId::of_statement(&st) {
        row_families()
            .lock()
            .expect("family map")
            .insert(id.hex(), family.to_owned());
    }
    st
}

/// A `key:revocation` of `subject_seed`'s key, signed by `signer_seed`.
#[must_use]
pub fn key_revocation(
    signer_seed: &str,
    subject_seed: &str,
    revoked_after_ms: Option<u64>,
) -> Vec<u8> {
    let signer = signing_key(signer_seed);
    let iss = identity_ref(&thumbprint(signer.public_key()));
    let mut m = vec![
        (
            text("asserted_at"),
            Value::Uint(ms(crate::host::clock::now())),
        ),
        (text("author"), text(&iss)),
    ];
    if let Some(b) = revoked_after_ms {
        m.push((text("revoked_after"), Value::Uint(b)));
    }
    sign_row_statement(
        &signer,
        &iss,
        &kid(subject_seed),
        "scores",
        super::liveness::KEY_REVOCATION_FAMILY,
        &det_map(m),
        vec![],
    )
    .expect("fixture_switch: sign a key revocation")
}

/// A reader holding each `(seed, identity types)`'s [`key_record`].
#[must_use]
pub fn held_keys(records: &[(&str, &[&str])]) -> HeldKeys {
    let mut keys = HeldKeys::new();
    for (seed, types) in records {
        keys.insert_record(key_record(seed, types));
    }
    keys
}

/// **A key's `federation_keys` read model** (edition 2): what
/// `projection::key_projection` writes for [`key_record`]`(seed, types)`.
#[must_use]
pub fn key_row(seed: &str, identity_types: &[&str]) -> KeyRecord {
    key_row_with(seed, identity_types, &KeyRecordOptions::default())
}

/// [`key_row`] of [`key_record_with`].
///
/// # Panics
/// A record the key plane does not find valid (e.g. one breaking the end
/// rule): a witness of that refusal uses [`key_record_with`] directly.
#[must_use]
pub fn key_row_with(seed: &str, identity_types: &[&str], opts: &KeyRecordOptions) -> KeyRecord {
    let st = key_record_with(seed, identity_types, opts);
    let mut held = HeldKeys::new();
    if let Some(s) = &opts.signer {
        held.insert_record(key_record(s, &["user"]));
    }
    held.insert_record(st);
    let p = super::projection::key_projection(&held, &kid_digest(seed))
        .unwrap_or_else(|e| panic!("fixture_switch: key_row({seed}): {e}"))
        .unwrap_or_else(|| panic!("fixture_switch: key_row({seed}): no valid record"));
    serde_json::from_value(serde_json::json!({
        "key_id": p.key_id,
        "pubkey_ed25519_base64": p.pubkey_ed25519_base64,
        "pubkey_ml_dsa_65_base64": p.pubkey_ml_dsa_65_base64,
        "algorithm": crate::federation::types::algorithm::HYBRID,
        "identity_type": p.identity_type,
        "identity_ref": p.key_id,
        "valid_from": p.valid_from,
        "valid_until": p.valid_until,
        "registration_envelope": p.registration_envelope,
        "original_content_hash": p.original_content_hash,
        "scrub_signature_classical": p.scrub_signature_classical,
        "scrub_key_id": p.scrub_key_id,
        "scrub_timestamp": p.scrub_timestamp,
        "pqc_completed_at": p.scrub_timestamp,
        "persist_row_hash": p.persist_row_hash,
        "attestation_evidence": p.attestation_evidence,
        "consent_role": "unregistered",
    }))
    .expect("fixture_switch: the projection is a KeyRecord")
}

/// The `key:record` statement a [`key_row`] carries.
#[must_use]
pub fn key_statement_of(rec: &KeyRecord) -> Option<Vec<u8>> {
    rec.registration_envelope
        .get(STATEMENT_MEMBER)
        .and_then(serde_json::Value::as_str)
        .and_then(|h| hex::decode(h).ok())
}

/// The edition-2 shape of an earlier key-record builder's record: `key_id`
/// is the seed; `identity_type` the earlier comma-joined set; `valid_until`
/// and `asserted_at` the earlier instants, fitted to the end rule (a node /
/// agent record runs at most 365 days; one whose end is before the default
/// start starts a day before its end).
///
/// # Panics
/// A `user` / `accord_holder` record given an end: such a key carries none
/// (RULINGS, key liveness); a witness of an ended key revokes it instead
/// ([`key_revocation`]).
#[must_use]
pub fn key_row_for_earlier(
    key_id: &str,
    identity_type: &str,
    asserted_at: Option<chrono::DateTime<chrono::Utc>>,
    valid_until: Option<chrono::DateTime<chrono::Utc>>,
) -> KeyRecord {
    let types = identity_types_of(identity_type);
    let no_end = types.iter().any(|t| matches!(*t, "user" | "accord_holder"));
    assert!(
        !(no_end && valid_until.is_some()),
        "fixture_switch: a {identity_type} key carries no end in edition 2; revoke it \
         (key_revocation) to end it"
    );
    let mut at = asserted_at.map_or_else(|| default_asserted_at(&types), ms);
    let mut until = valid_until.map(ms);
    if must_end(&types) {
        let u = until.unwrap_or(at.saturating_add(NODE_KEY_MAX_MS));
        if u < at {
            at = u.saturating_sub(DAY_MS);
        }
        until = Some(u.min(at.saturating_add(NODE_KEY_MAX_MS)));
    }
    // The fixed-instant guard follows this key: a default window is
    // remembered, an explicit one forgets any earlier default.
    note_window(
        key_id,
        if asserted_at.is_none() && valid_until.is_none() {
            default_window(&types)
        } else {
            None
        },
    );
    key_row_with(
        key_id,
        &types,
        &KeyRecordOptions {
            asserted_at_ms: Some(at),
            valid_until_ms: until,
            ..KeyRecordOptions::default()
        },
    )
}

// ---------------------------------------------------------------------------
// The typed planes' statements (their struct builders are not flipped)
// ---------------------------------------------------------------------------

/// One `group:roster` member.
#[derive(Clone, Debug)]
pub struct RosterMember<'a> {
    /// The member's seed.
    pub seed: &'a str,
    /// When it joined, POSIX ms.
    pub joined_at_ms: u64,
    /// Its role, if any.
    pub role: Option<&'a str>,
}

/// A `group:roster` row (counted: no author), as `signer_seed`'s voice.
/// Each further member's voice is [`voice_of`].
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn roster_statement(
    group_kind: &str,
    group_seed: &str,
    name: &str,
    version: u64,
    members: &[RosterMember<'_>],
    consensus_protocol: &str,
    founded_at_ms: u64,
    prev: Option<Digest32>,
    signer_seed: &str,
) -> Vec<u8> {
    let group = kid(group_seed);
    let mut ms_: Vec<Value> = members
        .iter()
        .map(|m| {
            let mut e = vec![
                (text("key"), text(&kid(m.seed))),
                (text("joined_at"), Value::Uint(m.joined_at_ms)),
            ];
            if let Some(r) = m.role {
                e.push((text("role"), text(r)));
            }
            det_map(e)
        })
        .collect();
    // Sorted by each entry's full encoding (P1's set rule), not by `key`.
    ms_.sort_by_key(cde::encode);
    let mut p = vec![
        (text("asserted_at"), Value::Uint(founded_at_ms)),
        (text("group_kind"), text(group_kind)),
        (text("group"), text(&group)),
        (text("name"), text(name)),
        (text("version"), Value::Uint(version)),
        (text("members"), Value::Array(ms_)),
        (text("founded_at"), Value::Uint(founded_at_ms)),
        (text("consensus_protocol"), text(consensus_protocol)),
    ];
    if let Some(d) = prev {
        p.push((
            text("refs"),
            det_map(vec![(
                // P1: a roster names its predecessor version by `refs.head`.
                text("head"),
                ciris_verify_core::edition2::row_ref(&d),
            )]),
        ));
    }
    let key = signing_key(signer_seed);
    let iref = identity_ref(&thumbprint(key.public_key()));
    sign_row_statement(
        &key,
        &iref,
        &group,
        "scores",
        "group:roster",
        &det_map(p),
        vec![],
    )
    .expect("fixture_switch: sign a roster")
}

/// A `membership:{stage}` row (`removal` | `widening`; counted), as
/// `signer_seed`'s voice. The dimension is `membership:{stage}:v1`.
#[must_use]
pub fn membership_statement(
    stage: &str,
    group_kind: &str,
    group_seed: &str,
    member_seed: &str,
    effective_at_ms: u64,
    signer_seed: &str,
) -> Vec<u8> {
    let member = kid(member_seed);
    let mut p = vec![
        (text("asserted_at"), Value::Uint(effective_at_ms)),
        (text("dimension"), text(&format!("membership:{stage}:v1"))),
        (text("group_kind"), text(group_kind)),
        (text("group"), text(&kid(group_seed))),
        (text("member"), text(&member)),
        (text("effective_at"), Value::Uint(effective_at_ms)),
    ];
    match stage {
        "removal" => p.push((text("removed_at"), Value::Uint(effective_at_ms))),
        "widening" => p.push((text("joined_at"), Value::Uint(effective_at_ms))),
        other => panic!("fixture_switch: membership stage {other:?}"),
    }
    let key = signing_key(signer_seed);
    let iref = identity_ref(&thumbprint(key.public_key()));
    sign_row_statement(
        &key,
        &iref,
        &member,
        "scores",
        "membership:.stage",
        &det_map(p),
        vec![],
    )
    .expect("fixture_switch: sign a membership change")
}

/// **The edition-2 twin of `tier_ingest::test_support::
/// bound_transit_revocation_input`** (same inputs): `subject`'s
/// `consent:state:revoked:v1` row about `target` (family
/// `consent:state:.stance` from the dimension), score 1.0, confidence 0.9,
/// `extra`'s members merged into the payload, at tier `local`, signed by
/// `subject`'s composite through the codec. `attestation_id` is IGNORED as an
/// id (an edition-2 row is named by the id this node computes: read
/// [`rid`]). `subject` is a seed or a kid this module minted; put the row
/// with [`put_signed`] after [`put_key`]`(subject, ..)`.
///
/// # Panics
/// The door refuses the row; `extra` is not a JSON object.
#[must_use]
pub fn transit_revocation_row(
    attestation_id: &str,
    subject: &str,
    target: &str,
    subject_key_ids: Vec<String>,
    cohort_scope: &str,
    asserted_at: chrono::DateTime<chrono::Utc>,
    extra: serde_json::Value,
) -> Attestation {
    let asserted = crate::federation::admission::truncate_to_substrate_resolution(asserted_at);
    let mut envelope = serde_json::json!({
        "dimension": "consent:state:revoked:v1",
        "score": 1.0,
        "confidence": 0.9,
    });
    if let (Some(obj), Some(more)) = (envelope.as_object_mut(), extra.as_object()) {
        for (k, v) in more {
            obj.insert(k.clone(), v.clone());
        }
    } else {
        assert!(
            extra.is_null(),
            "fixture_switch: `extra` is not a JSON object"
        );
    }
    let literal: Attestation = serde_json::from_value(serde_json::json!({
        "attestation_id": attestation_id,
        "attesting_key_id": kid(subject),
        "attested_key_id": target,
        "attestation_type": attestation_type::SCORES,
        "asserted_at": asserted,
        "attestation_envelope": envelope,
        "original_content_hash": "",
        "scrub_signature_classical": "",
        "scrub_key_id": kid(subject),
        "scrub_timestamp": asserted,
        "persist_row_hash": "",
        "subject_key_ids": subject_key_ids,
        "cohort_scope": cohort_scope,
        "tier": crate::federation::types::attestation_tier::LOCAL,
    }))
    .expect("fixture_switch: the transit revocation literal");
    row_of(&literal, subject)
}

// ---------------------------------------------------------------------------
// 5. Store helpers (any FederationDirectory: sqlite AND postgres)
// ---------------------------------------------------------------------------

/// Put one statement through the one entry (`ingest::put_statement`) at
/// tier `federation`.
///
/// # Errors
/// The door's and the gates' refusals.
pub async fn put_statement<D: FederationDirectory + ?Sized>(
    dir: &D,
    statement: &[u8],
) -> Result<StatementOutcome, Error> {
    super::ingest::put_statement(dir, statement, None, INGEST_TIER).await
}

/// Make `seed`'s key live in `dir` ([`key_record`]); its identity-ref.
///
/// # Panics
/// The store refuses the record.
pub async fn put_key<D: FederationDirectory + ?Sized>(
    dir: &D,
    seed: &str,
    identity_types: &[&str],
) -> String {
    put_key_with(dir, seed, identity_types, &KeyRecordOptions::default()).await
}

/// [`put_key`] of [`key_record_with`].
///
/// # Panics
/// The store refuses the record.
pub async fn put_key_with<D: FederationDirectory + ?Sized>(
    dir: &D,
    seed: &str,
    identity_types: &[&str],
    opts: &KeyRecordOptions,
) -> String {
    if let Some(s) = &opts.signer {
        put_statement(dir, &key_record(s, &["user"]))
            .await
            .unwrap_or_else(|e| panic!("fixture_switch: put_key({s}): {e}"));
    }
    put_statement(dir, &key_record_with(seed, identity_types, opts))
        .await
        .unwrap_or_else(|e| panic!("fixture_switch: put_key({seed}): {e}"));
    let default = opts.asserted_at_ms.is_none() && opts.valid_until_ms.is_none() && !opts.no_end;
    note_window(
        seed,
        if default {
            default_window(identity_types)
        } else {
            None
        },
    );
    kid(seed)
}

/// Put the `key:record` a [`key_row`] carries.
///
/// # Panics
/// A record that carries no statement; the store refuses it.
pub async fn put_key_row<D: FederationDirectory + ?Sized>(dir: &D, rec: &KeyRecord) {
    let st = key_statement_of(rec).unwrap_or_else(|| {
        panic!(
            "fixture_switch: {} is an earlier-form record (no ceg_statement)",
            rec.key_id
        )
    });
    put_statement(dir, &st)
        .await
        .unwrap_or_else(|e| panic!("fixture_switch: put_key_row({}): {e}", rec.key_id));
}

/// Put the statement a mapped row carries (at the row's tier).
///
/// # Errors
/// The door's and the gates' refusals.
///
/// # Panics
/// A row that carries no statement.
pub async fn put_signed<D: FederationDirectory + ?Sized>(
    dir: &D,
    row: &Attestation,
) -> Result<StatementOutcome, Error> {
    let st = carried_statement(row).unwrap_or_else(|| {
        panic!(
            "fixture_switch: put_signed: row {} carries no statement",
            row.attestation_id
        )
    });
    check_default_window(&st);
    super::ingest::put_statement(dir, &st, None, tier_of(row)).await
}

/// v62.0.0 (K2, red round 3; CC 3.2 *The first binding (MUST)*, C557; CC 2.7.5
/// "a seat is two consents"; CC 2.7.3: a row short of a voice is HELD, never
/// refused) — **an owner binding, landed the way the door counts it.** The
/// `ownership:{relation}:{target_kind}:{version}` family names the bound key
/// as its second signer (`second_signers: bound_node`, member `sub`, CC 3.2 /
/// CC 3.4.5, the vendored `family_authorship.json`), and
/// `admission::check_owner_binding_counted` counts the owner's voice AND the
/// bound key's voice before the typed row lands. So:
///
/// 1. the owner's statement the row carries goes through the statement door
///    ([`put_signed`]): it is kept and the row is held (`Pending`, reason
///    `count_short`) until the bound key speaks;
/// 2. the bound key's own voice over the SAME payload ([`voice_of`] by
///    `node_seed`) goes through the same door ([`put_statement`]) and lands
///    the row.
///
/// Returns the second statement's outcome: `Row` when the binding lands;
/// `Voice` when it was already held; `Pending` while another counted voice
/// is still short (an affiliation's quorum, CC 3.2 ruling (a)).
///
/// The owner's statement is NEVER put through `put_attestation`: that entry
/// runs the counted gate outside a fold attempt, so a binding short of the
/// node's voice is refused there `owner_binding_counted_short` (the 23 reds
/// this helper retires), not held.
///
/// Both statements are judged against their signers' default windows
/// ([`check_default_window`]): a default node key's record starts
/// [`NODE_DEFAULT_BACK_DAYS`] before today, so a binding dated before that (a
/// fixed calendar date) panics here, naming the fix, instead of waiting
/// `AttesterKeyUnknown` at the node's voice.
///
/// # Errors
/// The door's and the gates' refusals of either statement.
///
/// # Panics
/// A row that carries no statement (the earlier form: put it through
/// `put_attestation`); a statement outside its signer's default window.
pub async fn land_owner_binding<D: FederationDirectory + ?Sized>(
    dir: &D,
    binding: &Attestation,
    node_seed: &str,
) -> Result<StatementOutcome, Error> {
    let st = carried_statement(binding).unwrap_or_else(|| {
        panic!(
            "fixture_switch: land_owner_binding: binding {} carries no statement",
            binding.attestation_id
        )
    });
    let voice = voice_of(&st, node_seed);
    check_default_window(&voice);
    put_signed(dir, binding).await?;
    put_statement(dir, &voice).await
}

/// [`statement_of`] put through the store; the row as mapped.
///
/// # Errors
/// The door's and the gates' refusals.
pub async fn try_put_row<D: FederationDirectory + ?Sized>(
    dir: &D,
    a: &Attestation,
    seed: &str,
) -> Result<Attestation, Error> {
    let st = try_statement_of_door(a, seed)?;
    check_default_window(&st);
    super::ingest::put_statement(dir, &st, None, tier_of(a)).await?;
    try_row_of_statement(&st, tier_of(a))
}

/// [`try_put_row`], panicking on a refusal.
pub async fn put_row<D: FederationDirectory + ?Sized>(
    dir: &D,
    a: &Attestation,
    seed: &str,
) -> Attestation {
    try_put_row(dir, a, seed)
        .await
        .unwrap_or_else(|e| panic!("fixture_switch: put_row: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strip_body_comments(s: &str) -> String {
        s.lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The body text of `pub fn name` in `src` (to its closing brace).
    fn body_of(src: &str, name: &str) -> Option<String> {
        let mut from = 0;
        while let Some(i) = src[from..].find(&format!("fn {name}")) {
            let start = from + i;
            let after = &src[start + 3 + name.len()..];
            if !after.starts_with(['(', '<']) {
                from = start + 1;
                continue;
            }
            let open = start + src[start..].find('{')?;
            let (mut depth, mut j) = (1usize, open + 1);
            let bytes = src.as_bytes();
            while depth > 0 && j < bytes.len() {
                match bytes[j] {
                    b'{' => depth += 1,
                    b'}' => depth -= 1,
                    _ => {}
                }
                j += 1;
            }
            return Some(strip_body_comments(&src[open..j]));
        }
        None
    }

    /// The typed-row builders of every `mod test_support` under `src/`,
    /// re-derived from disk.
    fn builders_on_disk() -> Vec<String> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut out = Vec::new();
        let mut stack = vec![root.join("src")];
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(&dir).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                if p.extension().and_then(|x| x.to_str()) != Some("rs") {
                    continue;
                }
                let s = std::fs::read_to_string(&p).unwrap();
                let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
                let mut from = 0;
                while let Some(i) = s[from..].find("mod test_support") {
                    let start = from + i;
                    let after = s[start + "mod test_support".len()..].trim_start();
                    if !after.starts_with('{') {
                        from = start + 1;
                        continue;
                    }
                    let Some(open) = s[start..].find('{') else {
                        break;
                    };
                    let (mut depth, mut j) = (1usize, start + open + 1);
                    let bytes = s.as_bytes();
                    while depth > 0 && j < bytes.len() {
                        match bytes[j] {
                            b'{' => depth += 1,
                            b'}' => depth -= 1,
                            _ => {}
                        }
                        j += 1;
                    }
                    let body = &s[start + open + 1..j.saturating_sub(1)];
                    for (k, _) in body.match_indices("fn ") {
                        let head = &body[..k];
                        let line_start = head.rfind('\n').map_or(0, |n| n + 1);
                        let prefix = head[line_start..].trim();
                        let public = ["pub", "pub(crate)"]
                            .iter()
                            .any(|v| prefix == *v || prefix.starts_with(&format!("{v} ")));
                        if !public {
                            continue;
                        }
                        let rest = &body[k + 3..];
                        let name: String = rest
                            .chars()
                            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                            .collect();
                        let sig_end = rest.find(['{', ';']).unwrap_or(rest.len());
                        let sig = &rest[..sig_end];
                        let Some(arrow) = sig.find("->") else {
                            continue;
                        };
                        let ret = &sig[arrow..];
                        let typed = [
                            "SignedAttestation",
                            "SignedKeyRecord",
                            "SignedFamily",
                            "SignedCommunity",
                        ]
                        .iter()
                        .any(|t| ret.contains(t))
                            || ret
                                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                                .any(|w| w == "Attestation" || w == "KeyRecord");
                        if typed {
                            out.push(format!("{rel}::{name}"));
                        }
                    }
                    from = j;
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// **I1912**: the flip list is every typed-row builder on disk.
    #[test]
    fn i1912_the_flip_list_is_complete() {
        let mut listed: Vec<String> = FLIP.iter().map(|s| (*s).to_owned()).collect();
        listed.sort();
        assert_eq!(builders_on_disk(), listed, "I1912: FLIP is stale");
        assert_eq!(FLIP.len(), 35, "I1912: the count");
    }

    /// **I2541 (E0)**: every builder of [`FLIP`] not in [`NOT_FLIPPED`]
    /// reaches the switch: its body (comments stripped) reads
    /// `emit_edition2`, or seals through `seal_row` / `seal_row_in_place` /
    /// `reseal`, which read it. Re-derived from disk, so a builder that stops
    /// reaching the switch is red.
    #[test]
    fn i2541_every_flipped_builder_reaches_the_switch() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let seal = [
            "emit_edition2",
            "seal_row(",
            "seal_row_in_place(",
            "reseal(",
        ];
        for entry in FLIP {
            if NOT_FLIPPED.contains(entry) {
                continue;
            }
            let (file, name) = entry.split_once("::").unwrap();
            let src = std::fs::read_to_string(root.join(file)).unwrap();
            let body = body_of(&src, name).unwrap_or_else(|| panic!("I2541: {entry} not found"));
            if *entry == "src/federation/tier_ingest.rs::seal_row" {
                // seal_row delegates to seal_row_in_place, which reads it.
                let inner = body_of(&src, "seal_row_in_place").unwrap();
                assert!(inner.contains("emit_edition2"), "I2541: seal_row_in_place");
                continue;
            }
            let reaches = |b: &str| seal.iter().any(|s| b.contains(s));
            // Directly, or through one helper of the same file it calls.
            // Every identifier written directly before a `(`: a call such as
            // `sealed(member, ..)` on one line is a callee as much as one whose
            // arguments start on the next line.
            let callees = body
                .match_indices('(')
                .filter_map(|(i, _)| {
                    let head = &body[..i];
                    let start = head
                        .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                        .map_or(0, |j| j + 1);
                    let ident = &head[start..];
                    (!ident.is_empty() && ident != name).then_some(ident)
                })
                .filter_map(|t| body_of(&src, t))
                .any(|b| reaches(&b));
            assert!(
                reaches(&body) || callees,
                "I2541: {entry} does not reach the switch"
            );
        }
        for entry in NOT_FLIPPED {
            assert!(FLIP.contains(entry), "I2541: {entry} is not a builder");
        }
    }

    /// **I2550 (the async scope)**: inside `with_earlier_form_async` every
    /// poll reads the earlier form, across an await and on a multi-thread
    /// runtime's workers; outside it the default is back; a nested
    /// `with_edition2_async` turns it back on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn i2550_the_async_scope_holds_across_awaits() {
        assert!(emit_edition2());
        let inside = with_earlier_form_async(async {
            let before = emit_edition2();
            tokio::task::yield_now().await;
            let after = emit_edition2();
            let nested = with_edition2_async(async { emit_edition2() }).await;
            (before, after, nested)
        })
        .await;
        assert_eq!(inside, (false, false, true), "I2550");
        assert!(emit_edition2(), "I2550: restored");
    }

    #[test]
    fn i1912_the_switch_is_per_thread_and_restores() {
        assert!(emit_edition2(), "I1912: default ON");
        assert!(!with_earlier_form(emit_edition2));
        assert!(emit_edition2(), "I1912: restored");
        assert!(with_earlier_form(|| with_edition2(emit_edition2)));
        let other = std::thread::spawn(|| with_earlier_form(emit_edition2));
        assert!(!other.join().unwrap());
        assert!(emit_edition2(), "I1912: per thread");
    }

    /// **I2542**: `kid` is the identity-ref of the key `local_signer` signs
    /// with, `signing_key` reads an identity-ref it derived back to its seed,
    /// and a seed's first 32 bytes name it.
    #[test]
    fn i2542_kid_names_the_local_signers_key() {
        let k = kid("e0-alpha");
        assert!(is_kid(&k));
        assert_eq!(kid(&k), k, "I2542: an identity-ref is kept");
        assert_eq!(
            thumbprint(signing_key(&k).public_key()),
            kid_digest("e0-alpha"),
            "I2542: the kid resolves to its seed"
        );
        let long = "e0-0123456789abcdef0123456789abcdef";
        assert_eq!(
            kid(long),
            kid(&format!("{long}-suffix")),
            "I2542: the first 32 bytes"
        );
        assert_ne!(kid("e0-alpha"), kid("e0-beta"));
        assert_eq!(seed_of(&k), "e0-alpha", "I2542: seed_of inverts kid");
        assert_eq!(seed_of("e0-alpha"), "e0-alpha");
        let thumb = kid_thumb("e0-alpha");
        assert_eq!(thumb.len(), 43, "I2542: the bare thumbprint");
        assert!(k.ends_with(&thumb) && !thumb.contains(':'));
        let h = format!("sha256:{}", "ab".repeat(32));
        assert_eq!(
            kid_or_keep(&h),
            h,
            "I2542: a canonical-hash subject is kept"
        );
        let c = format!("canonical:{h}");
        assert_eq!(kid_or_keep(&c), c);
        assert_eq!(kid_or_keep(&"cd".repeat(32)), "cd".repeat(32));
        // A kid is never a seed: an unknown identity-ref is refused, never
        // seeded from its (shared) first 32 bytes.
        let unknown = format!(
            "{}{}",
            ciris_verify_core::edition2::IDENTITY_REF_PREFIX,
            "A".repeat(43)
        );
        assert!(
            std::panic::catch_unwind(|| signing_key(&unknown)).is_err(),
            "I2542: an unminted kid does not seed"
        );
        // The earlier-form helpers resolve a MINTED kid through the map (the
        // same key), and refuse an unminted one.
        assert_eq!(
            crate::federation::tier_ingest::test_support::hybrid_pubkeys(&k),
            crate::federation::tier_ingest::test_support::hybrid_pubkeys("e0-alpha"),
            "I2542: a minted kid is its seed's key"
        );
        assert!(std::panic::catch_unwind(|| {
            crate::federation::tier_ingest::test_support::hybrid_pubkeys(&unknown)
        })
        .is_err());
    }

    fn literal(dimension: &str, at: &str) -> Attestation {
        serde_json::from_value(serde_json::json!({
            "attestation_id": "literal",
            "attesting_key_id": "e0-signer",
            "attested_key_id": "e0-subject",
            "attestation_type": "scores",
            "asserted_at": at,
            "attestation_envelope": {
                "dimension": dimension,
                "score": 0.75,
                "confidence": 0.9,
            },
            "original_content_hash": "",
            "scrub_signature_classical": "",
            "scrub_key_id": "e0-signer",
            "scrub_timestamp": at,
            "persist_row_hash": "",
        }))
        .unwrap()
    }

    fn strip(a: &Attestation) -> serde_json::Value {
        let mut e = a.attestation_envelope.clone();
        let o = e.as_object_mut().unwrap();
        for k in [
            STATEMENT_MEMBER,
            "row",
            "author",
            "asserted_at",
            "expires_at",
            REFERENCES_MEMBER,
        ] {
            o.remove(k);
        }
        e
    }

    /// **I2540 (the codec round trip)**: an earlier-form-shaped literal
    /// through `row_of` keeps its envelope (less the mapping's own members),
    /// type, subject (as an identity-ref), instant (at ms) and tier; its
    /// id is the node-computed one; and `statement_of` of the mapped row is
    /// the same statement, byte for byte.
    #[test]
    fn i2540_the_codec_round_trips() {
        let dim = "evidence:safety_battery:capture:a:b:v1";
        let a = literal(dim, "2026-01-02T03:04:05.678Z");
        let st = statement_of(&a, "e0-signer");
        let row = row_of(&a, "e0-signer");
        assert_eq!(strip(&row), strip(&a), "I2540: the envelope survives");
        assert_eq!(row.attestation_type, a.attestation_type);
        assert_eq!(row.attested_key_id, kid("e0-subject"));
        assert_eq!(row.attesting_key_id, kid("e0-signer"));
        assert_eq!(row.scrub_key_id, kid("e0-signer"));
        assert_eq!(row.asserted_at, a.asserted_at, "I2540: the instant");
        assert_eq!(row.tier, a.tier);
        assert_eq!(rid(&row), row.attestation_id, "I2540: rid");
        assert_eq!(row.attestation_id, row.persist_row_hash);
        assert_eq!(carried_statement(&row).as_deref(), Some(st.as_slice()));
        assert_eq!(statement_of(&row, "e0-signer"), st, "I2540: and back");
        // Re-sealing under the row's own (kid) signer is the same statement.
        let signer = row.attesting_key_id.clone();
        assert_eq!(statement_of(&row, &signer), st, "I2540: re-seal by kid");
        assert_eq!(family_of(&a), "evidence:.suite:.kind:.cell:.prefix");
    }

    /// **I2543 (a composer carries its target's family)**: `composer_of`
    /// names the target by its row id under `refs.target`, which the mapping
    /// projects back as `references_attestation_id`; a literal composer
    /// naming a minted row by `rid` finds the same family.
    #[test]
    fn i2543_a_composer_names_its_target_and_family() {
        let target = row_of(
            &literal(
                "evidence:safety_battery:capture:a:b:v1",
                "2026-01-02T03:04:05Z",
            ),
            "e0-signer",
        );
        let w = composer_of("withdraws", &target, "e0-signer");
        assert_eq!(w.attestation_type, "withdraws");
        assert_eq!(
            w.attestation_envelope[REFERENCES_MEMBER],
            serde_json::json!(rid(&target)),
            "I2543: refs.target is the target's row id"
        );
        let (p, _) = statement_parts(&carried_statement(&w).unwrap()).unwrap();
        assert_eq!(
            p.get_int(-70002).and_then(Value::as_text),
            Some("evidence:.suite:.kind:.cell:.prefix"),
            "I2543: the target's family"
        );
        let mut lit = target.clone();
        lit.attestation_type = "withdraws".into();
        lit.attestation_envelope = serde_json::json!({ REFERENCES_MEMBER: rid(&target) });
        assert_eq!(family_of(&lit), "evidence:.suite:.kind:.cell:.prefix");
    }

    /// **I2544 (a further voice is a voice of the same row)**: a counted
    /// roster's second member's statement names the same row id; an
    /// authored row's voice keeps the payload bytes.
    #[test]
    fn i2544_a_voice_is_of_the_same_row() {
        let st = roster_statement(
            "community",
            "e0-group",
            "e0 room",
            1,
            &[
                RosterMember {
                    seed: "e0-a",
                    joined_at_ms: 1_000,
                    role: Some("founder"),
                },
                RosterMember {
                    seed: "e0-b",
                    joined_at_ms: 1_000,
                    role: None,
                },
            ],
            "majority",
            1_000,
            None,
            "e0-a",
        );
        let v = voice_of(&st, "e0-b");
        assert_ne!(v, st);
        assert_eq!(
            RowId::of_statement(&v),
            RowId::of_statement(&st),
            "I2544: one row, two voices"
        );
        assert_eq!(
            super::super::door::raw_payload(&v),
            super::super::door::raw_payload(&st)
        );
    }

    /// **I2545 (the key plane)**: a node record ends within 365 days of its
    /// start and is live today; a user record carries no end; the read model
    /// carries its statement under the identity-ref; a node record with no
    /// end is refused by the end rule (`key_record_out_of_window`).
    #[test]
    fn i2545_key_records_keep_the_end_rule() {
        let now = ms(crate::host::clock::now());
        let node = key_row("e0-node", &["node"]);
        assert_eq!(node.key_id, kid("e0-node"));
        assert_eq!(node.identity_ref, node.key_id);
        let from = ms(node.valid_from);
        let until = ms(node.valid_until.expect("I2545: a node record ends"));
        assert!(from <= now && now <= until, "I2545: live today");
        assert!(until - from <= NODE_KEY_MAX_MS, "I2545: at most 365 days");
        assert!(
            from + NODE_DEFAULT_BACK_DAYS * DAY_MS <= now,
            "I2545: the default window reaches 180 days back"
        );
        assert!(
            until >= now + 180 * DAY_MS,
            "I2545: a forward margin of months, not days"
        );
        assert!(
            key_statement_of(&node).is_some(),
            "I2545: carries its statement"
        );
        assert_eq!(
            super::super::projection::edition_of_key_record(&node),
            super::super::projection::EDITION_TWO
        );
        let user = key_row("e0-user", &["user"]);
        assert_eq!(user.valid_until, None, "I2545: a user record has no end");
        let open = key_record_with(
            "e0-node",
            &["node"],
            &KeyRecordOptions {
                no_end: true,
                ..KeyRecordOptions::default()
            },
        );
        match try_admit(&open, &signer_held(&open)) {
            Err(Error::MalformedRow { reason, .. }) => assert_eq!(
                reason,
                super::super::token::KEY_RECORD_OUT_OF_WINDOW,
                "I2545: a node record with no end"
            ),
            other => panic!("I2545: {other:?}"),
        }
    }

    /// **I2549 (the fixed-instant guard)**: a key put with the DEFAULT node
    /// window that signs a row outside it panics naming the rule (node / agent
    /// rows are now-relative; fixed dates take a key with no end), and an
    /// explicit record for the same key lifts the guard.
    #[test]
    fn i2549_a_default_key_outside_its_window_names_the_fix() {
        let seed = "e0-window-node";
        note_window(seed, default_window(&["node"]));
        let mut a = literal(
            "evidence:safety_battery:capture:a:b:v1",
            "2020-01-01T00:00:00Z",
        );
        a.attested_key_id = seed.into();
        let st = statement_of(&a, seed);
        let msg = std::panic::catch_unwind(|| check_default_window(&st))
            .expect_err("I2549: refused")
            .downcast::<String>()
            .map(|b| *b)
            .unwrap_or_default();
        assert!(
            msg.contains("NOW-RELATIVE") && msg.contains("user / accord_holder"),
            "I2549: names the fix: {msg}"
        );
        // A now-relative row is inside the window.
        a.asserted_at = crate::host::clock::now();
        check_default_window(&statement_of(&a, seed));
        // An explicit record forgets the default window.
        note_window(seed, None);
        a.asserted_at = "2020-01-01T00:00:00Z".parse().unwrap();
        check_default_window(&statement_of(&a, seed));
    }

    /// **I2551 (the transit revocation twin)**: the edition-2 transit
    /// revocation is `subject`'s `consent:state:revoked:v1` row at tier
    /// `local`, signed as `kid(subject)`, carrying its statement, under the
    /// computed id, with `extra` and the subjects in its payload.
    #[test]
    fn i2551_the_transit_revocation_twin() {
        let at = crate::host::clock::now();
        let row = transit_revocation_row(
            "ignored",
            "e0-tr-subject",
            "e0-tr-target",
            vec!["e0-tr-peer".to_owned()],
            crate::federation::types::cohort_scope::FEDERATION,
            at,
            serde_json::json!({ "note": "i2551" }),
        );
        assert_eq!(row.attesting_key_id, kid("e0-tr-subject"));
        assert_eq!(row.attested_key_id, kid("e0-tr-target"));
        assert_eq!(row.tier, crate::federation::types::attestation_tier::LOCAL);
        assert_eq!(row.attestation_id, rid(&row), "I2551: the computed id");
        assert_eq!(row.subject_key_ids, vec![kid("e0-tr-peer")]);
        assert_eq!(row.attestation_envelope["note"], "i2551");
        assert_eq!(family_of(&row), "consent:state:.stance");
        assert!(carried_statement(&row).is_some());
    }

    /// **I2552 (the weight column)**: a literal that sets only the typed
    /// `weight` column carries it as the payload's fixed-scale `weight`
    /// (2.5 → 2_500_000), and an envelope `weight` wins over the column.
    #[test]
    fn i2552_the_weight_column_is_carried() {
        let mut a = literal(
            "evidence:safety_battery:capture:a:b:v1",
            "2026-01-02T03:04:05Z",
        );
        a.weight = Some(2.5);
        let (_, p) = statement_parts(&statement_of(&a, "e0-signer")).unwrap();
        assert_eq!(
            p.get_text("weight").and_then(Value::as_i64),
            Some(2_500_000),
            "I2552: the column, fixed6"
        );
        a.attestation_envelope["weight"] = serde_json::json!(0.5);
        let (_, p) = statement_parts(&statement_of(&a, "e0-signer")).unwrap();
        assert_eq!(
            p.get_text("weight").and_then(Value::as_i64),
            Some(500_000),
            "I2552: the envelope's own weight"
        );
    }

    /// **I2546 (the builders flip)**: with the switch ON, `seal_row` returns
    /// the edition-2 row (signed as `kid(signer)`, carrying its statement,
    /// under the node-computed id); OFF, the earlier form, as before.
    #[test]
    fn i2546_seal_row_reads_the_switch() {
        use crate::federation::tier_ingest::test_support::seal_row;
        let a = literal(
            "evidence:safety_battery:capture:a:b:v1",
            "2026-01-02T03:04:05Z",
        );
        let on = seal_row("e0-signer", a.clone());
        assert_eq!(on.attesting_key_id, kid("e0-signer"));
        assert!(carried_statement(&on).is_some(), "I2546: edition 2");
        assert_eq!(on.attestation_id, rid(&on));
        let off = with_earlier_form(|| seal_row("e0-signer", a.clone()));
        assert_eq!(off.attesting_key_id, "e0-signer", "I2546: the earlier form");
        assert!(carried_statement(&off).is_none());
    }
    /// **I2548 (the builders' families round-trip)**: each flipped builder's
    /// row (an owner binding, a `moderate` delegation, a replication grant, a
    /// membership proposal and its acceptance) is the mapping of its carried
    /// statement, and re-sealing it under its own signer is that statement
    /// again, byte for byte, and the same row.
    #[test]
    fn i2548_the_builders_rows_round_trip() {
        use crate::federation::membership_acceptance::test_support as ma;
        use crate::federation::tier_ingest::test_support as ts;
        let at = crate::federation::admission::truncate_to_substrate_resolution(
            crate::host::clock::now(),
        );
        let proposal = ma::proposal_row("e0-prop", "affiliations", "e0-room", "e0-mem", None, at);
        let rows = vec![
            ts::owner_binding_attestation("e0-ob", "e0-owner", "e0-node"),
            ts::moderate_delegation_attestation("e0-md", "e0-owner", "e0-mod"),
            crate::federation::consent_peer_set::test_support::grant("e0-g", "e0-node", "e0-peer"),
            ma::acceptance_row("e0-mem", &proposal, at),
            proposal,
        ];
        for row in &rows {
            let family = family_of(row);
            let st =
                carried_statement(row).unwrap_or_else(|| panic!("I2548: {family}: not edition 2"));
            assert_eq!(rid(row), row.attestation_id, "I2548: {family}: rid");
            let signer = row.attesting_key_id.clone();
            assert_eq!(
                statement_of(row, &signer),
                st,
                "I2548: {family}: re-seals to its own statement"
            );
            assert_eq!(&row_of(row, &signer), row, "I2548: {family}: the same row");
        }
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod store_tests {
    //! I2547 on every backend: sqlite, and postgres when a test DSN is set.
    use super::*;

    /// **I2547 (through the store)**: a key put by `put_key` is live, and a
    /// row put by `put_row` is held under the id the codec computed, signed
    /// by the key's identity-ref.
    async fn exercise_put_key_and_row<D: FederationDirectory + ?Sized>(dir: &D) {
        let signer = format!("e0-st-{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
        let k = put_key(dir, &signer, &["user"]).await;
        assert_eq!(k, kid(&signer));
        let now = crate::host::clock::now();
        let a: Attestation = serde_json::from_value(serde_json::json!({
            "attestation_id": "x",
            "attesting_key_id": signer,
            "attested_key_id": signer,
            "attestation_type": "scores",
            "asserted_at": now,
            "attestation_envelope": {
                "dimension": "evidence:safety_battery:capture:a:b:v1",
                "score": 0.5,
                "confidence": 0.5,
            },
            "original_content_hash": "",
            "scrub_signature_classical": "",
            "scrub_key_id": signer,
            "scrub_timestamp": now,
            "persist_row_hash": "",
        }))
        .unwrap();
        let row = put_row(dir, &a, &signer).await;
        let held = dir
            .get_attestation(&rid(&row))
            .await
            .unwrap()
            .expect("I2547: held under the computed id");
        assert_eq!(
            held.attesting_key_id, k,
            "I2547: signed as the identity-ref"
        );
        assert!(
            dir.lookup_public_key(&k).await.unwrap().is_some(),
            "I2547: the key's read model"
        );
    }

    /// **I2553 (keys no seed names)**: a hand-built composite goes live by
    /// `put_key_for_composite` and signs a row the store holds under the
    /// computed id; a seeded `local_signer`'s key goes live by
    /// `put_key_for_signer` as `kid(alias)`.
    async fn exercise_foreign_keys<D: FederationDirectory + ?Sized>(dir: &D) {
        let key = CompositeSigningKey::from_seeds(&[0x52; 32], &[0x51; 32]);
        let k = put_key_for_composite(dir, &key, &["user"]).await;
        assert!(is_foreign_kid(&k), "I2553: a foreign kid");
        assert_eq!(seed_of(&k), k, "I2553: no seed is recovered");
        let now = crate::host::clock::now();
        let a: Attestation = serde_json::from_value(serde_json::json!({
            "attestation_id": "x",
            "attesting_key_id": k,
            "attested_key_id": k,
            "attestation_type": "scores",
            "asserted_at": now,
            "attestation_envelope": {
                "dimension": "evidence:safety_battery:capture:a:b:v1",
                "score": 0.5,
                "confidence": 0.5,
            },
            "original_content_hash": "",
            "scrub_signature_classical": "",
            "scrub_key_id": k,
            "scrub_timestamp": now,
            "persist_row_hash": "",
        }))
        .unwrap();
        let st = statement_of_with_key(&a, &key, &family_of(&a));
        put_statement(dir, &st)
            .await
            .expect("I2553: the row is admitted");
        let row = row_of_statement(&st, INGEST_TIER);
        assert!(dir.get_attestation(&rid(&row)).await.unwrap().is_some());
        let alias = format!("e0-ls-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let signer = crate::federation::tier_ingest::test_support::local_signer(&alias);
        assert_eq!(
            put_key_for_signer(dir, &signer, &["user"]).await,
            kid(&alias),
            "I2553: a seeded signer's kid"
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i2553_foreign_keys_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(exercise_foreign_keys(&b)).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i2553_foreign_keys_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(exercise_foreign_keys(&b)).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i2547_put_key_and_row_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(exercise_put_key_and_row(&b)).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i2547_put_key_and_row_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(exercise_put_key_and_row(&b)).await;
    }
}

// v62.0.0 (wave T1) — the typed-plane builders' edition-2 twins
// (`family_voices`, `community_voices`, `family_revocation_voices`, ...,
// `put_voices`, `row_id_of`), so a held test reaches them as `e2::..`.
pub use super::group_fixtures::*;

/// v62.0.0 (wave O1) — the shared `identity:occurrence` bind builders
/// (`edition2::fixture_occurrence`; O1.api.md).
pub use super::fixture_occurrence::{
    occurrence_bind_voices, put_agent_owner_binding, put_bind, BindOptions,
};

// v62.0.0 (wave T2) — the remaining typed planes' edition-2 twins
// (`revocation_statement`, `occurrence_revocation_voice`,
// `takedown_statement`, `custody_statement`, `key_grant_statement`,
// `delivery_receipt_statement`, `cosign_statement`), as `e2::..`.
pub use super::typed_fixtures::*;
// v62.0.0 (wave W1b) — a ROOTED edition-2 trust root (`W1.api.md`).
pub use super::fixture_trust_root::{rooted_trust_root, try_rooted_trust_root, RootedTrustRoot};
