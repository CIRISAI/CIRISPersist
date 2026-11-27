//! v62.0.0 (CE-fix1; CC 2.6.1.11, CC 4.2, CC 5.3.4; CIRISConstitution
//! `formal/ceremony/CEREMONY.md` §3) — **the trust-root genesis ceremony's
//! OFFLINE builders**: every statement the ceremony signs, built by persist's
//! own producers with NO engine and NO store, for a signer outside persist (a
//! holder's YubiKey, a seat's offline custody).
//!
//! Each builder is a pure function over its inputs. It returns a
//! [`Draft`] `{ protected, payload, sig_structure }`; the signer makes ONE
//! composite (ML-DSA-65 + Ed25519, CC 2.6.1.7) signature over
//! `sig_structure`, and [`Draft::assemble`] over that signature is the
//! `COSE_Sign1` statement. Every builder dates its statement from an instant
//! passed in (POSIX ms); none reads a clock. Each step has a self-check
//! running the SAME reading the import door runs, so the ceremony checks a
//! statement before it seals or publishes it. Nothing here does I/O, and
//! nothing is gated on `test-anchor`.
//!
//! In ceremony order (CEREMONY §3):
//!
//! 1. **Each holder's `key:record`** (`identity_type` {`accord_holder`}, no
//!    `valid_until`, the custody evidence): [`holder_key_record_draft`] over
//!    a [`CustodyEvidence`]; check with [`check_key_record`]. The holders'
//!    thumbprints are the release's default anchor:
//!    [`thumbprint_anchor`].
//! 2. **Each seat's `key:record`** (`identity_type` {`node`}, `valid_until`
//!    at most 365 days): [`seat_key_record_draft`]; and **its
//!    `identity:occurrence` binding** (the self pair, `device_class`
//!    `server`, `transport_destination`'s five members, the two X-Wing keys
//!    at the payload's top level, `refs.head` and `refs.also.cites` naming
//!    the seat's record, and its signed `dial_hints`, CE-fix3, at least one
//!    `tcp` hint): [`seat_binding_draft`] over a [`BindTransport`] and the
//!    seat's [`Hint`]s
//!    and the record's row id ([`row_id_of`]); check with
//!    [`check_seat_binding`].
//! 3. **Each holder's pre-signed halt** (`accord:invoke:constitutional`, one
//!    holder, composite): [`halt_draft`] (or [`invocation_draft`] for a
//!    drill, step 11). It is sealed until published; check it against the
//!    bundle's placement with [`check_halt`]. Verify's reader takes the
//!    invocation's members as a closed map, so the halt carries no `refs`
//!    and names no record: it verifies under the key the bundle in force
//!    places for its holder.
//!    **Step 3 precedes step 4:** [`check_offer_with_halts`] refuses the
//!    whole ceremony unless every holder the bundle lists has exactly one
//!    sealed halt the bundle accepts ([`halt_coverage`]). A node's import
//!    requires no halt.
//! 4. **The genesis** (`ceg-genesis-bundle/2`, version 1, no `prev`):
//!    [`BundleTerms`] → [`bundle_payload`], and one voice per holder,
//!    [`bundle_voice_draft`]; check the whole offer (every row of steps 1
//!    and 2 and every voice) with [`check_genesis_offer`], which is the
//!    import door's reading on a fresh node.
//! 5. **The anchor**: [`thumbprint_anchor`] (the holders' thumbprints), and
//!    once step 4 is signed, the object id [`bundle_object_id`] for
//!    [`Anchor::ObjectId`].
//!
//! The holders' signatures over the accord manifest and the identity
//! templates are not statements: they are ONE composite over a signing
//! domain's preimage (CC 2.6.1.7, F0-cp8): [`accord_manifest_v2_preimage`],
//! [`identity_template_preimage`], [`domain_preimage`]; checked with
//! [`verify_domain_composite`] under the holder's composite key.
//!
//! **Two layers.** Run the pure checks (above, no backend feature) while
//! drafting; run the real-door import into a throwaway node
//! ([`import_offer_into_throwaway`], feature `sqlite`) as the final gate
//! before any holder seals.
//!
//! The import is the node's own door: `Engine::put_genesis_bundle` (the rows
//! of steps 1 and 2 with the voices of step 4, under the anchor of step 5),
//! then each sealed halt through `Engine::put_edition2_statement` once
//! published.

use std::collections::BTreeMap;

use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::family::SelectContext;
use ciris_verify_core::edition2::genesis::{RowFault, SEAT_DEVICE_CLASS, XWING_PUBKEY_LEN};
use ciris_verify_core::edition2::keys::KeyRecord;
use ciris_verify_core::edition2::{identity_ref, thumbprint, KeyDirectory, KeyLookup};

use crate::federation::edition2::{door, emit, genesis, halt, names::RowId, occurrence, payloads};
use crate::federation::{malformed_row, Error};

pub use crate::federation::edition2::emit::Draft;
pub use crate::federation::edition2::genesis::{
    bundle_payload, Anchor, BundleTerms, GenesisPlacement,
};
pub use crate::federation::edition2::halt::{InvocationRow, InvocationTerms, InvokeKind};
pub use crate::federation::edition2::occurrence::BindTransport;
pub use crate::federation::edition2::signing_domain::{
    accord_manifest_v2_message, domain_preimage, verify_domain_composite, SigningDomain,
};
pub use ciris_crypto::composite::CompositePublicKey;
/// v62.0.0 (CE-fix3) — a FedCode dial hint (Verify 23.3.3,
/// `edition2::fedcode::Hint`; BELIEVED until the pin).
pub use ciris_verify_core::edition2::fedcode::Hint;
pub use ciris_verify_core::edition2::Digest32;

/// The `identity_type` of an accord holder's record.
pub const ACCORD_HOLDER: &str = "accord_holder";
/// The `identity_type` of a seat's record.
pub const NODE: &str = "node";
/// The hardware class the custody gate accepts for a holder (CC 4.2.2.1).
pub const YUBIKEY_5_FIPS: &str = "YubiKey_5_FIPS";
/// The `pq_custody` the custody gate requires of a holder (CC 4.2.2.1).
pub const REMOVABLE_OFFLINE: &str = "removable_offline";

/// The plane the ceremony's own refusals carry: the edition-2 door's.
const PLANE: &str = door::PLANE;

/// **A holder's custody evidence** (CC 4.2.2.1): the record's
/// `attestation_evidence`. `chain` is DER, leaf FIRST (for a YubiKey: the
/// slot-9c attestation, then `f9`, then every intermediate up to, not
/// including, the vendor root). There is no nonce or challenge member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyEvidence {
    /// `hardware_class`.
    pub hardware_class: String,
    /// `pq_custody`.
    pub pq_custody: String,
    /// `chain`, DER certificates, leaf first.
    pub chain: Vec<Vec<u8>>,
}

impl CustodyEvidence {
    /// A YubiKey 5 FIPS holder's evidence: `removable_offline` over `chain`.
    #[must_use]
    pub fn yubikey_5_fips(chain: Vec<Vec<u8>>) -> Self {
        CustodyEvidence {
            hardware_class: YUBIKEY_5_FIPS.to_owned(),
            pq_custody: REMOVABLE_OFFLINE.to_owned(),
            chain,
        }
    }

    /// The evidence in the form [`emit::key_record_payload`] takes (the
    /// chain as hex DER; written as CBOR byte strings).
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "hardware_class": self.hardware_class,
            "pq_custody": self.pq_custody,
            "chain": self.chain.iter().map(hex::encode).collect::<Vec<_>>(),
        })
    }
}

/// The identity-ref of a composite key (RFC 9679 thumbprint URN): what every
/// statement of a fresh key carries as `iss` / `author`.
#[must_use]
pub fn identity_ref_of(key: &CompositePublicKey) -> String {
    identity_ref(&thumbprint(key))
}

/// The kid of a composite key (its RFC 9679 thumbprint).
#[must_use]
pub fn kid_of(key: &CompositePublicKey) -> Digest32 {
    thumbprint(key)
}

/// The row id a drafted ROW will have once signed: the row id reads the row
/// type, family, `sub`, `author` and payload bytes, never the signature, so
/// a binding can cite its seat's record before the record is signed.
/// `None` for an object draft (a bundle voice): see [`bundle_object_id`].
#[must_use]
pub fn row_id_of(draft: &Draft) -> Option<Digest32> {
    RowId::of_statement(&draft.assemble(Vec::new())).map(|r| r.0)
}

// ------------------------------------------------------------------ steps 1, 2: key records

/// **A key's own `key:record`, drafted** (CC 2.4.1.1): the producer
/// `Engine::register_self_federation_key` uses
/// ([`emit::self_key_record_payload`] + [`emit::key_record_statement_draft`]).
/// A `node` / `agent` record asked no end ends `asserted_at + 365 days`.
///
/// # Errors
/// `edition2_payload_invalid` (an empty identity set, a payload the door
/// would refuse).
pub fn key_record_draft(
    key: &CompositePublicKey,
    identity_type: &[&str],
    asserted_at_ms: u64,
    valid_until_ms: Option<u64>,
    evidence: Option<&CustodyEvidence>,
) -> Result<Draft, Error> {
    let evidence = evidence.map(CustodyEvidence::to_json);
    emit::key_record_draft(
        key,
        identity_type,
        asserted_at_ms,
        valid_until_ms,
        evidence.as_ref(),
    )
    .map_err(|e| emit::produce_error("ceremony_key_record", e))
}

/// **Step 1 — a holder's `key:record`**: `identity_type` {`accord_holder`},
/// no `valid_until`, `attestation_evidence` = `evidence`. Signed by the
/// holder's own composite key.
///
/// # Errors
/// As [`key_record_draft`].
pub fn holder_key_record_draft(
    key: &CompositePublicKey,
    asserted_at_ms: u64,
    evidence: &CustodyEvidence,
) -> Result<Draft, Error> {
    key_record_draft(key, &[ACCORD_HOLDER], asserted_at_ms, None, Some(evidence))
}

/// **Step 2a — a seat's `key:record`**: `identity_type` {`node`}, ending at
/// `valid_until_ms` (at most 365 days after `asserted_at`; `None` is that
/// longest end). Signed by the seat's own composite key.
///
/// # Errors
/// As [`key_record_draft`].
pub fn seat_key_record_draft(
    key: &CompositePublicKey,
    asserted_at_ms: u64,
    valid_until_ms: Option<u64>,
) -> Result<Draft, Error> {
    key_record_draft(key, &[NODE], asserted_at_ms, valid_until_ms, None)
}

/// A key directory of keys in hand: what a fresh node's door resolves a
/// self-signed statement's kid against.
struct KeysInHand(BTreeMap<Digest32, CompositePublicKey>);

impl KeysInHand {
    fn of(keys: &[&CompositePublicKey]) -> Self {
        KeysInHand(keys.iter().map(|k| (thumbprint(k), (*k).clone())).collect())
    }
}

impl KeyDirectory for KeysInHand {
    fn lookup(&self, kid: &Digest32, _asserted_at: u64) -> KeyLookup {
        self.0
            .get(kid)
            .cloned()
            .map_or(KeyLookup::NotHeld, |k| KeyLookup::Held(Box::new(k)))
    }
}

/// A row through the edition-2 door's pure reading under `keys`: the
/// statement form, Verify's verdict in its family, the key-of-issuer
/// check, the row id, the key-record end rule (`door::admit_row`), then
/// the family's closed payload (`payloads::check`).
fn admit(statement: &[u8], keys: &KeysInHand) -> Result<door::AdmittedRow, Error> {
    let a = door::admit_row(statement, keys, None, SelectContext::default())?;
    payloads::check(&a.family, &a.payload)?;
    Ok(a)
}

/// **Check a signed `key:record`** (steps 1, 2a) as the door reads it,
/// under the key it records: the row through the edition-2 door's pure
/// reading, then Verify's record rule (`check_key_record`). A holder's
/// custody chain is judged at seating, by [`check_genesis_offer`].
///
/// # Errors
/// The door's refusals by their tokens; `key_record_*` for a payload off
/// the record rule.
pub fn check_key_record(statement: &[u8]) -> Result<KeyRecord, Error> {
    door::require_statement_form(statement)?;
    let (_, payload) = crate::federation::edition2::liveness::statement_parts(statement)
        .ok_or_else(|| {
            Error::malformed_row(
                PLANE,
                malformed_row::EDITION2_STATEMENT_INVALID,
                "not_cose_sign1",
            )
        })?;
    let record = ciris_verify_core::edition2::keys::check_key_record(&payload)
        .map_err(|e| door::key_record_refusal(&identity_ref_of_payload(&payload), &payload, &e))?;
    let a = admit(statement, &KeysInHand::of(&[&record.key]))?;
    if a.family != emit::KEY_RECORD_FAMILY {
        return Err(Error::malformed_row(
            PLANE,
            malformed_row::EDITION2_FAMILY_INVALID,
            format!("the statement is of family {}, not key:record", a.family),
        ));
    }
    Ok(record)
}

fn identity_ref_of_payload(payload: &Value) -> String {
    payload
        .get_text("author")
        .and_then(Value::as_text)
        .unwrap_or_default()
        .to_owned()
}

// ------------------------------------------------------------------ step 2b: the seat binding

/// The binding terms of a seat (CC 2.6.1.11, CC 3.3.6.2): the self pair
/// (`author` = `identity_key_id` = `occurrence_key_id` = the seat's
/// identity-ref), `device_class` `server`, no end, `transport`, and
/// `refs.head` and `refs.also.cites` naming the seat's own `key:record`
/// (`seat_record`, its row id), and `dial_hints` (CE-fix3: most preferred
/// first; a genesis serve seat needs one `tcp` hint, judged by Verify's
/// reader).
#[must_use]
pub fn seat_binding_terms(
    seat: &CompositePublicKey,
    seat_record: &Digest32,
    asserted_at_ms: u64,
    transport: BindTransport,
    dial_hints: Vec<Hint>,
) -> occurrence::BindTerms {
    let iref = identity_ref_of(seat);
    occurrence::BindTerms {
        author: iref.clone(),
        identity_key_id: iref.clone(),
        occurrence_key_id: iref,
        device_class: SEAT_DEVICE_CLASS.to_owned(),
        asserted_at_ms,
        valid_until_ms: None,
        hardware_attestation: None,
        encryption_pubkeys: None,
        transport: Some(transport),
        head: Some(RowId(*seat_record)),
        further_heads: Vec::new(),
        cites: vec![RowId(*seat_record)],
        dial_hints,
    }
}

/// **Step 2b — a seat's `identity:occurrence` binding, drafted** for the
/// seat's own key ([`seat_binding_terms`] through the occurrence producer
/// [`occurrence::bind_draft`]). `transport` carries the Reticulum link keys,
/// the app name and aspects (the `transport_destination` map, whose
/// `destination_hash` is derived), and BOTH X-Wing keys
/// (`transit_xwing_pubkey`, `onion_hop_xwing_pubkey`, 1216 bytes each),
/// stated at the payload's top level. `dial_hints` (CE-fix3; CC 2.6.1.11)
/// are the seat's signed dial hints, MOST PREFERRED FIRST, at most eight,
/// written byte for byte as Verify's FedCode hint bodies; a genesis serve
/// seat needs at least one `tcp` hint. Persist does not judge them: Verify's
/// bundle reader does ([`check_genesis_offer`] surfaces its
/// `seat_dial_hints_missing` / `dial_hint_malformed` by name).
///
/// # Errors
/// `edition2_payload_invalid`: a destination hash that does not derive, an
/// X-Wing key missing, a hint Verify's encoder refuses (`hint_parts`: an
/// `Unknown` hint, a bad body; its `FedCodeE2Error` token in the message),
/// or a payload the door would refuse.
pub fn seat_binding_draft(
    seat: &CompositePublicKey,
    seat_record: &Digest32,
    asserted_at_ms: u64,
    transport: BindTransport,
    dial_hints: Vec<Hint>,
) -> Result<Draft, Error> {
    let both = transport
        .transit_xwing_pubkey
        .as_ref()
        .is_some_and(|k| k.len() == XWING_PUBKEY_LEN)
        && transport
            .onion_hop_xwing_pubkey
            .as_ref()
            .is_some_and(|k| k.len() == XWING_PUBKEY_LEN);
    if !both {
        return Err(Error::InvalidArgument(format!(
            "edition2_payload_invalid: ceremony_seat_binding: a seat binding carries both \
             X-Wing keys (transit_xwing_pubkey, onion_hop_xwing_pubkey), {XWING_PUBKEY_LEN} \
             bytes each (CC 2.6.1.11)"
        )));
    }
    // CE-fix3 — every hint must be one Verify's minter encodes
    // (`fedcode::hint_parts`: it refuses `Unknown`, a minter emits only
    // assigned types), refused up front with Verify's own token.
    for (i, h) in dial_hints.iter().enumerate() {
        if let Err(e) = ciris_verify_core::edition2::fedcode::hint_parts(h) {
            return Err(Error::InvalidArgument(format!(
                "edition2_payload_invalid: ceremony_seat_binding: dial hint {i}: {}",
                e.token()
            )));
        }
    }
    let terms = seat_binding_terms(seat, seat_record, asserted_at_ms, transport, dial_hints);
    let kid = occurrence::own_kid(&terms.occurrence_key_id)?;
    occurrence::bind_draft(&terms, &terms.occurrence_key_id, &kid)
}

/// **Check a signed seat binding** (step 2b) as the bundle reader and the
/// door read it: the row through the edition-2 door's pure reading under
/// the seat's key, then Verify's seat-binding rule (`check_seat_binding`:
/// the transport destination, both X-Wing keys and their separation, the
/// self pair, `device_class` `server`, and the record cited). Returns the
/// two X-Wing keys `(transit, onion_hop)`.
///
/// # Errors
/// The door's refusals; `genesis_bundle_row_invalid` leading with Verify's
/// fault token (`binding_names_no_record`, `binding_xwing_member`, an X-Wing
/// reuse token, `row_invalid`, …).
pub fn check_seat_binding(
    statement: &[u8],
    seat: &CompositePublicKey,
    seat_record: &Digest32,
) -> Result<([u8; XWING_PUBKEY_LEN], [u8; XWING_PUBKEY_LEN]), Error> {
    let a = admit(statement, &KeysInHand::of(&[seat]))?;
    ciris_verify_core::edition2::genesis::check_seat_binding(&a.payload, seat, seat_record).map_err(
        |f: RowFault| {
            Error::malformed_row(
                PLANE,
                malformed_row::GENESIS_BUNDLE_ROW_INVALID,
                format!(
                    "{}: the seat binding is not one the bundle reader places (CC 2.6.1.11)",
                    f.token()
                ),
            )
        },
    )
}

// ------------------------------------------------------------------ step 3: the halt

/// **Any invocation, drafted** for its holder (CC 4.2.1.1): `holder_key` is
/// the composite key the bundle places for `t.holder` (for a fresh holder,
/// the key its identity-ref names). Step 3's halt is
/// [`InvokeKind::Constitutional`] ([`halt_draft`]); step 11's first drill is
/// [`InvokeKind::Drill`].
///
/// # Errors
/// `edition2_payload_invalid`.
pub fn invocation_draft(
    holder_key: &CompositePublicKey,
    t: &InvocationTerms,
) -> Result<Draft, Error> {
    halt::invocation_draft(t, &thumbprint(holder_key))
}

/// **Step 3 — a holder's pre-signed constitutional halt, drafted**:
/// `author` / `iss` the holder's identity-ref, `sub` and `accord_root` the
/// accord's `family_key_id`, the holder's own 32-byte `nonce`, and a
/// `valid_until` after `asserted_at` (it bounds the replay window, never the
/// halt's reach). Sign it with the holder's composite key AFTER the holder's
/// step-1 record exists and under that same key, then seal it.
///
/// # Errors
/// As [`invocation_draft`].
pub fn halt_draft(
    holder_key: &CompositePublicKey,
    accord_root: &str,
    invocation_id: &str,
    nonce: [u8; 32],
    asserted_at_ms: u64,
    valid_until_ms: u64,
) -> Result<Draft, Error> {
    invocation_draft(
        holder_key,
        &InvocationTerms {
            kind: InvokeKind::Constitutional,
            holder: identity_ref_of(holder_key),
            accord_root: accord_root.to_owned(),
            invocation_id: invocation_id.to_owned(),
            nonce,
            asserted_at_ms,
            valid_until_ms,
            payload_digest: None,
        },
    )
}

/// **Check a signed invocation** (a sealed halt) against the bundle that
/// will be in force (`placement`, from [`check_genesis_offer`]): the
/// invocation door's pure reading ([`halt::read_invocation`]: Verify's
/// `verify_invocation_row` under the bundle's holders, then the edition-2
/// door). The replay fold and the latch are the store's.
///
/// # Errors
/// As [`halt::read_invocation`]: a key the bundle does not place waits
/// (the retryable unknown-signer error); `iss_not_holder`;
/// `accord_invocation_invalid` with the reader's token.
pub fn check_halt(statement: &[u8], placement: &GenesisPlacement) -> Result<InvocationRow, Error> {
    let roster = halt::HaltRoster::from_placement(placement);
    halt::read_invocation(statement, &roster).map(|(inv, _)| inv)
}

// ------------------------------------------------------------------ step 3 before step 4: every holder's halt

/// A listed holder has no sealed halt among the offered statements.
pub const CEREMONY_HALT_MISSING: &str = "ceremony_halt_missing";
/// A listed holder has more than one sealed halt: the ceremony seals ONE.
pub const CEREMONY_HALT_DUPLICATE: &str = "ceremony_halt_duplicate";
/// A halt whose signer is no holder the bundle lists (it was signed for
/// another bundle, or by another key): refused, never ignored.
pub const CEREMONY_HALT_NOT_A_HOLDER: &str = "ceremony_halt_not_a_holder";
/// A halt the invocation reading refuses under the bundle for another
/// reason (another accord, an empty window, not a constitutional halt, …).
pub const CEREMONY_HALT_INVALID: &str = "ceremony_halt_invalid";

/// One fault of the ceremony's halt coverage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HaltFault {
    /// [`CEREMONY_HALT_MISSING`]: the holder (identity-ref) has no halt.
    Missing {
        /// The holder.
        holder: String,
    },
    /// [`CEREMONY_HALT_DUPLICATE`]: the holder has `count` (> 1) halts.
    Duplicate {
        /// The holder.
        holder: String,
        /// How many.
        count: usize,
    },
    /// [`CEREMONY_HALT_NOT_A_HOLDER`]: offered halt `index` (in the order the
    /// halts were given) is signed by no listed holder.
    NotAHolder {
        /// The halt's index.
        index: usize,
        /// The reading's error, as text.
        reason: String,
    },
    /// [`CEREMONY_HALT_INVALID`]: offered halt `index` is refused for
    /// another reason.
    Invalid {
        /// The halt's index.
        index: usize,
        /// Why.
        reason: String,
    },
}

impl HaltFault {
    /// The fault's token.
    #[must_use]
    pub fn token(&self) -> &'static str {
        match self {
            Self::Missing { .. } => CEREMONY_HALT_MISSING,
            Self::Duplicate { .. } => CEREMONY_HALT_DUPLICATE,
            Self::NotAHolder { .. } => CEREMONY_HALT_NOT_A_HOLDER,
            Self::Invalid { .. } => CEREMONY_HALT_INVALID,
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::Missing { holder } => {
                format!("{CEREMONY_HALT_MISSING}: holder {holder} has no sealed halt")
            }
            Self::Duplicate { holder, count } => format!(
                "{CEREMONY_HALT_DUPLICATE}: holder {holder} has {count} sealed halts; the \
                 ceremony seals exactly one per holder"
            ),
            Self::NotAHolder { index, reason } => format!(
                "{CEREMONY_HALT_NOT_A_HOLDER}: halt {index} is signed by no holder this bundle \
                 lists (another bundle's?): {reason}"
            ),
            Self::Invalid { index, reason } => {
                format!("{CEREMONY_HALT_INVALID}: halt {index}: {reason}")
            }
        }
    }
}

/// One listed holder's sealed halts, as [`halt_coverage`] read them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HolderHalt {
    /// The holder's identity-ref, as the bundle lists it.
    pub holder: String,
    /// The row ids of the holder's halts the reading accepted (exactly one
    /// when the coverage is complete).
    pub halts: Vec<Digest32>,
}

/// **The ceremony's halt coverage** (CEREMONY step 3 before step 4): for
/// every holder the bundle lists, its sealed halts; and every fault.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HaltCoverage {
    /// Each listed holder, in the placement's `holders` order.
    pub holders: Vec<HolderHalt>,
    /// Every fault ([`HaltFault`]); empty when complete.
    pub faults: Vec<HaltFault>,
}

impl HaltCoverage {
    /// Every listed holder has exactly one accepted halt, and no offered
    /// halt was refused.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.faults.is_empty()
    }

    /// The refusal of an incomplete coverage: `InvalidArgument`, leading
    /// with the first fault's token and naming every fault.
    #[must_use]
    pub fn refusal(&self) -> Option<Error> {
        if self.faults.is_empty() {
            return None;
        }
        let all: Vec<String> = self.faults.iter().map(HaltFault::describe).collect();
        Some(Error::InvalidArgument(format!(
            "{}; every holder the bundle lists seals exactly one constitutional halt before \
             the genesis is published (CEREMONY step 3 before step 4)",
            all.join("; ")
        )))
    }
}

/// **Read the ceremony's halt coverage** against `placement` (the bundle
/// the ceremony built): each of `halts` through [`check_halt`] under that
/// bundle. The rule (CE-fix2):
///
/// - every holder the bundle lists has EXACTLY ONE accepted constitutional
///   halt (none: [`CEREMONY_HALT_MISSING`]; more: [`CEREMONY_HALT_DUPLICATE`]);
/// - a halt signed by a key the bundle places for no listed holder is
///   refused ([`CEREMONY_HALT_NOT_A_HOLDER`]): it signals the wrong bundle;
/// - any other refused halt, or an invocation that is not a constitutional
///   halt, is [`CEREMONY_HALT_INVALID`].
///
/// Pure. This is the CEREMONY's rule, not a node's: a node imports a bundle
/// holding nobody's halt (the halts stay sealed offline with their signers
/// until published), so neither the genesis door nor
/// [`check_genesis_offer`] requires halts.
#[must_use]
pub fn halt_coverage(placement: &GenesisPlacement, halts: &[Vec<u8>]) -> HaltCoverage {
    let mut holders: Vec<HolderHalt> = placement
        .holders
        .iter()
        .map(|h| HolderHalt {
            holder: h.identity_ref.clone(),
            halts: Vec::new(),
        })
        .collect();
    let mut faults = Vec::new();
    for (index, st) in halts.iter().enumerate() {
        match check_halt(st, placement) {
            Ok(inv) if inv.kind() != InvokeKind::Constitutional => {
                faults.push(HaltFault::Invalid {
                    index,
                    reason: format!(
                        "a {} invocation, not a constitutional halt",
                        inv.kind().as_str()
                    ),
                });
            }
            Ok(inv) => match holders.iter_mut().find(|h| h.holder == inv.author()) {
                Some(h) => h.halts.push(*inv.row_id()),
                // Unreachable under Verify's reading (the author is the
                // placed holder of the signing key); kept as a fault, never
                // silently counted.
                None => faults.push(HaltFault::NotAHolder {
                    index,
                    reason: format!("author {} is not listed", inv.author()),
                }),
            },
            Err(e) if is_not_a_holder(&e) => faults.push(HaltFault::NotAHolder {
                index,
                reason: e.to_string(),
            }),
            Err(e) => faults.push(HaltFault::Invalid {
                index,
                reason: e.to_string(),
            }),
        }
    }
    for h in &holders {
        match h.halts.len() {
            0 => faults.push(HaltFault::Missing {
                holder: h.holder.clone(),
            }),
            1 => {}
            count => faults.push(HaltFault::Duplicate {
                holder: h.holder.clone(),
                count,
            }),
        }
    }
    HaltCoverage { holders, faults }
}

/// A halt reading that says the signer is no listed holder: its key is not
/// one the bundle places (the retryable unknown-signer error), or the key is
/// a holder's under another `iss` (`iss_not_holder`).
fn is_not_a_holder(e: &Error) -> bool {
    match e {
        Error::MalformedRow { reason, .. } => *reason == malformed_row::ISS_NOT_HOLDER,
        other => other.kind() == "federation_attester_key_unknown",
    }
}

/// **The whole-ceremony check** (CEREMONY step 3 before step 4):
/// [`check_genesis_offer`] over every statement that is not an invocation,
/// then [`halt_coverage`] of the invocations among `statements` against the
/// ONE bundle the offer places. Refused unless the coverage is complete.
/// [`check_genesis_offer`] keeps its meaning (the bundle alone, as a node
/// reads it); this adds the ceremony's own rule on top.
///
/// # Errors
/// As [`check_genesis_offer`]; `InvalidArgument` when the offer places more
/// than one bundle; [`HaltCoverage::refusal`] (leading with
/// [`CEREMONY_HALT_MISSING`], [`CEREMONY_HALT_DUPLICATE`],
/// [`CEREMONY_HALT_NOT_A_HOLDER`] or [`CEREMONY_HALT_INVALID`], naming
/// every fault).
pub fn check_offer_with_halts(
    statements: &[Vec<u8>],
    anchor: &Anchor,
    now_ms: u64,
) -> Result<(GenesisPlacement, HaltCoverage), Error> {
    let (halts, offer): (Vec<Vec<u8>>, Vec<Vec<u8>>) = statements
        .iter()
        .cloned()
        .partition(|s| halt::is_invocation(s));
    let mut placed = check_genesis_offer(&offer, anchor, now_ms)?;
    if placed.len() != 1 {
        return Err(Error::InvalidArgument(format!(
            "ceremony: the offer places {} bundles; the ceremony seals one",
            placed.len()
        )));
    }
    let placement = placed.remove(0);
    let coverage = halt_coverage(&placement, &halts);
    match coverage.refusal() {
        Some(e) => Err(e),
        None => Ok((placement, coverage)),
    }
}

// ------------------------------------------------------------------ steps 4, 5: the genesis and its anchor

/// **Step 4 — one holder's voice over the bundle, drafted**: `iss` the
/// holder's identity-ref, `sub` the bundle's `family_key_id` (CE-fix4, RFC
/// 9943), `kid` its key's thumbprint, `iat` the bundle's `asserted_at`.
/// Every holder signs (CC 5.3.4).
#[must_use]
pub fn bundle_voice_draft(holder_key: &CompositePublicKey, terms: &BundleTerms) -> Draft {
    genesis::bundle_voice_draft(
        &thumbprint(holder_key),
        &identity_ref_of(holder_key),
        &bundle_payload(terms),
        terms.asserted_at_ms,
    )
}

/// **Step 5 — the bundle's object id**: what [`Anchor::ObjectId`] names
/// once the bundle is signed.
#[must_use]
pub fn bundle_object_id(terms: &BundleTerms) -> Digest32 {
    genesis::bundle_object_id(&bundle_payload(terms))
}

/// **Step 5 — the release's default anchor**: the holders' thumbprints
/// (CC 5.3.4). It exists from step 1.
#[must_use]
pub fn thumbprint_anchor(holder_keys: &[&CompositePublicKey]) -> Anchor {
    Anchor::Thumbprints(holder_keys.iter().map(|k| thumbprint(k)).collect())
}

/// **Check the whole genesis offer** (steps 1, 2 and 4) as the import door
/// reads it on a fresh node: [`genesis::check_genesis_offer`], with the
/// clock-skew bound at `now_ms` (the instant the ceremony checks at). The
/// statements are every holder's and seat's `key:record`, every seat
/// binding and every bundle voice, in any order. Returns each placement
/// (one for a first bundle): its holders, its seats with their X-Wing
/// keys, its charter.
///
/// # Errors
/// As [`genesis::check_genesis_offer`]; `InvalidArgument` for an instant
/// that is not one.
pub fn check_genesis_offer(
    statements: &[Vec<u8>],
    anchor: &Anchor,
    now_ms: u64,
) -> Result<Vec<GenesisPlacement>, Error> {
    let now = i64::try_from(now_ms)
        .ok()
        .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis)
        .ok_or_else(|| Error::InvalidArgument(format!("ceremony: {now_ms} is not an instant")))?;
    genesis::check_genesis_offer(statements, Some(anchor), now)
}

// ------------------------------------------------------------------ the final gate: the real door

/// One seat as a node holds it after the import.
#[cfg(feature = "sqlite")]
#[derive(Clone, Debug)]
pub struct ImportedSeat {
    /// The seat's identity-ref.
    pub identity_ref: String,
    /// `transit_xwing_pubkey`, as the genesis in force places it.
    pub transit_xwing_pubkey: [u8; XWING_PUBKEY_LEN],
    /// `onion_hop_xwing_pubkey`, as the genesis in force places it.
    pub onion_hop_xwing_pubkey: [u8; XWING_PUBKEY_LEN],
    /// v62.0.0 (CE-fix3) — the seat's signed `dial_hints`, as the genesis in
    /// force places them (Verify's `PlacedSeat::dial_hints`, BELIEVED),
    /// most preferred first.
    pub dial_hints: Vec<Hint>,
    /// The seat's projected routes (`list_transport_destinations_for`).
    pub routes: Vec<crate::federation::self_at_login::TransportDestination>,
}

/// What a node holds after [`import_offer_into_throwaway`].
#[cfg(feature = "sqlite")]
#[derive(Clone, Debug)]
pub struct ImportedOffer {
    /// Each bundle the genesis door placed.
    pub placed: Vec<GenesisPlacement>,
    /// The holders of the genesis in force, by identity-ref.
    pub holders: Vec<String>,
    /// The seats of the genesis in force, with their keys and routes.
    pub seats: Vec<ImportedSeat>,
    /// Each invocation (a sealed halt) offered, through the statement door
    /// after the genesis: what the door answered.
    pub invocations: Vec<crate::federation::edition2::ingest::StatementOutcome>,
    /// A constitutional halt is latched for the accord in force.
    pub halt_latched: bool,
    /// v62.0.0 (CE-fix2) — the ceremony's halt coverage of the invocations
    /// among the statements, against the bundle the door placed
    /// ([`halt_coverage`]). Reported, never required: the import succeeds
    /// without halts, as a node's does.
    pub halt_coverage: HaltCoverage,
}

/// **The ceremony's final gate: the whole offer through the REAL doors of a
/// throwaway node.** Opens a private in-memory SQLite store (nothing on
/// disk; dropped on return), runs `statements` (every `key:record`, seat
/// binding and bundle voice, in any order) through the genesis import door
/// (`edition2::genesis::put_genesis_bundle`: Verify's reader, the custody
/// gate at seating under the production attestation roots, one device per
/// holder, each named row's own door, the key read models, the occurrence
/// rows and route projection, one transaction) under `anchor`, then offers
/// every invocation among `statements` (a sealed halt, a drill) through the
/// statement door (`edition2::ingest::put_statement`). Reads back what a
/// node would hold: `genesis_in_force`, each seat's X-Wing keys, each
/// seat's `list_transport_destinations_for`, the accord's active halt.
///
/// Uses no `test-anchor` fixture and no test-only root: in a production
/// build the custody gate's roots are Verify's baked store, so the
/// ceremony's real hardware evidence is judged as a node judges it. The
/// door's clock-skew bound reads the host clock (the import is run at the
/// ceremony's own time).
///
/// Run the pure checks ([`check_genesis_offer`] and the per-step checks)
/// while drafting; run this as the final gate before any holder seals.
///
/// Halts (CE-fix2): the coverage of every holder the bundle lists is
/// REPORTED (`halt_coverage`), never required. A node's import door must
/// import a bundle while holding nobody's halt (the halts stay sealed offline
/// with their signers until published); the ceremony's own rule is
/// [`check_offer_with_halts`].
///
/// Sqlite-only because this is an offline ceremony TOOL over a private
/// in-memory store, not a node door: the doors it calls
/// (`put_genesis_bundle`, `ingest::put_statement`) are the same generic code
/// both backends run, each witnessed on sqlite and postgres (I2310–I2320,
/// I2323, I2287).
///
/// # Errors
/// The store's open / migration failure (`Backend`); the genesis door's
/// refusals by their tokens (a bundle the door holds short concludes
/// nothing, and is an error here: `genesis_bundle_count_unmet`); the
/// statement door's refusal of a halt the coverage accepted.
#[cfg(feature = "sqlite")]
pub async fn import_offer_into_throwaway(
    statements: &[Vec<u8>],
    anchor: &Anchor,
) -> Result<ImportedOffer, Error> {
    use crate::federation::edition2::ingest::{put_statement, INGEST_TIER};
    use crate::federation::FederationDirectory as _;
    use crate::store::Backend as _;

    let store = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .map_err(|e| Error::Backend(format!("ceremony throwaway store: open: {e}")))?;
    store
        .run_migrations()
        .await
        .map_err(|e| Error::Backend(format!("ceremony throwaway store: migrations: {e}")))?;
    let (invocations_in, offer): (Vec<Vec<u8>>, Vec<Vec<u8>>) = statements
        .iter()
        .cloned()
        .partition(|s| halt::is_invocation(s));
    let admission = genesis::put_genesis_bundle(&store, &offer, Some(anchor)).await?;
    if admission.placed.is_empty() {
        return Err(admission.not_placed.first().map_or_else(
            || {
                Error::malformed_row(
                    PLANE,
                    malformed_row::GENESIS_BUNDLE_MALFORMED,
                    "ceremony: the offer placed no bundle",
                )
            },
            |n| {
                Error::malformed_row(
                    PLANE,
                    n.token,
                    format!(
                        "ceremony: bundle {} is not placed: {}{}",
                        hex::encode(n.object_id),
                        n.detail.as_deref().unwrap_or(n.token),
                        // CE-fix4 — Verify's per-statement refusals, by name.
                        if n.refused.is_empty() {
                            String::new()
                        } else {
                            format!("; refused statements: {}", n.refused.join(", "))
                        }
                    ),
                )
            },
        ));
    }
    // v62.0.0 (CE-fix2) — the halt coverage, against the bundle the door
    // placed (the head of what it placed). Only the halts the coverage
    // accepted are offered to the statement door; a refused one is reported
    // in `halt_coverage.faults` (and would only wait or be refused there).
    let coverage = admission
        .placed
        .last()
        .map(|p| halt_coverage(p, &invocations_in))
        .unwrap_or_default();
    let refused: std::collections::BTreeSet<usize> = coverage
        .faults
        .iter()
        .filter_map(|f| match f {
            HaltFault::NotAHolder { index, .. } | HaltFault::Invalid { index, .. } => Some(*index),
            HaltFault::Missing { .. } | HaltFault::Duplicate { .. } => None,
        })
        .collect();
    let mut invocations = Vec::new();
    for (i, st) in invocations_in.iter().enumerate() {
        if refused.contains(&i) {
            continue;
        }
        invocations.push(put_statement(&store, st, None, INGEST_TIER).await?);
    }
    let g = genesis::genesis_in_force(&store).await?;
    let mut seats = Vec::new();
    for s in g.seats() {
        seats.push(ImportedSeat {
            identity_ref: s.identity_ref.clone(),
            transit_xwing_pubkey: s.transit_xwing_pubkey,
            onion_hop_xwing_pubkey: s.onion_hop_xwing_pubkey,
            dial_hints: s.dial_hints.clone(),
            routes: store
                .list_transport_destinations_for(&s.identity_ref)
                .await?,
        });
    }
    let halt_latched = match g.family_key_id() {
        Some(accord) => store.get_active_halt(accord).await?.is_some(),
        None => false,
    };
    Ok(ImportedOffer {
        placed: admission.placed,
        holders: crate::federation::edition2::trust_root_group::holders_in_force(&g),
        seats,
        invocations,
        halt_latched,
        halt_coverage: coverage,
    })
}

// ------------------------------------------------------------------ the manifests

/// **The bytes a holder signs for the accord manifest (v2)**:
/// [`domain_preimage`]`(AccordManifest,`
/// [`accord_manifest_v2_message`]`(manifest_sha256_hex, manifest_size,
/// signer_identity))`, 84 bytes. One composite over these.
///
/// # Errors
/// As [`accord_manifest_v2_message`].
pub fn accord_manifest_v2_preimage(
    manifest_sha256_hex: &str,
    manifest_size: u64,
    signer_identity: &str,
) -> Result<Vec<u8>, Error> {
    let message = accord_manifest_v2_message(manifest_sha256_hex, manifest_size, signer_identity)?;
    Ok(domain_preimage(SigningDomain::AccordManifest, &message))
}

/// **Check a holder's accord manifest signature (v2) under its key**:
/// ONE composite over [`accord_manifest_v2_preimage`] under `holder_key`,
/// whose identity-ref is `signer_identity`. The holder role is checked on a
/// node by `signing_domain::verify_accord_manifest_v2` (the bundle in force);
/// here the key in hand stands for it.
///
/// # Errors
/// `InvalidArgument` for a malformed statement or a `signer_identity` that
/// is not `holder_key`'s; `verify_composite_invalid`.
pub fn verify_accord_manifest_v2_with_key(
    holder_key: &CompositePublicKey,
    manifest_sha256_hex: &str,
    manifest_size: u64,
    signer_identity: &str,
    composite_sig: &[u8],
) -> Result<(), Error> {
    if identity_ref_of(holder_key) != signer_identity {
        return Err(Error::InvalidArgument(format!(
            "accord manifest: signer_identity {signer_identity} is not the identity-ref of the \
             key it is checked under"
        )));
    }
    let message = accord_manifest_v2_message(manifest_sha256_hex, manifest_size, signer_identity)?;
    verify_domain_composite(
        holder_key,
        SigningDomain::AccordManifest,
        &message,
        composite_sig,
    )
}

/// **The bytes a holder signs for an identity template manifest**:
/// [`domain_preimage`]`(IdentityTemplate, message)`, where `message` is the
/// template manifest's own bytes as the Agent's tooling fixes them.
#[must_use]
pub fn identity_template_preimage(message: &[u8]) -> Vec<u8> {
    domain_preimage(SigningDomain::IdentityTemplate, message)
}

// The witnesses: `federation::edition2::ceremony_invariants` (I2280–I2287).
