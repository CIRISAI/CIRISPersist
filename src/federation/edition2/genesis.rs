//! The genesis bundle of this edition, `ceg-genesis-bundle/2`: the generic
//! parts (CC 2.6.1.11, CC 2.6.1.12, CC 5.3.4).
//!
//! The payload rule belongs to CC and the verifier. CIRISConstitution's
//! proposal (`rc20-review/genesis/PROPOSAL.md`, built from persist's
//! superseded draft `docs/GENESIS_BUNDLE_V2_DRAFT.md`, CIRISPersist#1274) has
//! not landed, and persist builds no payload member from it. This module
//! holds what is true under CC 2.6.1.11 and the proposal alike:
//!
//! - every voice is a `ceg-object-statement` with `typ`
//!   `ceg-genesis-bundle/2`, read by Verify 23.1.3's `verify_object_statement`:
//!   - a JSON bundle (the earlier form) is `earlier_form_object`;
//!   - a row is `edition2_not_a_row`;
//!   - a voice that is Invalid or Waiting is not counted, and the others
//!     stand;
//! - the bundle is **counted**: one statement per holder over one payload,
//!   with no `author`, so every voice has one object id, computed here
//!   (`["CEG-object/2", typ, null, payload]`). Statements over other payload
//!   bytes are other objects ([`group_by_object`]), never merged and never
//!   counted;
//! - a reader holding a pin roots only the pinned object. Any other bundle
//!   roots nothing for it (`genesis_bundle_not_pinned`);
//! - `version` is a sequence from 1. No `refs.prev` means the fresh genesis
//!   at `version` 1. With a prev, it is prev's version plus one
//!   (`genesis_bundle_malformed`, `version_prev_mismatch`). This is a consistency check,
//!   never a rank;
//! - the count:
//!   - the fresh genesis is signed by **every** holder;
//!   - a later bundle is signed by a strict majority of its predecessor's
//!     holders, plus every holder it adds or whose commitment it changes
//!     ([`CountRule`], [`BundleContext::must_sign`]);
//!   - a voice from a key outside the counting roster counts for nothing;
//!   - a count not met concludes nothing (`genesis_bundle_count_unmet`). The
//!     bundle is held, never finally refused;
//! - a seat's X-Wing keys are live from the binding the genesis names
//!   ([`seat_xwing_from_binding`]). After that they move only by a counted
//!   `transport:canonical_rebind` (CC 3.3.6.2; persist's
//!   `transport_rebind::rebind_held_for` reads the carried row).

use std::collections::{BTreeMap, BTreeSet};

use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::{verify_object_statement, Digest32, ObjectVerdict};

use super::door::{raw_payload, require_statement_form, AdmittedRow, PLANE};
use super::liveness::statement_parts;
use super::names::{names_of, single, RowId};
use crate::federation::{malformed_row, Error};

/// The `typ` of the genesis bundle of this edition.
pub const GENESIS_BUNDLE_TYP: &str = "ceg-genesis-bundle/2";

/// The genesis bundle's own reasons (`federation_malformed_row`).
pub mod token {
    pub use crate::federation::malformed_row::{
        GENESIS_BUNDLE_COUNT_UNMET as COUNT_UNMET, GENESIS_BUNDLE_MALFORMED as MALFORMED,
        GENESIS_BUNDLE_NOT_PINNED as NOT_PINNED,
        GENESIS_BUNDLE_READER_UNAVAILABLE as READER_UNAVAILABLE,
        GENESIS_BUNDLE_SEAT_BINDING as SEAT_BINDING,
    };
}

/// The X-Wing public key length: ML-KEM-768 `pk_M` (1184) then X25519 `pk_X`
/// (32) (CC 3.3.6.2).
pub const XWING_PUBKEY_LEN: usize = 1216;

/// The ML-KEM-768 half's length.
const XWING_PK_M_LEN: usize = 1184;

fn refuse(reason: &'static str, message: impl Into<String>) -> Error {
    Error::malformed_row(PLANE, reason, message)
}

/// How a bundle is counted (CC 5.3.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CountRule {
    /// Every holder of the roster: the fresh genesis.
    Every,
    /// A strict majority of the predecessor's holders (2·valid > n): a later
    /// bundle.
    StrictMajority,
}

impl CountRule {
    fn met(self, valid: usize, n: usize) -> bool {
        match self {
            CountRule::Every => valid == n,
            CountRule::StrictMajority => 2 * valid > n,
        }
    }
}

/// What the caller holds to judge a bundle by.
#[derive(Clone, Debug)]
pub struct BundleContext<'a> {
    /// The holders whose voices count, by key thumbprint. For the fresh
    /// genesis this is the roster the bundle seats. For a later bundle it is
    /// the predecessor's.
    pub roster: &'a BTreeSet<Digest32>,
    /// How the roster's voices are counted.
    pub count: CountRule,
    /// Holders who must sign beside the count: on a later bundle, each one it
    /// adds and each continuing one whose commitment it changes.
    pub must_sign: &'a BTreeSet<Digest32>,
    /// The pinned object id, when the reader holds one (CC 5.3.4).
    pub pin: Option<&'a Digest32>,
    /// The predecessor's `(object id, version)`, when the bundle names one.
    pub predecessor: Option<(&'a Digest32, u64)>,
}

/// A bundle whose generic rules hold and whose count is met.
#[derive(Clone, Debug)]
pub struct VerifiedBundle {
    /// The object id, computed here.
    pub object_id: RowId,
    /// `version`.
    pub version: u64,
    /// `refs.prev`, when present.
    pub prev: Option<RowId>,
    /// The holders whose voices counted.
    pub signed_by: BTreeSet<Digest32>,
    /// The decoded payload, for the payload rule's reader.
    pub payload: Value,
}

/// Statements grouped by the object id their payload bytes give. Bytes that
/// carry no payload are left out: the reader refuses them.
#[must_use]
pub fn group_by_object(voices: &[Vec<u8>]) -> BTreeMap<RowId, Vec<Vec<u8>>> {
    let mut out: BTreeMap<RowId, Vec<Vec<u8>>> = BTreeMap::new();
    for v in voices {
        if let Some(p) = raw_payload(v) {
            out.entry(RowId::of_object(GENESIS_BUNDLE_TYP, None, &p))
                .or_default()
                .push(v.clone());
        }
    }
    out
}

/// Verify one bundle's voices under its generic rules.
///
/// # Errors
/// - `earlier_form_object` for a voice of the earlier form;
/// - `edition2_not_a_row` for a row, or another `typ`;
/// - `row_ref_edition_1` for an edition-1 `refs.prev`;
/// - [`token`]'s reasons. `count_unmet` and `not_pinned` conclude nothing
///   for this reader. They are not a finding against the bundle.
pub fn verify_bundle(
    voices: &[Vec<u8>],
    keys: &dyn super::liveness::KeyOwnership,
    cx: &BundleContext<'_>,
) -> Result<VerifiedBundle, Error> {
    // The object: the first voice's payload. Others over other bytes are
    // other objects, and do not count here.
    let mut object: Option<(RowId, Vec<u8>)> = None;
    let mut signed_by = BTreeSet::new();
    let mut voiced = BTreeSet::new();
    let mut payload: Option<Value> = None;
    for v in voices {
        require_statement_form(v)?;
        if let Some((protected, _)) = statement_parts(v) {
            if protected.get_int(-70001).is_some() {
                return Err(refuse(
                    malformed_row::EDITION2_NOT_A_ROW,
                    "a row statement offered as a genesis bundle voice",
                ));
            }
        }
        let Some(pb) = raw_payload(v) else {
            continue;
        };
        let id = RowId::of_object(GENESIS_BUNDLE_TYP, None, &pb);
        match &object {
            None => object = Some((id, pb.clone())),
            Some((oid, _)) if *oid != id => continue,
            Some(_) => {}
        }
        let o = match verify_object_statement(v, keys) {
            ObjectVerdict::Valid(o) => o,
            // A voice Invalid on its own, or waiting on its key, is not
            // counted; the others stand.
            ObjectVerdict::Invalid(_) | ObjectVerdict::Waiting { .. } => continue,
        };
        if o.typ != GENESIS_BUNDLE_TYP {
            return Err(refuse(
                malformed_row::EDITION2_NOT_A_ROW,
                format!("a `{}` object offered as a genesis bundle", o.typ),
            ));
        }
        // The reader's own id must be the one computed here: the bundle has
        // no author, so a voice that carries one is another object.
        if o.object_id != id.0 {
            continue;
        }
        // Every statement's `iat` is required and is ⌊asserted_at / 1000⌋
        // (the settled bundle/2 rule; CC 2.6.2).
        let asserted_at = o.payload.get_text("asserted_at").and_then(Value::as_u64);
        match (o.iat, asserted_at) {
            (Some(iat), Some(at)) if iat == at / 1000 => {}
            _ => {
                return Err(refuse(
                    token::MALFORMED,
                    format!(
                        "iat_mismatch: a statement's iat {:?} is not floor(asserted_at {:?} / \
                         1000)",
                        o.iat, asserted_at
                    ),
                ));
            }
        }
        // A voice counts only under a key of its `iss` (I2101): one whose
        // key is of another identity, or whose chain waits, is not counted;
        // the others stand.
        if super::door::require_key_of_iss(keys, &o.kid, &o.iss).is_err() {
            continue;
        }
        voiced.insert(o.kid);
        if cx.roster.contains(&o.kid) {
            signed_by.insert(o.kid);
        }
        payload.get_or_insert(o.payload);
    }
    let Some((object_id, _)) = object else {
        return Err(refuse(token::COUNT_UNMET, "the bundle carries no voice"));
    };
    if let Some(pin) = cx.pin {
        if *pin != object_id.0 {
            return Err(refuse(
                token::NOT_PINNED,
                format!(
                    "the bundle's object id {} is not the pinned {}: it roots nothing for this \
                     reader (CC 5.3.4)",
                    object_id.hex(),
                    hex::encode(pin)
                ),
            ));
        }
    }
    let Some(payload) = payload else {
        return Err(refuse(
            token::COUNT_UNMET,
            "no voice of the bundle verifies under a held key",
        ));
    };
    super::door::refuse_edition_one(&payload)?;
    let names = names_of(&payload).map_err(|e| {
        refuse(
            malformed_row::EDITION2_STATEMENT_INVALID,
            format!("refs: {e:?}"),
        )
    })?;
    let prev = single(&names, "prev");
    let version = payload
        .get_text("version")
        .and_then(Value::as_u64)
        .filter(|v| *v >= 1)
        .ok_or_else(|| {
            refuse(
                token::MALFORMED,
                "version_prev_mismatch: `version` is absent or zero",
            )
        })?;
    match (prev, cx.predecessor) {
        (None, _) if version != 1 => {
            return Err(refuse(
                token::MALFORMED,
                format!("version_prev_mismatch: a bundle with no prev is the fresh genesis, version 1, not {version}"),
            ));
        }
        (Some(_), _) if version == 1 => {
            return Err(refuse(
                token::MALFORMED,
                "version_prev_mismatch: a bundle of version 1 names no prev (CC 2.6.1.11)",
            ));
        }
        (Some(p), Some((pid, pver))) if p.0 != *pid || version != pver + 1 => {
            return Err(refuse(
                token::MALFORMED,
                format!(
                    "version_prev_mismatch: prev names {} at version {version}; the held predecessor is {} at {pver}",
                    p.hex(),
                    hex::encode(pid)
                ),
            ));
        }
        _ => {}
    }
    let missing: Vec<String> = cx
        .must_sign
        .iter()
        .filter(|k| !voiced.contains(*k))
        .map(hex::encode)
        .collect();
    if cx.roster.is_empty()
        || !cx.count.met(signed_by.len(), cx.roster.len())
        || !missing.is_empty()
    {
        return Err(refuse(
            token::COUNT_UNMET,
            format!(
                "{} of the counting roster's {} holders signed under {:?}; holders who must \
                 sign and did not: {missing:?} (CC 5.3.4)",
                signed_by.len(),
                cx.roster.len(),
                cx.count
            ),
        ));
    }
    Ok(VerifiedBundle {
        object_id,
        version,
        prev,
        signed_by,
        payload,
    })
}

/// A seat's live X-Wing keys from the binding row the genesis names (CC
/// 3.3.6.2, CEREMONY.md step 2): `(transit_xwing_pubkey,
/// onion_hop_xwing_pubkey)`.
///
/// The binding is an admitted edition-2 row signed by the seat's own key. It
/// carries both keys, each a byte string of exactly [`XWING_PUBKEY_LEN`], and
/// no half equal to the other key's half (the in-row separation). Edition 2
/// carries no v1 `transit_kex_pubkeys` pair: a binding with one is refused,
/// never read.
///
/// The members are read at the payload's top level. Where they stand inside
/// the binding's family is the payload rule CC has not landed. The reader
/// moves with it.
///
/// # Errors
/// [`token::SEAT_BINDING`].
pub fn seat_xwing_from_binding(
    binding: &AdmittedRow,
    seat_kid: &Digest32,
) -> Result<([u8; XWING_PUBKEY_LEN], [u8; XWING_PUBKEY_LEN]), Error> {
    if binding.kid != *seat_kid {
        return Err(refuse(
            token::SEAT_BINDING,
            "the binding is not signed by the seat's own key",
        ));
    }
    if binding.payload.get_text("transit_kex_pubkeys").is_some() {
        return Err(refuse(
            token::SEAT_BINDING,
            "an edition-2 binding carries the v1 `transit_kex_pubkeys` pair: the edition's \
             transit key is X-Wing only",
        ));
    }
    let member = |name: &str| {
        binding
            .payload
            .get_text(name)
            .and_then(Value::as_bytes)
            .and_then(|b| <[u8; XWING_PUBKEY_LEN]>::try_from(b).ok())
            .ok_or_else(|| {
                refuse(
                    token::SEAT_BINDING,
                    format!("the binding carries no `{name}` byte string of 1216 bytes"),
                )
            })
    };
    let transit = member("transit_xwing_pubkey")?;
    let onion = member("onion_hop_xwing_pubkey")?;
    if transit[..XWING_PK_M_LEN] == onion[..XWING_PK_M_LEN]
        || transit[XWING_PK_M_LEN..] == onion[XWING_PK_M_LEN..]
    {
        return Err(refuse(
            token::SEAT_BINDING,
            "the transit and onion-hop X-Wing keys share a half (CC 3.3.6.2 key separation)",
        ));
    }
    Ok((transit, onion))
}

/// What a verified bundle seats, read from its settled members `holders` and
/// `serve_nodes` (sets of identity-refs; CC 5.3.4, the settled bundle/2
/// rule). When Verify publishes its bundle reader, persist consumes the
/// placement that reader yields and does not place rows again.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BundleInForce {
    /// The bundle's object id.
    pub object_id: Option<RowId>,
    /// The accord's roster.
    pub holders: BTreeSet<String>,
    /// The seated serve nodes.
    pub serve_nodes: BTreeSet<String>,
}

fn identity_ref_set(payload: &Value, member: &str) -> Result<BTreeSet<String>, Error> {
    let arr = payload
        .get_text(member)
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| {
            refuse(
                token::MALFORMED,
                format!("members_missing: `{member}` is not a non-empty set"),
            )
        })?;
    let mut out = BTreeSet::new();
    let mut last: Option<Vec<u8>> = None;
    for v in arr {
        let t = v
            .as_text()
            .filter(|t| ciris_verify_core::edition2::is_identity_ref(t))
            .ok_or_else(|| {
                refuse(
                    token::MALFORMED,
                    format!("members_missing: `{member}` holds a non identity-ref"),
                )
            })?;
        let enc = ciris_verify_core::cde::encode(v);
        if last.as_ref().is_some_and(|l| *l >= enc) {
            return Err(refuse(
                token::MALFORMED,
                format!("`{member}` is not a set in CDE order (federation_set_semantics_unsorted)"),
            ));
        }
        last = Some(enc);
        out.insert(t.to_owned());
    }
    Ok(out)
}

impl BundleInForce {
    /// Read the seated sets from a verified bundle.
    ///
    /// # Errors
    /// `genesis_bundle_malformed`: a set missing, unsorted, or holding a
    /// non identity-ref, or `holders` and `serve_nodes` overlapping
    /// (`holders_seats_overlap`).
    pub fn of(bundle: &VerifiedBundle) -> Result<Self, Error> {
        let holders = identity_ref_set(&bundle.payload, "holders")?;
        let serve_nodes = identity_ref_set(&bundle.payload, "serve_nodes")?;
        if !holders.is_disjoint(&serve_nodes) {
            return Err(refuse(
                token::MALFORMED,
                "holders_seats_overlap: a key is both a holder and a seat",
            ));
        }
        Ok(BundleInForce {
            object_id: Some(bundle.object_id),
            holders,
            serve_nodes,
        })
    }

    /// **Canonical standing under ruling C** (CIRISPersist#1274, CC 4.2.1):
    /// a seat is canonical exactly when its identity-ref is in `serve_nodes`
    /// of the bundle in force. The identity-ref names the key's genesis key,
    /// so standing survives record renewals and rotation (CC 2.6.1.7). It
    /// moves only by a later bundle.
    #[must_use]
    pub fn is_canonical(&self, identity_ref: &str) -> bool {
        self.serve_nodes.contains(identity_ref)
    }
}

/// **The genesis door** (approved for slice E2a). It verifies a bundle's
/// generic rules, takes the placement from CIRISVerify's bundle verdict (the
/// holders, and each seat with its two X-Wing keys, consumed and never placed
/// again here), then stores the voices in `ceg_statements` (typ
/// `ceg-genesis-bundle/2`; `row_type`, `family`, `sub` NULL).
///
/// TODO(verify-bundle-reader): Verify's reader does not exist at Verify 23.1.3. Until
/// it does, the placement step refuses `genesis_bundle_reader_unavailable`
/// and NOTHING is stored. A bundle held without its placement would seat
/// rows no reader has placed.
///
/// # Errors
/// [`verify_bundle`]'s; `genesis_bundle_reader_unavailable`.
pub async fn put_genesis_bundle<F>(
    dir: &F,
    voices: &[Vec<u8>],
    cx: &BundleContext<'_>,
) -> Result<VerifiedBundle, Error>
where
    F: crate::federation::FederationDirectory + ?Sized,
{
    let mut keys = super::liveness::HeldKeys::new();
    for v in voices {
        if let Some(kid) = super::ingest::statement_kid(v) {
            for st in dir
                .edition2_statements_about(
                    ciris_verify_core::edition2::keys::KEY_RECORD_FAMILY,
                    &ciris_verify_core::edition2::identity_ref(&kid),
                )
                .await?
            {
                keys.insert_record(st);
            }
        }
    }
    let bundle = verify_bundle(voices, &keys, cx)?;
    place_by_verify_reader(&bundle)?;
    for v in voices {
        if let ObjectVerdict::Valid(o) = verify_object_statement(v, &keys) {
            if o.object_id == bundle.object_id.0 {
                dir.put_edition2_object(&super::store::HeldObject {
                    object_id: bundle.object_id,
                    statement_id: o.statement_id,
                    typ: o.typ,
                    kid: o.kid,
                    iss: o.iss,
                    bytes: v.clone(),
                })
                .await?;
            }
        }
    }
    Ok(bundle)
}

/// The placement step: CIRISVerify's bundle verdict. TODO(verify-bundle-reader).
fn place_by_verify_reader(bundle: &VerifiedBundle) -> Result<(), Error> {
    Err(refuse(
        token::READER_UNAVAILABLE,
        format!(
            "bundle {} verified its generic rules, but its placement is CIRISVerify's bundle \
             reader's, which Verify 23.1.3 does not ship: nothing is stored",
            bundle.object_id.hex()
        ),
    ))
}

/// **The bundles in force**: the tips of the held genesis lineage, followed
/// by `refs.prev` links from a fresh genesis (version 1, no prev), never by
/// instant (CC 2.6.1.11, CC 2.7.8). With a pin, only the pinned genesis
/// roots a lineage. With none, every held fresh genesis does, and two of
/// them are a fork: both are tips.
///
/// # Errors
/// Directory read failures.
pub async fn bundles_in_force<F>(
    dir: &F,
    pin: Option<&Digest32>,
) -> Result<Vec<BundleInForce>, Error>
where
    F: crate::federation::FederationDirectory + ?Sized,
{
    let voices = dir.edition2_objects(GENESIS_BUNDLE_TYP).await?;
    let mut nodes: BTreeMap<RowId, (Option<RowId>, Value)> = BTreeMap::new();
    for (id, vs) in group_by_object(&voices) {
        let Some((_, payload)) = vs.first().and_then(|v| statement_parts(v)) else {
            continue;
        };
        let prev = names_of(&payload).ok().and_then(|n| single(&n, "prev"));
        nodes.insert(id, (prev, payload));
    }
    let mut frontier: Vec<RowId> = nodes
        .iter()
        .filter(|(id, (prev, _))| prev.is_none() && pin.is_none_or(|p| id.0 == *p))
        .map(|(id, _)| *id)
        .collect();
    let mut tips = Vec::new();
    let mut seen = BTreeSet::new();
    while let Some(id) = frontier.pop() {
        if !seen.insert(id) {
            continue;
        }
        let children: Vec<RowId> = nodes
            .iter()
            .filter(|(_, (prev, _))| *prev == Some(id))
            .map(|(c, _)| *c)
            .collect();
        if children.is_empty() {
            let (_, payload) = &nodes[&id];
            let vb = VerifiedBundle {
                object_id: id,
                version: payload
                    .get_text("version")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                prev: nodes[&id].0,
                signed_by: BTreeSet::new(),
                payload: payload.clone(),
            };
            if let Ok(f) = BundleInForce::of(&vb) {
                tips.push(f);
            }
        }
        frontier.extend(children);
    }
    Ok(tips)
}

/// **Canonical standing under ruling C** over the held lineage: the key's
/// identity-ref is in `serve_nodes` of every bundle in force. A reader that
/// holds two tips takes only what both name (CC 2.7.8). With no bundle held,
/// no edition-2 key is canonical.
///
/// # Errors
/// Directory read failures.
pub async fn is_canonical_by_bundle<F>(dir: &F, identity_ref: &str) -> Result<bool, Error>
where
    F: crate::federation::FederationDirectory + ?Sized,
{
    let tips = bundles_in_force(dir, None).await?;
    Ok(!tips.is_empty() && tips.iter().all(|t| t.is_canonical(identity_ref)))
}
