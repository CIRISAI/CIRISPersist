//! The genesis bundle of this edition, `ceg-genesis-bundle/2` (CC 2.6.1.11,
//! CC 4.2.6, CC 5.3.4), read by CIRISVerify 23.3.0's bundle reader
//! (`ciris_verify_core::edition2::genesis`).
//!
//! The payload rule, the count, the anchor, the named rows, the custody gate,
//! roster changes, recovery and re-seating are all Verify's. Persist consumes
//! the [`GenesisPlacement`] the reader yields and never places a row again.
//! What persist adds is the store around it:
//!
//! - **The door** ([`put_genesis_bundle`]). One statement list carries bundle
//!   voices and the rows they name (key records, seat bindings, a recovery
//!   key's record). The voices may be several objects: a whole lineage can
//!   travel at once. Each object is read in lineage order ([`read_lineage`]):
//!   - a first bundle not held yet is rooted by the caller's [`Anchor`];
//!   - a first bundle already held is rooted by its own object id;
//!   - a later bundle is read against its held predecessor.
//!
//!   The door then stores what Verify reads Valid: first its named rows, then
//!   its voices. Nothing of a bundle that is not Valid is stored:
//!   - a bundle waiting on a named row or its predecessor is the retryable
//!     unknown-signer error;
//!   - an Invalid bundle is `genesis_bundle_malformed` with Verify's reason;
//!   - a bundle that concludes nothing carries Verify's own token.
//! - **The bundles in force** ([`genesis_in_force`]), re-derived from the
//!   held voices and rows on every call (cached by content hash), never by
//!   instant:
//!   - `prev` links are followed to the head (`follow_to_head`);
//!   - a fork is held as tips (`find_forks`), and a reader acts only on what
//!     every tip names (`tips_in_common`, CC 2.6.1.11).
//! - **Canonical standing, ruling C**: a key is canonical when its
//!   identity-ref is a seat (`serve_nodes`) of the bundle in force, common to
//!   every tip ([`is_canonical_by_bundle`]). With no bundle held, no key is
//!   canonical, and the node is pre-genesis.
//! - **The accord's halt roster** ([`GenesisInForce::halt_roster`]): the
//!   holders of the bundle in force for an accord, each at the key the bundle
//!   places for it. With no bundle held, the halt waits
//!   (`edition2::halt::roster_in_force`).
//!
//! The custody gate verifies the holders' attestation chains against
//! [`attestation_roots`], which is Verify's baked store in production.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, PoisonError};

use ciris_verify_core::cde::{self, Value};
// Verify's roster type: persist's `edition2::halt::HaltRoster` is a
// re-export of it at the 23.3.0 pin (slice C3).
use ciris_crypto::composite::CompositePublicKey;
use ciris_verify_core::edition2::accord_halt::{HaltRoster, RosterHolder};
use ciris_verify_core::edition2::family::SelectContext;
use ciris_verify_core::edition2::genesis::BINDING_FAMILY;
use ciris_verify_core::edition2::genesis::{
    follow_to_head, read_genesis_bundles, tips_in_common, GenesisInput, Head, Inconclusive,
    Predecessor,
};
pub use ciris_verify_core::edition2::genesis::{
    Anchor, BundleReading, Fork, GenesisCharter, GenesisPlacement, GenesisVerdict, PlacedHolder,
    PlacedSeat, PlacedTransparencyService, TipsInCommon,
};
use ciris_verify_core::edition2::keys::{check_key_record, KEY_RECORD_FAMILY};
use ciris_verify_core::edition2::{
    object_id, statement_id, Digest32, KeyDirectory, KeyLookup, KeyOf,
};
use ciris_verify_core::trust_anchor_store::TrustAnchorStore;

use super::door::{AdmittedRow, PLANE};
use super::liveness::{BundleSeats, KEY_REVOCATION_FAMILY};
use super::names::{names_of, single, RowId};
use super::store::HeldObject;
use crate::federation::{malformed_row, Error, FederationDirectory};

/// The `typ` of the genesis bundle of this edition.
pub const GENESIS_BUNDLE_TYP: &str = ciris_verify_core::edition2::genesis::GENESIS_BUNDLE_TYP;

/// The genesis bundle's own reasons (`federation_malformed_row`). Each is
/// the token Verify's reader answers with.
pub mod token {
    pub use crate::federation::malformed_row::{
        GENESIS_BUNDLE_COUNT_UNMET as COUNT_UNMET, GENESIS_BUNDLE_MALFORMED as MALFORMED,
        GENESIS_BUNDLE_NOT_ANCHORED as NOT_ANCHORED,
        GENESIS_BUNDLE_PREV_NOT_VALID as PREV_NOT_VALID, GENESIS_BUNDLE_ROW_INVALID as ROW_INVALID,
        GENESIS_BUNDLE_ROW_UNPLACED as ROW_UNPLACED, GENESIS_HOLDER_CUSTODY as HOLDER_CUSTODY,
        HOLDER_DEVICE_SHARED as DEVICE_SHARED,
    };

    /// The label of a bundle that waits on a named row or its predecessor
    /// ([`super::NotPlaced::token`]). It is never a refusal: the door
    /// answers it with the retryable unknown-signer error.
    pub const WAITING: &str = "genesis_bundle_waiting";
}

fn refuse(reason: &'static str, message: impl Into<String>) -> Error {
    Error::malformed_row(PLANE, reason, message)
}

// ------------------------------------------------------------------ roots

#[cfg(any(test, feature = "test-anchor"))]
static TEST_ATTESTATION_ROOTS: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

#[cfg(any(test, feature = "test-anchor"))]
fn test_attestation_roots() -> Vec<Vec<u8>> {
    TEST_ATTESTATION_ROOTS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

#[cfg(not(any(test, feature = "test-anchor")))]
fn test_attestation_roots() -> Vec<Vec<u8>> {
    Vec::new()
}

/// The trust store of the bundle reader's custody gate (CC 4.2.2.1): Verify's
/// baked roots (`trust_anchor_store::baked::default_store`). A test build
/// adds the roots registered with [`add_test_attestation_root`] as further
/// YubiKey PIV key-attestation roots.
#[must_use]
pub fn attestation_roots() -> TrustAnchorStore {
    use ciris_verify_core::trust_anchor_store::{baked, environments, single, Purpose};
    let store = baked::default_store();
    let extra = test_attestation_roots();
    if extra.is_empty() {
        store
    } else {
        store.with_store(single(
            environments::YUBIKEY_PIV,
            Purpose::KeyAttestation,
            extra,
        ))
    }
}

/// **Test builds only.** Add a YubiKey PIV key-attestation root (DER) to
/// [`attestation_roots`] for the rest of the process. Roots are only ever
/// added, so a test never narrows another's. A test ceremony whose holders
/// carry mock attestation chains registers its mock root before it calls
/// [`put_genesis_bundle`]. In a `test-anchor` build outside `cfg(test)` this
/// does nothing unless Verify's test-anchor mode is active.
#[cfg(any(test, feature = "test-anchor"))]
pub fn add_test_attestation_root(der: Vec<u8>) {
    if !cfg!(test) && !ciris_verify_core::test_anchor::test_anchor_active() {
        return;
    }
    let mut roots = TEST_ATTESTATION_ROOTS
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if !roots.contains(&der) {
        roots.push(der);
    }
}

// ------------------------------------------------------------------ statements

/// A `COSE_Sign1`'s parts: the protected header and payload, as signed and
/// decoded. No check: judging is the reader's.
struct CoseParts {
    protected_raw: Vec<u8>,
    payload_raw: Vec<u8>,
    protected: Value,
    payload: Value,
}

fn cose_parts(bytes: &[u8]) -> Option<CoseParts> {
    let Value::Tag(18, inner) = cde::decode(bytes).ok()? else {
        return None;
    };
    let parts = inner.as_array()?;
    if parts.len() != 4 {
        return None;
    }
    let protected_raw = parts[0].as_bytes()?.to_vec();
    let payload_raw = parts[2].as_bytes()?.to_vec();
    let protected = cde::decode(&protected_raw).ok()?;
    let payload = cde::decode(&payload_raw).ok()?;
    Some(CoseParts {
        protected_raw,
        payload_raw,
        protected,
        payload,
    })
}

/// A bundle voice's object id and `refs.prev`, from its bytes: `None` for a
/// statement whose `typ` is not `ceg-genesis-bundle/2`. The object id is
/// computed here, as Verify computes it (`["CEG-object/2", typ, author /
/// null, payload]`).
fn voice_of(p: &CoseParts) -> Option<(Digest32, Option<Digest32>)> {
    let typ = p.protected.get_int(16).and_then(Value::as_text)?;
    if typ != GENESIS_BUNDLE_TYP {
        return None;
    }
    let author = p.payload.get_text("author").and_then(Value::as_text);
    let oid = object_id(GENESIS_BUNDLE_TYP, author, &p.payload_raw);
    let prev = names_of(&p.payload)
        .ok()
        .and_then(|n| single(&n, "prev"))
        .map(|r| r.0);
    Some((oid, prev))
}

/// The rows a bundle payload names (every `refs` name but `prev`).
fn named_by(payload: &Value) -> Vec<Digest32> {
    names_of(payload)
        .map(|ns| {
            ns.into_iter()
                .filter(|n| n.role != "prev")
                .map(|n| n.row.0)
                .collect()
        })
        .unwrap_or_default()
}

/// A held voice's store record, read from its bytes.
fn held_object(object: Digest32, bytes: &[u8]) -> Option<HeldObject> {
    let p = cose_parts(bytes)?;
    let kid = <[u8; 32]>::try_from(p.protected.get_int(4)?.as_bytes()?).ok()?;
    let iss = p.protected.get_int(15)?.get_int(1)?.as_text()?.to_owned();
    Some(HeldObject {
        object_id: RowId(object),
        statement_id: statement_id(&p.protected_raw, &p.payload_raw),
        typ: GENESIS_BUNDLE_TYP.to_owned(),
        kid,
        iss,
        bytes: bytes.to_vec(),
    })
}

// ------------------------------------------------------------------ the lineage

/// What [`read_lineage`] is given.
#[derive(Clone, Copy, Debug)]
pub struct LineageInput<'a> {
    /// The held voices. A held first bundle is rooted by its own object id:
    /// the door admitted it under the anchor of its day.
    pub held: &'a [Vec<u8>],
    /// The offered voices. A first bundle among them that is not held is
    /// rooted by [`Self::anchor`].
    pub offered: &'a [Vec<u8>],
    /// The row statements the reader holds or was given, by row id.
    pub rows: &'a BTreeMap<Digest32, Vec<u8>>,
    /// The reader's anchor for a first bundle not held (CC 5.3.4). `None`:
    /// nothing new is rooted.
    pub anchor: Option<&'a Anchor>,
    /// The custody gate's roots ([`attestation_roots`]).
    pub attestation_roots: &'a TrustAnchorStore,
}

/// One object of the lineage, as Verify read it.
#[derive(Clone, Debug)]
pub struct LineageObject {
    /// Verify's reading of the object.
    pub reading: BundleReading,
    /// The object's voices that no reader step refused: what the store keeps.
    pub kept: Vec<Vec<u8>>,
    /// The rows its payload names (every `refs` name but `prev`).
    pub named: Vec<Digest32>,
    /// `refs.prev`.
    pub prev: Option<Digest32>,
    /// A voice of it is held.
    pub held: bool,
    /// A voice of it was offered.
    pub offered: bool,
}

/// Every object of the lineage, in read order (roots first, then each
/// object after its predecessor; last, any whose predecessor nothing names).
#[derive(Clone, Debug, Default)]
pub struct LineageReading {
    /// The objects.
    pub objects: Vec<LineageObject>,
    /// Statements (indices into `held ++ offered`) that are no bundle voice:
    /// another `typ`, or bytes that do not decode. Verify would refuse each
    /// on its own; the others stand.
    pub unreadable: Vec<usize>,
}

struct Pending {
    prev: Option<Digest32>,
    voices: Vec<Vec<u8>>,
    named: Vec<Digest32>,
    held: bool,
    offered: bool,
}

/// **Read a genesis lineage** with Verify's reader, object by object in
/// `prev` order, each against its held predecessor's reading (Valid, or
/// not Valid). Pure: no clock, no I/O.
#[must_use]
pub fn read_lineage(input: &LineageInput<'_>) -> LineageReading {
    let mut out = LineageReading::default();
    let mut objects: BTreeMap<Digest32, Pending> = BTreeMap::new();
    let all = input
        .held
        .iter()
        .map(|b| (b, true))
        .chain(input.offered.iter().map(|b| (b, false)));
    for (i, (bytes, held)) in all.enumerate() {
        let Some(parts) = cose_parts(bytes) else {
            out.unreadable.push(i);
            continue;
        };
        let Some((oid, prev)) = voice_of(&parts) else {
            out.unreadable.push(i);
            continue;
        };
        let o = objects.entry(oid).or_insert_with(|| Pending {
            prev,
            voices: Vec::new(),
            named: named_by(&parts.payload),
            held: false,
            offered: false,
        });
        if held {
            o.held = true;
        } else {
            o.offered = true;
        }
        if !o.voices.contains(bytes) {
            o.voices.push(bytes.clone());
        }
    }

    let mut read: BTreeMap<Digest32, BundleReading> = BTreeMap::new();
    let mut order: Vec<Digest32> = Vec::new();
    loop {
        let ready: Vec<Digest32> = objects
            .iter()
            .filter(|(id, o)| {
                !read.contains_key(*id) && o.prev.is_none_or(|p| read.contains_key(&p))
            })
            .map(|(id, _)| *id)
            .collect();
        if ready.is_empty() {
            break;
        }
        for id in ready {
            let r = read_one(&id, &objects[&id], &read, input);
            read.insert(id, r);
            order.push(id);
        }
    }
    // The rest name a predecessor no held or offered voice carries (or a
    // cycle): Verify answers Waiting on it.
    let rest: Vec<Digest32> = objects
        .keys()
        .filter(|id| !read.contains_key(*id))
        .copied()
        .collect();
    for id in rest {
        let r = read_one(&id, &objects[&id], &BTreeMap::new(), input);
        read.insert(id, r);
        order.push(id);
    }

    for id in order {
        let (Some(reading), Some(p)) = (read.remove(&id), objects.remove(&id)) else {
            continue;
        };
        let refused: BTreeSet<usize> = reading.refused.iter().map(|r| r.index).collect();
        let kept = p
            .voices
            .into_iter()
            .enumerate()
            .filter(|(i, _)| !refused.contains(i))
            .map(|(_, v)| v)
            .collect();
        out.objects.push(LineageObject {
            reading,
            kept,
            named: p.named,
            prev: p.prev,
            held: p.held,
            offered: p.offered,
        });
    }
    out
}

/// Verify's reading of one object, its voices alone, against its
/// predecessor's reading when one was read.
fn read_one(
    id: &Digest32,
    o: &Pending,
    read: &BTreeMap<Digest32, BundleReading>,
    input: &LineageInput<'_>,
) -> BundleReading {
    let own;
    let anchor = match o.prev {
        Some(_) => None,
        None if o.held => {
            own = Anchor::ObjectId(*id);
            Some(&own)
        }
        None => input.anchor,
    };
    let preds: Vec<Predecessor<'_>> = match o.prev.and_then(|p| read.get(&p).map(|r| (p, r))) {
        Some((_, r)) if r.verdict.placement().is_some() => r
            .verdict
            .placement()
            .map(Predecessor::Valid)
            .into_iter()
            .collect(),
        Some((p, _)) => vec![Predecessor::NotValid(p)],
        None => Vec::new(),
    };
    let reading = read_genesis_bundles(&GenesisInput {
        statements: &o.voices,
        rows: input.rows,
        anchor,
        predecessors: &preds,
        attestation_roots: input.attestation_roots,
    });
    // Statements refused before grouping are this object's own voices:
    // file them with it, so the store keeps none of them.
    let top = reading.refused;
    match reading.bundles.into_iter().find(|b| b.object_id == *id) {
        Some(mut b) => {
            b.refused.extend(top);
            b
        }
        // Every voice was refused on its own: nothing counts.
        None => BundleReading {
            object_id: *id,
            verdict: GenesisVerdict::Nothing(Inconclusive::CountUnmet),
            refused: top,
        },
    }
}

// ------------------------------------------------------------------ in force

/// v62.0.0 (HL-fix1) — what [`GenesisInForce::head_standing`] answers.
#[derive(Clone, Copy, Debug)]
pub enum HeadStanding<'a> {
    /// A tip in force: count over its holders.
    InForce(&'a GenesisPlacement),
    /// A held Valid bundle a later held bundle superseded: never counted
    /// over (its holders are not the bundle in force's).
    Superseded,
    /// No held Valid bundle: wait on it.
    NotHeld,
}

/// **The genesis in force**, as the held voices and rows give it.
#[derive(Clone, Debug, Default)]
pub struct GenesisInForce {
    /// How many bundle objects are held. The door stores only bundles
    /// Verify reads Valid, so more held than [`Self::valid`] means a held
    /// bundle no longer reads Valid (the posture's `divergent`).
    pub held: usize,
    /// Every held bundle Verify reads Valid, in lineage order.
    pub valid: Vec<GenesisPlacement>,
    /// The head, following `prev` from the root, when there is no fork.
    pub head: Option<GenesisPlacement>,
    /// Every fork among the Valid bundles; non-empty means no head.
    pub forks: Vec<Fork>,
    /// The tips and what every tip names. `None` with nothing held, or on a
    /// fork of the genesis (two Valid first bundles), where a reader roots on
    /// neither.
    pub common: Option<TipsInCommon>,
    /// The Valid lineage as served (CC 2.6.1.2): each bundle's named rows,
    /// then its voices, in lineage order, as received.
    pub statements: Vec<Vec<u8>>,
}

impl GenesisInForce {
    /// Is a Valid genesis held?
    #[must_use]
    pub fn is_held(&self) -> bool {
        !self.valid.is_empty()
    }

    /// The accord's name (`family_key_id`), which a later bundle never
    /// changes.
    #[must_use]
    pub fn family_key_id(&self) -> Option<&str> {
        self.head
            .as_ref()
            .or_else(|| self.valid.first())
            .map(|p| p.family_key_id.as_str())
    }

    /// v62.0.0 (HL-fix1; CC 4.2.1.3, CC 3.4.7) — **the standing of a bundle
    /// a row names in `refs.head`**: one of the tips in force
    /// ([`HeadStanding::InForce`]), a held Valid bundle a later one
    /// superseded ([`HeadStanding::Superseded`]), or none held
    /// ([`HeadStanding::NotHeld`]). The one reading every door counting over
    /// "the bundle in force" uses (the seat re-bind, the halt lifecycle), so
    /// none counts voices against a predecessor's holders.
    #[must_use]
    pub fn head_standing(&self, head: &Digest32) -> HeadStanding<'_> {
        if let Some(p) = self.tips().into_iter().find(|t| t.object_id == *head) {
            return HeadStanding::InForce(p);
        }
        if self.valid.iter().any(|p| p.object_id == *head) {
            HeadStanding::Superseded
        } else {
            HeadStanding::NotHeld
        }
    }

    /// v62.0.0 (KR-fix2 rev 3; CC rc22 7b4a55e) — **the `asserted_at` of the
    /// NEXT bundle of the lineage this node holds after `head`**: the held
    /// Valid bundle whose `refs.prev` is `head` (the earliest of them on a
    /// fork of successors). `None`: the node holds no successor of `head`.
    /// The instant a row counted over `head`'s holders is read against
    /// (`trust_root_group::voices_before_successor`).
    #[must_use]
    pub fn successor_instant(&self, head: &Digest32) -> Option<u64> {
        self.valid
            .iter()
            .filter(|p| p.prev == Some(*head))
            .map(|p| p.asserted_at)
            .min()
    }

    /// The tips: the head, or each tip of a fork of successors.
    #[must_use]
    pub fn tips(&self) -> Vec<&GenesisPlacement> {
        if let Some(h) = &self.head {
            return vec![h];
        }
        self.common
            .as_ref()
            .map(|c| {
                c.tips
                    .iter()
                    .filter_map(|t| self.valid.iter().find(|p| p.object_id == *t))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The holders every tip seats under the same key.
    #[must_use]
    pub fn holders(&self) -> &[PlacedHolder] {
        self.common
            .as_ref()
            .map_or(&[][..], |c| c.holders.as_slice())
    }

    /// The seats every tip lists with the same key and X-Wing keys.
    #[must_use]
    pub fn seats(&self) -> &[PlacedSeat] {
        self.common.as_ref().map_or(&[][..], |c| c.seats.as_slice())
    }

    /// The seat of `identity_ref`, if every tip seats it alike.
    #[must_use]
    pub fn seat(&self, identity_ref: &str) -> Option<&PlacedSeat> {
        self.seats().iter().find(|s| s.identity_ref == identity_ref)
    }

    /// **Canonical standing under ruling C**: `identity_ref` is a seat of
    /// the bundle in force (of every tip). The identity-ref names the key's
    /// genesis key, so standing survives a re-seat at a new key.
    #[must_use]
    pub fn is_canonical(&self, identity_ref: &str) -> bool {
        self.seat(identity_ref).is_some()
    }

    /// v62.0.0 (F0-cp8) — is `identity_ref` an accord holder of the bundle in
    /// force (every tip seats it alike, [`Self::holders`])?
    #[must_use]
    pub fn is_holder(&self, identity_ref: &str) -> bool {
        // v62.0.0 (KB-fix1) — the one holder reader.
        super::trust_root_group::holders_in_force(self)
            .iter()
            .any(|h| h == identity_ref)
    }

    /// The keys the bundle in force seats, by identity-ref: each holder and
    /// each seat at its placed key. No bundle held:
    /// [`BundleSeats::not_held`].
    #[must_use]
    pub fn bundle_seats(&self) -> BundleSeats {
        if !self.is_held() {
            return BundleSeats::not_held();
        }
        BundleSeats::held(
            self.holders()
                .iter()
                .map(|h| (h.identity_ref.clone(), h.kid))
                .chain(self.seats().iter().map(|s| (s.identity_ref.clone(), s.kid))),
        )
    }

    /// **The halt roster** of `accord_root`: the holders of the bundle in
    /// force, each at its placed key, when the accord in force is
    /// `accord_root`. `None` (the halt waits) with no bundle held, on a fork
    /// of the genesis, or for another accord.
    ///
    /// The bundle named is the head, or the first tip of a fork. The fuse is
    /// the head's charter's `halt_fuse_secs`, or the tips' when they agree.
    #[must_use]
    pub fn halt_roster(&self, accord_root: &str) -> Option<HaltRoster> {
        let common = self.common.as_ref()?;
        if self.family_key_id()? != accord_root {
            return None;
        }
        let bundle = match &self.head {
            Some(h) => h.object_id,
            None => *common.tips.first()?,
        };
        let fuse = match &self.head {
            Some(h) => h.charter.halt_fuse_secs,
            None => {
                let tips = self.tips();
                let mut it = tips.iter().map(|t| t.charter.halt_fuse_secs);
                let first = it.next().flatten();
                if it.all(|f| f == first) {
                    first
                } else {
                    None
                }
            }
        };
        // v62.0.0 (KB-fix1) — through the one holder reader
        // (`trust_root_group::holders_in_force`), so halts, root validity,
        // durable mesh config and grants read one holder set. The roster
        // keeps each holder's KEY from the placement (a halt is counted by
        // identity-ref AND key).
        let in_force = super::trust_root_group::holders_in_force(self);
        Some(HaltRoster::new(
            accord_root.to_owned(),
            bundle,
            common
                .holders
                .iter()
                .filter(|h| in_force.contains(&h.identity_ref))
                .map(|h| RosterHolder {
                    identity_ref: h.identity_ref.clone(),
                    key: h.key.clone(),
                })
                .collect(),
            fuse,
        ))
    }
}

/// The genesis in force a lineage reading gives (the store's re-read, and
/// the pure witnesses').
pub(crate) fn in_force_of(
    r: &LineageReading,
    rows: &BTreeMap<Digest32, Vec<u8>>,
) -> GenesisInForce {
    let valid: Vec<GenesisPlacement> = r
        .objects
        .iter()
        .filter_map(|o| o.reading.verdict.placement().cloned())
        .collect();
    let refs: Vec<&GenesisPlacement> = valid.iter().collect();
    let (head, forks) = match follow_to_head(&refs) {
        Head::Head(p) => (Some(p.clone()), Vec::new()),
        Head::Fork(f) => (None, f),
        Head::Nothing => (None, Vec::new()),
    };
    let common = tips_in_common(&refs);
    let mut statements = Vec::new();
    let mut served_rows = BTreeSet::new();
    for o in &r.objects {
        if o.reading.verdict.placement().is_none() {
            continue;
        }
        for id in &o.named {
            if served_rows.insert(*id) {
                if let Some(b) = rows.get(id) {
                    statements.push(b.clone());
                }
            }
        }
        statements.extend(o.kept.iter().cloned());
    }
    GenesisInForce {
        held: r.objects.iter().filter(|o| o.held).count(),
        valid,
        head,
        forks,
        common,
        statements,
    }
}

/// The rows each voice's payload names, by row id: the held one, else the
/// `carried` one, if given. Also the ids of those that are held.
///
/// "Held" here is one fact only: this node stores at least one statement of
/// the row id (`ceg_statements`). For the rows a bundle names that is also
/// "landed", so `admit_named` skips a held row (SR-fix2):
/// - a `key:record` is never held back by the fold (it is a door input); its
///   read model is re-derived for a placed key by `plan_keys`, whether or not
///   the offer carries it;
/// - a seat binding has the shape Verify's reader requires (`author`,
///   `identity_key_id`, `occurrence_key_id` and the statement's `iss` and
///   `sub` are all the seat's identity reference), so alone at the occurrence
///   door it speaks in the occurrence key's own role: signed by that key it
///   lands at once (the identity's own key answers for it), signed by any
///   other key it is refused `occurrence_voice_not_own_key` and nothing is
///   kept. A binding stored here was therefore written with its occurrence
///   row; its route is projected again by the import
///   (`occurrence_admit::reproject_held_occurrence_routes`).
async fn named_rows<F>(
    dir: &F,
    voices: &[Vec<u8>],
    carried: &BTreeMap<Digest32, Vec<u8>>,
) -> Result<(BTreeMap<Digest32, Vec<u8>>, BTreeSet<Digest32>), Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut want = BTreeSet::new();
    for v in voices {
        if let Some(p) = cose_parts(v) {
            if voice_of(&p).is_some() {
                want.extend(named_by(&p.payload));
            }
        }
    }
    let mut rows = BTreeMap::new();
    let mut held = BTreeSet::new();
    for id in want {
        let mut voices = dir.edition2_voices(&RowId(id)).await?;
        if voices.is_empty() {
            if let Some(c) = carried.get(&id) {
                rows.insert(id, c.clone());
            }
            continue;
        }
        // v62.0.0 (SR-fix2; I2118) — the reader verifies a named
        // `key:record` under the key it records, so the voice it is handed
        // is that key's OWN. A rotation record is one row with two voices
        // (the new key's and its predecessor's, CC 2.4.1.1), read back in
        // statement-id order: the first could be the predecessor's, which
        // the reader cannot verify under the recorded key. Any other row
        // (one voice, or no recorded key): the first.
        let own = voices.iter().position(|v| {
            super::ingest::is_key_record(v)
                && super::liveness::recorded_kid(v)
                    .is_some_and(|k| super::ingest::statement_kid(v) == Some(k))
        });
        rows.insert(id, voices.swap_remove(own.unwrap_or(0)));
        held.insert(id);
    }
    Ok((rows, held))
}

const CACHE_LEN: usize = 8;

/// Readings by the content they were read from: the reader is pure, so the
/// same voices, rows and roots give the same answer.
static IN_FORCE_CACHE: Mutex<Vec<(Digest32, GenesisInForce)>> = Mutex::new(Vec::new());

fn cache_key(voices: &[Vec<u8>], rows: &BTreeMap<Digest32, Vec<u8>>) -> Digest32 {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    let mut sorted: Vec<&Vec<u8>> = voices.iter().collect();
    sorted.sort();
    sorted.dedup();
    for v in sorted {
        h.update((v.len() as u64).to_be_bytes());
        h.update(v);
    }
    h.update([0xff]);
    for (id, b) in rows {
        h.update(id);
        h.update((b.len() as u64).to_be_bytes());
        h.update(b);
    }
    h.update([0xfe]);
    for r in test_attestation_roots() {
        h.update((r.len() as u64).to_be_bytes());
        h.update(&r);
    }
    h.finalize().into()
}

fn cache_get(key: &Digest32) -> Option<GenesisInForce> {
    IN_FORCE_CACHE
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, f)| f.clone())
}

fn cache_put(key: Digest32, f: &GenesisInForce) {
    let mut c = IN_FORCE_CACHE
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if c.iter().any(|(k, _)| *k == key) {
        return;
    }
    if c.len() >= CACHE_LEN {
        c.remove(0);
    }
    c.push((key, f.clone()));
}

/// **The genesis in force** on this node: every held voice and the rows it
/// names, read by Verify's reader in lineage order (each held first bundle
/// rooted by its own object id).
///
/// # Errors
/// Directory read failures.
pub async fn genesis_in_force<F>(dir: &F) -> Result<GenesisInForce, Error>
where
    F: FederationDirectory + ?Sized,
{
    // v62.0.0 (wave GC5; CC 2.6.1.11, 2.7.3) — only the voices of bundles
    // that concluded: a bundle HELD short of its count is kept, never in
    // force, never served, and never rooted by its own object id.
    let (voices, _) = held_voices(dir).await?;
    if voices.is_empty() {
        return Ok(GenesisInForce::default());
    }
    let (rows, _) = named_rows(dir, &voices, &BTreeMap::new()).await?;
    let key = cache_key(&voices, &rows);
    if let Some(hit) = cache_get(&key) {
        return Ok(hit);
    }
    let roots = attestation_roots();
    let reading = read_lineage(&LineageInput {
        held: &voices,
        offered: &[],
        rows: &rows,
        anchor: None,
        attestation_roots: &roots,
    });
    let f = in_force_of(&reading, &rows);
    cache_put(key, &f);
    Ok(f)
}

/// v62.0.0 (RL-fix6; CC 2.7.3, CC 5.3.4) — **the read key of "the bundle in
/// force"**: `family:ceg-genesis-bundle/2`, one key for the node. The
/// bundle in force is a node-wide reading (every held voice, one lineage),
/// so no narrower key is correct: a gate that waits because NO bundle is in
/// force cannot name a family or a holder it has never seen.
///
/// The import door touches it on every placement ([`put_genesis_bundle`]: a
/// first bundle, an amend, a successor, a recovery, a re-seat — each is a
/// placement). A halt latching or lifting does not change the bundle in
/// force (the reading reads voices, their named rows and the bundles' own
/// holds, never a lifecycle row), so it does not touch it.
#[must_use]
pub fn bundle_in_force_read_key() -> String {
    super::fold::Dep::Family(GENESIS_BUNDLE_TYP.to_owned()).read_key()
}

/// v62.0.0 (RL-fix6) — declare [`bundle_in_force_read_key`] read by the
/// running fold attempt (a no-op outside one: `fold::reads` is a
/// `try_with`). Called by the readers a GATE asks "is this a seat / a holder
/// of the bundle in force" through ([`bundles_in_force`],
/// [`is_canonical_by_bundle`], [`bundle_seats_in_force`],
/// `trust_root_group::bundle_quorum_over`), by the founder check
/// (`canonical_community::reads_founder`, for `is_bundle_holder`) and by the
/// no-root hold (`posture::require_seated_accord_roster` on an empty
/// roster). NOT by [`genesis_in_force`] itself: every edition-2 row reads it
/// (`recovery_signer::refuse_recovery_key_signer` runs on each), so the key
/// there would put every row of the node in `ceg_fold_reads` and re-fold
/// all of them on every placement. Nor by `is_bundle_holder` or
/// `admission::accord_holder_roster`, which `trust_root_valid` and the standing cache
/// walk for every row a trusted root's conferral gates.
pub fn reads_bundle_in_force() {
    super::fold::reads(super::fold::Dep::Family(GENESIS_BUNDLE_TYP.to_owned()));
}

/// **The bundles in force**: the tips of the held Valid lineage (one
/// without a fork), followed by `refs.prev`, never by instant (CC 2.6.1.11).
///
/// # Errors
/// Directory read failures.
pub async fn bundles_in_force<F>(dir: &F) -> Result<Vec<GenesisPlacement>, Error>
where
    F: FederationDirectory + ?Sized,
{
    reads_bundle_in_force();
    let f = genesis_in_force(dir).await?;
    Ok(f.tips().into_iter().cloned().collect())
}

/// **Canonical standing under ruling C** over the held lineage: the
/// identity-ref is a seat of the bundle in force, common to every tip. With
/// no bundle held, no edition-2 key is canonical.
///
/// # Errors
/// Directory read failures.
pub async fn is_canonical_by_bundle<F>(dir: &F, identity_ref: &str) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    reads_bundle_in_force();
    Ok(genesis_in_force(dir).await?.is_canonical(identity_ref))
}

/// The keys the bundle in force seats, by identity-ref
/// ([`GenesisInForce::bundle_seats`]), for the key-of-issuer check's seat
/// arm.
///
/// # Errors
/// Directory read failures.
pub async fn bundle_seats_in_force<F>(dir: &F) -> Result<BundleSeats, Error>
where
    F: FederationDirectory + ?Sized,
{
    reads_bundle_in_force();
    Ok(genesis_in_force(dir).await?.bundle_seats())
}

/// What the trust-root route serves: the Valid lineage's named rows and
/// voices, as received ([`GenesisInForce::statements`]). The same list at
/// [`put_genesis_bundle`] on a fresh node, with an anchor that roots the
/// first bundle, reproduces the lineage.
///
/// # Errors
/// Directory read failures.
pub async fn genesis_statements<F>(dir: &F) -> Result<Vec<Vec<u8>>, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(genesis_in_force(dir).await?.statements)
}

// ------------------------------------------------------------------ the door

/// An offered bundle the door did not place. Nothing of it was stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotPlaced {
    /// The object id.
    pub object_id: Digest32,
    /// Verify's token ([`token`]), or [`token::WAITING`].
    pub token: &'static str,
    /// Verify's reason or detail; for a waiting bundle, what it waits on.
    pub detail: Option<String>,
    /// It waits on a named row or its predecessor: retryable.
    pub waiting: bool,
    /// v62.0.0 (CE-fix4) — the object's statements Verify's reader refused
    /// on their own, each `statement {index}: {token}` with Verify's token
    /// (`statement_sub_not_family`, …), in reading order. A bundle whose
    /// voices were all refused reads `genesis_bundle_count_unmet`; this names
    /// why.
    pub refused: Vec<String>,
}

/// What [`put_genesis_bundle`] did.
#[derive(Clone, Debug)]
pub struct GenesisAdmission {
    /// Each offered bundle Verify read Valid, in lineage order. Its named
    /// rows and voices are held.
    pub placed: Vec<GenesisPlacement>,
    /// Each offered bundle that is not Valid.
    pub not_placed: Vec<NotPlaced>,
    /// Offered statements (by index) that are neither a bundle voice nor a
    /// row: each refused on its own, the others stand.
    pub unreadable: Vec<usize>,
    /// The genesis in force after the store.
    pub in_force: GenesisInForce,
}

fn not_placed(
    object_id: Digest32,
    v: &GenesisVerdict,
    refused_statements: &[ciris_verify_core::edition2::genesis::RefusedStatement],
) -> Option<NotPlaced> {
    let (token, detail, waiting) = match v {
        GenesisVerdict::Valid(_) => return None,
        // v62.0.0 (DV-fix1) — one fault, one spelling. Since CIRISVerify
        // 23.3.3 / 23.4.0 the bundle reader judges "one device per holder"
        // (CC 4.2.3) itself, as `Invalid(Malformed::HolderDeviceShared)`
        // (reason `holder_device_shared`); persist keeps no second check.
        // It surfaces persist's `holder_device_shared` token (C4-fix2), with
        // Verify's reason as the detail; every other Invalid reason stays
        // `genesis_bundle_malformed` (Verify's vectors: the
        // `recovery_commitment_*` reasons included).
        GenesisVerdict::Invalid(m) => (
            if m.reason() == token::DEVICE_SHARED {
                token::DEVICE_SHARED
            } else {
                token::MALFORMED
            },
            Some(m.reason().to_owned()),
            false,
        ),
        GenesisVerdict::Waiting(w) => {
            let mut on: Vec<String> = w
                .rows
                .iter()
                .map(|r| format!("row:{}", hex::encode(r)))
                .collect();
            on.extend(w.prev.iter().map(|p| format!("prev:{}", hex::encode(p))));
            on.extend(w.kids.iter().map(|k| format!("kid:{}", hex::encode(k))));
            (token::WAITING, Some(on.join(",")), true)
        }
        GenesisVerdict::Nothing(i) => (i.token(), i.detail().map(str::to_owned), false),
    };
    Some(NotPlaced {
        object_id,
        token,
        detail,
        waiting,
        refused: refused_statements
            .iter()
            .map(|r| format!("statement {}: {}", r.index, r.fault.token()))
            .collect(),
    })
}

/// v62.0.0 (wave GC5; CC 2.6.1.11 "a count not yet met concludes nothing,
/// and the bundle is held"; CC 2.7.3) — the bundle readings that HOLD the
/// bundle's voices, concluding nothing: its count unmet (or a recovery's
/// statement that does not count), its held predecessor not Valid, a named
/// row unplaced or Invalid. Each reads another statement (a further
/// holder's voice, the predecessor's reading, a named row), so it is a fold,
/// never a refusal. Not held: a first bundle the reader's anchor does not
/// select (the anchor is this node's own configuration, and a held first
/// bundle would be rooted by its own id), and a holder's custody (the
/// holder's own key plane).
fn holds_bundle(i: &Inconclusive) -> bool {
    matches!(
        i,
        Inconclusive::CountUnmet
            | Inconclusive::Commitment(_)
            | Inconclusive::PrevNotValid
            | Inconclusive::RowUnplaced { .. }
            | Inconclusive::RowInvalid { .. }
    )
}

/// v62.0.0 (wave GC5) — the held bundle voices, split in two: the voices of
/// bundles that concluded (Valid when stored), and of bundles HELD short
/// (their object id is held in the fold, `ceg_fold_held`). Only the first
/// are "held" to Verify's lineage reader: a held first bundle is rooted by
/// its own object id, which a bundle that never concluded must not be.
async fn held_voices<F>(dir: &F) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>), Error>
where
    F: FederationDirectory + ?Sized,
{
    let all = dir.edition2_objects(GENESIS_BUNDLE_TYP).await?;
    let mut short_of: BTreeMap<Digest32, bool> = BTreeMap::new();
    let (mut concluded, mut short) = (Vec::new(), Vec::new());
    for v in all {
        let oid = cose_parts(&v)
            .as_ref()
            .and_then(voice_of)
            .map(|(oid, _)| oid);
        let is_short = match oid {
            None => false,
            Some(o) => match short_of.get(&o) {
                Some(b) => *b,
                None => {
                    let b = dir.fold_held(&RowId(o)).await?.is_some();
                    short_of.insert(o, b);
                    b
                }
            },
        };
        if is_short {
            short.push(v);
        } else {
            concluded.push(v);
        }
    }
    Ok((concluded, short))
}

/// v62.0.0 (wave GC5; G0 v4) — record a bundle's fold state under its object
/// id: plane `typed_final` (a count once met is final; a bundle is never
/// un-concluded, CC 2.7.5), the local door, the ingest tier.
async fn record_bundle<F>(
    dir: &F,
    object_id: Digest32,
    held: Option<(String, String)>,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let id = RowId(object_id);
    let read = super::fold::Dep::Row(id).read_key();
    super::fold::arriving(
        super::fold::Arrival {
            row_id: id,
            replicated: false,
            tier: super::ingest::INGEST_TIER.to_owned(),
            plane: super::fold::plane::TYPED_FINAL,
            slot: read.clone(),
        },
        super::fold::record(
            dir,
            id,
            GENESIS_BUNDLE_TYP,
            super::ingest::INGEST_TIER,
            held,
            BTreeSet::from([read]),
        ),
    )
    .await
}

fn error_of(n: &NotPlaced) -> Error {
    let oid = hex::encode(n.object_id);
    if n.waiting {
        let first = n
            .detail
            .as_deref()
            .and_then(|d| d.split(',').next())
            .unwrap_or_default();
        return Error::unknown_signer(&format!("{GENESIS_BUNDLE_TYP}:{first}"), PLANE);
    }
    // v62.0.0 (CE-fix4) — Verify's per-statement refusals, by name.
    let refused = if n.refused.is_empty() {
        String::new()
    } else {
        format!("; refused statements: {}", n.refused.join(", "))
    };
    refuse(
        n.token,
        format!(
            "{}: bundle {oid} is not placed (CC 2.6.1.11); nothing of it is stored{refused}",
            n.detail.as_deref().unwrap_or(n.token)
        ),
    )
}

/// The keys a Valid bundle places: each holder's, seat's and witness's, and
/// the key each named `key:record` records (a recovery key's included).
/// Verify's reader has judged whose each is (CC 2.6.1.11: a key changes
/// hands only by a bundle), so a placed key answers for the identity a row
/// it signs names, as Verify's own `PlacedKey` does.
struct BundleKeys(BTreeMap<Digest32, CompositePublicKey>);

impl BundleKeys {
    fn of(p: &GenesisPlacement, named: &[Digest32], rows: &BTreeMap<Digest32, Vec<u8>>) -> Self {
        let mut m = BTreeMap::new();
        for h in &p.holders {
            m.insert(h.kid, h.key.clone());
        }
        for s in &p.seats {
            m.insert(s.kid, s.key.clone());
        }
        // v62.0.0 (PIN-fix2; CIRISVerify 23.4.1, CC v1.0-rc22-pre2) — the
        // charter's transparency services (were `witnesses`).
        for w in &p.transparency_services {
            m.insert(w.kid, w.key.clone());
        }
        for id in named {
            let Some(parts) = rows.get(id).and_then(|b| cose_parts(b)) else {
                continue;
            };
            if let Ok(r) = check_key_record(&parts.payload) {
                m.insert(r.kid, r.key);
            }
        }
        BundleKeys(m)
    }
}

impl KeyDirectory for BundleKeys {
    fn lookup(&self, kid: &Digest32, _asserted_at: u64) -> KeyLookup {
        self.0
            .get(kid)
            .cloned()
            .map_or(KeyLookup::NotHeld, |k| KeyLookup::Held(Box::new(k)))
    }

    fn key_of(&self, kid: &Digest32, _iss: &Digest32) -> KeyOf {
        if self.0.contains_key(kid) {
            KeyOf::Yes
        } else {
            KeyOf::No
        }
    }
}

/// A named row's own refusal, as the bundle's: the row's token, the message
/// naming the bundle and the row.
fn named_row_refused(object: &Digest32, row: &Digest32, e: Error) -> Error {
    match e {
        Error::MalformedRow {
            plane,
            reason,
            message,
        } => Error::malformed_row(
            plane,
            reason,
            format!(
                "bundle {} names row {}, which its own door refuses (a row is the same row \
                 inside a bundle and alone): {message}",
                hex::encode(object),
                hex::encode(row)
            ),
        ),
        other => other,
    }
}

/// **The named rows' own doors** (CC ruling (a): "a row is the same row
/// inside a bundle and alone"). Each named row not held is admitted by the
/// edition-2 door (`door::admit_row`: form, size, Verify's verdict in its
/// family, the key-of-issuer check, the row id, the key-record end rule)
/// under the keys the bundle places, then its closed payload is checked
/// (`payloads::check`). A seat binding's occurrence gates that read the
/// store alone (acts-for, the clock-skew bound) are answered by the
/// placement and the host clock. Nothing is read or stored. The rows come back
/// key plane first, so a row a named key signs follows that key's record.
///
/// # Errors
/// The first named row's refusal, under the row's own token
/// ([`named_row_refused`]).
/// The YubiKey serial extension (`1.3.6.1.4.1.41482.3.7`), its OID's DER
/// content bytes.
const OID_YUBICO_SERIAL: [u8; 10] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xc4, 0x0a, 0x03, 0x07];

/// One DER TLV at the start of `b`: `(tag, contents, rest)`. Single-byte
/// tags and definite lengths only (an X.509 certificate uses no other);
/// anything else is `None`.
fn der_tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = b.split_first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (&l0, rest) = rest.split_first()?;
    let (len, rest) = if l0 < 0x80 {
        (usize::from(l0), rest)
    } else {
        let n = usize::from(l0 & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |a, &x| (a << 8) | usize::from(x));
        (len, &rest[n..])
    };
    if rest.len() < len {
        return None;
    }
    Some((tag, &rest[..len], &rest[len..]))
}

/// v62.0.0 (C4-fix2; CC 4.2.3) — the token serial a YubiKey PIV
/// attestation leaf names (extension `1.3.6.1.4.1.41482.3.7`, an OCTET
/// STRING wrapping a non-negative DER INTEGER, as Verify's verifier reads
/// it). `None` for a leaf that does not parse as an X.509 certificate, has
/// no such extension, or carries a value that is not such an integer.
#[must_use]
pub fn yubikey_serial(leaf_der: &[u8]) -> Option<u64> {
    let (0x30, cert, _) = der_tlv(leaf_der)? else {
        return None;
    };
    let (0x30, tbs, _) = der_tlv(cert)? else {
        return None;
    };
    let mut fields = tbs;
    while !fields.is_empty() {
        let (tag, body, next) = der_tlv(fields)?;
        fields = next;
        // `extensions [3] EXPLICIT Extensions`
        if tag != 0xa3 {
            continue;
        }
        let (0x30, mut exts, _) = der_tlv(body)? else {
            return None;
        };
        while !exts.is_empty() {
            let (0x30, ext, next) = der_tlv(exts)? else {
                return None;
            };
            exts = next;
            let (0x06, oid, after_oid) = der_tlv(ext)? else {
                return None;
            };
            if oid != OID_YUBICO_SERIAL {
                continue;
            }
            // `critical BOOLEAN DEFAULT FALSE`, then `extnValue OCTET STRING`.
            let (tag, value, after) = der_tlv(after_oid)?;
            let (tag, value) = if tag == 0x01 {
                let (t, v, _) = der_tlv(after)?;
                (t, v)
            } else {
                (tag, value)
            };
            if tag != 0x04 {
                return None;
            }
            let (0x02, int, tail) = der_tlv(value)? else {
                return None;
            };
            if !tail.is_empty() || int.is_empty() || int[0] & 0x80 != 0 {
                return None;
            }
            let digits = if int.len() > 1 && int[0] == 0 {
                &int[1..]
            } else {
                int
            };
            if digits.len() > 8 {
                return None;
            }
            return Some(digits.iter().fold(0u64, |a, &x| (a << 8) | u64::from(x)));
        }
        return None;
    }
    None
}

/// v62.0.0 (DV-fix1) — **name the shared device** in a not-placed bundle's
/// detail when Verify's reader refused it `holder_device_shared` (its
/// verdict names the fault, not the device): from the bundle's own named
/// holder `key:record`s, the serial two listed holders' leaves both name
/// (persist's own [`yubikey_serial`], the parse the door already uses).
/// Appended after Verify's reason: `holder_device_shared; holders A and B
/// both name YubiKey serial N`. Nothing is judged here; a bundle whose
/// device cannot be named keeps Verify's reason alone.
fn name_shared_device(n: &mut NotPlaced, o: &LineageObject, rows: &BTreeMap<Digest32, Vec<u8>>) {
    if n.detail.as_deref() != Some(token::DEVICE_SHARED) {
        return;
    }
    let Some(payload) = o.kept.iter().find_map(|v| cose_parts(v)).map(|p| p.payload) else {
        return;
    };
    let holders: BTreeSet<&str> = payload
        .get_text("holders")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_text).collect())
        .unwrap_or_default();
    let mut by_serial: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    for id in &o.named {
        let Some(p) = rows.get(id).and_then(|st| cose_parts(st)) else {
            continue;
        };
        let Ok(rec) = check_key_record(&p.payload) else {
            continue;
        };
        let Some(author) = p
            .payload
            .get_text("author")
            .and_then(Value::as_text)
            .filter(|a| holders.contains(a))
        else {
            continue;
        };
        if let Some(serial) = rec.chain.first().and_then(|leaf| yubikey_serial(leaf)) {
            by_serial
                .entry(serial)
                .or_default()
                .insert(author.to_owned());
        }
    }
    if let Some((serial, who)) = by_serial.into_iter().find(|(_, w)| w.len() > 1) {
        let who: Vec<String> = who.into_iter().collect();
        n.detail = Some(format!(
            "{}; holders {} both name YubiKey serial {serial}",
            token::DEVICE_SHARED,
            who.join(" and ")
        ));
    }
}

fn admit_named(
    object: &Digest32,
    p: &GenesisPlacement,
    named: &[Digest32],
    rows: &BTreeMap<Digest32, Vec<u8>>,
    held: &BTreeSet<Digest32>,
) -> Result<Vec<AdmittedRow>, Error> {
    admit_named_at(object, p, named, rows, held, crate::host::clock::now())
}

/// [`admit_named`] with the clock-skew bound read at `now` (v62.0.0
/// CE-fix1: the offline ceremony's [`check_genesis_offer`] passes its own
/// instant; the door passes the host clock).
fn admit_named_at(
    object: &Digest32,
    p: &GenesisPlacement,
    named: &[Digest32],
    rows: &BTreeMap<Digest32, Vec<u8>>,
    held: &BTreeSet<Digest32>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<AdmittedRow>, Error> {
    let keys = BundleKeys::of(p, named, rows);
    let mut out = Vec::new();
    for id in named {
        if held.contains(id) {
            continue;
        }
        let Some(bytes) = rows.get(id) else {
            continue;
        };
        let a = super::door::admit_row(bytes, &keys, Some(id), SelectContext::default())
            .map_err(|e| named_row_refused(object, id, e))?;
        super::payloads::check(&a.family, &a.payload)
            .map_err(|e| named_row_refused(object, id, e))?;
        if a.family == BINDING_FAMILY {
            // The occurrence door's store-reading gates, answered by the
            // placement: the binding's author acts for its identity because
            // the bundle seats that key for it (CC 2.6.1.11), and its
            // instant is not ahead of this node's clock.
            if !p
                .seats
                .iter()
                .any(|s| s.identity_ref == a.iss && s.kid == a.kid)
            {
                return Err(named_row_refused(
                    object,
                    id,
                    refuse(
                        token::ROW_INVALID,
                        "row_signer: the binding is not signed by the key the bundle places \
                         for its seat",
                    ),
                ));
            }
            let at = i64::try_from(a.asserted_at_ms)
                .ok()
                .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis)
                .ok_or_else(|| {
                    named_row_refused(
                        object,
                        id,
                        refuse(
                            malformed_row::EDITION2_PAYLOAD_INVALID,
                            "`asserted_at` is not an instant",
                        ),
                    )
                })?;
            crate::federation::operational::check_skew_bound(at, now)
                .map_err(|e| named_row_refused(object, id, e))?;
        }
        out.push(a);
    }
    out.sort_by_key(|a| !(a.family == KEY_RECORD_FAMILY || a.family == KEY_REVOCATION_FAMILY));
    Ok(out)
}

// ------------------------------------------------------------------ the builders

/// v62.0.0 (CE-fix1; CC 2.6.1.11, CC 5.3.4) — **what a `ceg-genesis-bundle/2`
/// states**: the payload members Verify's bundle reader takes
/// (`parse_payload`), with no witness directory. Every key is an
/// identity-ref; every row is named by its row id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleTerms {
    /// `version`: 1 for a first bundle.
    pub version: u64,
    /// `refs.prev`: a later bundle's predecessor (none on version 1).
    pub prev: Option<Digest32>,
    /// `asserted_at`, POSIX ms (the voices' `iat` is its seconds).
    pub asserted_at_ms: u64,
    /// The accord's `family_key_id`.
    pub family_key_id: String,
    /// `holders`: the holders' identity-refs.
    pub holders: Vec<String>,
    /// `serve_nodes`: the seats' identity-refs.
    pub serve_nodes: Vec<String>,
    /// `refs.also.cites`: every row the bundle names (the holders' and
    /// seats' `key:record`s, the seats' bindings, a recovery key's record).
    pub cites: Vec<Digest32>,
    /// `charter.recovery_commitments`: one per holder, by identity-ref.
    pub recovery_commitments: Vec<(String, Digest32)>,
    /// `charter.scope`: at least `infra:attest` and `infra:serve`. A SET: the
    /// host passes it in any order, and [`bundle_payload`] writes it in CDE set
    /// order (shortest encoding first, then bytewise), the order Verify's
    /// reader requires (a lexicographic list is `federation_set_semantics_
    /// unsorted` there). A repeated token is collapsed, not refused.
    pub scope: Vec<String>,
    /// `charter.halt_fuse_secs`; `None` leaves the reader's default.
    pub halt_fuse_secs: Option<u32>,
}

/// A CBOR set: members sorted by their encodings, no duplicate.
fn cbor_set(mut xs: Vec<Value>) -> Value {
    xs.sort_by_key(cde::encode);
    xs.dedup();
    Value::Array(xs)
}

/// v62.0.0 (CE-fix1) — **the payload of a genesis bundle** (CC 2.6.1.11),
/// in the deterministic map order and with every set sorted by encoding:
/// the one producer of the bundle the ceremony signs and of the test
/// ceremony (`fixture_genesis`). Judging it is the reader's.
#[must_use]
pub fn bundle_payload(t: &BundleTerms) -> Value {
    use super::emit::sorted_map;
    use ciris_verify_core::edition2::{hash_digest_value, row_ref};
    let text = |s: &str| Value::Text(s.to_owned());
    let mut refs = vec![(
        text("also"),
        sorted_map(vec![(
            text("cites"),
            cbor_set(t.cites.iter().map(row_ref).collect()),
        )]),
    )];
    if let Some(p) = &t.prev {
        refs.push((text("prev"), row_ref(p)));
    }
    let mut charter = vec![
        (
            text("recovery_commitments"),
            sorted_map(
                t.recovery_commitments
                    .iter()
                    .map(|(h, c)| (text(h.as_str()), hash_digest_value(c)))
                    .collect(),
            ),
        ),
        (
            text("scope"),
            cbor_set(t.scope.iter().map(|s| text(s.as_str())).collect()),
        ),
    ];
    if let Some(f) = t.halt_fuse_secs {
        charter.push((text("halt_fuse_secs"), Value::Uint(u64::from(f))));
    }
    sorted_map(vec![
        (text("refs"), sorted_map(refs)),
        (text("version"), Value::Uint(t.version)),
        (text("asserted_at"), Value::Uint(t.asserted_at_ms)),
        (text("family_key_id"), text(t.family_key_id.as_str())),
        (
            text("holders"),
            cbor_set(t.holders.iter().map(|h| text(h.as_str())).collect()),
        ),
        (
            text("serve_nodes"),
            cbor_set(t.serve_nodes.iter().map(|h| text(h.as_str())).collect()),
        ),
        (text("charter"), sorted_map(charter)),
    ])
}

/// v62.0.0 (CE-fix1) — the bundle's object id (`["CEG-object/2", typ,
/// null, payload]`): what an object-id anchor names, and what a holder
/// publishes once the bundle is signed (CEREMONY step 5).
#[must_use]
pub fn bundle_object_id(payload: &Value) -> Digest32 {
    object_id(GENESIS_BUNDLE_TYP, None, &cde::encode(payload))
}

/// v62.0.0 (CE-fix1; CC 5.3.4) — **one signer's voice over a bundle,
/// drafted**: the object header (`kid`, `iss`, `sub` the payload's
/// `family_key_id` (CE-fix4), `typ` `ceg-genesis-bundle/2`, `iat` the
/// bundle's `asserted_at` in seconds), the payload as encoded.
/// The signer (a holder; a recovery key speaking as its holder's `iss`)
/// signs `Draft::sig_structure` with its composite key.
#[must_use]
pub fn bundle_voice_draft(
    kid: &Digest32,
    iss: &str,
    payload: &Value,
    asserted_at_ms: u64,
) -> super::emit::Draft {
    // v62.0.0 (CE-fix4) — `sub` = the payload's `family_key_id` (the
    // lineage), as every bundle voice states it.
    let sub = payload.get_text("family_key_id").and_then(Value::as_text);
    let protected = super::produce::object_protected(
        kid,
        iss,
        sub,
        GENESIS_BUNDLE_TYP,
        Some(asserted_at_ms / 1000),
    );
    let payload = cde::encode(payload);
    let sig_structure = ciris_verify_core::edition2::sig_structure(&protected, &payload);
    super::emit::Draft {
        protected,
        payload,
        sig_structure,
    }
}

/// v62.0.0 (CE-fix1) — **the genesis door's reading of an offer on a fresh
/// node, with no store**: what [`put_genesis_bundle`] would place on a node
/// holding nothing, read from `statements` alone (bundle voices and the
/// rows they name) under `anchor`, with the clock-skew bound at `now`.
/// Every check the door runs before it writes runs here, in its order:
/// the statement form and window of every statement; Verify's lineage
/// reader (payload, count, anchor, custody gate against
/// [`attestation_roots`]); one device per holder; each named row's own door
/// under the keys the bundle places, its closed payload, and a seat
/// binding's signer and typed payload. Pure: no I/O, no backend feature.
///
/// NOT covered (the store's, run only by the real door): the occurrence
/// write plan and route projection of each seat binding, the key read
/// models, the transaction, and anything that reads held rows (a later
/// bundle's held predecessor, voices held short). For those, the ceremony's
/// final gate is `crate::ceremony::import_offer_into_throwaway`.
///
/// A bundle the door would HOLD short (a count not yet met) is an error
/// here: the ceremony seals only a bundle that places.
///
/// # Errors
/// The door's own errors, by the same tokens: `earlier_form_object`,
/// `genesis_bundle_malformed` (`no_voice`, or an Invalid bundle), the
/// retryable unknown-signer error for a bundle waiting on a row it does not
/// carry, Verify's inconclusive tokens (`genesis_bundle_not_anchored`,
/// `genesis_bundle_count_unmet`, `genesis_holder_custody`, …),
/// `holder_device_shared` (Verify's, the device named), and a named row's own
/// refusal.
pub fn check_genesis_offer(
    statements: &[Vec<u8>],
    anchor: Option<&Anchor>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<GenesisPlacement>, Error> {
    let mut offered: Vec<Vec<u8>> = Vec::new();
    let mut carried: BTreeMap<Digest32, Vec<u8>> = BTreeMap::new();
    for s in statements {
        super::door::require_statement_form(s)?;
        let parts = cose_parts(s);
        if parts.as_ref().and_then(voice_of).is_some() {
            if let Some(p) = parts.as_ref() {
                super::door::check_valid_until_after_asserted_at(&p.payload)?;
            }
            offered.push(s.clone());
        } else if let Some(id) = RowId::of_statement(s) {
            carried.entry(id.0).or_insert_with(|| s.clone());
        }
    }
    if offered.is_empty() {
        return Err(refuse(
            token::MALFORMED,
            "no_voice: the statements carry no `ceg-genesis-bundle/2` voice",
        ));
    }
    let mut rows = BTreeMap::new();
    for v in &offered {
        if let Some(p) = cose_parts(v) {
            for id in named_by(&p.payload) {
                if let Some(c) = carried.get(&id) {
                    rows.insert(id, c.clone());
                }
            }
        }
    }
    let roots = attestation_roots();
    let reading = read_lineage(&LineageInput {
        held: &[],
        offered: &offered,
        rows: &rows,
        anchor,
        attestation_roots: &roots,
    });
    let none_held = BTreeSet::new();
    let mut placed = Vec::new();
    let mut refused = Vec::new();
    for o in &reading.objects {
        if let Some(mut n) = not_placed(o.reading.object_id, &o.reading.verdict, &o.reading.refused)
        {
            name_shared_device(&mut n, o, &rows);
            refused.push(n);
            continue;
        }
        let Some(p) = o.reading.verdict.placement() else {
            continue;
        };
        // The seat binding's typed payload (`occurrence::read_payload`, pure)
        // is read; the occurrence write plan and its route projection are the
        // store's (backend-gated `occurrence_admit`), run by the real door
        // (`crate::ceremony::import_offer_into_throwaway`).
        for a in admit_named_at(&o.reading.object_id, p, &o.named, &rows, &none_held, now)?
            .iter()
            .filter(|a| a.family == BINDING_FAMILY)
        {
            let _occurrence = super::occurrence::read_payload(a)?;
        }
        placed.push(p.clone());
    }
    match refused.first() {
        Some(n) => Err(error_of(n)),
        None if placed.is_empty() => Err(refuse(
            token::MALFORMED,
            "no_voice: no offered statement is a readable bundle voice",
        )),
        None => Ok(placed),
    }
}

// ------------------------------------------------------------------ dial hints (CE-fix3)

/// v62.0.0 (CE-fix3) — the refusal of a BAKED bundle one of whose serve
/// seats has no `tcp` dial hint (a node cold-booting from the bake could
/// not dial it). The bake gate's own token: Verify's reader refuses a
/// genesis serve seat with no `tcp` hint first (`seat_dial_hints_missing`),
/// so on a Verify-placed bundle this is the second line, run on the
/// placement a bake ships.
pub const BAKED_SEAT_NOT_DIALABLE: &str = "baked_seat_not_dialable";

/// v62.0.0 (CE-fix3; Eric's ruling: trust-root dial hints go SIGNED in the
/// bundle) — **every serve seat of `p` is dialable**: it carries at least
/// one `tcp` dial hint: Verify's `edition2::has_tcp_hint` over
/// `PlacedSeat::dial_hints` (23.3.3, BELIEVED until the pin). Pure.
///
/// # Errors
/// `InvalidArgument` leading with [`BAKED_SEAT_NOT_DIALABLE`], naming the
/// first such seat.
pub fn check_seats_dialable(p: &GenesisPlacement) -> Result<(), Error> {
    // Verify's own seat check (23.3.3), never a re-derivation of it.
    for s in &p.seats {
        if !ciris_verify_core::edition2::has_tcp_hint(&s.dial_hints) {
            return Err(Error::InvalidArgument(format!(
                "{BAKED_SEAT_NOT_DIALABLE}: serve seat {} of bundle {} carries no tcp dial \
                 hint; a baked genesis must be dialable from a cold boot",
                s.identity_ref,
                hex::encode(p.object_id)
            )));
        }
    }
    Ok(())
}

/// v62.0.0 (CE-fix3; GB-fix1) — **every genesis bundle this build BAKES**:
/// `(name, bytes)`, the bytes a CDE array of the bundle's statements (its
/// voices and every row it names, as bstr), each statement BYTE-FOR-BYTE as
/// the ceremony signed it (only the array framing is this build's). v62.0
/// bakes the real HUMANITY_ACCORD genesis (minted 2026-11-21; package
/// `ciris-genesis-2026-11-21-public`): bundle `cb9ada31…deb5`, version 1,
/// holders A1/B1/C1, one serve seat `canonical-1`. Its eight statements, in
/// put order, are [`BAKED_GENESIS_STATEMENTS`]. A fresh node imports it at
/// open through the import door ([`import_baked_genesis`]). A bake anywhere
/// else is refused by the from-disk witness (I2293).
pub const BAKED_BUNDLES: &[(&str, &[u8])] = &[(
    "humanity-accord-v1",
    include_bytes!("baked/humanity-accord-genesis-v1.cbor"),
)];

/// v62.0.0 (GB-fix1) — the object id of the baked bundle (`terms.json`'s
/// `bundle_object_id`): the anchor a fresh node imports it under.
pub const BAKED_GENESIS_OBJECT_ID: &str =
    "cb9ada31fbce34103a8b01acecc67bbb8cb0e96c1210bb83e40c5f34d8e6deb5";

/// v62.0.0 (GB-fix1) — the baked bundle's statements in put order, by their
/// file in the ceremony package and its SHA-256 (the package's `SHA256SUMS`):
/// the three holders' key records, the seat's key record and its occurrence
/// binding (the five rows the voices cite), then the three holders' voices.
pub const BAKED_GENESIS_STATEMENTS: [(&str, &str); 8] = [
    (
        "holder-record-0.cose",
        "77448a059b81a91256bc297e717d515b0b0e7b74089fbcae28d74dc059d6a284",
    ),
    (
        "holder-record-1.cose",
        "fa2515f80597460c912bdb6d2839d475c04c06c136dfbdecce416b2122754694",
    ),
    (
        "holder-record-2.cose",
        "7205dec0015cee38278d43b17e27ddf3a3048c68d5203116431396333ddae0c3",
    ),
    (
        "seat-record-0.cose",
        "19059c7ac7099a2b5e7095b68f0b5c56dafe718ae0a6d8bbe5fdadce5f6ea6b1",
    ),
    (
        "seat-binding-0.cose",
        "b98406f054d0264bba5a8f46bc49658a100be87027356109d4a87baed11804a8",
    ),
    (
        "voice-0.cose",
        "32d13cddfddb6723558732f48592ead1a23c9bd2d5f0a496f1debcdc2d73b616",
    ),
    (
        "voice-1.cose",
        "edf8cb41d7dc7898756e58361d3bf6e426ccf6bbbdf76c07aab928ef5839a169",
    ),
    (
        "voice-2.cose",
        "b116e0b2c7715211cc33f77a5f626ba527e61fd2645abb908996e8157c457815",
    ),
];

/// v62.0.0 (GB-fix1) — the SHA-256 of the baked array itself
/// (`baked/humanity-accord-genesis-v1.cbor`).
pub const BAKED_GENESIS_ARRAY_SHA256: &str =
    "4bd259f1d1df8513de210bca4bc1544f8fdcb548f4f964b33355412b8df50e95";

/// v62.0.0 (GB-fix1) — a baked bundle's statements: the CDE array's bstr
/// elements, as they are (no element is re-encoded). `None`: not an array of
/// bstr.
#[must_use]
pub fn baked_statements(bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    let v = cde::decode(bytes).ok()?;
    let a = v.as_array()?;
    a.iter().map(|s| s.as_bytes().map(<[u8]>::to_vec)).collect()
}

/// v62.0.0 (GB-fix1) — **the anchor a production node imports the baked
/// genesis under**: [`Anchor::ObjectId`] of [`BAKED_GENESIS_OBJECT_ID`], a
/// CONSTANT of this source computed once from the ceremony package, never
/// derived from the baked bytes at run time (a changed baked byte changes
/// the bundle's object id, and the bundle is then void for this reader:
/// Verify's `NotAnchored`). No environment variable or configuration
/// reaches it.
///
/// # Panics
/// Never: the constant is 64 hex (I2468 pins it).
#[must_use]
pub fn baked_genesis_anchor() -> Anchor {
    let mut oid = [0u8; 32];
    hex::decode_to_slice(BAKED_GENESIS_OBJECT_ID, &mut oid)
        .expect("BAKED_GENESIS_OBJECT_ID is 64 hex");
    Anchor::ObjectId(oid)
}

/// v62.0.0 (GB-fix1) — what an import of baked bundles did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BakedImport {
    /// The node held no genesis bundle; the baked bundles were offered at the
    /// import door and these object ids (hex) were placed.
    Imported(Vec<String>),
    /// The node already holds a genesis bundle (the baked one, a later one of
    /// its lineage, or any other): nothing was offered and nothing changed.
    AlreadyHeld,
    /// This build bakes no bundle.
    NoneBaked,
}

/// v62.0.0 (GB-fix1; CC 2.6.1.11, CC 5.3.4) — **a fresh node imports the
/// baked genesis**: [`import_genesis_bundles`] of [`BAKED_BUNDLES`] under
/// [`baked_genesis_anchor`]. Importing is not ACCEPTING: the node stays
/// rootless until its own (or its owner's) acceptance edge names the root
/// (`Engine::accept_root`; CC 3.2 T3).
///
/// # Errors
/// As [`import_genesis_bundles`].
pub async fn import_baked_genesis<F>(dir: &F) -> Result<BakedImport, Error>
where
    F: FederationDirectory + ?Sized,
{
    import_genesis_bundles(dir, BAKED_BUNDLES, &baked_genesis_anchor()).await
}

/// v62.0.0 (GB-fix1) — **offer `bundles` (each a CDE array of statements) at
/// THE import door** ([`put_genesis_bundle`]) under `anchor`, when `dir`
/// holds no genesis bundle. Idempotent: a node holding any bundle (the same
/// one on a reopen, a later bundle of its lineage, which holds the first as
/// its `prev`, or another) offers nothing and changes nothing. The order of
/// statements within a bundle is not significant to the door: voices and
/// rows are told apart by their own bytes, rows are found by row id, and key
/// records are admitted first.
///
/// # Errors
/// `genesis_bundle_malformed` for bytes that are not an array of statements;
/// the import door's refusal, unchanged (`genesis_bundle_not_anchored`, a
/// named row's own token, `genesis_holder_custody`, ...), including a bundle
/// the door kept without placing it; directory reads.
pub async fn import_genesis_bundles<F>(
    dir: &F,
    bundles: &[(&str, &[u8])],
    anchor: &Anchor,
) -> Result<BakedImport, Error>
where
    F: FederationDirectory + ?Sized,
{
    if bundles.is_empty() {
        return Ok(BakedImport::NoneBaked);
    }
    if genesis_in_force(dir).await?.held > 0 {
        return Ok(BakedImport::AlreadyHeld);
    }
    let mut placed = Vec::new();
    for (name, bytes) in bundles {
        let statements = baked_statements(bytes).ok_or_else(|| {
            refuse(
                token::MALFORMED,
                format!("baked bundle {name}: not a CDE array of statements"),
            )
        })?;
        let admission = put_genesis_bundle(dir, &statements, Some(anchor)).await?;
        if let Some(n) = admission.not_placed.first() {
            return Err(error_of(n));
        }
        placed.extend(admission.placed.iter().map(|p| hex::encode(p.object_id)));
    }
    Ok(BakedImport::Imported(placed))
}

/// v62.0.0 (GB-fix1) — what the open leg did ([`import_baked_genesis_at_boot`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootImport {
    /// As [`import_genesis_bundles`] answered.
    Done(BakedImport),
    /// Skipped: Verify's test-anchor mode is active (a test rig roots its
    /// own ceremony).
    TestAnchor,
    /// The import door refused the baked bundle: its token. The node opens
    /// ROOTLESS (a supported state: the mesh runs) and says so loudly.
    Refused(String),
}

/// The refusal token of an import error: a malformed row's reason, else the
/// error's kind.
fn token_of(e: &Error) -> String {
    match e {
        Error::MalformedRow { reason, .. } => (*reason).to_string(),
        other => other.kind().to_owned(),
    }
}

/// v62.0.0 (GB-fix1) — **the open leg**: [`import_baked_genesis`] at a
/// node's open, run by the Engine's production constructors and by the
/// Python wheel's open alike (one function), after the migrations and
/// before anything reads standing. Never boot-fatal and never silent: a
/// refusal is logged at ERROR with its token and the node opens rootless.
pub async fn import_baked_genesis_at_boot<F>(dir: &F) -> BootImport
where
    F: FederationDirectory + ?Sized,
{
    import_bundles_at_boot(dir, BAKED_BUNDLES, &baked_genesis_anchor()).await
}

/// [`import_baked_genesis_at_boot`] over given bundles (the witnesses' seam:
/// a corrupted COPY is offered here; the baked bytes are never changed).
pub(crate) async fn import_bundles_at_boot<F>(
    dir: &F,
    bundles: &[(&str, &[u8])],
    anchor: &Anchor,
) -> BootImport
where
    F: FederationDirectory + ?Sized,
{
    // (Never in lib unit tests: their witnesses run this leg itself.)
    #[cfg(all(feature = "test-anchor", not(test)))]
    if ciris_verify_core::test_anchor::test_anchor_active() {
        return BootImport::TestAnchor;
    }
    match import_genesis_bundles(dir, bundles, anchor).await {
        Ok(done) => {
            if let BakedImport::Imported(ids) = &done {
                tracing::info!(
                    bundles = ?ids,
                    "the baked genesis was imported at the import door (not accepted: the \
                     node roots nothing until it accepts the root)"
                );
            }
            BootImport::Done(done)
        }
        Err(e) => {
            let token = token_of(&e);
            tracing::error!(
                posture = "pre_genesis",
                token = %token,
                error = %e,
                "THE BAKED GENESIS WAS REFUSED at the import door ({token}); this node opens \
                 holding no root (rootless: the mesh runs, nothing is rooted)"
            );
            BootImport::Refused(token)
        }
    }
}

/// v62.0.0 (CE-fix3) — **the bake gate**: a baked bundle (`bytes`, a CDE
/// array of statements) reads Valid under its OWN object id
/// ([`check_genesis_offer`], with every refusal of Verify's reader by its
/// name: `seat_dial_hints_missing`, `dial_hint_malformed`,
/// `Malformed { member: "dial_hints" }`), and every seat of every placed
/// bundle is dialable ([`check_seats_dialable`]). Pure.
///
/// # Errors
/// `genesis_bundle_malformed` for bytes that are not an array of statements
/// or carry no bundle voice; as [`check_genesis_offer`];
/// [`BAKED_SEAT_NOT_DIALABLE`].
pub fn check_baked_bundle(
    bytes: &[u8],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<GenesisPlacement>, Error> {
    let statements: Vec<Vec<u8>> = baked_statements(bytes).ok_or_else(|| {
        refuse(
            token::MALFORMED,
            "baked bundle: not a CDE array of statements",
        )
    })?;
    let oid = statements
        .iter()
        .find_map(|s| cose_parts(s).as_ref().and_then(voice_of).map(|(o, _)| o))
        .ok_or_else(|| refuse(token::MALFORMED, "baked bundle: no bundle voice"))?;
    let placed = check_genesis_offer(&statements, Some(&Anchor::ObjectId(oid)), now)?;
    for p in &placed {
        check_seats_dialable(p)?;
    }
    Ok(placed)
}

/// v62.0.0 (CE-fix3) — **the trust-root bootstrap dial set**: every seat of
/// the genesis in force with its signed dial hints, `(identity_ref, hint)`,
/// most preferred first per seat. Replaces the earlier-form
/// `KeyRecord::transport_hints()` read over `list_canonical_servers`.
///
/// v62.0.0 (HT-fix1; CC rc22 2.6.8: "a dialler skips" a hint of an unknown
/// type) — an `Unknown` hint (carried, as signed, by Verify's reader) is
/// SKIPPED here: it is no dialable bootstrap entry, and it does not drop the
/// seat's known hints around it.
#[must_use]
pub fn bootstrap_hints(
    g: &GenesisInForce,
) -> Vec<(String, ciris_verify_core::edition2::fedcode::Hint)> {
    use ciris_verify_core::edition2::fedcode::Hint;
    g.seats()
        .iter()
        .flat_map(|s| {
            s.dial_hints
                .iter()
                .filter(|h| !matches!(h, Hint::Unknown { .. }))
                .map(move |h| (s.identity_ref.clone(), h.clone()))
        })
        .collect()
}

/// v62.0.0 (CE-fix3) — one bootstrap hint as the host surface's JSON:
/// `{identity_ref, type, body_hex}` (the FedCode hint, byte for byte, via
/// Verify's `fedcode::hint_parts`; an `Unknown` hint as signed), plus the
/// readable members of a known kind: `kind` (`tcp` | `udp` | `auto` |
/// `rnode` | `http` | `i2p` | `kiss` | `ble` | `unknown`), and `host` /
/// `port` (tcp, udp), `url` (http), `destination_hex` (i2p), or
/// `frequency_hz` / `bitrate` / `callsign` (kiss; `callsign` null when not
/// named). v62.0.0 (HT-fix2): i2p / kiss / ble.
#[must_use]
pub fn dial_hint_json(
    identity_ref: &str,
    h: &ciris_verify_core::edition2::fedcode::Hint,
) -> serde_json::Value {
    use ciris_verify_core::edition2::fedcode::{hint_parts, Hint};
    let mut o = serde_json::json!({ "identity_ref": identity_ref });
    // `hint_parts` refuses `Unknown` (a minter emits only assigned types);
    // a placed `Unknown` hint carries its own type and body as signed.
    let parts = match h {
        Hint::Unknown { tag, body } => Some((*tag, body.clone())),
        other => hint_parts(other).ok(),
    };
    if let Some((tag, body)) = parts {
        o["type"] = serde_json::json!(tag);
        o["body_hex"] = serde_json::json!(hex::encode(body));
    }
    match h {
        Hint::Tcp { host, port } => {
            o["kind"] = "tcp".into();
            o["host"] = host.clone().into();
            o["port"] = (*port).into();
        }
        Hint::Udp { host, port } => {
            o["kind"] = "udp".into();
            o["host"] = host.clone().into();
            o["port"] = (*port).into();
        }
        Hint::Auto { .. } => o["kind"] = "auto".into(),
        Hint::RNode { .. } => o["kind"] = "rnode".into(),
        Hint::Http { url } => {
            o["kind"] = "http".into();
            o["url"] = url.clone().into();
        }
        // v62.0.0 (HT-fix2; CC rc22 2.6.8, Verify 23.4.0 320d41f) — types 6,
        // 7 and 8.
        Hint::I2p { destination } => {
            o["kind"] = "i2p".into();
            o["destination_hex"] = hex::encode(destination).into();
        }
        Hint::Kiss {
            frequency_hz,
            bitrate,
            callsign,
        } => {
            o["kind"] = "kiss".into();
            o["frequency_hz"] = (*frequency_hz).into();
            o["bitrate"] = (*bitrate).into();
            o["callsign"] = callsign.clone().into();
        }
        Hint::Ble => o["kind"] = "ble".into(),
        _ => o["kind"] = "unknown".into(),
    }
    o
}

/// A test seam on [`GenesisWrite`]: a backend fails the transaction after
/// every write and before the commit. Always [`WriteFault::None`] outside
/// the witnesses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WriteFault {
    /// No fault.
    #[default]
    None,
    /// Fail after every write, before the commit (the rollback witness).
    BeforeCommit,
}

/// **What a placed genesis offer writes, in ONE backend transaction**
/// ([`FederationDirectory::put_edition2_genesis`]): all or nothing. The
/// backend answers whether each planned occurrence's upsert applied, in
/// order.
#[derive(Clone, Debug, Default)]
pub struct GenesisWrite {
    /// Each named row its own door admitted, key plane first
    /// (`ceg_statements`, `ceg_row_names`).
    pub rows: Vec<AdmittedRow>,
    /// The read models of the keys the bundles place (`federation_keys`,
    /// `federation_revocations`).
    pub keys: super::projection::ProjectionSet,
    /// Each kept bundle voice (`ceg_statements`, typ `ceg-genesis-bundle/2`).
    pub objects: Vec<HeldObject>,
    /// Each seat binding's typed occurrence row (`federation_identity_
    /// occurrences` + its history), planned by the occurrence door's own
    /// plan (wave O1), written in the same transaction.
    pub(crate) occurrences: Vec<crate::federation::occurrence_admit::PlannedOccurrence>,
    /// The witnesses' seam.
    pub fault: WriteFault,
}

/// The read models of the keys a placement seats, derived from the held key
/// plane plus the offer's admitted key records, with the placement's seats
/// answering whose each placed key is (`HeldKeys::with_seats`). Reads only.
async fn plan_keys<F>(
    dir: &F,
    p: &GenesisPlacement,
    rows: &[AdmittedRow],
    into: &mut super::projection::ProjectionSet,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let placed: Vec<(String, Digest32)> = p
        .holders
        .iter()
        .map(|h| (h.identity_ref.clone(), h.kid))
        .chain(p.seats.iter().map(|s| (s.identity_ref.clone(), s.kid)))
        .chain(
            p.transparency_services
                .iter()
                .map(|w| (w.identity_ref.clone(), w.kid)),
        )
        .collect();
    let seats = BundleSeats::held(placed.iter().cloned());
    for (_, kid) in &placed {
        let mut held = super::ingest::held_keys_for_kid(dir, kid)
            .await?
            .with_seats(seats.clone());
        for r in rows.iter().filter(|r| r.family == KEY_RECORD_FAMILY) {
            held.insert_record(r.bytes.clone());
        }
        let set = super::projection::projection_set(&held, kid)?;
        for k in set.keys {
            if !into.keys.iter().any(|x| x.key_id == k.key_id) {
                into.keys.push(k);
            }
        }
        for r in set.revocations {
            if !into
                .revocations
                .iter()
                .any(|x| x.revocation_id == r.revocation_id)
            {
                into.revocations.push(r);
            }
        }
    }
    Ok(())
}

/// **The genesis door.**
///
/// `statements` carries bundle voices (one or more objects: a lineage may
/// travel whole) and the rows they name, in any order; rows already held
/// need not be sent. `anchor` roots a first bundle not already held (CC
/// 5.3.4); `None` roots nothing new.
///
/// Each offered bundle Verify reads Valid is stored: its named rows, then
/// its voices in `ceg_statements` (typ `ceg-genesis-bundle/2`; `row_type`,
/// `family`, `sub` NULL). Nothing of an offered bundle that is not Valid is
/// stored.
///
/// A named row is the same row inside a bundle and alone (CC ruling (a)):
/// before anything is stored, each named row not held passes its own door
/// under the keys the bundle places ([`admit_named`]). Then the rows, the
/// placed keys' read models and the voices are written in ONE backend
/// transaction ([`GenesisWrite`]): a failure anywhere leaves nothing.
///
/// # Errors
/// - a named row its own door refuses: the WHOLE offer is refused under the
///   row's own token (e.g. `edition2_payload_invalid` for a seat binding
///   without `device_class`), and nothing is stored;
///
/// and only when no offered bundle is placed:
/// - `earlier_form_object` for a statement of the earlier form (a bundle/1
///   JSON object included);
/// - `genesis_bundle_malformed` when no `ceg-genesis-bundle/2` voice is
///   offered, and for an Invalid bundle (Verify's reason first in the
///   message);
/// - the retryable unknown-signer error (`federation_attester_key_unknown`)
///   for a bundle waiting on a named row or its predecessor;
/// - Verify's token for a bundle that concludes nothing:
///   `genesis_bundle_not_anchored`, `genesis_bundle_prev_not_valid`,
///   `genesis_bundle_row_unplaced`, `genesis_bundle_row_invalid`,
///   `genesis_holder_custody`, `genesis_bundle_count_unmet`;
/// - storage failures (at any time).
pub async fn put_genesis_bundle<F>(
    dir: &F,
    statements: &[Vec<u8>],
    anchor: Option<&Anchor>,
) -> Result<GenesisAdmission, Error>
where
    F: FederationDirectory + ?Sized,
{
    put_genesis_bundle_with(dir, statements, anchor, WriteFault::None).await
}

/// [`put_genesis_bundle`] with a write fault injected (the witnesses' seam).
pub(crate) async fn put_genesis_bundle_with<F>(
    dir: &F,
    statements: &[Vec<u8>],
    anchor: Option<&Anchor>,
    fault: WriteFault,
) -> Result<GenesisAdmission, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut offered: Vec<Vec<u8>> = Vec::new();
    let mut carried: BTreeMap<Digest32, Vec<u8>> = BTreeMap::new();
    let mut unreadable = Vec::new();
    for (i, s) in statements.iter().enumerate() {
        super::door::require_statement_form(s)?;
        let parts = cose_parts(s);
        if parts.as_ref().and_then(voice_of).is_some() {
            // v62.0.0 (kernel pass 2, K1) — a stated window covers some
            // instant (bundle object voices too).
            if let Some(p) = parts.as_ref() {
                super::door::check_valid_until_after_asserted_at(&p.payload)?;
            }
            offered.push(s.clone());
        } else if let Some(id) = RowId::of_statement(s) {
            carried.entry(id.0).or_insert_with(|| s.clone());
        } else {
            unreadable.push(i);
        }
    }
    if offered.is_empty() {
        return Err(refuse(
            token::MALFORMED,
            "no_voice: the statements carry no `ceg-genesis-bundle/2` voice",
        ));
    }
    // v62.0.0 (wave GC5; CC 2.6.1.11) — the voices of a bundle held short
    // are read again beside the offered ones (as offered: never rooted by
    // their own id), so a count met one voice at a time concludes. Only the
    // objects a voice of THIS offer names answer for it.
    let (held, short) = held_voices(dir).await?;
    let oids = |vs: &[Vec<u8>]| -> BTreeSet<Digest32> {
        vs.iter()
            .filter_map(|s| cose_parts(s).as_ref().and_then(voice_of).map(|(o, _)| o))
            .collect()
    };
    let fresh = oids(offered.as_slice());
    // The bundles this node stores (concluded, or held short): a bundle is
    // held only on a lineage rooted here, never on an unrooted one.
    let mut stored = oids(held.as_slice());
    stored.extend(oids(short.as_slice()));
    let offered: Vec<Vec<u8>> = short.into_iter().chain(offered).collect();
    let every: Vec<Vec<u8>> = held.iter().chain(offered.iter()).cloned().collect();
    let (rows, held_rows) = named_rows(dir, &every, &carried).await?;
    let roots = attestation_roots();
    let reading = read_lineage(&LineageInput {
        held: &held,
        offered: &offered,
        rows: &rows,
        anchor,
        attestation_roots: &roots,
    });
    // Every Valid offered bundle's named rows pass their own doors BEFORE
    // anything is stored: a bundle naming a row the door would refuse alone
    // is refused whole.
    let mut plans = Vec::new();
    let mut refused = Vec::new();
    // v62.0.0 (wave GC5) — the bundles held short: each one's kept voices
    // and its reason (Verify's token, its detail).
    let mut short_bundles: Vec<(Digest32, Vec<HeldObject>, String, String)> = Vec::new();
    for o in &reading.objects {
        if !o.offered {
            continue;
        }
        if let Some(mut n) = not_placed(o.reading.object_id, &o.reading.verdict, &o.reading.refused)
        {
            name_shared_device(&mut n, o, &rows);
            if let GenesisVerdict::Nothing(i) = &o.reading.verdict {
                // Held only on a lineage this node roots: a later bundle
                // whose predecessor it stores, or a first bundle whose
                // count (judged after its anchor) is short.
                let rooted = match o.prev {
                    Some(p) => stored.contains(&p),
                    None => matches!(i, Inconclusive::CountUnmet | Inconclusive::Commitment(_)),
                };
                if rooted && holds_bundle(i) {
                    let objects: Vec<HeldObject> = o
                        .kept
                        .iter()
                        .filter_map(|v| held_object(o.reading.object_id, v))
                        .collect();
                    if !objects.is_empty() {
                        let oid = hex::encode(o.reading.object_id);
                        short_bundles.push((
                            o.reading.object_id,
                            objects,
                            i.token().to_owned(),
                            format!(
                                "{}: bundle {oid} is held and concludes nothing (CC 2.6.1.11)",
                                n.detail.as_deref().unwrap_or(n.token)
                            ),
                        ));
                    }
                }
            }
            if fresh.contains(&o.reading.object_id) {
                refused.push(n);
            }
            continue;
        }
        let Some(p) = o.reading.verdict.placement() else {
            continue;
        };
        // v62.0.0 (DV-fix1) — one device per holder (CC 4.2.3) is Verify's
        // reader's (`holder_device_shared`, judged before a placement exists);
        // persist keeps no second check.
        let admitted = admit_named(&o.reading.object_id, p, &o.named, &rows, &held_rows)?;
        plans.push((o, p, admitted));
    }
    // The keys' read models, derived now (reads only) with the bundle's
    // placement in view: its seats answer whose each placed key is.
    let mut write = GenesisWrite {
        fault,
        ..GenesisWrite::default()
    };
    let mut placed = Vec::new();
    let mut seen_rows = BTreeSet::new();
    for (o, p, admitted) in plans {
        for a in &admitted {
            if seen_rows.insert(a.row_id) {
                write.rows.push(a.clone());
            }
        }
        for v in &o.kept {
            if let Some(obj) = held_object(o.reading.object_id, v) {
                write.objects.push(obj);
            }
        }
        placed.push(p.clone());
    }
    // v62.0.0 (wave GC5) — a bundle held short is kept, and its hold is
    // recorded BEFORE its voices are written: a stored voice whose object
    // is not fold-held reads as a concluded bundle (`held_voices`).
    for (oid, objects, reason, detail) in &short_bundles {
        record_bundle(dir, *oid, Some((reason.clone(), detail.clone()))).await?;
        write.objects.extend(objects.iter().cloned());
    }
    if placed.is_empty() && short_bundles.is_empty() {
        return Err(refused.first().map_or_else(
            || {
                refuse(
                    token::MALFORMED,
                    "no_voice: no offered statement is a readable bundle voice",
                )
            },
            error_of,
        ));
    }
    for p in &placed {
        plan_keys(dir, p, &write.rows, &mut write.keys).await?;
    }
    // Each seat binding's typed occurrence row, planned by the occurrence
    // door's own plan (pure): the bundle's count is its author's authority.
    let mut after = Vec::new();
    for a in write.rows.iter().filter(|a| a.family == BINDING_FAMILY) {
        let occurrence = super::occurrence::read_payload(a)?;
        let pair = (
            occurrence.identity_key_id.clone(),
            occurrence.occurrence_key_id.clone(),
        );
        let bind = super::occurrence::OccurrenceBind {
            occurrence,
            author_key_id: ciris_verify_core::edition2::identity_ref(&a.kid),
            row_id: a.row_id,
            statements: vec![a.bytes.clone()],
        };
        let (planned, route) = crate::federation::occurrence_admit::plan_edition2_occurrence(bind)?;
        write.occurrences.push(planned);
        after.push((pair, route));
    }
    // Every row, every key read model, every occurrence row and every voice:
    // one transaction. It answers whether each occurrence upsert applied.
    let applied = dir.put_edition2_genesis(&write).await?;
    // The routes the bindings project go through their own door after the
    // commit (wave O1's `after_edition2_occurrence`; no re-wrap for a seat,
    // whose pair is itself). A failure here leaves the genesis held with a
    // seat's route missing.
    for (((identity, occurrence), route), applied) in after.iter().zip(applied) {
        crate::federation::occurrence_admit::after_edition2_occurrence(
            dir,
            applied,
            identity,
            occurrence,
            route.as_ref(),
        )
        .await?;
    }
    // v62.0.0 (SR-fix2; I2111) — offering the same bundle again projects a
    // missing route. A named row this node already holds is not admitted
    // again (`admit_named`), so a held binding plans no occurrence and the
    // loop above never sees it: each placed seat whose binding this offer
    // did not write has the routes of its held occurrences projected again
    // (the route table's monotonic upsert: nothing changes over a held
    // route, and a newer route is never replaced).
    let written: BTreeSet<&str> = after
        .iter()
        .map(|((_, occurrence), _)| occurrence.as_str())
        .collect();
    let mut reprojected: BTreeSet<&str> = BTreeSet::new();
    for seat in placed.iter().flat_map(|p| p.seats.iter()) {
        let key = seat.identity_ref.as_str();
        if written.contains(key) || !reprojected.insert(key) {
            continue;
        }
        crate::federation::occurrence_admit::reproject_held_occurrence_routes(dir, key).await?;
    }
    // v62.0.0 (wave GC5) — a bundle held short that this offer completed
    // concludes: its hold is cleared (after the write, so its voices never
    // read as concluded before they are stored).
    for p in &placed {
        let id = RowId(p.object_id);
        if dir.fold_held(&id).await?.is_some() {
            record_bundle(dir, p.object_id, None).await?;
        }
    }
    // v62.0.0 (wave G0; CC 2.7.3) — the bundle's rows are inputs like any
    // other: every held or concluded row whose fold read what they touch is
    // re-folded (they bypass `put_statement`, whose tail does this).
    let mut touched = std::collections::BTreeSet::new();
    let mut own = std::collections::BTreeSet::new();
    for row in &write.rows {
        touched.extend(super::fold::touches(row));
        own.insert(row.row_id);
    }
    // v62.0.0 (wave GC5) — and the bundles themselves: a row that names a
    // bundle (a seat re-bind's `refs.head`) re-folds when it is placed.
    for p in &placed {
        touched.insert(super::fold::Dep::Row(RowId(p.object_id)).read_key());
    }
    // v62.0.0 (RL-fix6) — and "the bundle in force" itself: a row held
    // because no bundle (or an earlier one) was in force declared this key
    // (`reads_bundle_in_force`), whatever bundle, holder or seat it never
    // got to name. Every placement touches it (a re-offer of a held bundle
    // too: the rows it wakes re-fold to the answer they had).
    if !placed.is_empty() {
        touched.insert(bundle_in_force_read_key());
    }
    // fix4 — a row is never its own fold dependent.
    Box::pin(super::fold::refold_touched_excluding(dir, touched, &own)).await?;
    let in_force = genesis_in_force(dir).await?;
    Ok(GenesisAdmission {
        placed,
        not_placed: refused,
        unreadable,
        in_force,
    })
}
