//! v62.0.0 (slice C) — **the row view**: one owned, typed view of a verified,
//! well-formed persist row, as the kernel reads it (`ciris_kernel::Row` and
//! its spec traits; KERNEL_SEAMS §5.2's `RowView`, with `refs` as `names`).
//!
//! | kernel | persist |
//! |---|---|
//! | `Row::Id` | [`RowId`] — the 32 bytes of `persist_row_hash` |
//! | `Row::names()` | the digests the row's signed bytes name (`references_attestation_id`, a version's `prev_head_digest` / `charter_digest`) |
//! | `Row::signer()` | `attesting_key_id` |
//! | `SeatRow` | the seat fields ([`SeatFields`]) the adapter reads from the row and its family |
//! | `WindowRow` | the window fields ([`WindowFields`]); the instant is ONE signer's own `asserted_at`, as [`Micros`] |
//! | `KeyEndRow` | a key record's `valid_from` / `valid_until` ([`KeyEndFields`]) |
//!
//! The view OWNS what `names()` and the slices return, so the kernel's
//! borrowed accessors read it without a second allocation per call.
//!
//! **rc20 wire forms.** The kernel types an object from the form of its
//! reference (`seat::Obj::from_reference`: a `[-16, digest]` row id is a row,
//! a `urn:ietf:params:oauth:ckt:sha-256:` identity reference is a key). Today
//! persist's `attested_key_id` and `references_attestation_id` are bare
//! strings, so the adapter builds the [`Obj`] directly — `Obj::Key` from a
//! bare key id, `Obj::Row` from a hex `persist_row_hash` — and never calls
//! `from_reference`. [`obj_of_reference`] is the rc20 path, ready for the day
//! the signed object carries the typed forms (I1831).

use ciris_kernel::cut::CutSpec;
use ciris_kernel::key_end::{EndRule, KeyEndRow, Record};
use ciris_kernel::seat::{Conf, Obj, Reference, SeatKind, SeatRow};
use ciris_kernel::window::{WinKind, WindowRow};
use ciris_kernel::Row;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Microseconds since the epoch: the substrate's resolution (KERNEL_SEAMS
/// §5.2). Every instant the adapter hands the kernel is one signer's own.
pub type Micros = i64;

/// A row's digest: the 32 bytes of its `persist_row_hash`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RowId(pub [u8; 32]);

impl std::fmt::Debug for RowId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RowId({})", hex::encode(&self.0[..6]))
    }
}

impl RowId {
    /// The id of a persist row from its hex `persist_row_hash`. A hash that is
    /// not 64 hex characters (a test fixture's placeholder) is digested, so
    /// two distinct placeholders stay two distinct ids (I1830).
    #[must_use]
    pub fn of_hash(persist_row_hash: &str) -> Self {
        let mut out = [0u8; 32];
        if persist_row_hash.len() == 64 && hex::decode_to_slice(persist_row_hash, &mut out).is_ok()
        {
            return RowId(out);
        }
        Self::of_label(&["persist_row_hash", persist_row_hash])
    }

    /// An id for a row of a graph the adapter builds alone (a ballot's
    /// founding version, seats, head and counted act): no digest, only a
    /// tag and an index, unique within that graph. Never mixed with stored
    /// rows' ids.
    #[must_use]
    pub fn synthetic(tag: u8, i: u32) -> Self {
        let mut out = [0u8; 32];
        out[0] = 0xff;
        out[1] = tag;
        out[28..].copy_from_slice(&i.to_be_bytes());
        RowId(out)
    }

    /// A synthetic id for a row the adapter presents but persist does not
    /// store as one row (a group's founding version read from its record, a
    /// ballot's counted act). Domain-separated from [`Self::of_hash`]'s
    /// fallback by the first label.
    #[must_use]
    pub fn of_label(parts: &[&str]) -> Self {
        let mut h = Sha256::new();
        h.update(b"ciris-persist/kernel-adapter/v1");
        for p in parts {
            h.update((p.len() as u64).to_be_bytes());
            h.update(p.as_bytes());
        }
        RowId(h.finalize().into())
    }
}

/// The rc20 path: the [`Obj`] a typed reference names, read from its form
/// alone (`seat::Obj::from_reference`). A 32-byte SHA-256 `hash-digest` is a
/// row; an identity reference is a key, carried as its full URN text.
#[must_use]
pub fn obj_of_reference(r: Reference<'_>) -> Option<Obj<RowId, String>> {
    Obj::from_reference(
        r,
        |d| {
            let mut out = [0u8; 32];
            out.copy_from_slice(d);
            RowId(out)
        },
        str::to_owned,
    )
}

/// The seat fields of a row (`ciris_kernel::seat::SeatRow`). Every field has
/// the kernel's default for a row that does not carry it.
#[derive(Clone, Debug)]
pub struct SeatFields {
    /// What the row is.
    pub kind: SeatKind,
    /// The keys an offer or unseat names.
    pub to: Vec<String>,
    /// Its scope.
    pub scope: Option<String>,
    /// Its object.
    pub obj: Option<Obj<RowId, String>>,
    /// Who confers.
    pub conf: Option<Conf>,
    /// The offer a conferred seat is under.
    pub under: Option<RowId>,
    /// Further VERIFIED signatures on the row itself.
    pub cosigners: Vec<String>,
    /// The subjects a row names.
    pub subjects: Vec<String>,
    /// The heads a counted row is counted over.
    pub head: Vec<RowId>,
    /// The policy word a count is read from.
    pub policy: Option<String>,
    /// The scope counted.
    pub counted: Option<String>,
    /// A declared threshold.
    pub need: Option<usize>,
    /// An acceptance's offer, a cosignature's content.
    pub of: Option<RowId>,
    /// A withdrawal's target.
    pub target: Option<RowId>,
    /// The whole-number weights of a `weighted` count.
    pub weights: Vec<(String, u64)>,
    /// v62.0.0 (R2-delegation) — the grant carries sub-delegation: it may
    /// confer the same scope or a narrower one (the kernel's `sub()`).
    pub sub: bool,
}

impl SeatFields {
    /// The fields of a row the seat does not read.
    #[must_use]
    pub fn other() -> Self {
        Self::of(SeatKind::Other)
    }

    /// Fields of the given kind, every other field empty.
    #[must_use]
    pub fn of(kind: SeatKind) -> Self {
        SeatFields {
            kind,
            to: Vec::new(),
            scope: None,
            obj: None,
            conf: None,
            under: None,
            cosigners: Vec::new(),
            subjects: Vec::new(),
            head: Vec::new(),
            policy: None,
            counted: None,
            need: None,
            of: None,
            target: None,
            weights: Vec::new(),
            sub: false,
        }
    }
}

/// The window fields of a row (`ciris_kernel::window::WindowRow`).
#[derive(Clone, Debug, Default)]
pub struct WindowFields {
    /// What the row is, if a window row.
    pub kind: Option<WinKind>,
    /// An opener's window name in the table.
    pub window: Option<String>,
    /// An opener's target key.
    pub target_key: Option<String>,
    /// What an answer or a landing says.
    pub says: Option<String>,
    /// A landing's receipt.
    pub receipt: Option<RowId>,
    /// A receipt's or landing's own instant, the signer's own.
    pub at: Option<Micros>,
}

/// The key-end fields of a row (`ciris_kernel::key_end::KeyEndRow`).
#[derive(Clone, Debug)]
pub struct KeyEndFields {
    /// The key a record is of.
    pub key: String,
    /// Its own signed instant.
    pub from: Micros,
    /// Its stated end.
    pub until: Option<Micros>,
    /// The old key of a rotation.
    pub succ_of: Option<String>,
    /// The old key's instant on it.
    pub at_old: Option<Micros>,
    /// The keys whose signatures it carries.
    pub sigs: Vec<String>,
    /// Whether it must, may or must not state an end.
    pub end: EndRule,
}

/// **The view.** One per row an answer reads.
#[derive(Clone, Debug)]
pub struct KRow {
    /// The row's digest.
    pub id: RowId,
    /// The digests its signed bytes name.
    pub names: Vec<RowId>,
    /// `attesting_key_id`.
    pub signer: String,
    /// The seat's reading.
    pub seat: SeatFields,
    /// The window's reading.
    pub win: WindowFields,
    /// A key record's reading.
    pub key_end: Option<KeyEndFields>,
    /// The signer's own signed instant (`asserted_at`), for the fold
    /// default's per-signer order (CC 3.5.1). Never compared across signers.
    pub at: Micros,
}

impl KRow {
    /// A view with the given id, names and signer, reading as nothing.
    #[must_use]
    pub fn new(id: RowId, names: Vec<RowId>, signer: impl Into<String>) -> Self {
        KRow {
            id,
            names,
            signer: signer.into(),
            seat: SeatFields::other(),
            win: WindowFields::default(),
            key_end: None,
            at: 0,
        }
    }

    /// With these seat fields.
    #[must_use]
    pub fn with_seat(mut self, seat: SeatFields) -> Self {
        self.seat = seat;
        self
    }

    /// With the signer's own instant.
    #[must_use]
    pub fn at(mut self, at: Micros) -> Self {
        self.at = at;
        self
    }

    /// The key ids that signed it: the signer and every verified cosigner.
    #[must_use]
    pub fn voices(&self) -> BTreeSet<&str> {
        let mut v: BTreeSet<&str> = self.seat.cosigners.iter().map(String::as_str).collect();
        v.insert(self.signer.as_str());
        v
    }
}

impl Row for KRow {
    type Id = RowId;
    type Key = String;
    fn id(&self) -> &RowId {
        &self.id
    }
    fn names(&self) -> &[RowId] {
        &self.names
    }
    fn signer(&self) -> &String {
        &self.signer
    }
}

impl SeatRow for KRow {
    type Word = String;
    fn seat_kind(&self) -> SeatKind {
        self.seat.kind
    }
    fn to(&self) -> &[String] {
        &self.seat.to
    }
    fn scope(&self) -> Option<&String> {
        self.seat.scope.as_ref()
    }
    fn obj(&self) -> Option<Obj<RowId, String>> {
        self.seat.obj.clone()
    }
    fn conf(&self) -> Option<Conf> {
        self.seat.conf
    }
    fn under(&self) -> Option<&RowId> {
        self.seat.under.as_ref()
    }
    fn cosigners(&self) -> &[String] {
        &self.seat.cosigners
    }
    fn subjects(&self) -> &[String] {
        &self.seat.subjects
    }
    fn head(&self) -> &[RowId] {
        &self.seat.head
    }
    fn policy(&self) -> Option<&String> {
        self.seat.policy.as_ref()
    }
    fn counted(&self) -> Option<&String> {
        self.seat.counted.as_ref()
    }
    fn need(&self) -> Option<usize> {
        self.seat.need
    }
    fn of(&self) -> Option<&RowId> {
        self.seat.of.as_ref()
    }
    fn target(&self) -> Option<&RowId> {
        self.seat.target.as_ref()
    }
    fn weights(&self) -> &[(String, u64)] {
        &self.seat.weights
    }
    fn sub(&self) -> bool {
        self.seat.sub
    }
}

impl WindowRow for KRow {
    type T = Micros;
    fn win_kind(&self) -> Option<WinKind> {
        self.win.kind
    }
    fn window(&self) -> Option<&String> {
        self.win.window.as_ref()
    }
    fn target_key(&self) -> Option<&String> {
        self.win.target_key.as_ref()
    }
    fn says(&self) -> Option<&String> {
        self.win.says.as_ref()
    }
    fn receipt(&self) -> Option<&RowId> {
        self.win.receipt.as_ref()
    }
    fn at(&self) -> Option<Micros> {
        self.win.at
    }
}

impl KeyEndRow for KRow {
    type T = Micros;
    fn record(&self) -> Option<Record<'_, String, Micros>> {
        self.key_end.as_ref().map(|k| Record {
            key: &k.key,
            from: k.from,
            until: k.until,
            succ_of: k.succ_of.as_ref(),
            at_old: k.at_old,
            sigs: &k.sigs,
            end: k.end,
        })
    }
}

/// The cut persist presents today: no row is a cut. The answers this slice
/// switches (a count at a head, a seat, an acceptance edge) are read over
/// rows persist has already folded for retraction; the cut replaces those
/// folds in a later slice (the breaker deletion, KERNEL_SEAMS §2.2).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoCut;

impl CutSpec<KRow> for NoCut {
    type Slot = String;
    type Say = ();
    fn key_slot(&self, k: &String) -> String {
        k.clone()
    }
    fn on_slots(&self, r: &KRow) -> BTreeSet<String> {
        std::iter::once(r.signer.clone()).collect()
    }
    fn cuts_of(&self, _r: &KRow) -> BTreeSet<String> {
        BTreeSet::new()
    }
    fn says(&self, _r: &KRow) {}
}

/// Micros of a persist instant.
#[must_use]
pub fn micros(t: chrono::DateTime<chrono::Utc>) -> Micros {
    t.timestamp_micros()
}

/// v62.0.0 (slice J0) — the carried edition-2 statement of a stored row, if
/// it carries one (`ceg_statement`, lowercase hex).
fn carried_statement(a: &crate::federation::types::Attestation) -> Option<Vec<u8>> {
    a.attestation_envelope
        .get(crate::federation::edition2::ingest::STATEMENT_MEMBER)
        .and_then(serde_json::Value::as_str)
        .and_then(|h| hex::decode(h).ok())
}

/// v62.0.0 (slice J0) — **a stored row's id.** A row that carries an
/// edition-2 statement is named by the row id THIS node computes from the
/// statement's bytes (CC 2.6.1.3; `edition2::names::RowId::of_statement`),
/// never by a column a peer could have supplied. An earlier-form row is named
/// by its `persist_row_hash` (computed by persist at admission) until the JSON
/// cut.
#[must_use]
pub fn row_id(a: &crate::federation::types::Attestation) -> RowId {
    carried_statement(a)
        .and_then(|s| crate::federation::edition2::names::RowId::of_statement(&s))
        .map_or_else(|| RowId::of_hash(&a.persist_row_hash), |id| RowId(id.0))
}

/// v62.0.0 (slice J0) — **what an edition-2 row names**: the row ids of its
/// signed `refs` (edition 2 only), each with its role. `None` for a row that
/// carries no statement (the earlier form names by `references_attestation_id`).
#[must_use]
pub fn row_names(a: &crate::federation::types::Attestation) -> Option<Vec<(String, RowId)>> {
    let s = carried_statement(a)?;
    let (_, names) = crate::federation::edition2::names::of_statement_names(&s)?;
    Some(
        names
            .into_iter()
            .map(|n| (n.role, RowId(n.row.0)))
            .collect(),
    )
}

/// The view of a stored attestation: its id, the digests its signed bytes
/// name, its signer and its instant. The seat and window readings are the
/// caller's (they depend on the family the row is read as).
///
/// `names` resolves `references_attestation_id` through `id_of`, the caller's
/// map from an `attestation_id` to the `persist_row_hash` of the row it names
/// (persist names rows by id on today's wire, by digest from rc20 on). A
/// reference the map does not resolve names a row not held, which the
/// kernel's door then waits on.
pub fn attestation_view(
    a: &crate::federation::types::Attestation,
    id_of: &dyn Fn(&str) -> Option<RowId>,
) -> KRow {
    let mut names = Vec::new();
    // v62.0.0 (slice J0) — an edition-2 row names what its signed refs name.
    if let Some(e2) = row_names(a) {
        return KRow::new(
            row_id(a),
            e2.into_iter().map(|(_, id)| id).collect(),
            a.attesting_key_id.clone(),
        )
        .at(micros(a.asserted_at));
    }
    // only a structural composer's pointer names a row (CC 4.5.1.1)
    let composer = crate::federation::precedence::is_structural_composer(&a.attestation_type);
    if let Some(r) = composer
        .then(|| {
            crate::federation::precedence::references_attestation_id_from_envelope(
                &a.attestation_envelope,
            )
        })
        .flatten()
    {
        names.push(id_of(r).unwrap_or_else(|| RowId::of_label(&["unheld", r])));
    }
    KRow::new(row_id(a), names, a.attesting_key_id.clone()).at(micros(a.asserted_at))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn i1830_a_row_id_is_the_hash_bytes_and_placeholders_stay_distinct() {
        let h = "ab".repeat(32);
        assert_eq!(RowId::of_hash(&h).0, [0xab; 32]);
        assert_ne!(RowId::of_hash("h1"), RowId::of_hash("h2"));
        assert_ne!(RowId::of_hash("h1"), RowId::of_label(&["h1"]));
    }

    #[test]
    fn i1831_the_rc20_reference_forms_type_the_object() {
        let d = [7u8; 32];
        assert_eq!(
            obj_of_reference(Reference::Digest {
                alg: ciris_kernel::seat::SHA_256,
                digest: &d
            }),
            Some(Obj::Row(RowId(d)))
        );
        let urn = format!("{}{}", ciris_kernel::seat::IDENTITY_PREFIX, "A".repeat(43));
        assert_eq!(
            obj_of_reference(Reference::Text(&urn)),
            Some(Obj::Key(urn.clone()))
        );
        // today's bare key id names nothing through the rc20 path
        assert_eq!(obj_of_reference(Reference::Text("node-key-1")), None);
    }
}
