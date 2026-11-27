//! The accord's halt and invocation door (v62.0.0, JSON-cut slice A; CC
//! 4.2.1.1, CC 4.2.1.3, CC 4.2.6).
//!
//! An invocation (`accord:invoke:{constitutional,notify,drill}:…`) is ONE
//! row with ONE composite statement from a SINGLE accord holder: no count.
//! Its signer is judged against the holders of the genesis bundle in force
//! for its `accord_root` ([`HaltRoster`]); the halt names no head.
//!
//! v62.0.0 (slice C3) — the reader is CIRISVerify 23.3.0's
//! `edition2::accord_halt` ([`verify_invocation_row`]), re-exported here with
//! its types; persist keeps only the store door around it. It answers in
//! three ways ([`HaltReading`], `#[must_use]`):
//! - `valid`;
//! - `waiting:{kid,bundle,kid+bundle}`: the statement's key is not one the
//!   roster holds (a later bundle may seat it). A halt is never refused while
//!   the roster that would judge it is unknown;
//! - `refused:{token}` ([`HaltRefusal`]): `iss_not_holder` (the key is a
//!   holder's, but `iss` is not that holder), `statement_invalid:*`,
//!   `family:*`, `member:*`, `wrong_row_type`, `wrong_family`,
//!   `other_accord`, `valid_until_not_after_asserted_at`.
//!
//! With no bundle in force held for the accord, [`put_invocation`] waits on
//! the bundle itself, before any reading (Verify's reader takes a roster).
//!
//! [`put_invocation`] is the store door: a valid invocation is deduplicated
//! (`accord_invocation_replayed`: an `invocation_id` or a `nonce` already
//! held for the accord within its `valid_until`), kept in `ceg_statements`,
//! and a constitutional halt latches the accord's active halt.
//!
//! v62.0.0 (C2-fix, ceremony gap 8; CC 4.2.1.1, CC 4.2.1.3) — **the
//! lifecycle and the fuse.** [`put_lifecycle`] is the store door of a
//! counted lifecycle row (`accord:lifecycle:{confirmed,active}`), read by
//! Verify's [`verify_lifecycle_row`] under the roster of the bundle its
//! `refs.head` names, over the halt its `refs.target` names. Its voices are
//! kept as they arrive; short of a strict majority the row is held
//! (`count_short`); counted, it drives the latch. [`halt_in_force`] reads the
//! latch at an instant. The transitions are Verify's `HaltLatch` table
//! (`accord_halt_latch`, model `AccordHaltFuse.tla`):
//!
//! | row (verified)          | no halt in force     | lone halt                                  | confirmed halt  |
//! |-------------------------|----------------------|--------------------------------------------|-----------------|
//! | constitutional          | **latch** (receipt)  | changes nothing (the fuse is not reset)    | changes nothing |
//! | `confirmed` (counted)   | changes nothing      | **confirm**, if it names this halt         | changes nothing |
//! | `active` (counted)      | changes nothing      | **resume**, if it names this halt          | **resume**, if it names this halt |
//! | time                    | —                    | **lapses** once `halt_fuse_secs` are COUNTED | never lapses  |
//!
//! - v62.0.0 (HALT-235; CIRISVerify 23.5.0, a SECURITY release) — the fuse
//!   is ELAPSED time counted on this node's monotonic fuse clock from
//!   receipt ([`halt_reading`]; Verify's `HaltLatch::advance`), never a
//!   wall-clock deadline: a wall clock set forward no longer lapses a real
//!   halt. The latch (its counted `elapsed_ms` and last checkpoint) is stored
//!   whole with the halt row (`accord_active_halt.latch_json`) at every door
//!   that judges an accord row and at [`checkpoint_fuse`]; across a process
//!   restart nothing is counted (a new boot), so it runs long, never short.
//!   A row stored without a latch re-derives it from the invocation it names
//!   at zero elapsed (never un-halted). Its length is the bundle in force's
//!   `halt_fuse_secs` (86400 when the charter omits it); `set_at` is a report.
//! - A lapsed halt is gone before anything else is judged: a confirmation
//!   counted after the fuse confirms nothing, and a fresh halt latches anew.
//! - A confirmation is KEPT as the latch's state: the counted `confirmed` row
//!   that confirmed the halt in force concludes (its fold state is clear); a
//!   counted row that changed nothing is not concluded (it keeps whatever
//!   hold its short voices recorded, `count_short`, or none), so it never
//!   confirms a halt latched later. There is no registered token yet for
//!   "counted, names no halt in force"; see C2-fix's notes.
//! - A halt received after its `valid_until` that a counted `active` row
//!   already names does not fire (CC 4.2.1.1).
//! - A re-put of a held halt is not a new receipt: it latches nothing.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::family::SelectContext;
use ciris_verify_core::edition2::identity_ref;

pub use ciris_verify_core::accord_halt_latch::{
    ForwardRow, HaltLatch, LatchOutcome, MonotonicReading,
};
pub use ciris_verify_core::edition2::accord_halt::{
    named_accord_root, named_head, verify_invocation_row, verify_lifecycle_row, HaltReading,
    HaltRefusal, HaltRoster, HaltWaiting, InvocationRow, InvokeKind, LifecycleKind, LifecycleRow,
    RosterHolder, ACCORD_ROW_TYPE, DEFAULT_HALT_FUSE_SECS, FAMILY_CONSTITUTIONAL, FAMILY_DRILL,
    FAMILY_LIFECYCLE, FAMILY_NOTIFY,
};

use super::door::AdmittedRow;
use super::liveness::statement_parts;
use super::names::RowId;
use crate::federation::{malformed_row, Error, FederationDirectory};

/// The plane name the halt door's refusals carry.
pub const PLANE: &str = "accord_halt";
/// v62.0.0 (HL-fix1; CC 4.2.1.3) — the detail token of a lifecycle voice
/// whose `refs.head` names a superseded bundle: refused under
/// `accord_invocation_invalid`, nothing kept.
pub const LIFECYCLE_HEAD_NOT_IN_FORCE: &str = "accord_lifecycle_head_not_in_force";
/// The `typ` a waiting halt names when it waits on the accord's bundle.
const GENESIS_BUNDLE_TYP: &str = "ceg-genesis-bundle/2";
/// The three invocation families.
pub const INVOCATION_FAMILIES: [&str; 3] = [FAMILY_CONSTITUTIONAL, FAMILY_NOTIFY, FAMILY_DRILL];

/// Is `statement` of an invocation family (by its header, unverified)?
#[must_use]
pub fn is_invocation(statement: &[u8]) -> bool {
    statement_parts(statement).is_some_and(|(h, _)| {
        h.get_int(-70002)
            .and_then(Value::as_text)
            .is_some_and(|f| InvokeKind::from_family(f).is_some())
    })
}

/// The roster of the genesis bundle in force for `accord_root`, if held:
/// the holders Verify's bundle reader places, each at its placed key
/// ([`super::genesis::GenesisInForce::halt_roster`]). `None` with no bundle
/// held, on a fork of the genesis, or when the accord in force is another:
/// every invocation at the store door then waits on its bundle.
///
/// # Errors
/// Directory read failures.
pub async fn roster_in_force<F>(dir: &F, accord_root: &str) -> Result<Option<HaltRoster>, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(super::genesis::genesis_in_force(dir)
        .await?
        .halt_roster(accord_root))
}

/// Is `statement` of the lifecycle family (by its header, unverified)?
#[must_use]
pub fn is_lifecycle(statement: &[u8]) -> bool {
    statement_parts(statement)
        .is_some_and(|(h, _)| h.get_int(-70002).and_then(Value::as_text) == Some(FAMILY_LIFECYCLE))
}

/// What [`put_invocation`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvocationOutcome {
    /// The invocation.
    pub invocation: InvocationRow,
    /// Was the statement new here.
    pub new: bool,
    /// Did it latch the accord's active halt (a constitutional halt).
    pub latched: bool,
    /// v62.0.0 (wave GC4; CC 2.7.2, 2.7.3) — the statement is HELD and
    /// concludes nothing: an earlier invocation of the same accord carries
    /// its `invocation_id` or `nonce` (a replay). The fold reason is
    /// `accord_invocation_replayed` (`edition2::fold::why_held`). The
    /// ingest door answers `StatementOutcome::Pending` for it.
    pub held: bool,
}

/// The retryable error of a waiting reading, naming the first key the
/// roster does not hold, else the bundle it waits on.
fn waiting_error(w: &HaltWaiting) -> Error {
    let named = w.kids.first().map_or_else(
        || {
            w.bundles.first().map_or_else(
                || GENESIS_BUNDLE_TYP.to_owned(),
                |b| format!("{GENESIS_BUNDLE_TYP}:{}", hex::encode(b)),
            )
        },
        identity_ref,
    );
    Error::unknown_signer(&named, PLANE)
}

/// The terminal error of a refused reading: `iss_not_holder` by that name,
/// every other refusal `accord_invocation_invalid` with the reader's token.
fn refusal_error(r: &HaltRefusal) -> Error {
    match r {
        HaltRefusal::IssNotHolder => Error::malformed_row(
            PLANE,
            malformed_row::ISS_NOT_HOLDER,
            "the statement's key is an accord holder's, but its iss is not that holder \
             (CC 4.2.1.1)",
        ),
        other => Error::malformed_row(
            PLANE,
            malformed_row::ACCORD_INVOCATION_INVALID,
            format!("refused:{}", other.token()),
        ),
    }
}

/// v62.0.0 (wave GC4; CC 2.7.2 "one set, one answer") — one held
/// invocation statement of an accord, as the replay fold reads it.
#[derive(Debug, Clone)]
struct HeldInvocation {
    row: RowId,
    asserted_at: u64,
    valid_until: u64,
    invocation_id: String,
    nonce: Vec<u8>,
    constitutional: bool,
}

impl HeldInvocation {
    fn of(statement: &[u8], family: &str) -> Option<Self> {
        let (_, p) = statement_parts(statement)?;
        Some(Self {
            row: RowId::of_statement(statement)?,
            asserted_at: p.get_text("asserted_at").and_then(Value::as_u64)?,
            valid_until: p.get_text("valid_until").and_then(Value::as_u64)?,
            invocation_id: p
                .get_text("invocation_id")
                .and_then(Value::as_text)?
                .to_owned(),
            nonce: p.get_text("nonce").and_then(Value::as_bytes)?.to_vec(),
            constitutional: family == FAMILY_CONSTITUTIONAL,
        })
    }

    /// The fold's order: `asserted_at`, then the row id.
    fn rank(&self) -> (u64, RowId) {
        (self.asserted_at, self.row)
    }

    /// Is `later` (ranked after `self`) a replay of `self`: the same
    /// `invocation_id` or `nonce`, asserted before `self`'s `valid_until`?
    fn replayed_by(&self, later: &Self) -> bool {
        (self.invocation_id == later.invocation_id || self.nonce == later.nonce)
            && later.asserted_at < self.valid_until
    }
}

/// v62.0.0 (wave GC4; CC 2.7.2, 2.7.3) — **the replay fold** over every held
/// invocation of one accord: in rank order, an invocation is a REPLAY when
/// it is [`HeldInvocation::replayed_by`] an earlier invocation that is not
/// itself a replay ("a replayed or second row changes nothing", CC 4.2.1.1:
/// it excludes nothing). A function of the held set: the same invocations
/// count whichever arrived first. Returns the replays, each with the row
/// that excludes it.
fn replay_fold(mut held: Vec<HeldInvocation>) -> BTreeMap<RowId, RowId> {
    held.sort_by_key(HeldInvocation::rank);
    held.dedup_by_key(|h| h.row);
    let mut counted: Vec<&HeldInvocation> = Vec::new();
    let mut replays = BTreeMap::new();
    for h in &held {
        match counted.iter().find(|c| c.replayed_by(h)) {
            Some(by) => {
                replays.insert(h.row, by.row);
            }
            None => counted.push(h),
        }
    }
    replays
}

/// v62.0.0 (CE-fix1) — **the invocation door's pure reading** under
/// `roster` (the bundle in force for the statement's accord): the statement
/// form, Verify's [`verify_invocation_row`], then the edition-2 door's
/// [`admit_row`](super::door::admit_row) under the roster's keys. No store,
/// no clock: what [`put_invocation_at`] reads before it keeps anything, and
/// what an offline ceremony checks a pre-signed halt against before sealing
/// it. The replay fold and the latch are the store's.
///
/// # Errors
/// `earlier_form_object`; a waiting reading as the retryable
/// `federation_attester_key_unknown`; `iss_not_holder`; every other refusal
/// `accord_invocation_invalid` with the reader's token; the door's own
/// refusals.
pub fn read_invocation(
    bytes: &[u8],
    roster: &HaltRoster,
) -> Result<(InvocationRow, AdmittedRow), Error> {
    super::door::require_statement_form(bytes)?;
    let inv = match verify_invocation_row(bytes, roster) {
        HaltReading::Valid(inv) => inv,
        HaltReading::Waiting(w) => return Err(waiting_error(&w)),
        HaltReading::Refused(r) => return Err(refusal_error(&r)),
    };
    // No holder check here: Verify's verify_invocation_row already requires
    // iss to be the bundle-placed holder key and author == iss (Verify
    // v23.3.1 edition2/accord_halt.rs:718 and :800), under this same roster.
    let admitted = super::door::admit_row(bytes, roster, None, SelectContext::default())?;
    Ok((inv, admitted))
}

/// v62.0.0 (CE-fix1; CC 4.2.1.1) — **what an invocation states**: the
/// closed member set Verify's reader takes (`author`, `accord_root`,
/// `invocation_id`, `nonce`, `asserted_at`, `valid_until`, and
/// `payload_digest` on a notify only). No `refs`: the reader's map is
/// closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvocationTerms {
    /// Which invocation (the row's family).
    pub kind: InvokeKind,
    /// The holder's identity-ref: `author`, `iss`.
    pub holder: String,
    /// The accord's `family_key_id`: `accord_root` and the CWT `sub`.
    pub accord_root: String,
    /// `invocation_id`.
    pub invocation_id: String,
    /// `nonce`, 32 bytes the signer chooses (the store's replay key).
    pub nonce: [u8; 32],
    /// `asserted_at`, POSIX ms.
    pub asserted_at_ms: u64,
    /// `valid_until`, POSIX ms, after `asserted_at`: it bounds the replay
    /// window only, never the halt's reach.
    pub valid_until_ms: u64,
    /// `payload_digest` (SHA-256), a notify's only.
    pub payload_digest: Option<super::Digest32>,
}

/// v62.0.0 (CE-fix1) — the payload of an invocation, in the deterministic
/// map order.
#[must_use]
pub fn invocation_payload(t: &InvocationTerms) -> Value {
    let text = |s: &str| Value::Text(s.to_owned());
    let mut m = vec![
        (text("author"), text(t.holder.as_str())),
        (text("accord_root"), text(t.accord_root.as_str())),
        (text("invocation_id"), text(t.invocation_id.as_str())),
        (text("nonce"), Value::Bytes(t.nonce.to_vec())),
        (text("asserted_at"), Value::Uint(t.asserted_at_ms)),
        (text("valid_until"), Value::Uint(t.valid_until_ms)),
    ];
    if let Some(d) = &t.payload_digest {
        m.push((
            text("payload_digest"),
            ciris_verify_core::edition2::hash_digest_value(d),
        ));
    }
    super::emit::sorted_map(m)
}

/// v62.0.0 (CE-fix1; CC 4.2.1.1) — **an invocation drafted for its holder
/// to sign** (a pre-signed, sealed halt included): row type `scores`, the
/// kind's family, `sub` the accord, `iss` and `author` the holder's
/// identity-ref, `kid` the thumbprint of the key the bundle in force places
/// for the holder (its own identity-ref's key until a recovery re-seats it).
/// The holder signs `Draft::sig_structure` with that composite key (both
/// halves); `Draft::assemble` is the statement.
///
/// # Errors
/// `edition2_payload_invalid`: a payload the door would refuse.
pub fn invocation_draft(
    t: &InvocationTerms,
    kid: &super::Digest32,
) -> Result<super::emit::Draft, Error> {
    super::emit::draft_row(
        kid,
        &t.holder,
        &t.accord_root,
        ACCORD_ROW_TYPE,
        t.kind.family(),
        &invocation_payload(t),
    )
    .map_err(|e| super::emit::produce_error("accord_invocation", e))
}

/// **The invocation store door.** `roster` is the bundle in force for the
/// statement's accord ([`roster_in_force`]); `None` waits on that bundle.
///
/// - a waiting reading is the retryable `federation_attester_key_unknown`,
///   naming the key or the bundle;
/// - `iss_not_holder` is refused by that name; every other refusal is
///   `accord_invocation_invalid` with the reader's token;
/// - v62.0.0 (wave GC4; CC 2.7.2, 2.7.3) — an invocation that collides with
///   an earlier-ranked held invocation of the same accord (the same
///   `invocation_id` or `nonce`, within that one's `valid_until`) is a
///   replay: KEPT, concluding nothing (`held`, fold reason
///   `accord_invocation_replayed`), never refused. An invocation that
///   out-ranks a held one it collides with makes THAT one the replay: it is
///   recorded held, and the active halt it latched is cleared. Whichever
///   arrives first, the same invocation counts;
/// - a valid invocation is kept in `ceg_statements`; a constitutional halt
///   latches the accord's active halt (`set_active_halt(accord_root, row
///   id)`): ONE holder's statement, no count.
///
/// v62.0.0 (C2-fix) — a constitutional halt latches only as the latch
/// table above allows: not while another halt is in force (a second halt
/// changes nothing and does not reset the fuse), not on a re-put of a held
/// halt, and not when received after its `valid_until` while a counted
/// `active` row names it. A lapsed halt in the table is replaced.
///
/// # Errors
/// As above; directory failures.
pub async fn put_invocation<F>(
    dir: &F,
    bytes: &[u8],
    roster: Option<&HaltRoster>,
) -> Result<InvocationOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    put_invocation_at(dir, bytes, roster, crate::host::clock::now()).await
}

/// [`put_invocation`] received at `now` (the wall instant of receipt: a
/// report, and the `valid_until` comparison; the fuse is counted on
/// [`halt_reading`]).
///
/// # Errors
/// As [`put_invocation`].
pub async fn put_invocation_at<F>(
    dir: &F,
    bytes: &[u8],
    roster: Option<&HaltRoster>,
    now: DateTime<Utc>,
) -> Result<InvocationOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    put_invocation_with(dir, bytes, roster, now, halt_reading()).await
}

/// v62.0.0 (HALT-235) — [`put_invocation_at`] at an explicit fuse
/// `reading` (the witnesses' seam).
///
/// # Errors
/// As [`put_invocation`].
pub(crate) async fn put_invocation_with<F>(
    dir: &F,
    bytes: &[u8],
    roster: Option<&HaltRoster>,
    now: DateTime<Utc>,
    reading: MonotonicReading,
) -> Result<InvocationOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(roster) = roster else {
        super::door::require_statement_form(bytes)?;
        // No bundle in force is held for the accord: wait on it.
        return Err(Error::unknown_signer(
            &format!(
                "{GENESIS_BUNDLE_TYP}:{}",
                named_accord_root(bytes).unwrap_or_default()
            ),
            PLANE,
        ));
    };
    // v62.0.0 (CE-fix1) — the pure reading, shared with the offline
    // ceremony's self-check (`crate::ceremony::check_halt`).
    let (inv, admitted) = read_invocation(bytes, roster)?;
    let accord_root = roster.accord_root();
    let new = dir.put_edition2_statement(&admitted).await?;
    // v62.0.0 (wave GC4; CC 2.7.2, 2.7.3) — the replay fold over every held
    // invocation of the accord, this one included (it is kept first: a
    // replay is held, never refused). Each row whose standing changed is
    // recorded: a replay held `accord_invocation_replayed` (and a halt it
    // latched un-latched), a row no longer a replay cleared.
    let mut held = Vec::new();
    let mut family_of: BTreeMap<RowId, &'static str> = BTreeMap::new();
    for family in INVOCATION_FAMILIES {
        for st in dir.edition2_statements_about(family, accord_root).await? {
            if let Some(h) = HeldInvocation::of(&st, family) {
                family_of.insert(h.row, family);
                held.push(h);
            }
        }
    }
    let own = RowId(*inv.row_id());
    if let std::collections::btree_map::Entry::Vacant(e) = family_of.entry(own) {
        // The store lists what it holds; this one was just kept.
        if let Some(f) = INVOCATION_FAMILIES
            .iter()
            .copied()
            .find(|f| *f == admitted.family)
        {
            if let Some(h) = HeldInvocation::of(bytes, f) {
                e.insert(f);
                held.push(h);
            }
        }
    }
    let constitutional: BTreeMap<RowId, bool> =
        held.iter().map(|h| (h.row, h.constitutional)).collect();
    let replays = replay_fold(held);
    for (row, family) in &family_of {
        let was_held = super::fold::why_held(dir, row).await?.is_some();
        match replays.get(row) {
            Some(by) if !was_held || *row == own => {
                record_replay(
                    dir,
                    *row,
                    family,
                    format!(
                        "{}: invocation row {} repeats the invocation_id or nonce of the \
                         earlier invocation row {} of {accord_root}, within its valid_until \
                         (CC 4.2.1.1)",
                        malformed_row::ACCORD_INVOCATION_REPLAYED,
                        row.hex(),
                        by.hex(),
                    ),
                )
                .await?;
                dir.clear_active_halt(accord_root, &row.hex()).await?;
            }
            None if was_held => {
                super::fold::record(
                    dir,
                    *row,
                    family,
                    super::ingest::INGEST_TIER,
                    None,
                    std::iter::once(super::fold::Dep::Row(*row).read_key()).collect(),
                )
                .await?;
                // No longer a replay: a constitutional halt latches if none is.
                if *row != own
                    && constitutional.get(row).copied().unwrap_or(false)
                    && dir.get_active_halt(accord_root).await?.is_none()
                {
                    // HALT-235 — no latch yet: the next read re-derives it
                    // from this invocation (elapsed zero).
                    dir.set_active_halt(accord_root, &row.hex(), None).await?;
                }
            }
            _ => {}
        }
    }
    if replays.contains_key(&own) {
        return Ok(InvocationOutcome {
            invocation: inv,
            new,
            latched: false,
            held: true,
        });
    }
    let mut latched = inv.kind() == InvokeKind::Constitutional
        && new
        && latch_allows(dir, roster, &inv, own, now, reading).await?;
    if latched {
        // v62.0.0 (HALT-235; CIRISVerify 23.5.0) — the halt latches on a
        // clear latch at this reading: its fuse is counted from here.
        let fuse = u64::from(roster.halt_fuse_secs());
        let mut latch = HaltLatch::new();
        latched = matches!(
            latch.apply_forward(ForwardRow::Invocation(&inv), reading, ms_of(now), fuse),
            LatchOutcome::Paused
        );
        if latched {
            store_latch(dir, accord_root, &hex::encode(inv.row_id()), &latch).await?;
        }
    }
    Ok(InvocationOutcome {
        invocation: inv,
        new,
        latched,
        held: false,
    })
}

/// v62.0.0 (wave GC4) — record an invocation row as a replay: held,
/// concluding nothing, reason `accord_invocation_replayed`. It reads only
/// its own row: the replay fold is re-run by [`put_invocation`] for every
/// invocation of the accord that arrives (it is not a re-fold of
/// `edition2::fold`, whose door tail does not re-enter the halt plane).
async fn record_replay<F>(dir: &F, row: RowId, family: &str, detail: String) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    super::fold::record(
        dir,
        row,
        family,
        super::ingest::INGEST_TIER,
        Some((
            super::fold::reason::ACCORD_INVOCATION_REPLAYED.to_owned(),
            detail,
        )),
        std::iter::once(super::fold::Dep::Row(row).read_key()).collect(),
    )
    .await
}

// ------------------------------------------------------------------ the latch

/// v62.0.0 (C2-fix; HALT-235) — the halt in force for an accord
/// ([`halt_in_force`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HaltInForce {
    /// The active halt's id as the table keeps it (the halt's row id, hex).
    pub halt_id: String,
    /// The halt's row id; `None` for an id that is not one (a halt of the
    /// earlier form, which no edition-2 row confirms or ends).
    pub halt_row: Option<RowId>,
    /// When THIS node received it, on its wall clock: a REPORT. Nothing
    /// decides on it (the fuse is the latch's counted elapsed time).
    pub received_at: DateTime<Utc>,
    /// Confirmed by a counted `confirmed` row before its fuse ran.
    pub confirmed: bool,
    /// v62.0.0 (HALT-235) — the fuse time a lone halt has left, in
    /// milliseconds of counted (monotonic) time; `None` once confirmed, for
    /// an earlier-form halt, or for a latch that could not be re-derived
    /// (which never lapses).
    pub remaining_ms: Option<u64>,
    /// v62.0.0 (HALT-235) — the node's latch, advanced to the reading this
    /// answer was made at (`None` for an earlier-form halt or one that could
    /// not be re-derived). The door stores it.
    pub latch: Option<HaltLatch>,
}

/// v62.0.0 (HALT-235; CIRISVerify 23.5.0) — **one reading of this node's
/// fuse clock**: the host clock seam's monotonic reading, under a boot
/// identity drawn once per process. Persist's node profile carries no
/// verify-core `host` tier (`FuseMeter`), so every process start is a new
/// boot: `HaltLatch::advance` counts ZERO across a restart, which only ever
/// extends a halt (it runs long, never short). A wall-clock change moves
/// nothing here.
#[must_use]
pub fn halt_reading() -> MonotonicReading {
    use std::sync::OnceLock;
    static BOOT: OnceLock<[u8; 16]> = OnceLock::new();
    let boot = *BOOT.get_or_init(|| {
        use sha2::Digest as _;
        let mut h = sha2::Sha256::new();
        h.update(b"ciris.persist.fuse-boot.v1");
        h.update(
            crate::host::clock::now()
                .timestamp_nanos_opt()
                .unwrap_or_default()
                .to_le_bytes(),
        );
        h.update(
            crate::host::clock::current()
                .monotonic()
                .as_nanos()
                .to_le_bytes(),
        );
        let d = h.finalize();
        let mut b = [0u8; 16];
        b.copy_from_slice(&d[..16]);
        b
    });
    MonotonicReading {
        monotonic_ms: u64::try_from(crate::host::clock::current().monotonic().as_millis())
            .unwrap_or(u64::MAX),
        boot,
    }
}

/// The fuse in force for `accord_root`: the bundle in force's
/// `halt_fuse_secs`, or 86400.
async fn fuse_secs<F>(dir: &F, accord_root: &str) -> Result<u64, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(u64::from(
        roster_in_force(dir, accord_root)
            .await?
            .map_or(DEFAULT_HALT_FUSE_SECS, |r| r.halt_fuse_secs()),
    ))
}

fn row_id_of_hex(s: &str) -> Option<RowId> {
    hex::decode(s)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .map(RowId)
}

fn ms_of(t: DateTime<Utc>) -> Option<u64> {
    u64::try_from(t.timestamp_millis()).ok()
}

/// v62.0.0 (HALT-235; CC 4.2.1.1) — **re-derive the latch of a stored halt
/// that carries none** (a row written before the latch was stored, or by the
/// earlier-form host verb): the invocation the row names is read again under
/// the roster in force and re-applied to a clear latch at `reading`, at the
/// wall instant of its admission (`edition2_first_held_us`) when the store
/// knows it. The halt re-latches with ZERO elapsed: an upgrade only ever
/// extends a halt, it never comes up un-halted. Only the halt the row names
/// is re-applied (never every held invocation: an old, long-lapsed halt
/// would pause agents again). `None`: the invocation or the roster is not
/// held, so it cannot be re-read (the caller keeps the halt in force).
async fn derive_latch<F>(
    dir: &F,
    accord_root: &str,
    halt_row: &RowId,
    reading: MonotonicReading,
    fuse: u64,
) -> Result<Option<HaltLatch>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(roster) = roster_in_force(dir, accord_root).await? else {
        return Ok(None);
    };
    let Some(bytes) = dir.edition2_voices(halt_row).await?.into_iter().next() else {
        return Ok(None);
    };
    let Ok((inv, _)) = read_invocation(&bytes, &roster) else {
        return Ok(None);
    };
    let received_wall_ms = dir
        .edition2_first_held_us(halt_row)
        .await
        .ok()
        .flatten()
        .and_then(|us| u64::try_from(us / 1000).ok());
    let mut latch = HaltLatch::new();
    match latch.apply_forward(
        ForwardRow::Invocation(&inv),
        reading,
        received_wall_ms,
        fuse,
    ) {
        LatchOutcome::Paused => Ok(Some(latch)),
        _ => Ok(None),
    }
}

/// The latch a stored halt carries, parsed; `None` for none or for a latch
/// of another shape (a 23.4-shaped latch does not deserialize under 23.5.0).
fn stored_latch(active: &crate::federation::accord_quorum::ActiveHalt) -> Option<HaltLatch> {
    active
        .latch_json
        .as_deref()
        .and_then(|j| serde_json::from_str::<HaltLatch>(j).ok())
}

/// The leaf of a lifecycle statement's `dimension`
/// (`accord:lifecycle:{kind}:vN`), unverified: read only from rows this door
/// counted.
fn lifecycle_leaf(statement: &[u8]) -> Option<String> {
    let (_, p) = statement_parts(statement)?;
    let d = p.get_text("dimension").and_then(Value::as_text)?;
    d.strip_prefix("accord:lifecycle:")
        .and_then(|rest| rest.split(':').next())
        .map(str::to_owned)
}

/// Is there a counted lifecycle row of `kind` naming `halt` as its target,
/// concluded by this door (its fold state clear)?
async fn concluded_lifecycle<F>(dir: &F, halt: &RowId, kind: LifecycleKind) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    for row in dir.edition2_rows_naming(halt, "target").await? {
        let Some(state) = dir.fold_state(&row).await? else {
            continue;
        };
        // VD-step1 — concluded is the one verdict's (`verdict::row_state`).
        if state.family != FAMILY_LIFECYCLE
            || !super::verdict::row_state(dir, &row).await?.is_concluded()
        {
            continue;
        }
        let voices = dir.edition2_voices(&row).await?;
        if voices
            .first()
            .and_then(|v| lifecycle_leaf(v))
            .is_some_and(|leaf| leaf == kind.as_str())
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// v62.0.0 (C2-fix, ceremony gap 8; HALT-235) — **the halt in force** for
/// `accord_root`: the latched halt, unless it is a lone halt whose fuse has
/// run (its COUNTED elapsed time, on this node's monotonic fuse clock,
/// reached `halt_fuse_secs`: CIRISVerify 23.5.0's `HaltLatch`; never the wall
/// clock) or a counted `active` row has ended it. A read: it changes nothing
/// (the next door that judges a row checkpoints the latch, or clears a
/// lapsed halt from the table).
///
/// # Errors
/// Directory read failures.
pub async fn halt_in_force<F>(
    dir: &F,
    accord_root: &str,
    now: DateTime<Utc>,
) -> Result<Option<HaltInForce>, Error>
where
    F: FederationDirectory + ?Sized,
{
    halt_in_force_with(dir, accord_root, now, halt_reading()).await
}

/// v62.0.0 (HALT-235) — [`halt_in_force`] at an explicit fuse `reading`
/// (the witnesses' seam). `now` is the wall clock and decides NOTHING here:
/// a lone halt lapses only when its counted elapsed time reaches
/// `halt_fuse_secs` (CIRISVerify 23.5.0's `HaltLatch`); a wall clock set
/// forward does not lapse it.
///
/// # Errors
/// Directory read failures.
pub(crate) async fn halt_in_force_with<F>(
    dir: &F,
    accord_root: &str,
    now: DateTime<Utc>,
    reading: MonotonicReading,
) -> Result<Option<HaltInForce>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let _ = now;
    let Some(active) = dir.get_active_halt(accord_root).await? else {
        return Ok(None);
    };
    let Some(halt_row) = row_id_of_hex(&active.active_halt_id) else {
        // A halt of the earlier form: no edition-2 row confirms, ends or
        // lapses it here; it is reported as it stands.
        return Ok(Some(HaltInForce {
            halt_id: active.active_halt_id,
            halt_row: None,
            received_at: active.set_at,
            confirmed: false,
            remaining_ms: None,
            latch: None,
        }));
    };
    if concluded_lifecycle(dir, &halt_row, LifecycleKind::Active).await? {
        return Ok(None);
    }
    let confirmed = concluded_lifecycle(dir, &halt_row, LifecycleKind::Confirmed).await?;
    let fuse = fuse_secs(dir, accord_root).await?;
    // The stored latch, else re-derived (an upgraded store, or a row the
    // earlier-form verb wrote); one that cannot be re-derived keeps the halt
    // in force and never lapses (never un-halted).
    let latch = match stored_latch(&active) {
        Some(l) => Some(l),
        None => derive_latch(dir, accord_root, &halt_row, reading, fuse).await?,
    };
    let Some(mut latch) = latch else {
        return Ok(Some(HaltInForce {
            halt_id: active.active_halt_id,
            halt_row: Some(halt_row),
            received_at: active.set_at,
            confirmed,
            remaining_ms: None,
            latch: None,
        }));
    };
    // A regression signal changes nothing here: the time is not counted.
    let _ = latch.advance(reading);
    let names_it = latch
        .active_halt(fuse)
        .is_some_and(|h| h.halt_row == halt_row.0);
    if !confirmed && !names_it {
        return Ok(None);
    }
    let remaining_ms = if confirmed {
        None
    } else {
        latch.remaining_ms(fuse)
    };
    Ok(Some(HaltInForce {
        halt_id: active.active_halt_id,
        halt_row: Some(halt_row),
        received_at: active.set_at,
        confirmed,
        remaining_ms,
        latch: Some(latch),
    }))
}

/// Clear a halt the table still keeps but that is no longer in force at
/// `reading` (lapsed, or ended): "a lone halt whose fuse has run is gone
/// before anything else is judged". A halt in force has its advanced latch
/// STORED (HALT-235: every door that judges an accord row checkpoints the
/// fuse). Returns the halt in force.
async fn settle_latch<F>(
    dir: &F,
    accord_root: &str,
    now: DateTime<Utc>,
    reading: MonotonicReading,
) -> Result<Option<HaltInForce>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let in_force = halt_in_force_with(dir, accord_root, now, reading).await?;
    match &in_force {
        None => {
            if let Some(stale) = dir.get_active_halt(accord_root).await? {
                dir.clear_active_halt(accord_root, &stale.active_halt_id)
                    .await?;
            }
        }
        Some(h) => {
            if let Some(latch) = &h.latch {
                store_latch(dir, accord_root, &h.halt_id, latch).await?;
            }
        }
    }
    Ok(in_force)
}

/// v62.0.0 (HALT-235) — store the node's latch with its halt row (the whole
/// `HaltLatch` JSON).
async fn store_latch<F>(
    dir: &F,
    accord_root: &str,
    halt_id: &str,
    latch: &HaltLatch,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let json = serde_json::to_string(latch)
        .map_err(|e| Error::Backend(format!("halt latch: serialize: {e}")))?;
    dir.set_active_halt(accord_root, halt_id, Some(&json)).await
}

/// v62.0.0 (HALT-235) — **checkpoint the accord's fuse now** (the periodic
/// store a host's tick drives): advance the latch of a halt in force to this
/// node's reading and store it; clear a halt whose fuse has run. Without a
/// tick the fuse is still counted at every door within one process (from
/// the last stored checkpoint), so it runs long, never short. The halt in
/// force.
///
/// # Errors
/// Directory failures.
pub async fn checkpoint_fuse<F>(dir: &F, accord_root: &str) -> Result<Option<HaltInForce>, Error>
where
    F: FederationDirectory + ?Sized,
{
    settle_latch(dir, accord_root, crate::host::clock::now(), halt_reading()).await
}

/// [`checkpoint_fuse`] at an explicit fuse `reading` (the witnesses' seam).
///
/// # Errors
/// As [`checkpoint_fuse`].
#[cfg(test)]
pub(crate) async fn checkpoint_fuse_with<F>(
    dir: &F,
    accord_root: &str,
    reading: MonotonicReading,
) -> Result<Option<HaltInForce>, Error>
where
    F: FederationDirectory + ?Sized,
{
    settle_latch(dir, accord_root, crate::host::clock::now(), reading).await
}

/// May the constitutional halt `inv` latch at `now`?
async fn latch_allows<F>(
    dir: &F,
    roster: &HaltRoster,
    inv: &InvocationRow,
    own: RowId,
    now: DateTime<Utc>,
    reading: MonotonicReading,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    if settle_latch(dir, roster.accord_root(), now, reading)
        .await?
        .is_some()
    {
        // A second halt changes nothing and does not reset the fuse.
        return Ok(false);
    }
    let received_after = u64::try_from(now.timestamp_millis()).is_ok_and(|n| n > inv.valid_until());
    if received_after && concluded_lifecycle(dir, &own, LifecycleKind::Active).await? {
        // Past its valid_until, a halt a held resumption names does not fire.
        return Ok(false);
    }
    Ok(true)
}

/// What [`put_lifecycle`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LifecycleOutcome {
    /// The voice is kept; the row's voices are short of a strict majority
    /// (held `count_short`).
    Pending {
        /// The lifecycle row.
        row_id: RowId,
        /// Was the statement new.
        new: bool,
    },
    /// The row is counted and changed the latch.
    Applied {
        /// The lifecycle row.
        row_id: RowId,
        /// Was the statement new.
        new: bool,
        /// `Confirmed` or `Active` (resumed).
        kind: LifecycleKind,
    },
    /// The row is counted and changed nothing: it names no halt in force
    /// (another halt, one that lapsed, or none).
    Unchanged {
        /// The lifecycle row.
        row_id: RowId,
        /// Was the statement new.
        new: bool,
    },
}

impl LifecycleOutcome {
    /// The lifecycle row.
    #[must_use]
    pub fn row_id(&self) -> RowId {
        match self {
            Self::Pending { row_id, .. }
            | Self::Applied { row_id, .. }
            | Self::Unchanged { row_id, .. } => *row_id,
        }
    }

    /// Was the statement new.
    #[must_use]
    pub fn is_new(&self) -> bool {
        match self {
            Self::Pending { new, .. } | Self::Applied { new, .. } | Self::Unchanged { new, .. } => {
                *new
            }
        }
    }
}

fn malformed_lifecycle(member: &str) -> Error {
    Error::malformed_row(
        PLANE,
        malformed_row::ACCORD_INVOCATION_INVALID,
        format!("refused:member:{member}"),
    )
}

/// The halt a lifecycle row targets, verified as Verify read it: under the
/// roster of a held Valid bundle of `accord_root`. `None`: not verifiable
/// under any held bundle (it waits).
fn verified_halt(
    halt: &[u8],
    placements: &[super::genesis::GenesisPlacement],
) -> Option<InvocationRow> {
    placements.iter().find_map(|p| {
        match verify_invocation_row(halt, &HaltRoster::from_placement(p)) {
            HaltReading::Valid(inv) => Some(inv),
            HaltReading::Waiting(_) | HaltReading::Refused(_) => None,
        }
    })
}

/// v62.0.0 (C2-fix, ceremony gap 8; CC 4.2.1.1, CC 4.2.1.3) — **the
/// lifecycle store door**, received now. See [`put_lifecycle_at`].
///
/// # Errors
/// As [`put_lifecycle_at`].
pub async fn put_lifecycle<F>(dir: &F, bytes: &[u8]) -> Result<LifecycleOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    put_lifecycle_at(dir, bytes, crate::host::clock::now()).await
}

/// **The lifecycle store door** at `now`:
///
/// - the bundle `refs.head` names must be a held Valid bundle, else the
///   statement WAITS on it (retryable `federation_attester_key_unknown`
///   naming `ceg-genesis-bundle/2:<id>`). v62.0.0 (HL-fix1) — it must be a
///   bundle IN FORCE (a tip, `GenesisInForce::head_standing`): a held bundle
///   a later one superseded is refused by name
///   ([`LIFECYCLE_HEAD_NOT_IN_FORCE`], under `accord_invocation_invalid`),
///   nothing kept, and its voices count nothing. The halt `refs.target` names must
///   be held and verify under a held bundle, else it waits on that row;
/// - the statement alone is read by [`verify_lifecycle_row`] under that
///   bundle's roster: a key the roster does not hold WAITS; `iss_not_holder`
///   is refused by name; every other statement fault is
///   `accord_invocation_invalid` with the reader's token. Nothing of a
///   refused or waiting statement is kept;
/// - a valid voice is kept (`ceg_statements`); the row's held voices are
///   counted: short of a strict majority it is held `count_short`
///   ([`LifecycleOutcome::Pending`]); counted, it is applied to the latch
///   at `now` (the table in this module's header). A row that confirmed the
///   halt in force, and every counted resumption, concludes; a confirmation
///   that changed nothing is not concluded.
///
/// # Errors
/// As above; directory failures.
pub async fn put_lifecycle_at<F>(
    dir: &F,
    bytes: &[u8],
    now: DateTime<Utc>,
) -> Result<LifecycleOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    super::door::require_statement_form(bytes)?;
    let state = super::genesis::genesis_in_force(dir).await?;
    put_lifecycle_in(dir, bytes, now, halt_reading(), &state).await
}

/// v62.0.0 (HALT-235) — [`put_lifecycle_at`] at an explicit fuse `reading`
/// over the genesis in force `state` (the witnesses' seam).
///
/// # Errors
/// As [`put_lifecycle_at`].
pub(crate) async fn put_lifecycle_in<F>(
    dir: &F,
    bytes: &[u8],
    now: DateTime<Utc>,
    reading: MonotonicReading,
    state: &super::genesis::GenesisInForce,
) -> Result<LifecycleOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    super::door::require_statement_form(bytes)?;
    let head = named_head(bytes).ok_or_else(|| malformed_lifecycle("head"))?;
    let target = statement_parts(bytes)
        .and_then(|(_, p)| super::names::names_of(&p).ok())
        .and_then(|n| super::names::single(&n, "target"))
        .ok_or_else(|| malformed_lifecycle("target"))?;
    // v62.0.0 (HL-fix1, SECURITY; CC 4.2.1.3 "against the bundle in force")
    // — the roster is the bundle IN FORCE that `refs.head` names, never any
    // held Valid bundle: `state.valid` holds the predecessors too, so a voice
    // naming a superseded head would count a removed holder against the old
    // roster. The one head reading, shared with the seat re-bind door.
    let roster = match state.head_standing(&head) {
        super::genesis::HeadStanding::InForce(p) => HaltRoster::from_placement(p),
        // A refusal, nothing kept: no later row brings a superseded bundle
        // back into force (a bundle is never un-superseded), so there is
        // nothing a hold could wait for.
        super::genesis::HeadStanding::Superseded => {
            return Err(Error::malformed_row(
                PLANE,
                malformed_row::ACCORD_INVOCATION_INVALID,
                format!(
                    "{LIFECYCLE_HEAD_NOT_IN_FORCE}: `refs.head` names bundle {}, which a later \
                     held bundle superseded; a lifecycle row is counted against the bundle in \
                     force (CC 4.2.1.3)",
                    hex::encode(head)
                ),
            ));
        }
        super::genesis::HeadStanding::NotHeld => {
            return Err(Error::unknown_signer(
                &format!("{GENESIS_BUNDLE_TYP}:{}", hex::encode(head)),
                PLANE,
            ));
        }
    };
    let wait_on_halt = || Error::unknown_signer(&format!("row:{}", target.hex()), PLANE);
    let Some(halt_bytes) = dir.edition2_voices(&target).await?.into_iter().next() else {
        return Err(wait_on_halt());
    };
    let Some(halt) = verified_halt(&halt_bytes, &state.valid) else {
        return Err(wait_on_halt());
    };
    // The statement alone: a voice, a wait, or a refusal.
    match verify_lifecycle_row(&[bytes.to_vec()], &roster, &halt) {
        HaltReading::Valid(_) => {}
        HaltReading::Refused(HaltRefusal::CountUnmet { have, .. }) if have >= 1 => {}
        HaltReading::Refused(HaltRefusal::CountUnmet { .. }) => {
            // No voice counted and nothing refused: its key is one the
            // roster does not hold (CC 4.2.1.1: it waits, never refused).
            let named = super::ingest::statement_kid(bytes)
                .map_or_else(|| format!("row:{}", target.hex()), |k| identity_ref(&k));
            return Err(Error::unknown_signer(&named, PLANE));
        }
        HaltReading::Waiting(w) => return Err(waiting_error(&w)),
        HaltReading::Refused(r) => return Err(refusal_error(&r)),
    }
    let admitted: AdmittedRow =
        super::door::admit_row(bytes, &roster, None, SelectContext::default())?;
    let row_id = admitted.row_id;
    let new = dir.put_edition2_statement(&admitted).await?;
    let mut voices = dir.edition2_voices(&row_id).await?;
    if !voices.iter().any(|v| v.as_slice() == bytes) {
        voices.push(bytes.to_vec());
    }
    let row = match verify_lifecycle_row(&voices, &roster, &halt) {
        HaltReading::Valid(row) => row,
        HaltReading::Waiting(_) | HaltReading::Refused(_) => {
            super::fold::record_pending(
                dir,
                row_id,
                FAMILY_LIFECYCLE,
                super::ingest::INGEST_TIER,
                None,
                std::iter::once(super::fold::Dep::Row(target).read_key()).collect(),
            )
            .await?;
            return Ok(LifecycleOutcome::Pending { row_id, new });
        }
    };
    let accord_root = roster.accord_root();
    let in_force = settle_latch(dir, accord_root, now, reading).await?;
    let names_it = in_force
        .as_ref()
        .and_then(|h| h.halt_row)
        .is_some_and(|h| h.0 == *row.target());
    let kind = row.kind();
    let applied = match kind {
        LifecycleKind::Confirmed => {
            let applies = names_it && in_force.as_ref().is_some_and(|h| !h.confirmed);
            // v62.0.0 (HALT-235) — the latch records the confirmation (a
            // confirmed halt never lapses), stored with the row.
            if applies {
                if let Some(h) = in_force.as_ref() {
                    if let Some(mut latch) = h.latch.clone() {
                        let fuse = u64::from(roster.halt_fuse_secs());
                        let _ = latch.apply_forward(
                            ForwardRow::Lifecycle(&row),
                            reading,
                            ms_of(now),
                            fuse,
                        );
                        store_latch(dir, accord_root, &h.halt_id, &latch).await?;
                    }
                }
            }
            applies
        }
        LifecycleKind::Active => {
            if names_it {
                dir.clear_active_halt(accord_root, &target.hex()).await?;
            }
            names_it
        }
    };
    // A counted resumption is remembered whether or not it ended a halt in
    // force (Verify's `held_resumptions`): a late halt it names never fires.
    if applied || kind == LifecycleKind::Active {
        super::fold::record(
            dir,
            row_id,
            FAMILY_LIFECYCLE,
            super::ingest::INGEST_TIER,
            None,
            std::iter::once(super::fold::Dep::Row(target).read_key()).collect(),
        )
        .await?;
    }
    Ok(if applied {
        LifecycleOutcome::Applied { row_id, new, kind }
    } else {
        LifecycleOutcome::Unchanged { row_id, new }
    })
}
