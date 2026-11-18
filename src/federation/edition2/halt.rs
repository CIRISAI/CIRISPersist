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
//! Not here: the counted lifecycle rows (`confirmed`, `active`; Verify's
//! `verify_lifecycle_row`) and the fuse (`HaltLatch::apply_forward`).
//! TODO(cut-a-halt-lifecycle).

use std::collections::BTreeMap;

use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::family::SelectContext;
use ciris_verify_core::edition2::identity_ref;

pub use ciris_verify_core::edition2::accord_halt::{
    named_accord_root, verify_invocation_row, HaltReading, HaltRefusal, HaltRoster, HaltWaiting,
    InvocationRow, InvokeKind, RosterHolder, ACCORD_ROW_TYPE, FAMILY_CONSTITUTIONAL, FAMILY_DRILL,
    FAMILY_NOTIFY,
};

use super::door::AdmittedRow;
use super::liveness::statement_parts;
use super::names::RowId;
use crate::federation::{malformed_row, Error, FederationDirectory};

/// The plane name the halt door's refusals carry.
pub const PLANE: &str = "accord_halt";
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
    super::door::require_statement_form(bytes)?;
    let Some(roster) = roster else {
        // No bundle in force is held for the accord: wait on it.
        return Err(Error::unknown_signer(
            &format!(
                "{GENESIS_BUNDLE_TYP}:{}",
                named_accord_root(bytes).unwrap_or_default()
            ),
            PLANE,
        ));
    };
    let inv = match verify_invocation_row(bytes, roster) {
        HaltReading::Valid(inv) => inv,
        HaltReading::Waiting(w) => return Err(waiting_error(&w)),
        HaltReading::Refused(r) => return Err(refusal_error(&r)),
    };
    let accord_root = roster.accord_root();
    let admitted: AdmittedRow =
        super::door::admit_row(bytes, roster, None, SelectContext::default())?;
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
        let was_held = dir.fold_held(row).await?.is_some();
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
                    dir.set_active_halt(accord_root, &row.hex()).await?;
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
    let latched = inv.kind() == InvokeKind::Constitutional;
    if latched {
        dir.set_active_halt(accord_root, &hex::encode(inv.row_id()))
            .await?;
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
