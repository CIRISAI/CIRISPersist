//! v59.0.0 (CIRISPersist#1099; CC 3.3.6.3, CIRISConstitution#178;
//! `CLM-self-roster-two-paths`, `CLM-self-roster-authority`) — **the key
//! roster of a self, and its door.**
//!
//! A self is one fedID, a `user`-role identity (a node or an agent identity's
//! occurrences are not a roster, and are written as before). The keys that
//! may sign as it are its **roster**: the
//! genesis key (the fedID's own key) and every ACTIVE `identity_occurrence`
//! under it whose key carries the `user` role. A node's own key and an agent's
//! key are not roster keys: CC 3.3.6.3 keeps "the node's own key" apart from
//! the self's keys, and neither a node nor an agent accepts for itself (CC
//! 3.2, CC 3.4.7.3). Their occurrences under the self are KEM targets, written
//! as before (`signer_acts_for`), and this door does not gate them.
//!
//! # The door: one key of two or more proposes
//!
//! Before this cut any active occurrence added or revoked any other at once —
//! `formal/self_roster`'s **unilateral** configuration, which a stolen device
//! wins in two steps (`unilateral3_stolen`). Now an addition (a signed
//! `identity_occurrence` of a user-role key not on the roster) and an eviction
//! (a `withdraws` against the pair's `identity:occurrence:v1` row, of a live
//! roster key; for the genesis key, against the self pair `(fedID, fedID)`'s
//! row, signed by another roster key) are each a
//! **proposal**, decided by THE shared two-path function
//! ([`super::two_path::decide_all`]) under [`policy`]:
//!
//! - it lands at once by a strict majority of the live roster, proposer
//!   counted (at ONE key the addition is the owner's approval alone — the
//!   add-device flow, unchanged);
//! - or by the lone path, after [`W_SELF_SECS`] on THIS node's clock with no
//!   strict majority of the other members objecting, and for an eviction only
//!   if the target signed nothing since the proposal arrived.
//!
//! v62.0.0: a roster changes only by the edition-2 statements, an
//! `identity:occurrence` bind or an `identity:occurrence_revocation`, whose
//! door asks [`gate_edition2`]. A change that lands proceeds; one that does
//! not is HELD (its statements kept) and lands later by an answer, a further
//! statement, or the lone path ([`execute_due`]).
//!
//! v62.0.0 (WD-fix7; the lead's ruling) — the EARLIER-FORM gate (on
//! `put_identity_occurrence` and on the attestation door's `withdraws` of an
//! `identity:occurrence:v1` row) and the proposal row it minted are retired:
//! that row carried no statement, so every door refused it
//! `earlier_form_object` and no proposal was ever opened. The proposal-row
//! readers below ([`carried_of_row`], [`is_proposal_row`], and the plan's
//! earlier-form receipts) read rows no v62 door stores.
//!
//! # The rows
//!
//! | row | dimension | attester → attested | carries |
//! |---|---|---|---|
//! | proposal | [`DIMENSION_PROPOSAL`] | proposer → fedID | [`PROPOSAL_MEMBER`]: `{identity_key_id, kind, target_key_id, carrier, <carrier>}`, the signed object |
//! | assent | [`DIMENSION_ASSENT`] | roster key → fedID | `cohort: "self"`, `cohort_key_id`, `objects_to_attestation_id` |
//! | objection | [`DIMENSION_OBJECTION`] (`objection:raised:v1`) | roster key → fedID | the same members |
//!
//! All three live in CC 3.1.9.2's `objection:{state}` family (the reverse-
//! quorum shape CIRISConstitution#178 names); `proposal` and `assent` are new
//! states minted here and reported to CC for registration. The proposal row
//! is MINTED by persist from the signed object it carries, the key plane's
//! rule (`key_plane::minted_row`): its signature columns are the object's own,
//! every other column is a pure function of the object, and its id is
//! `sha256("ciris:objection:proposal:v1:" ‖ JCS(object))`, so every node that
//! holds the object names the same proposal and an answer signed on one node
//! counts on all of them. Answers are ordinary rows a roster key signs
//! ([`vote_envelope`]).
//!
//! **What a peer sees.** Nothing pending: a proposal is not an
//! `identity:occurrence:v1` row or a `withdraws`, and (v59.0.0, the
//! sealed-transport cut) there is no framed carriage. Once a proposal lands
//! the effect is written as any other row. A v58 peer receives the proposal
//! row itself and refuses it (its signature is the carried object's, which a
//! v58 generic verify does not read): it never applies a pending change.
//!
//! # Not carried in this cut (named, not hidden)
//!
//! - **Re-asserting a live key's occurrence** (new KEM keys, a new transport
//!   binding) is not a roster change and stays a `signer_acts_for` write.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};

use super::two_path::{
    self, Answers, LandingPath, Proposal, ProposalKind, TwoPathDecision, TwoPathPolicy,
    TwoPathRefusal,
};
use super::types::{attestation_type, identity_type, Attestation, SignedIdentityOccurrence};
use super::{Error, FederationDirectory};

/// `W_self` (CC 3.3.6.3): the lone path's window, 86 400 s.
pub const W_SELF_SECS: i64 = 86_400;

/// The self roster's conditions on the two paths (CC 3.3.6.3): v60.0.0
/// (S6v), the CC governance policy table's `self_roster_add` /
/// `self_roster_evict` rows (CC 4.5.13, vendored at `v1.0-rc9`), admitted
/// inside the self corridor
/// ([`PolicyTable::self_roster`](super::governance_policy::PolicyTable::self_roster)),
/// with the door's own rule (an eviction's target silent all window; one open
/// proposal per proposer and per target). Only the window may move, and only
/// in a live test-anchor harness ([`w_self_secs`]).
///
/// # Errors
///
/// [`Error::GovernancePolicyRefused`] when the table's rows are outside the
/// self corridor, unreadable, or disagree: the door decides nothing.
pub fn policy() -> Result<TwoPathPolicy, Error> {
    let table = super::governance_policy::table()?.self_roster()?;
    Ok(harness_window(table))
}

/// A `test-anchor` build only: the live harness's window (#1111) replaces
/// the table's, the same rule as [`w_self_secs`]. Without the feature there
/// is nothing to replace, so production carries no window override at all.
#[cfg(feature = "test-anchor")]
fn harness_window(mut policy: TwoPathPolicy) -> TwoPathPolicy {
    if super::genesis::test_anchor_override_active() {
        if let Some(secs) = test_window::env_secs() {
            policy.window_secs = secs;
        }
    }
    policy
}

/// See the `test-anchor` twin: a production build decides under the table.
#[cfg(not(feature = "test-anchor"))]
fn harness_window(policy: TwoPathPolicy) -> TwoPathPolicy {
    policy
}

/// `W_self` as this node applies it: [`W_SELF_SECS`], on every production
/// build. v60.0.0 (CIRISPersist#1111, CIRISServer#794 T11) — a `test-anchor`
/// build whose test-anchor override is LIVE (the feature, the runtime arm and
/// verify's anti-production tripwire: [`test_window`]) uses
/// `CIRIS_TEST_W_SELF_SECS` instead, so a harness binary can watch a lone
/// path land without waiting a day. The window still runs on the node's
/// clock from the node's receipt; only its length moves.
#[must_use]
pub fn w_self_secs() -> i64 {
    #[cfg(feature = "test-anchor")]
    {
        test_window::window(
            super::genesis::test_anchor_override_active(),
            test_window::env_secs(),
        )
    }
    #[cfg(not(feature = "test-anchor"))]
    {
        W_SELF_SECS
    }
}

/// v60.0.0 (CIRISPersist#1111) — the test harness's `W_self`. Compiled only
/// with `feature = "test-anchor"`: a production build carries no read of
/// [`test_window::ENV`] (I1162's from-disk half pins that every read of it
/// sits in this module).
#[cfg(feature = "test-anchor")]
pub mod test_window {
    /// The variable a test-anchor harness sets: whole seconds, in
    /// `1..=`[`W_SELF_SECS`](super::W_SELF_SECS). It can shorten the window,
    /// never lengthen it; any other value is ignored with a warning.
    pub const ENV: &str = "CIRIS_TEST_W_SELF_SECS";

    /// [`ENV`], read once per process.
    pub(super) fn env_secs() -> Option<i64> {
        static SECS: std::sync::OnceLock<Option<i64>> = std::sync::OnceLock::new();
        *SECS.get_or_init(|| parse_secs(std::env::var(ENV).ok().as_deref()))
    }

    /// A value of [`ENV`]: whole seconds in `1..=`[`W_SELF_SECS`](super::W_SELF_SECS),
    /// else `None` (with a warning when the variable was set).
    #[must_use]
    pub fn parse_secs(raw: Option<&str>) -> Option<i64> {
        let raw = raw?;
        let secs = raw
            .trim()
            .parse::<i64>()
            .ok()
            .filter(|s| (1..=super::W_SELF_SECS).contains(s));
        if secs.is_none() {
            tracing::warn!(
                value = %raw,
                "{ENV} is not whole seconds in 1..={}: W_self stays {}",
                super::W_SELF_SECS,
                super::W_SELF_SECS
            );
        }
        secs
    }

    /// The window: `env_secs` when the test-anchor override is active, else
    /// [`W_SELF_SECS`](super::W_SELF_SECS). An env value without the
    /// override is inert.
    #[must_use]
    pub fn window(override_active: bool, env_secs: Option<i64>) -> i64 {
        match env_secs {
            Some(secs) if override_active => secs,
            _ => super::W_SELF_SECS,
        }
    }
}

/// The proposal row's dimension (CC 3.1.9.2 `objection:{state}`, whose open
/// vocabulary CC rc9 lists as `proposal`, `assent`, `raised`; minted here).
pub const DIMENSION_PROPOSAL: &str = "objection:proposal:v1";
/// An assent row's dimension (minted here; CC rc9 `objection:{state}`).
pub const DIMENSION_ASSENT: &str = "objection:assent:v1";
/// An objection row's dimension: the reverse quorum's own.
pub const DIMENSION_OBJECTION: &str = super::reverse_quorum::DIMENSION_OBJECTION;
/// The `cohort` an answer names.
pub const COHORT_SELF: &str = "self";
/// The envelope member a proposal row carries its object under.
pub const PROPOSAL_MEMBER: &str = "roster_proposal";

/// The members of a proposal object and of an answer envelope.
pub mod field {
    /// The self (fedID).
    pub const IDENTITY_KEY_ID: &str = "identity_key_id";
    /// `add` / `evict`.
    pub const KIND: &str = "kind";
    /// The key added or evicted.
    pub const TARGET_KEY_ID: &str = "target_key_id";
    /// Which signed object rides the proposal ([`super::carrier`]).
    pub const CARRIER: &str = "carrier";
    /// An answer's cohort (`self`).
    pub use super::super::reverse_quorum::field::COHORT;
    /// An answer's self.
    pub use super::super::reverse_quorum::field::COHORT_KEY_ID;
    /// Free text, never interpreted.
    pub use super::super::reverse_quorum::field::GROUNDS;
    /// The proposal an answer answers.
    pub use super::super::reverse_quorum::field::OBJECTS_TO;
}

/// The signed objects a proposal can carry. Each is also the member name.
pub mod carrier {
    /// A signed `identity_occurrence` (an addition).
    pub const IDENTITY_OCCURRENCE: &str = "identity_occurrence";
    /// A `withdraws` row against the pair's `identity:occurrence:v1` row —
    /// for the genesis key's eviction, the self pair `(fedID, fedID)`'s row.
    pub const WITHDRAWS: &str = "withdraws";
    /// v62.0.0 (wave O1, S1) — an edition-2 `identity:occurrence` bind,
    /// held in `ceg_statements` (no proposal row is minted).
    pub const EDITION2_OCCURRENCE: &str = "edition2_occurrence";
    /// v62.0.0 (wave O1, S1b) — an edition-2
    /// `identity:occurrence_revocation` (an eviction), held in
    /// `ceg_statements`.
    pub const EDITION2_EVICTION: &str = "edition2_eviction";
}

/// The node's clock for this door: THE purge clock (one clock read per door
/// call, no caller-chosen instant; the `cfg(test)` seam is the purge's), at
/// microseconds — the precision every backend stores (`TIMESTAMPTZ`), so a
/// receipt reads back as it was written.
pub(crate) fn roster_clock() -> DateTime<Utc> {
    chrono::SubsecRound::trunc_subsecs(super::steward_purge::purge_clock(), 6)
}

/// One proposal this node holds (V199): when it first held it, and whether it
/// has been settled.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SelfRosterReceipt {
    /// The proposal row's `attestation_id`.
    pub proposal_id: String,
    /// The self.
    pub identity_key_id: String,
    /// When THIS node first held it — the window's start.
    pub received_at: DateTime<Utc>,
    /// When it was settled, if it was.
    pub settled_at: Option<DateTime<Utc>>,
    /// `lands_quorum`, `lands_lone`, or a terminal refusal token.
    pub outcome: Option<String>,
}

/// The settle outcome a landing writes.
#[must_use]
pub const fn landed_outcome(path: LandingPath) -> &'static str {
    match path {
        LandingPath::Quorum => "lands_quorum",
        LandingPath::Lone => "lands_lone",
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  The roster fold
// ─────────────────────────────────────────────────────────────────────────

/// Does `key`'s record carry the `user` role?
pub(crate) async fn is_user_key<D>(dir: &D, key: &str) -> Result<bool, Error>
where
    D: FederationDirectory + ?Sized,
{
    Ok(dir
        .lookup_public_key(key)
        .await?
        .is_some_and(|k| identity_type::set_contains(&k.identity_type, identity_type::USER)))
}

/// **The live roster of `identity` now**: the genesis key and every ACTIVE
/// occurrence (revocations applied, the #421 re-establishment rule; v62.0.0,
/// within its half-open window) whose key is user-role.
pub async fn roster_now<D>(dir: &D, identity: &str) -> Result<BTreeSet<String>, Error>
where
    D: FederationDirectory + ?Sized,
{
    let mut roster = BTreeSet::new();
    let now = roster_clock();
    if !genesis_evicted_at(dir, identity, now).await? {
        roster.insert(identity.to_owned());
    }
    // v62.0.0 (wave O1) — an occurrence past its `valid_until` is not a
    // roster key: its window is half-open (`kernel::key_end::within_record`),
    // not only its revocation ends it (CC 3.3.6.4: "A roster key's occurrence
    // MAY state an end").
    let ms = |t: DateTime<Utc>| u64::try_from(t.timestamp_millis()).unwrap_or(0);
    for o in dir.list_identity_occurrences_active(identity).await? {
        if !crate::kernel::key_end::within_record(ms(now), ms(o.asserted_at), o.valid_until.map(ms))
        {
            continue;
        }
        if o.occurrence_key_id != identity && is_user_key(dir, &o.occurrence_key_id).await? {
            roster.insert(o.occurrence_key_id);
        }
    }
    Ok(roster)
}

/// Was `key` a live roster key of `identity` at `at`? The genesis key always
/// is. Another key is when it is user-role and some admitted assertion of the
/// pair (the V161 history, or the held row) was signed at or before `at`,
/// unexpired at `at`, and not revoked by a revocation in effect at `at` that
/// came after it (the #421 rule, read at `at`).
pub async fn is_roster_key_at<D>(
    dir: &D,
    identity: &str,
    key: &str,
    at: DateTime<Utc>,
) -> Result<bool, Error>
where
    D: FederationDirectory + ?Sized,
{
    if key == identity {
        return Ok(!genesis_evicted_at(dir, identity, at).await?);
    }
    if !is_user_key(dir, key).await? {
        return Ok(false);
    }
    let mut asserted: Vec<(DateTime<Utc>, Option<DateTime<Utc>>)> = dir
        .list_identity_occurrence_history_by_occurrence(key)
        .await?
        .into_iter()
        .filter(|h| h.identity_key_id == identity)
        .map(|h| (h.asserted_at, h.valid_until))
        .collect();
    asserted.extend(
        dir.list_identity_occurrences_by_occurrence_key(key)
            .await?
            .into_iter()
            .filter(|o| o.identity_key_id == identity)
            .map(|o| (o.asserted_at, o.valid_until)),
    );
    let revocations: Vec<DateTime<Utc>> = dir
        .list_identity_occurrence_revocations_for(identity)
        .await?
        .into_iter()
        .filter(|r| r.occurrence_key_id == key)
        .map(|r| r.effective_at)
        .collect();
    Ok(roster_assertion_live(&asserted, &revocations, at))
}

/// **The roster rule, pure** (the #421 rule, read at `at`): some assertion
/// signed by `at` and unexpired at `at`, with no revocation in effect at `at`
/// that came after it.
pub(crate) fn roster_assertion_live(
    asserted: &[(DateTime<Utc>, Option<DateTime<Utc>>)],
    revocations: &[DateTime<Utc>],
    at: DateTime<Utc>,
) -> bool {
    asserted.iter().any(|(asserted_at, valid_until)| {
        *asserted_at <= at
            && valid_until.is_none_or(|v| v > at)
            && !revocations
                .iter()
                .any(|effective| *effective <= at && *effective >= *asserted_at)
    })
}

/// **THE steward predicate** (CC 3.3.6.3, `CLM-self-roster-authority`;
/// CIRISServer#793): does `author` act as `steward` at `at`? It does when it
/// IS the steward, or when it is a live roster key of the steward's self at
/// `at` (the row's signed `asserted_at`) — any live roster key signs as the
/// fedID for every owner act; nothing is reserved to the genesis key. A key of
/// another self, or a key evicted before `at`, does not.
///
/// The consent fold's steward check
/// ([`grant_is_authored_for`](super::consent_by_humans::grant_is_authored_for),
/// and through it
/// [`consent_peers_by_principals`](super::consent_by_humans::consent_peers_by_principals))
/// and the owner seat ([`owner_of`](super::admission::owner_of), through
/// [`self_of_at`]) ask this, and nothing else. (v62.0.0: the
/// one-responsible-steward gate that asked it at the door is deleted; the
/// kernel's owner seat reads two selves as unowned.)
pub async fn acts_as_steward_at<D>(
    dir: &D,
    steward: &str,
    author: &str,
    at: DateTime<Utc>,
) -> Result<bool, Error>
where
    D: FederationDirectory + ?Sized,
{
    is_roster_key_at(dir, steward, author, at).await
}

/// **Was the genesis key of `identity` evicted by `at`?** (CC 3.3.6.3: "the
/// genesis key is roster key one and nothing more … the string survives as
/// the self's name if that key is later evicted"; rc9 69fd22e). Its eviction
/// is an identity-occurrence revocation of the pair `(fedID, fedID)` by
/// another live roster key, LANDING under the two paths: a `withdraws`
/// against the self pair's `identity:occurrence:v1` row (the transport
/// self-occurrence), signed by a key other than the genesis key at or before
/// `at` ([`genesis_withdrawal_of`]), whose proposal THIS node's door settled
/// as landed (V199 `lands_quorum` / `lands_lone`), and which is held.
///
/// Nothing else evicts it: a revocation of the pair admitted before the
/// door (a v58 `withdraws`, or a framed occurrence revocation kept as
/// `legacy_framed`) keeps its old meaning, retiring the transport
/// self-occurrence only; the genesis key's own `withdraws` of that row is the
/// same; a `withdraws` of its `key:record:v1` row is no eviction (the record
/// stays a valid key). The key record stays held, so every row the key signed
/// while live still verifies. It is terminal: no later assertion
/// re-establishes it.
pub async fn genesis_evicted_at<D>(
    dir: &D,
    identity: &str,
    at: DateTime<Utc>,
) -> Result<bool, Error>
where
    D: FederationDirectory + ?Sized,
{
    Ok(genesis_evicted_since(dir, identity)
        .await?
        .is_some_and(|since| since <= at))
}

/// The earliest instant [`genesis_evicted_at`] answers yes, if any.
pub(crate) async fn genesis_evicted_since<D>(
    dir: &D,
    identity: &str,
) -> Result<Option<DateTime<Utc>>, Error>
where
    D: FederationDirectory + ?Sized,
{
    // The held rows of the eviction's shape…
    let mut candidates = std::collections::BTreeMap::new();
    let mut pages = super::attestation_query::AttestationQuery::to(
        identity,
        super::attestation_query::FOLD_PAGE,
    )
    .types(&[attestation_type::WITHDRAWS])
    .pages();
    while let Some(page) = pages.next(dir).await? {
        for w in page {
            if w.attesting_key_id != identity
                && genesis_withdrawal_of(dir, &w).await?.as_deref() == Some(identity)
            {
                candidates.insert(w.attestation_id, w.asserted_at);
            }
        }
    }
    // …that THIS node's door landed (a pre-door one has no landed receipt).
    let landed = [
        landed_outcome(LandingPath::Quorum),
        landed_outcome(LandingPath::Lone),
    ];
    // v62.0.0 (wave O1; I3640) — the edition-2 eviction: an
    // `identity:occurrence_revocation` of the pair `(F, F)` proposed by
    // another roster key, landed through the self-roster door (this node's
    // receipt settled `lands_*`). Its instant is the revocation's
    // `asserted_at`.
    let mut since = genesis_evicted_since_edition2(dir, identity, &landed).await?;
    if candidates.is_empty() {
        return Ok(since);
    }
    for r in dir.list_settled_self_roster_proposals(identity).await? {
        if !r.outcome.as_deref().is_some_and(|o| landed.contains(&o)) {
            continue;
        }
        let Some(proposal) = dir.get_attestation(&r.proposal_id).await? else {
            continue;
        };
        if let Ok(Carried::Withdraws { row, .. }) = carried_of_row(dir, &proposal).await {
            if let Some(asserted) = candidates.get(&row.attestation_id) {
                since = Some(since.map_or(*asserted, |s| s.min(*asserted)));
            }
        }
    }
    Ok(since)
}

/// v62.0.0 (wave O1; I3640) — the earliest `asserted_at` of an edition-2
/// eviction of `identity`'s genesis key this node's door landed: an
/// `identity:occurrence_revocation` about the pair `(identity, identity)`,
/// read as [`Carried::Edition2Eviction`] with a proposer other than the
/// genesis key, whose receipt settled `lands_quorum` / `lands_lone`.
async fn genesis_evicted_since_edition2<D>(
    dir: &D,
    identity: &str,
    landed: &[&str],
) -> Result<Option<DateTime<Utc>>, Error>
where
    D: FederationDirectory + ?Sized,
{
    let mut rows = BTreeSet::new();
    for st in dir
        .edition2_statements_about(
            super::edition2::occurrence::OCCURRENCE_REVOCATION_FAMILY,
            identity,
        )
        .await?
    {
        if let Some(id) = super::edition2::names::RowId::of_statement(&st) {
            rows.insert(id.hex());
        }
    }
    let mut since: Option<DateTime<Utc>> = None;
    for id in rows {
        let Some(Carried::Edition2Eviction {
            identity_key_id,
            target_key_id,
            proposer,
            asserted_at,
            ..
        }) = super::edition2::occurrence::carried_of_bind(dir, &id).await?
        else {
            continue;
        };
        if identity_key_id != identity || target_key_id != identity || proposer == identity {
            continue;
        }
        let receipt = dir.edition2_roster_proposal(&id).await?;
        if receipt.is_some_and(|r| r.outcome.as_deref().is_some_and(|o| landed.contains(&o))) {
            since = Some(since.map_or(asserted_at, |s| s.min(asserted_at)));
        }
    }
    Ok(since)
}

/// The self whose genesis key `row` would evict, when it is that shape: a
/// `withdraws` naming the held `identity:occurrence:v1` row of a user-role
/// self's pair `(F, F)`, signed by a key other than `F`. `None` for any other
/// row — the genesis key withdrawing its own pair retires its transport
/// self-occurrence and evicts nothing; a `withdraws` of `F`'s `key:record:v1`
/// row is not this shape. Whether it LANDED is [`genesis_evicted_at`]'s.
pub async fn genesis_withdrawal_of<D>(dir: &D, row: &Attestation) -> Result<Option<String>, Error>
where
    D: FederationDirectory + ?Sized,
{
    if row.attestation_type != attestation_type::WITHDRAWS {
        return Ok(None);
    }
    let Some(target_id) =
        super::precedence::references_attestation_id_from_envelope(&row.attestation_envelope)
    else {
        return Ok(None);
    };
    let Some(target) = dir.get_attestation(target_id).await? else {
        return Ok(None);
    };
    let Some(signed) = super::key_plane::occurrence_of_row(&target) else {
        return Ok(None);
    };
    let pair = &signed.identity_occurrence;
    if pair.identity_key_id != pair.occurrence_key_id {
        return Ok(None);
    }
    let f = pair.identity_key_id.clone();
    if row.attesting_key_id == f || !is_user_key(dir, &f).await? {
        return Ok(None);
    }
    Ok(Some(f))
}

/// W, the past-freshness window (CIRISPersist#1049; CC 2.6.7, ruled 72 h):
/// the furthest in the past a row's signed `asserted_at` may sit when the
/// row is admitted on a roster key's standing at that instant.
pub const PAST_FRESHNESS_W_SECS: i64 = 259_200;

/// The refusal token of [`check_roster_act_fresh`] (CIRISPersist#1049).
pub const ASSERTED_AT_STALE: &str = "asserted_at_stale";

/// v60.0.0 (CIRISPersist#1049, #1036 item 2) — is `asserted_at` more than
/// [`PAST_FRESHNESS_W_SECS`] behind `now`? The one reading of W every door
/// that judges a chain at a row's signed instant applies before it lets that
/// instant stand alone (CC 2.6.7): the roster gate below, the licensure door,
/// the key_grant sealer and the consent `grant` chain.
#[must_use]
pub fn outside_past_freshness_window(asserted_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    asserted_at < now - chrono::Duration::seconds(PAST_FRESHNESS_W_SECS)
}

/// **The bound on [`acts_as_steward_at`]'s instant, at admission**
/// (CIRISPersist#1049; CC 2.6.7 W as ruled in 3.3.6.3, rc9 69fd22e): a row
/// whose author stands for one of `stewards` as a roster key at the row's
/// signed `asserted_at` but is NOT a live roster key of that self at receipt
/// (evicted or revoked since) is refused [`ASSERTED_AT_STALE`] when that
/// instant is more than [`PAST_FRESHNESS_W_SECS`] behind this node's clock —
/// so an evicted key cannot sign into the window in which it was still live.
/// A key that is live now is admitted at any age: a new device or node
/// syncing a self's history admits its legitimate old rows. A steward's own
/// row, and a row whose author is no roster key of any of them, pass (the
/// latter fails the steward check on its own terms).
///
/// # Errors
///
/// [`Error::AssertedAtStale`] (`kind()` `federation_invalid_argument`,
/// Display `asserted_at_stale: …`).
pub async fn check_roster_act_fresh<D>(
    dir: &D,
    stewards: &[String],
    author: &str,
    asserted_at: DateTime<Utc>,
) -> Result<(), Error>
where
    D: FederationDirectory + ?Sized,
{
    if stewards.iter().any(|s| s == author) {
        return Ok(());
    }
    let now = roster_clock();
    if !outside_past_freshness_window(asserted_at, now) {
        return Ok(());
    }
    for s in stewards {
        if is_roster_key_at(dir, s, author, asserted_at).await?
            && !is_roster_key_at(dir, s, author, now).await?
        {
            return Err(Error::AssertedAtStale {
                author: author.to_owned(),
                standing_for: s.clone(),
                plane: "roster",
                asserted_at,
                w_secs: PAST_FRESHNESS_W_SECS,
            });
        }
    }
    Ok(())
}

/// The self `key` signs as at `at`: the one user-role identity other than
/// `key` whose roster holds `key` at `at` ([`acts_as_steward_at`]), else `key`
/// itself (no such identity, or more than one: no single self to name).
pub async fn self_of_at<D>(dir: &D, key: &str, at: DateTime<Utc>) -> Result<String, Error>
where
    D: FederationDirectory + ?Sized,
{
    let mut candidates: BTreeSet<String> = dir
        .list_identity_occurrence_history_by_occurrence(key)
        .await?
        .into_iter()
        .map(|h| h.identity_key_id)
        .collect();
    candidates.extend(
        dir.list_identity_occurrences_by_occurrence_key(key)
            .await?
            .into_iter()
            .map(|o| o.identity_key_id),
    );
    let mut selves = Vec::new();
    for identity in candidates {
        if identity != key
            && is_user_key(dir, &identity).await?
            && acts_as_steward_at(dir, &identity, key, at).await?
        {
            selves.push(identity);
        }
    }
    Ok(match selves.as_slice() {
        [only] => only.clone(),
        _ => key.to_owned(),
    })
}

// ─────────────────────────────────────────────────────────────────────────
//  The proposal: what it carries, its row
// ─────────────────────────────────────────────────────────────────────────

/// The signed object a proposal carries, with what it changes.
#[derive(Debug, Clone, PartialEq)]
pub enum Carried {
    /// An addition: a signed occurrence of a key not on the roster.
    Occurrence(SignedIdentityOccurrence),
    /// An eviction by `withdraws` against the pair's occurrence row.
    Withdraws {
        /// The `withdraws` row, as its signer offered it.
        row: Attestation,
        /// The self.
        identity_key_id: String,
        /// The key it evicts.
        target_key_id: String,
    },
    /// v62.0.0 (wave O1, S1) — an addition by an edition-2
    /// `identity:occurrence` bind: its statements are held in
    /// `ceg_statements` under `row_id` (the occurrence key's own and at least
    /// one roster key's author statement). The proposal's id is the row id's
    /// hex; no JSON proposal row is minted.
    Edition2Occurrence {
        /// The bind's row id.
        row_id: super::edition2::names::RowId,
        /// The self.
        identity_key_id: String,
        /// The key it adds.
        target_key_id: String,
        /// The roster key whose author statement proposed it (identity-ref).
        proposer: String,
        /// The bind's `asserted_at`.
        asserted_at: DateTime<Utc>,
        /// The roster row it names by `refs.head` (CC 3.3.6.4: the
        /// thresholds count over the roster the proposal names,
        /// [`roster_at_heads`]).
        head: super::edition2::names::RowId,
        /// The other tips it merges, `refs.further_heads` (CC rc21).
        further_heads: Vec<super::edition2::names::RowId>,
    },
    /// v62.0.0 (wave O1, S1b) — an eviction by an edition-2
    /// `identity:occurrence_revocation` (T2's family): its voices are held in
    /// `ceg_statements` under `row_id`, each a roster key's statement as the
    /// self. The proposal's id is the row id's hex.
    Edition2Eviction {
        /// The revocation's row id.
        row_id: super::edition2::names::RowId,
        /// The self.
        identity_key_id: String,
        /// The key it evicts.
        target_key_id: String,
        /// The roster key of the lowest-id voice (identity-ref).
        proposer: String,
        /// The revocation's `asserted_at`.
        asserted_at: DateTime<Utc>,
        /// The roster row it names by `refs.head` ([`roster_at_heads`]).
        head: super::edition2::names::RowId,
        /// The other tips it merges, `refs.further_heads` (CC rc21).
        further_heads: Vec<super::edition2::names::RowId>,
    },
}

impl Carried {
    /// Add or evict.
    #[must_use]
    pub fn kind(&self) -> ProposalKind {
        match self {
            Self::Occurrence(_) | Self::Edition2Occurrence { .. } => ProposalKind::Add,
            Self::Withdraws { .. } | Self::Edition2Eviction { .. } => ProposalKind::Evict,
        }
    }

    /// The self.
    #[must_use]
    pub fn identity_key_id(&self) -> &str {
        match self {
            Self::Occurrence(s) => &s.identity_occurrence.identity_key_id,
            Self::Withdraws {
                identity_key_id, ..
            }
            | Self::Edition2Occurrence {
                identity_key_id, ..
            }
            | Self::Edition2Eviction {
                identity_key_id, ..
            } => identity_key_id,
        }
    }

    /// The key added or evicted.
    #[must_use]
    pub fn target_key_id(&self) -> &str {
        match self {
            Self::Occurrence(s) => &s.identity_occurrence.occurrence_key_id,
            Self::Withdraws { target_key_id, .. }
            | Self::Edition2Occurrence { target_key_id, .. }
            | Self::Edition2Eviction { target_key_id, .. } => target_key_id,
        }
    }

    /// Who signed it.
    #[must_use]
    pub fn proposer(&self) -> &str {
        match self {
            Self::Occurrence(s) => &s.attesting_key_id,
            Self::Withdraws { row, .. } => &row.attesting_key_id,
            Self::Edition2Occurrence { proposer, .. } | Self::Edition2Eviction { proposer, .. } => {
                proposer
            }
        }
    }

    /// Its signed instant.
    #[must_use]
    pub fn asserted_at(&self) -> DateTime<Utc> {
        match self {
            Self::Occurrence(s) => s.identity_occurrence.asserted_at,
            Self::Withdraws { row, .. } => row.asserted_at,
            Self::Edition2Occurrence { asserted_at, .. }
            | Self::Edition2Eviction { asserted_at, .. } => *asserted_at,
        }
    }
}

/// Is `row` a self-roster proposal row (by its signed dimension)?
#[must_use]
pub fn is_proposal_row(row: &Attestation) -> bool {
    row.attestation_type == attestation_type::SCORES
        && super::admission::envelope_dimension(&row.attestation_envelope)
            == Some(DIMENSION_PROPOSAL)
}

fn malformed(row: &Attestation, what: &str) -> Error {
    Error::malformed_row(
        "self_roster",
        super::malformed_row::ENVELOPE_MEMBER_INVALID,
        format!(
            "{DIMENSION_PROPOSAL} row {}: {what} (CIRISPersist#1099)",
            row.attestation_id
        ),
    )
}

/// The object a proposal row carries, read back. The withdraws carrier's
/// self and target are re-derived from the held occurrence row the
/// `withdraws` names, never taken from the object.
pub async fn carried_of_row<D>(dir: &D, row: &Attestation) -> Result<Carried, Error>
where
    D: FederationDirectory + ?Sized,
{
    let object = row
        .attestation_envelope
        .get(PROPOSAL_MEMBER)
        .ok_or_else(|| malformed(row, "no roster_proposal member"))?;
    let str_of = |k: &str| object.get(k).and_then(serde_json::Value::as_str);
    let carried_member = str_of(field::CARRIER).ok_or_else(|| malformed(row, "no carrier"))?;
    let inner = object
        .get(carried_member)
        .cloned()
        .ok_or_else(|| malformed(row, "the carrier member is absent"))?;
    let carried = match carried_member {
        carrier::IDENTITY_OCCURRENCE => {
            let mut inner = inner;
            if let Some(o) = inner
                .get_mut("identity_occurrence")
                .and_then(serde_json::Value::as_object_mut)
            {
                o.insert("persist_row_hash".to_owned(), String::new().into());
            }
            let mut s: SignedIdentityOccurrence = serde_json::from_value(inner)
                .map_err(|e| malformed(row, &format!("identity_occurrence: {e}")))?;
            s.identity_occurrence.persist_row_hash =
                super::types::compute_persist_row_hash(&s.identity_occurrence)?;
            Carried::Occurrence(s)
        }
        carrier::WITHDRAWS => {
            let mut inner = inner;
            if let Some(o) = inner.as_object_mut() {
                o.insert("persist_row_hash".to_owned(), String::new().into());
            }
            let mut w: Attestation = serde_json::from_value(inner)
                .map_err(|e| malformed(row, &format!("withdraws: {e}")))?;
            w.persist_row_hash = super::types::compute_persist_row_hash(&w)?;
            let (identity_key_id, target_key_id) =
                if let Some(rev) = super::key_plane::occurrence_withdrawal_of(dir, &w).await? {
                    (rev.identity_key_id, rev.occurrence_key_id)
                } else if let Some(genesis) = genesis_withdrawal_of(dir, &w).await? {
                    (genesis.clone(), genesis)
                } else {
                    return Err(Error::InvalidArgument(format!(
                        "{DIMENSION_PROPOSAL} row {}: the withdraws it carries names no held \
                         identity:occurrence:v1 or key:record:v1 row — re-offer once it is held",
                        row.attestation_id
                    )));
                };
            Carried::Withdraws {
                row: w,
                identity_key_id,
                target_key_id,
            }
        }
        other => return Err(malformed(row, &format!("unknown carrier {other:?}"))),
    };
    if str_of(field::IDENTITY_KEY_ID) != Some(carried.identity_key_id())
        || str_of(field::TARGET_KEY_ID) != Some(carried.target_key_id())
        || str_of(field::KIND) != Some(carried.kind().as_str())
    {
        return Err(malformed(
            row,
            "identity_key_id / target_key_id / kind disagree with the carried object",
        ));
    }
    Ok(carried)
}

// ─────────────────────────────────────────────────────────────────────────
//  Answers
// ─────────────────────────────────────────────────────────────────────────

/// The envelope of an answer to a proposal — an assent (`assent = true`) or
/// an objection — for a roster key to sign and put as a `scores` row
/// attested to the self (`attested_key_id = identity_key_id`). Defined here
/// so a producer and this node's fold agree byte for byte.
#[must_use]
pub fn vote_envelope(identity_key_id: &str, proposal_id: &str, assent: bool) -> serde_json::Value {
    serde_json::json!({
        "dimension": if assent { DIMENSION_ASSENT } else { DIMENSION_OBJECTION },
        "score": if assent { 1 } else { -1 },
        "confidence": 1,
        field::COHORT: COHORT_SELF,
        field::COHORT_KEY_ID: identity_key_id,
        field::OBJECTS_TO: proposal_id,
        field::GROUNDS: "",
    })
}

/// The self an answer row answers for, when it is one: a `scores` row on
/// [`DIMENSION_ASSENT`] / [`DIMENSION_OBJECTION`] naming `cohort: self`.
#[must_use]
pub fn answer_identity(row: &Attestation) -> Option<&str> {
    if row.attestation_type != attestation_type::SCORES {
        return None;
    }
    let dim = super::admission::envelope_dimension(&row.attestation_envelope)?;
    if dim != DIMENSION_ASSENT && dim != DIMENSION_OBJECTION {
        return None;
    }
    let env = &row.attestation_envelope;
    if env.get(field::COHORT)?.as_str()? != COHORT_SELF {
        return None;
    }
    env.get(field::COHORT_KEY_ID)?.as_str()
}

/// The held answers to `proposal`, and the target's latest signed act.
async fn answers_for<D>(
    dir: &D,
    identity: &str,
    proposal: &Proposal,
    rows: &[Attestation],
) -> Result<Answers, Error>
where
    D: FederationDirectory + ?Sized,
{
    let mut answers = Answers::default();
    let retired = super::admission::retracted_edge_ids(rows);
    for r in rows {
        if retired.contains(&r.attestation_id)
            || answer_identity(r) != Some(identity)
            || r.attestation_envelope
                .get(field::OBJECTS_TO)
                .and_then(serde_json::Value::as_str)
                != Some(proposal.id.as_str())
        {
            continue;
        }
        match super::admission::envelope_dimension(&r.attestation_envelope) {
            Some(DIMENSION_ASSENT) => {
                answers.approvers.insert(r.attesting_key_id.clone());
            }
            Some(DIMENSION_OBJECTION) => {
                answers.objectors.insert(r.attesting_key_id.clone());
            }
            _ => {}
        }
    }
    // Any signed act by the target answers (CC 3.3.6.3): its latest row.
    let one = std::num::NonZeroU32::new(1).expect("one");
    let mut pages = super::attestation_query::AttestationQuery::by(&proposal.target, one).pages();
    if let Some(page) = pages.next(dir).await? {
        answers
            .target_acts
            .extend(page.first().map(|a| a.asserted_at));
    }
    Ok(answers)
}

/// Every answer row held about `identity` (and the retractions naming them).
async fn answer_rows<D>(dir: &D, identity: &str) -> Result<Vec<Attestation>, Error>
where
    D: FederationDirectory + ?Sized,
{
    let mut rows = Vec::new();
    let mut pages = super::attestation_query::AttestationQuery::to(
        identity,
        super::attestation_query::FOLD_PAGE,
    )
    .dimension_any_of(&[DIMENSION_ASSENT, DIMENSION_OBJECTION])
    .pages();
    while let Some(page) = pages.next(dir).await? {
        rows.extend(page);
    }
    let ids: Vec<String> = rows.iter().map(|r| r.attestation_id.clone()).collect();
    if !ids.is_empty() {
        rows.extend(
            dir.list_composers_referencing_any(&ids, Some(identity), None)
                .await?,
        );
    }
    Ok(rows)
}

// ─────────────────────────────────────────────────────────────────────────
//  The plan: every open proposal of a self, decided
// ─────────────────────────────────────────────────────────────────────────

/// One open proposal of a self, as the door read it, with its decision.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Standing {
    /// The proposal.
    pub proposal: Proposal,
    /// Its decision at `decided_at`.
    pub decision: TwoPathDecision,
    /// The node's clock the decision was read at.
    pub decided_at: DateTime<Utc>,
    /// The keys whose assent counts toward the quorum.
    pub approvers: Vec<String>,
    /// The keys whose objection counts against the lone path.
    pub objectors: Vec<String>,
}

/// The plan for one self: the roster and every open proposal, decided at
/// `now`, `extra` (a proposal this node does not hold yet) included.
struct Plan {
    roster: BTreeSet<String>,
    entries: Vec<(Proposal, Answers, Carried, TwoPathDecision)>,
    /// Open proposals their proposer withdrew (a `withdraws` against the
    /// proposal row): out of the decision, settled `withdrawn` by the executor.
    withdrawn: Vec<String>,
    /// v62.0.0 (wave O1, S1b) — the same for edition-2 proposals (settled in
    /// `ceg_roster_proposals`).
    withdrawn_e2: Vec<String>,
}

/// The settle outcome of a proposal its proposer withdrew.
pub const WITHDRAWN_OUTCOME: &str = "withdrawn";

async fn plan<D>(
    dir: &D,
    identity: &str,
    extra: Option<(&Carried, &str)>,
    now: DateTime<Utc>,
    policy: &TwoPathPolicy,
) -> Result<Plan, Error>
where
    D: FederationDirectory + ?Sized,
{
    let roster = roster_now(dir, identity).await?;
    let mut held: Vec<(Proposal, Carried)> = Vec::new();
    let mut receipts = dir.list_open_self_roster_proposals(Some(identity)).await?;
    // v62.0.0 (wave O1, S1) — and this node's edition-2 receipts.
    receipts.extend(open_edition2_receipts(dir, Some(identity)).await?);
    // A proposal leaves `pending` when its proposer withdraws its row (CC
    // rc9 `2643ff1`: the self roster's open proposal is cleared by the
    // proposer's withdraws).
    let ids: Vec<String> = receipts.iter().map(|r| r.proposal_id.clone()).collect();
    let composers = if ids.is_empty() {
        Vec::new()
    } else {
        dir.list_composers_referencing_any(&ids, None, None).await?
    };
    let mut withdrawn = Vec::new();
    let mut withdrawn_e2 = Vec::new();
    for receipt in receipts {
        let Some(row) = dir.get_attestation(&receipt.proposal_id).await? else {
            // v62.0.0 (wave O1, S1) — an edition-2 bind's proposal: no row,
            // its statements held under the row id.
            if let Some(carried) =
                super::edition2::occurrence::carried_of_bind(dir, &receipt.proposal_id).await?
            {
                // S1b — the proposer's own edition-2 `withdraws` naming the
                // row id closes it.
                if super::edition2::occurrence::proposal_withdrawn(dir, &carried).await? {
                    withdrawn_e2.push(receipt.proposal_id);
                    continue;
                }
                held.push((
                    proposal_of(&carried, &receipt.proposal_id, receipt.received_at),
                    carried,
                ));
            }
            continue;
        };
        let carried = match carried_of_row(dir, &row).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(proposal_id = %receipt.proposal_id, error = %e, "held roster proposal unreadable");
                continue;
            }
        };
        if composers.iter().any(|w| {
            w.attestation_type == attestation_type::WITHDRAWS
                && w.attesting_key_id == carried.proposer()
                && super::precedence::references_attestation_id_from_envelope(
                    &w.attestation_envelope,
                ) == Some(receipt.proposal_id.as_str())
        }) {
            withdrawn.push(receipt.proposal_id);
            continue;
        }
        held.push((
            proposal_of(&carried, &receipt.proposal_id, receipt.received_at),
            carried,
        ));
    }
    if let Some((carried, id)) = extra {
        if !held.iter().any(|(p, _)| p.id == id) {
            held.push((proposal_of(carried, id, now), carried.clone()));
        }
    }
    let rows = answer_rows(dir, identity).await?;
    let mut with_answers = Vec::with_capacity(held.len());
    // O1 fix 12: in `decide_all`'s order (signed instant, then id), the
    // proposers of the entries ahead; a later edition-2 entry prefers a
    // proposer outside them (`one_open_per_proposer`).
    held.sort_by(|a, b| {
        (a.0.asserted_at, a.0.id.as_str()).cmp(&(b.0.asserted_at, b.0.id.as_str()))
    });
    let mut ahead_proposers: BTreeSet<String> = BTreeSet::new();
    for (mut p, mut c) in held {
        // T2's I3187: an edition-2 proposal's proposer is chosen among the
        // voices by keys on the roster at its named heads; with none, it is
        // not decided (held, concluding nothing).
        let e2_row = match &c {
            Carried::Edition2Occurrence { row_id, .. }
            | Carried::Edition2Eviction { row_id, .. } => Some(*row_id),
            Carried::Occurrence(_) | Carried::Withdraws { .. } => None,
        };
        if let (Some(heads), Some(row_id)) = (head_of(&c), e2_row) {
            if let Ok((at_heads, _)) = roster_reading(dir, identity, &heads).await {
                let exclude = match &c {
                    Carried::Edition2Eviction { target_key_id, .. } => Some(target_key_id.clone()),
                    _ => None,
                };
                match super::edition2::occurrence::proposer_on_roster(
                    dir,
                    &row_id,
                    identity,
                    &at_heads,
                    exclude.as_deref(),
                    &ahead_proposers,
                )
                .await?
                {
                    Some(k) => {
                        p.proposer.clone_from(&k);
                        c = with_proposer(c, k);
                    }
                    None => continue,
                }
            }
        }
        ahead_proposers.insert(p.proposer.clone());
        let mut a = answers_for(dir, identity, &p, &rows).await?;
        // v62.0.0 (wave O1, S1) — an edition-2 bind's further author
        // statements (roster keys signing as the self over the same payload)
        // are assents too.
        if let Carried::Edition2Occurrence { row_id, .. }
        | Carried::Edition2Eviction { row_id, .. } = &c
        {
            a.approvers.extend(
                super::edition2::occurrence::author_voice_keys(dir, row_id, identity).await?,
            );
        }
        with_answers.push((p, a, c));
    }
    // v62.0.0 (wave O1; CC 3.3.6.4, the CC 2.7 ruling) — an edition-2
    // proposal counts over the roster AT THE HEAD IT NAMES
    // ([`roster_at_head`]); the earlier form's over the roster now. One
    // decision per roster: the earlier form's, and one per named head.
    let mut decided: Vec<(String, TwoPathDecision)> = Vec::new();
    type ByHead<'a> = std::collections::BTreeMap<
        Option<Vec<super::edition2::names::RowId>>,
        Vec<(
            &'a Proposal,
            &'a Answers,
            Option<super::edition2::names::RowId>,
        )>,
    >;
    let mut by_head: ByHead<'_> = std::collections::BTreeMap::new();
    for (p, a, c) in &with_answers {
        let row = match c {
            Carried::Edition2Occurrence { row_id, .. }
            | Carried::Edition2Eviction { row_id, .. } => Some(*row_id),
            Carried::Occurrence(_) | Carried::Withdraws { .. } => None,
        };
        by_head.entry(head_of(c)).or_default().push((p, a, row));
    }
    for (head, entries) in by_head {
        let (at_head, refs) = match head {
            None => (
                roster.clone(),
                entries.iter().map(|(p, a, _)| (*p, *a)).collect::<Vec<_>>(),
            ),
            Some(heads) => {
                let (at_head, reach) = match roster_reading(dir, identity, &heads).await {
                    Ok(r) => r,
                    Err(e) => {
                        // A named head is not held or not landed yet: these
                        // proposals wait (the fold re-plans them when it
                        // lands).
                        tracing::debug!(error = %e, "self-roster heads not readable");
                        continue;
                    }
                };
                // CC 2.7.8: a row VOID for this reader is never decided
                // (the gate settles it on its next fold).
                let mut refs = Vec::new();
                for (p, a, row) in &entries {
                    let void = match row {
                        Some(r) => void_for_reader(dir, identity, r, &heads, &reach)
                            .await?
                            .is_some(),
                        None => false,
                    };
                    if !void {
                        refs.push((*p, *a));
                    }
                }
                (at_head, refs)
            }
        };
        decided.extend(
            two_path::decide_all(&at_head, &refs, now, policy)
                .into_iter()
                .map(|(p, d)| (p.id.clone(), d)),
        );
    }
    let mut entries = Vec::with_capacity(decided.len());
    for (id, d) in decided {
        if let Some(pos) = with_answers.iter().position(|(p, _, _)| p.id == id) {
            let (p, a, c) = with_answers.swap_remove(pos);
            entries.push((p, a, c, d));
        }
    }
    Ok(Plan {
        roster,
        entries,
        withdrawn,
        withdrawn_e2,
    })
}

fn proposal_of(carried: &Carried, id: &str, received_at: DateTime<Utc>) -> Proposal {
    Proposal {
        id: id.to_owned(),
        kind: carried.kind(),
        proposer: carried.proposer().to_owned(),
        target: carried.target_key_id().to_owned(),
        asserted_at: carried.asserted_at(),
        received_at,
    }
}

/// **Every open proposal of `identity`, decided now** — what a host shows the
/// self's devices so they can answer.
pub async fn standing<D>(dir: &D, identity: &str) -> Result<Vec<Standing>, Error>
where
    D: FederationDirectory + ?Sized,
{
    let policy = policy()?;
    let now = roster_clock();
    let plan = plan(dir, identity, None, now, &policy).await?;
    Ok(plan
        .entries
        .into_iter()
        .map(|(proposal, answers, _, decision)| {
            let live = |s: &BTreeSet<String>| -> Vec<String> {
                s.iter()
                    .filter(|k| plan.roster.contains(*k) && **k != proposal.proposer)
                    .cloned()
                    .collect()
            };
            let objectors = live(&answers.objectors);
            let approvers = live(&answers.approvers)
                .into_iter()
                .filter(|k| !objectors.contains(k))
                .collect();
            Standing {
                proposal,
                decision,
                decided_at: now,
                approvers,
                objectors,
            }
        })
        .collect())
}

// ─────────────────────────────────────────────────────────────────────────
//  The gate: every door that can change a roster asks it
// ─────────────────────────────────────────────────────────────────────────

/// Is `carried` a change to the self's roster? An addition of a user-role key
/// not on it; an eviction of a key on it other than the genesis key.
async fn is_roster_change<D>(
    dir: &D,
    carried: &Carried,
    roster: &BTreeSet<String>,
) -> Result<bool, Error>
where
    D: FederationDirectory + ?Sized,
{
    let (identity, target) = (carried.identity_key_id(), carried.target_key_id());
    // A self is a person (CC 3.3.6.3): a node or agent identity's
    // occurrences are not a roster.
    if !is_user_key(dir, identity).await? {
        return Ok(false);
    }
    // v62.0.0 (wave O1, S1b) — an edition-2 eviction: of a key on the
    // roster; of the genesis key only when ANOTHER roster key proposes it
    // (the genesis key revoking the self pair retires its transport
    // self-occurrence and evicts nothing, CC 3.3.6.4).
    if let Carried::Edition2Eviction { proposer, .. } = carried {
        return Ok(roster.contains(target) && !(target == identity && proposer == identity));
    }
    if target == identity {
        // The genesis key's eviction: a `withdraws` of the self pair's
        // `identity:occurrence:v1` row signed by ANOTHER roster key
        // ([`genesis_withdrawal_of`]). The genesis key's own `withdraws` of
        // that row retires the transport self-occurrence, as before, and
        // evicts nothing.
        let Carried::Withdraws { row, .. } = carried else {
            return Ok(false);
        };
        return Ok(genesis_withdrawal_of(dir, row).await?.is_some() && roster.contains(identity));
    }
    Ok(match carried.kind() {
        ProposalKind::Add => !roster.contains(target) && is_user_key(dir, target).await?,
        ProposalKind::Evict => roster.contains(target),
    })
}

/// v62.0.0 (wave O1, S1; CC 3.3.6.4) — **THE gate for an edition-2 bind**
/// (`edition2::occurrence::put_occurrence_voice`, on every author
/// statement): the two paths (quorum, lone), over a proposal whose id is
/// the bind's row id and whose statements are held in `ceg_statements`.
///
/// - `Ok(true)`: not a roster change, or it lands now (the quorum path: the
///   held author statements and the `objection:assent` answers naming the
///   row id count; the proposer counted). The door then writes the bind.
/// - `Ok(false)`: pending. This node's receipt is noted at its first hold
///   (the window's start, CC 3.3.6.4); the bind lands later by an answer, a
///   further author statement, or the lone path after `W_self` with no
///   majority of the others objecting ([`execute_for`] / [`execute_due`],
///   which land it from its held statements).
///
/// # Errors
/// [`Error::SelfRosterNotLanded`] (`decision` `refused…`) when no answer can
/// mend it (the proposer is not on the roster); the policy's refusal;
/// directory failures.
pub async fn gate_edition2<D>(dir: &D, carried: Carried) -> Result<bool, Error>
where
    D: FederationDirectory + ?Sized,
{
    let identity = carried.identity_key_id().to_owned();
    let (Carried::Edition2Occurrence { row_id, .. } | Carried::Edition2Eviction { row_id, .. }) =
        &carried
    else {
        return Err(Error::InvalidArgument(
            "gate_edition2: not an edition-2 proposal".into(),
        ));
    };
    let row_id = *row_id;
    let id = row_id.hex();
    let heads = head_of(&carried).unwrap_or_default();
    // Every named head is a read of this proposal (T2's I3186): when one
    // lands, G0's re-fold re-runs it (declared here as well as by the
    // roster fold, so the Ok(false) wait always carries it).
    for h in &heads {
        super::edition2::fold::reads(super::edition2::fold::Dep::Row(*h));
    }
    let now = roster_clock();
    // A settled landing or voiding is final for this reader (a re-fold that
    // re-runs a concluded row's door must not re-read it against its own
    // successors).
    let settled = match dir.edition2_roster_proposal(&id).await {
        Ok(r) => r.and_then(|r| r.outcome),
        Err(e) => return Err(e),
    };
    match settled.as_deref() {
        Some(o)
            if o == landed_outcome(LandingPath::Quorum)
                || o == landed_outcome(LandingPath::Lone) =>
        {
            return Ok(true);
        }
        Some(VOID_OUTCOME) => {
            super::edition2::fold::note(REASON_ROSTER_HEAD_SUPERSEDED);
            return Ok(false);
        }
        _ => {}
    }
    // Every landing is recorded (a receipt settled `lands_*`): the next
    // roster row names it as its head, and the genesis key's eviction is
    // read from it.
    if !is_user_key(dir, &identity).await? {
        record_landed(dir, &id, &identity, LandingPath::Quorum, now).await?;
        return Ok(true);
    }
    // CC 3.3.6.4 (the CC 2.7 ruling): counted over the roster the row names
    // (its head and further heads). A named row this node does not hold, or
    // that has not landed here, makes the proposal WAIT (CC 2.7.3: a row
    // waits for what it names): its receipt is noted and it stays open; the
    // fold re-plans it when the row lands (`roster_at_heads` declared the
    // reads).
    let (roster, reach) = match roster_reading(dir, &identity, &heads).await {
        Ok(r) => r,
        Err(Error::AttesterKeyUnknown { .. }) => {
            dir.note_edition2_roster_proposal(&id, &identity, now)
                .await?;
            return Ok(false);
        }
        Err(e) => return Err(e),
    };
    // CC 2.7.8: a stale sibling is VOID for this reader — held (its
    // statements kept), concluding nothing, under a fold reason; never a
    // door refusal. Settled so it is not re-planned.
    if let Some(detail) = void_for_reader(dir, &identity, &row_id, &heads, &reach).await? {
        tracing::debug!(%detail, "self-roster row void for this reader");
        super::edition2::fold::note(REASON_ROSTER_HEAD_SUPERSEDED);
        dir.note_edition2_roster_proposal(&id, &identity, now)
            .await?;
        dir.settle_edition2_roster_proposal(&id, VOID_OUTCOME, now)
            .await?;
        return Ok(false);
    }
    if !is_roster_change(dir, &carried, &roster).await? {
        record_landed(dir, &id, &identity, LandingPath::Quorum, now).await?;
        return Ok(true);
    }
    // T2's I3187: the proposer is chosen among the voices by keys ON the
    // roster at the named heads; a voice off it is kept and concludes
    // nothing, never a refusal. No such voice yet: the proposal waits.
    // O1 fix 8: an eviction's target never proposes it (`proposer_is_target`).
    let exclude = match &carried {
        Carried::Edition2Eviction { target_key_id, .. } => Some(target_key_id.clone()),
        _ => None,
    };
    let Some(proposer) = super::edition2::occurrence::proposer_on_roster(
        dir,
        &row_id,
        &identity,
        &roster,
        exclude.as_deref(),
        &BTreeSet::new(),
    )
    .await?
    else {
        dir.note_edition2_roster_proposal(&id, &identity, now)
            .await?;
        return Ok(false);
    };
    let carried = with_proposer(carried, proposer);
    let policy = policy()?;
    let plan = plan(dir, &identity, Some((&carried, &id)), now, &policy).await?;
    let decision = plan
        .entries
        .iter()
        .find(|(p, ..)| p.id == id)
        .map(|(.., d)| *d)
        .ok_or_else(|| Error::Backend(format!("self-roster plan lost proposal {id}")))?;
    if let TwoPathDecision::Lands { path } = decision {
        // The landing is recorded whether or not a receipt was held (a
        // roster change landing on its first offer, too): the genesis key's
        // eviction is read from it (`genesis_evicted_at`).
        record_landed(dir, &id, &identity, path, now).await?;
        return Ok(true);
    }
    let refused_for_good = matches!(
        decision,
        TwoPathDecision::Refused {
            reason: TwoPathRefusal::ProposerNotOnRoster
        } | TwoPathDecision::Cancelled { .. }
    );
    if refused_for_good {
        return Err(Error::SelfRosterNotLanded {
            identity_key_id: identity,
            target_key_id: carried.target_key_id().to_owned(),
            kind: carried.kind().as_str(),
            proposal_id: id,
            decision: decision.token(),
            earliest_lone_at: None,
            needs: 0,
        });
    }
    dir.note_edition2_roster_proposal(&id, &identity, now)
        .await?;
    Ok(false)
}

/// `c` with this proposer (an edition-2 proposal; others unchanged).
fn with_proposer(mut c: Carried, k: String) -> Carried {
    if let Carried::Edition2Occurrence { proposer, .. }
    | Carried::Edition2Eviction { proposer, .. } = &mut c
    {
        *proposer = k;
    }
    c
}

/// Record an edition-2 row's landing: this node's receipt, noted (first
/// seen) and settled `lands_*`.
async fn record_landed<D>(
    dir: &D,
    id: &str,
    identity: &str,
    path: LandingPath,
    now: DateTime<Utc>,
) -> Result<(), Error>
where
    D: FederationDirectory + ?Sized,
{
    dir.note_edition2_roster_proposal(id, identity, now).await?;
    dir.settle_edition2_roster_proposal(id, landed_outcome(path), now)
        .await
}

/// The heads an edition-2 proposal names (`refs.head`, then
/// `refs.further_heads` in order); `None` for the earlier form's.
fn head_of(c: &Carried) -> Option<Vec<super::edition2::names::RowId>> {
    match c {
        Carried::Edition2Occurrence {
            head,
            further_heads,
            ..
        }
        | Carried::Edition2Eviction {
            head,
            further_heads,
            ..
        } => {
            let mut v = vec![*head];
            v.extend(further_heads.iter().copied());
            Some(v)
        }
        Carried::Occurrence(_) | Carried::Withdraws { .. } => None,
    }
}

/// How many roster rows [`roster_at_heads`] loads for one reading.
const MAX_ROSTER_CHAIN: usize = 4096;

/// One landed roster row of a self, as the fold reads it.
#[derive(Clone, Debug)]
enum RosterStep {
    /// The genesis key's own `key:record` row: the root.
    Root,
    /// A landed bind adding this key.
    Add(String),
    /// A landed eviction of this key (or a VOID sibling's, which a merge
    /// names: an eviction on any merged branch stands); `effective` is false
    /// for the genesis key's own revocation of its pair (it evicts nothing).
    Evict(String, bool),
    /// A VOID sibling's addition: read for its parents only.
    Void,
}

/// v62.0.0 (wave O1; CC 2.7.8) — the settled outcome of a roster row that
/// is VOID for this reader: a sibling of a head this node has acknowledged
/// a successor of, or a row whose heads do not reach every tip this node
/// has acknowledged. Kept (its statements are held), concluding nothing.
pub const VOID_OUTCOME: &str = "void_superseded";

/// v62.0.0 (wave O1; CC 2.7.8) — the fold reason a VOID roster row is held
/// under (G0's `fold::note`; to append to `fold::reason::ALL`).
pub const REASON_ROSTER_HEAD_SUPERSEDED: &str = "roster_head_superseded";

/// The landed roster rows a reading loaded, with the rows each names.
type RosterGraph = std::collections::BTreeMap<
    super::edition2::names::RowId,
    (RosterStep, Vec<super::edition2::names::RowId>),
>;

/// Why a roster row could not be read.
enum RosterLoad {
    /// Not held, or not landed here: the reading waits on it.
    Wait(super::edition2::names::RowId),
    /// A malformed chain.
    Bad(Error),
}

/// Load `row` as a landed roster row of `identity` (declaring the read).
async fn roster_step<D>(
    dir: &D,
    identity: &str,
    genesis: &ciris_verify_core::edition2::Digest32,
    row: &super::edition2::names::RowId,
) -> Result<Result<(RosterStep, Vec<super::edition2::names::RowId>), RosterLoad>, Error>
where
    D: FederationDirectory + ?Sized,
{
    use super::edition2::liveness::{recorded_kid, statement_parts};
    use ciris_verify_core::cde::Value;
    super::edition2::fold::reads(super::edition2::fold::Dep::Row(*row));
    let bad = |why: String| {
        RosterLoad::Bad(Error::malformed_row(
            "self_roster",
            super::malformed_row::EDITION2_PAYLOAD_INVALID,
            format!("the roster of {identity}: {why}"),
        ))
    };
    let voices = dir.edition2_voices(row).await?;
    let Some((protected, _)) = voices.first().and_then(|v| statement_parts(v)) else {
        return Ok(Err(RosterLoad::Wait(*row)));
    };
    if protected.get_int(-70002).and_then(Value::as_text)
        == Some(ciris_verify_core::edition2::keys::KEY_RECORD_FAMILY)
    {
        if recorded_kid(&voices[0]) != Some(*genesis) {
            return Ok(Err(bad(format!(
                "{} is not the genesis key's own key:record",
                row.hex()
            ))));
        }
        return Ok(Ok((RosterStep::Root, Vec::new())));
    }
    let Some(carried) = super::edition2::occurrence::carried_of_bind(dir, &row.hex()).await? else {
        // O1 fix 5 (I3644/I3645): a roster row held with only its
        // occurrence key's own voice (its author's has not arrived) is not
        // readable YET. It WAITS, like an unheld row: the fold re-runs the
        // reader when the author's voice lands it. Any other family is not a
        // roster row.
        let family = protected.get_int(-70002).and_then(Value::as_text);
        if family == Some(super::edition2::occurrence::OCCURRENCE_FAMILY)
            || family == Some(super::edition2::occurrence::OCCURRENCE_REVOCATION_FAMILY)
        {
            return Ok(Err(RosterLoad::Wait(*row)));
        }
        return Ok(Err(bad(format!("{} is not a roster row", row.hex()))));
    };
    if carried.identity_key_id() != identity {
        return Ok(Err(bad(format!("{} is another self's row", row.hex()))));
    }
    let landed = [
        landed_outcome(LandingPath::Quorum),
        landed_outcome(LandingPath::Lone),
    ];
    let receipt = dir.edition2_roster_proposal(&row.hex()).await?;
    let outcome = receipt.and_then(|r| r.outcome);
    let void = outcome.as_deref() == Some(VOID_OUTCOME);
    if !void && !outcome.as_deref().is_some_and(|o| landed.contains(&o)) {
        return Ok(Err(RosterLoad::Wait(*row)));
    }
    let target = carried.target_key_id().to_owned();
    let (step, head, further) = match &carried {
        // A VOID sibling (CC 2.7.8) a merge names: its parents are read,
        // its addition is not (it never landed here).
        Carried::Edition2Occurrence {
            head,
            further_heads,
            ..
        } if void => (RosterStep::Void, *head, further_heads.clone()),
        Carried::Edition2Occurrence {
            head,
            further_heads,
            ..
        } => (RosterStep::Add(target), *head, further_heads.clone()),
        Carried::Edition2Eviction {
            head,
            further_heads,
            proposer,
            ..
        } => {
            let effective = !(target == identity && proposer == identity);
            (
                RosterStep::Evict(target, effective),
                *head,
                further_heads.clone(),
            )
        }
        Carried::Occurrence(_) | Carried::Withdraws { .. } => {
            return Ok(Err(bad(format!("{} is not an edition-2 row", row.hex()))));
        }
    };
    let mut parents = vec![head];
    parents.extend(further);
    Ok(Ok((step, parents)))
}

/// Load every row reachable from `from` into `graph`. `Err` carries the
/// first row that waits, or a malformed chain.
async fn load_roster_graph<D>(
    dir: &D,
    identity: &str,
    genesis: &ciris_verify_core::edition2::Digest32,
    from: &[super::edition2::names::RowId],
    graph: &mut RosterGraph,
) -> Result<Result<(), RosterLoad>, Error>
where
    D: FederationDirectory + ?Sized,
{
    let mut work: Vec<super::edition2::names::RowId> = from.to_vec();
    while let Some(row) = work.pop() {
        if graph.contains_key(&row) {
            continue;
        }
        if graph.len() >= MAX_ROSTER_CHAIN {
            return Ok(Err(RosterLoad::Bad(Error::malformed_row(
                "self_roster",
                super::malformed_row::EDITION2_PAYLOAD_INVALID,
                format!("the roster of {identity} is beyond the chain bound"),
            ))));
        }
        match roster_step(dir, identity, genesis, &row).await? {
            Ok((step, parents)) => {
                work.extend(parents.iter().copied());
                graph.insert(row, (step, parents));
            }
            Err(e) => return Ok(Err(e)),
        }
    }
    Ok(Ok(()))
}

/// Every row `row` reaches through the rows it names (itself included).
fn ancestors(
    graph: &RosterGraph,
    row: &super::edition2::names::RowId,
) -> BTreeSet<super::edition2::names::RowId> {
    let mut seen = BTreeSet::new();
    let mut work = vec![*row];
    while let Some(r) = work.pop() {
        if !seen.insert(r) {
            continue;
        }
        if let Some((_, parents)) = graph.get(&r) {
            work.extend(parents.iter().copied());
        }
    }
    seen
}

/// v62.0.0 (wave O1; CC 3.3.6.4, the CC 2.7 ruling, CC rc21's
/// `refs.further_heads`) — **the self's roster at the heads a row names**
/// (`refs.head` and every `refs.further_heads`), read from content (the same
/// on every node that holds the rows), order-independent:
///
/// - every landed roster row reachable from the named heads (by `refs.head`
///   and `refs.further_heads`) back to the genesis key's own `key:record`
///   row, the root; each a LANDED (this node's receipt settled `lands_*`)
///   `identity:occurrence` bind or `identity:occurrence_revocation` of the
///   self;
/// - a `user`-role key is a member when some bind of it is reachable that
///   EVERY reachable eviction of it is an ancestor of. So an eviction on any
///   merged branch stands (a VOID sibling's too, CC 2.7.8: its addition is
///   not read): merging never revives an evicted key, and a re-bind made
///   after the eviction restores it;
/// - the genesis key is a member unless an eviction of it by another key is
///   reachable or held (never re-established);
/// - a member whose occurrence has ended by now (the half-open window) is
///   not counted (as [`roster_now`]).
///
/// Every row read is declared to the fold (`fold::reads`), with the self
/// (`Dep::Key`), so a waiting reading re-folds when what it waits on lands.
///
/// # Errors
/// The retryable unknown signer naming `row:<hex>` while a named or
/// reachable row is not held or has not landed here (the row naming it
/// waits); `edition2_payload_invalid` for a malformed chain; directory
/// failures.
pub async fn roster_at_heads<D>(
    dir: &D,
    identity: &str,
    heads: &[super::edition2::names::RowId],
) -> Result<BTreeSet<String>, Error>
where
    D: FederationDirectory + ?Sized,
{
    Ok(roster_reading(dir, identity, heads).await?.0)
}

/// [`roster_at_heads`], with every roster row the named heads reach.
async fn roster_reading<D>(
    dir: &D,
    identity: &str,
    heads: &[super::edition2::names::RowId],
) -> Result<(BTreeSet<String>, BTreeSet<super::edition2::names::RowId>), Error>
where
    D: FederationDirectory + ?Sized,
{
    super::edition2::fold::reads(super::edition2::fold::Dep::key(identity));
    let genesis = super::edition2::ingest::kid_of_identity_ref(identity).ok_or_else(|| {
        Error::malformed_row(
            "self_roster",
            super::malformed_row::EDITION2_PAYLOAD_INVALID,
            format!("{identity} is not an identity-ref"),
        )
    })?;
    let mut graph = RosterGraph::new();
    match load_roster_graph(dir, identity, &genesis, heads, &mut graph).await? {
        Ok(()) => {}
        Err(RosterLoad::Wait(r)) => {
            return Err(Error::unknown_signer(
                &format!("row:{}", r.hex()),
                "self_roster",
            ));
        }
        Err(RosterLoad::Bad(e)) => return Err(e),
    }
    let mut reach: BTreeSet<super::edition2::names::RowId> = BTreeSet::new();
    for h in heads {
        reach.extend(ancestors(&graph, h));
    }
    let evictions: Vec<(&super::edition2::names::RowId, &String, bool)> = reach
        .iter()
        .filter_map(|r| match graph.get(r) {
            Some((RosterStep::Evict(k, effective), _)) => Some((r, k, *effective)),
            _ => None,
        })
        .collect();
    let mut roster = BTreeSet::new();
    if !evictions
        .iter()
        .any(|(_, k, effective)| *effective && k.as_str() == identity)
    {
        roster.insert(identity.to_owned());
    }
    let mut adds: std::collections::BTreeMap<&String, Vec<&super::edition2::names::RowId>> =
        std::collections::BTreeMap::new();
    for r in &reach {
        if let Some((RosterStep::Add(k), _)) = graph.get(r) {
            adds.entry(k).or_default().push(r);
        }
    }
    for (k, rows) in adds {
        if k.as_str() == identity || !is_user_key(dir, k).await? {
            continue;
        }
        let member = rows.iter().any(|a| {
            let anc = ancestors(&graph, a);
            evictions
                .iter()
                .filter(|(_, ek, _)| *ek == k)
                .all(|(e, _, _)| anc.contains(*e))
        });
        if member {
            roster.insert(k.clone());
        }
    }
    // The end rule (I3043): an occurrence past its `valid_until` is not a
    // roster key.
    let ms = |t: DateTime<Utc>| u64::try_from(t.timestamp_millis()).unwrap_or(0);
    let now = ms(roster_clock());
    let mut kept = BTreeSet::new();
    for k in roster {
        if k == identity {
            kept.insert(k);
            continue;
        }
        let live = dir
            .list_identity_occurrences_by_occurrence_key(&k)
            .await?
            .iter()
            .any(|o| {
                o.identity_key_id == identity
                    && crate::kernel::key_end::within_record(
                        now,
                        ms(o.asserted_at),
                        o.valid_until.map(ms),
                    )
            });
        if live {
            kept.insert(k);
        }
    }
    Ok((kept, reach))
}

/// v62.0.0 (wave O1; CC 2.7.8) — **THE stale-head rule**, the one place it
/// lives. A roster row `row` of `identity` naming `heads` (whose readable
/// chain reaches `reach`) is VOID for this reader when:
/// - this node has ACKNOWLEDGED (a landed receipt) another roster row that
///   names one of `heads`: `row` is a sibling of a head with an
///   acknowledged successor; or
/// - some tip this node has acknowledged is not in `reach`: a merge must
///   name every acknowledged tip, and a change never counts over a head
///   whose successor is acknowledged.
///
/// A reader that has acknowledged neither reads `row` as a tip. Order-
/// independent for a reader: acknowledgements are this node's own landings,
/// never "a later row this node holds". `Some(detail)` when void.
///
/// # Errors
/// Directory read failures.
async fn void_for_reader<D>(
    dir: &D,
    identity: &str,
    row: &super::edition2::names::RowId,
    heads: &[super::edition2::names::RowId],
    reach: &BTreeSet<super::edition2::names::RowId>,
) -> Result<Option<String>, Error>
where
    D: FederationDirectory + ?Sized,
{
    let settled = dir.list_settled_edition2_roster_proposals(identity).await?;
    let landed = [
        landed_outcome(LandingPath::Quorum),
        landed_outcome(LandingPath::Lone),
    ];
    for r in settled {
        if r.proposal_id == row.hex() || !r.outcome.as_deref().is_some_and(|o| landed.contains(&o))
        {
            continue;
        }
        let Some(c) = super::edition2::occurrence::carried_of_bind(dir, &r.proposal_id).await?
        else {
            continue;
        };
        if let Some(named) = head_of(&c) {
            if let Some(h) = named.iter().find(|h| heads.contains(h)) {
                return Ok(Some(format!(
                    "{} names {}, whose successor {} this node acknowledged",
                    row.hex(),
                    h.hex(),
                    r.proposal_id
                )));
            }
        }
    }
    if let Some((tip, further)) =
        super::edition2::occurrence::current_roster_heads(dir, identity).await?
    {
        if let Some(t) = std::iter::once(tip)
            .chain(further)
            .find(|t| !reach.contains(t))
        {
            return Ok(Some(format!(
                "{} does not reach the acknowledged tip {}",
                row.hex(),
                t.hex()
            )));
        }
    }
    Ok(None)
}

/// [`roster_at_heads`] at one named head.
///
/// # Errors
/// As [`roster_at_heads`].
pub async fn roster_at_head<D>(
    dir: &D,
    identity: &str,
    head: &super::edition2::names::RowId,
) -> Result<BTreeSet<String>, Error>
where
    D: FederationDirectory + ?Sized,
{
    roster_at_heads(dir, identity, std::slice::from_ref(head)).await
}

/// v62.0.0 (wave O1; the CC 2.7 ruling) — **the head a new roster row of
/// `identity` names** (`refs.head`): this node's latest landed roster tip,
/// else the genesis key's own `key:record` row
/// ([`super::edition2::occurrence::current_roster_heads`] gives every tip,
/// for `refs.further_heads`).
///
/// # Errors
/// The retryable unknown signer naming the self when neither is held;
/// directory failures.
pub async fn current_head<D>(
    dir: &D,
    identity: &str,
) -> Result<super::edition2::names::RowId, Error>
where
    D: FederationDirectory + ?Sized,
{
    super::edition2::occurrence::current_roster_head(dir, identity)
        .await?
        .ok_or_else(|| Error::unknown_signer(identity, "self_roster"))
}

/// v62.0.0 (wave O1, S1) — this node's open edition-2 receipts. v62.0.0
/// (PX-fix3) — a directory that keeps no edition-2 store (`Unsupported`) is an
/// error, never "none open" (I2190).
async fn open_edition2_receipts<D>(
    dir: &D,
    identity: Option<&str>,
) -> Result<Vec<SelfRosterReceipt>, Error>
where
    D: FederationDirectory + ?Sized,
{
    dir.list_open_edition2_roster_proposals(identity).await
}

/// Settle a proposal in the ledger that holds it: an edition-2 bind's in
/// `ceg_roster_proposals`, every other in V199's.
async fn settle<D>(
    dir: &D,
    carried: &Carried,
    id: &str,
    outcome: &str,
    now: DateTime<Utc>,
) -> Result<(), Error>
where
    D: FederationDirectory + ?Sized,
{
    match carried {
        Carried::Edition2Occurrence { .. } | Carried::Edition2Eviction { .. } => {
            dir.settle_edition2_roster_proposal(id, outcome, now).await
        }
        Carried::Occurrence(_) | Carried::Withdraws { .. } => {
            dir.settle_self_roster_proposal(id, outcome, now).await
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  The executor
// ─────────────────────────────────────────────────────────────────────────

/// After a proposal or an answer row is admitted (the attestation door's
/// hook): execute what lands for its self. Never fails the admission that
/// called it: the row is stored; a failure to execute is logged and the sweep
/// retries.
///
/// v61.1.0 (CIRISPersist#1220) — a proposal's receipt is NOT this hook's:
/// the attestation plan carries it (`PlannedAttestation::self_roster_receipt`)
/// and the executor writes it in the row's transaction, so a failed receipt
/// fails the row and a re-offer lands both. The note here is first-seen-wins
/// and so a no-op for every row this version stores; it remains only to heal
/// a proposal an earlier version held without its receipt (an after-commit
/// write that failed), at its re-offer — the one way such a row ever had to
/// recover.
pub(crate) async fn after_admission<D>(dir: &D, row: &Attestation)
where
    D: FederationDirectory + ?Sized,
{
    // v62.0.0 (WD-fix7) — an answer executes what it may land. (The
    // earlier-form proposal row this once noted is retired: no door stores
    // one.)
    let Some(identity) = answer_identity(row).map(str::to_owned) else {
        return;
    };
    if let Err(e) = execute_for(dir, &identity).await {
        tracing::warn!(identity_key_id = %identity, error = %e, "self-roster execute");
    }
}

/// **Execute what lands** for one self: decide every open proposal, execute
/// the first that lands through its own door, re-read the roster, decide
/// again; settle a proposal whose proposer has left the roster. Returns how
/// many landed.
pub async fn execute_for<D>(dir: &D, identity: &str) -> Result<usize, Error>
where
    D: FederationDirectory + ?Sized,
{
    let policy = policy()?;
    let mut landed = 0;
    let mut tried: BTreeSet<String> = BTreeSet::new();
    loop {
        let now = roster_clock();
        let plan = plan(dir, identity, None, now, &policy).await?;
        for id in &plan.withdrawn {
            dir.settle_self_roster_proposal(id, WITHDRAWN_OUTCOME, now)
                .await?;
        }
        for id in &plan.withdrawn_e2 {
            dir.settle_edition2_roster_proposal(id, WITHDRAWN_OUTCOME, now)
                .await?;
        }
        for (p, _, c, d) in &plan.entries {
            if matches!(
                d,
                TwoPathDecision::Refused {
                    reason: TwoPathRefusal::ProposerNotOnRoster,
                } | TwoPathDecision::Cancelled { .. }
            ) {
                settle(dir, c, &p.id, d.token(), now).await?;
            }
        }
        let Some((p, _, carried, TwoPathDecision::Lands { path })) = plan
            .entries
            .into_iter()
            .find(|(p, .., d)| d.lands() && !tried.contains(&p.id))
        else {
            return Ok(landed);
        };
        tried.insert(p.id.clone());
        let carried_kind = carried.clone();
        let applied = match carried {
            // v62.0.0 (wave O1, S1) — an edition-2 bind lands from its held
            // statements.
            Carried::Edition2Occurrence { row_id, .. } => {
                super::edition2::occurrence::land_held_bind(dir, &row_id).await
            }
            // v62.0.0 (wave O1, S1b) — an edition-2 eviction lands from its
            // held voices.
            Carried::Edition2Eviction { row_id, .. } => {
                super::edition2::occurrence::land_held_eviction(dir, &row_id).await
            }
            Carried::Occurrence(s) => dir.put_identity_occurrence(s).await,
            // v62.0.0 (WD-fix6) — a HOLD (the withdrawal's statement kept,
            // waiting; WD-fix4) is told from a refusal structurally
            // (`attestation_admit::kept_waiting`); the next pass's re-offer is
            // a no-op on the statement id.
            Carried::Withdraws { row, .. } => {
                let put = dir
                    .put_attestation(super::SignedAttestation {
                        attestation: row.clone(),
                    })
                    .await
                    .map(|_| ());
                if put.is_err() && super::attestation_admit::kept_waiting(dir, &row).await? {
                    tracing::info!(
                        proposal_id = %p.id,
                        "a landing roster proposal's withdrawal is kept and waiting (a hold)"
                    );
                }
                put
            }
        };
        match applied {
            Ok(()) => {
                settle(dir, &carried_kind, &p.id, landed_outcome(path), now).await?;
                landed += 1;
            }
            Err(e) => {
                tracing::warn!(proposal_id = %p.id, error = %e, "a landing roster proposal did not apply");
            }
        }
    }
}

/// **The sweep**: [`execute_for`] every self with an open proposal on this
/// node — what lands by the lone path lands here, when its window closes.
/// Returns how many landed.
pub async fn execute_due<D>(dir: &D) -> Result<usize, Error>
where
    D: FederationDirectory + ?Sized,
{
    let mut selves: BTreeSet<String> = dir
        .list_open_self_roster_proposals(None)
        .await?
        .into_iter()
        .map(|r| r.identity_key_id)
        .collect();
    // v62.0.0 (wave O1, S1) — the selves with an open edition-2 proposal.
    selves.extend(
        open_edition2_receipts(dir, None)
            .await?
            .into_iter()
            .map(|r| r.identity_key_id),
    );
    let mut landed = 0;
    for identity in selves {
        landed += execute_for(dir, &identity).await?;
    }
    Ok(landed)
}

// ─────────────────────────────────────────────────────────────────────────
//  The roster key's id (staged)
// ─────────────────────────────────────────────────────────────────────────

/// The device-derived roster key id prefix CC 3.3.6.3 refuses
/// (`device-<hex>-<fp>`, `CLM-self-roster-key-id`). **STAGED**: the refusal
/// lands when CIRISServer ships the `<fedID>-<own fingerprint>` form
/// (CIRISServer#793); until then this door accepts it, and
/// [`is_device_derived_roster_key_id`] only names it.
pub const DEVICE_DERIVED_ROSTER_KEY_PREFIX: &str = "device-";

/// Is `key_id` the device-derived spelling CC 3.3.6.3 will refuse? Staged:
/// nothing refuses on it yet.
#[must_use]
pub fn is_device_derived_roster_key_id(key_id: &str) -> bool {
    key_id.starts_with(DEVICE_DERIVED_ROSTER_KEY_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// STAGED (`CLM-self-roster-key-id`, CIRISServer#793): the device-derived
    /// id is named, and NOT refused, in this cut. When Server ships the
    /// `<fedID>-<fp>` form the refusal lands and this test flips.
    #[test]
    fn device_derived_roster_key_id_is_named_not_refused_staged() {
        assert!(is_device_derived_roster_key_id(
            "device-8bd181c931ba-abcdefghij"
        ));
        assert!(!is_device_derived_roster_key_id(
            "alice-person-user-abcdefghij-klmnopqrst"
        ));
    }

    /// The answer envelope a producer signs names the self and the proposal,
    /// and reads back through [`answer_identity`].
    #[test]
    fn vote_envelope_round_trips() {
        let e = vote_envelope("alice", "p-1", true);
        assert_eq!(e["dimension"], DIMENSION_ASSENT);
        assert_eq!(e[field::COHORT], COHORT_SELF);
        assert_eq!(e[field::OBJECTS_TO], "p-1");
        let o = vote_envelope("alice", "p-1", false);
        assert_eq!(o["dimension"], "objection:raised:v1");
        assert_eq!(o["score"], -1);
    }
}
