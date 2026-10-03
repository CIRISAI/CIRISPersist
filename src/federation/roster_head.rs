//! v53.0.0 (CC 3.2 T6, rc7 `36432c6`) — **roster rows and the head.**
//!
//! A witnessed lineage (a conferring family — one whose head names a charter
//! —, the accord family, and every trust-root-grade `infrastructure`
//! community) changes its roster on two surfaces: the record, whose versions
//! are the lineage head, and the roster planes (widenings, revocations,
//! resignations, serve-node joins), whose rows take effect at their own
//! `effective_at`. CC 3.2 T6 makes covering a roster row with a new version
//! the conferring quorum's duty, and the substrate never synthesises one. The
//! substrate enforces exactly three consequences:
//!
//! - **(i)** a version whose roster disagrees with the fold of the roster
//!   rows effective up to it is refused
//!   ([`Error::LineageVersionDisagreesWithFold`], `kind()`
//!   `federation_lineage_version_disagrees_with_roster_fold`);
//! - **(ii)** a roster row older than one `witness_cadence_secs` that no
//!   version covers marks the head **lagging** ([`RosterLag`], token
//!   [`LINEAGE_HEAD_LAGS_ROSTER`]); witnesses do not cosign a lagging head, so
//!   attaching on it goes stale through the T4a freshness gate. With witnessed
//!   mode off the lag is reported and nothing else changes;
//! - **(iii)** the row itself takes effect at its `effective_at`: the fold is
//!   the authority on who holds a seat, and a removal never waits on a
//!   ceremony. Nothing here gates the planes.
//!
//! Both questions are one comparison, [`fold_disagreement`]: apply the roster
//! planes to a record by the ONE authorized fold every roster gate reads
//! ([`authorized_family_roster_at`](super::authorized_family_roster_at) /
//! [`authorized_community_roster_at`](super::authorized_community_roster_at))
//! and name every key whose seat or role the fold moves. A row the record
//! already reflects moves nothing; a row it does not reflect moves its key.

use super::types::{Community, Family};
use super::{Error, FederationDirectory};

/// The wire token of a lagging head (CC 3.2 T6 names it).
pub const LINEAGE_HEAD_LAGS_ROSTER: &str = "lineage_head_lags_roster";

/// The `kind()` of a version refused under consequence (i).
pub const LINEAGE_VERSION_DISAGREES_WITH_FOLD: &str =
    "federation_lineage_version_disagrees_with_roster_fold";

/// One version of a lineage's record, either kind.
#[derive(Debug, Clone, Copy)]
pub enum LineageRecord<'a> {
    /// A family record (a conferring family, or the accord).
    Family(&'a Family),
    /// A community record (a trust-root-grade community).
    Community(&'a Community),
}

impl LineageRecord<'_> {
    /// The lineage id.
    #[must_use]
    pub fn key_id(&self) -> &str {
        match self {
            Self::Family(f) => &f.family_key_id,
            Self::Community(c) => &c.community_key_id,
        }
    }

    /// Is this record a witnessed lineage's (CC 3.2 T6)? A family is when it is
    /// the accord or its head names a charter (a conferring family — R2a's
    /// "a charter no version names is not in force", so an unnamed head confers
    /// nothing and is no lineage). A community is when it is trust-root grade
    /// (the reserved id, or an `infrastructure_constraint`).
    #[must_use]
    pub fn is_witnessed(&self) -> bool {
        match self {
            Self::Family(f) => {
                f.family_key_id == super::canonical_community::accord_family_key_id()
                    || !f.charter_digest.is_empty()
            }
            Self::Community(c) => super::canonical_community::is_trust_root_grade(c),
        }
    }

    /// `(key_id, role)` of every seat the record itself lists.
    fn seats(&self) -> std::collections::BTreeMap<String, String> {
        match self {
            Self::Family(f) => f
                .members
                .iter()
                .map(|m| (m.key_id.clone(), role_of(m.role.as_deref())))
                .collect(),
            Self::Community(c) => c
                .members
                .iter()
                .map(|m| (m.key_id.clone(), role_of(m.role.as_deref())))
                .collect(),
        }
    }
}

/// A role as the comparison reads it: an absent role is a `member` seat (the
/// fold and the record spell the default differently, never meaningfully).
fn role_of(role: Option<&str>) -> String {
    role.unwrap_or("member").to_owned()
}

/// **The ONE comparison.** The keys whose seat (present or not) or role the
/// roster planes move when folded over `record`'s members, sorted. Empty when
/// the record reflects every roster row it answers for.
///
/// The rows folded are those effective at or before `as_of` and, when `since`
/// is given, strictly after it: the rows the record answers for. A row the
/// record already reflects (a widening of a seated key, a revocation of an
/// absent one) moves nothing; a row the fold does not apply (no standing under
/// the record's protocol, or reversed) moves nothing either. A key the record
/// changed with no plane row about it is the record's own act and is not
/// judged here. The fold is the ONE authorized replay every roster gate reads
/// ([`authorized_roster_at`](super::authorized_roster_at)), over the same
/// stored events ([`community_roster_events`](super::community_roster_events),
/// [`family_roster_events`](super::family_roster_events)).
///
/// # Errors
///
/// Directory read failures.
pub async fn fold_disagreement<F>(
    directory: &F,
    record: LineageRecord<'_>,
    since: Option<chrono::DateTime<chrono::Utc>>,
    as_of: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    fold_disagreement_by(
        directory,
        record,
        &|e: &super::RosterEvent| since.is_none_or(|floor| e.effective_at > floor),
        as_of,
    )
    .await
}

/// [`fold_disagreement`] over the rows `answered` keeps: the one comparison
/// every caller shares, whichever rows it holds a version to.
async fn fold_disagreement_by<F>(
    directory: &F,
    record: LineageRecord<'_>,
    answered: &(dyn Fn(&super::RosterEvent) -> bool + Sync),
    as_of: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let folded: std::collections::BTreeMap<String, String> = match record {
        LineageRecord::Family(f) => {
            let mut events = Box::pin(super::family_roster_events(directory, f)).await?;
            events.retain(|e| answered(e));
            let members: Vec<super::types::CommunityMember> = f
                .members
                .iter()
                .map(super::family_member_as_roster_member)
                .collect();
            super::authorized_roster_at(&members, super::RosterRules::of_family(f), &events, as_of)
                .into_iter()
                .map(|m| (m.key_id, role_of(m.role.as_deref())))
                .collect()
        }
        LineageRecord::Community(c) => {
            let nodes = Box::pin(super::community_node_bearing_seats(directory, c)).await?;
            let mut events = Box::pin(super::community_roster_events(directory, c, &nodes)).await?;
            events.retain(|e| answered(e));
            super::authorized_roster_at(
                &c.members,
                super::RosterRules::of_community(c, &nodes),
                &events,
                as_of,
            )
            .into_iter()
            .map(|m| (m.key_id, role_of(m.role.as_deref())))
            .collect()
        }
    };
    let listed = record.seats();
    let mut moved: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for (key, role) in &listed {
        if folded.get(key) != Some(role) {
            moved.insert(key.clone());
        }
    }
    for key in folded.keys() {
        if !listed.contains_key(key) {
            moved.insert(key.clone());
        }
    }
    Ok(moved.into_iter().collect())
}

/// The instant after which the rows of `lineage_key_id` are the next
/// version's to answer for: the HELD head's signer-stamped instant on the
/// community arm (a trust-root link's `amended_at`, a birth's `founded_at`).
/// Rows effective before it were the held head's to answer — and the
/// trust-root design lets a later founders' amendment re-seat or re-role a key
/// a plane row once moved (`check_trust_root_roster_change`), so re-judging an
/// old row over a newer record would refuse what the chain admits. A family
/// version carries no signed instant: the family arm answers for every row,
/// which is CC 3.2 T6's own reading (the fold is the authority on who holds a
/// seat) — a conferring family moves a seat on the planes, then versions.
async fn held_floor<F>(
    directory: &F,
    record: LineageRecord<'_>,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(match record {
        LineageRecord::Family(_) => None,
        LineageRecord::Community(c) => {
            super::canonical_community::lookup_signed_community(directory, &c.community_key_id)
                .await?
                .map(|held| super::canonical_community::head_instant(&held))
        }
    })
}

/// When THIS node admitted each roster-plane row of a lineage, keyed by what
/// the fold's events carry: `(is_add, member key, effective_at)`. The
/// signer-chosen `effective_at` says when a row takes effect; it is no axis for
/// which version answers for the row or when its lag is due — a row signed
/// with an instant before the held head, admitted after it, is still a row the
/// head has not covered.
type Admissions = std::collections::BTreeMap<
    (bool, String, chrono::DateTime<chrono::Utc>),
    chrono::DateTime<chrono::Utc>,
>;

async fn admissions<F>(directory: &F, record: LineageRecord<'_>) -> Result<Admissions, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut out = Admissions::new();
    let mut note = |add: bool, key: &str, eff, at| {
        let slot = out.entry((add, key.to_owned(), eff)).or_insert(at);
        if at > *slot {
            *slot = at;
        }
    };
    match record {
        LineageRecord::Family(f) => {
            let id = &f.family_key_id;
            for s in directory
                .list_signed_family_membership_widenings_since(None, u32::MAX)
                .await?
            {
                let w = &s.widening.family_membership_widening;
                if &w.family_key_id == id {
                    note(true, &w.member_key_id, w.effective_at, s.admitted_at);
                }
            }
            for s in directory
                .list_signed_family_membership_revocations_since(None, u32::MAX)
                .await?
            {
                let r = &s.revocation.family_membership_revocation;
                if &r.family_key_id == id {
                    note(
                        false,
                        &r.removed_identity_key_id,
                        r.effective_at,
                        s.admitted_at,
                    );
                }
            }
        }
        LineageRecord::Community(c) => {
            let id = &c.community_key_id;
            for s in directory
                .list_signed_community_membership_widenings_since(None, u32::MAX)
                .await?
            {
                let w = &s.widening.community_membership_widening;
                if &w.community_key_id == id {
                    note(true, &w.member_key_id, w.effective_at, s.admitted_at);
                }
            }
            for s in directory
                .list_signed_community_membership_revocations_since(None, u32::MAX)
                .await?
            {
                let r = &s.revocation.community_membership_revocation;
                if &r.community_key_id == id {
                    note(
                        false,
                        &r.removed_identity_key_id,
                        r.effective_at,
                        s.admitted_at,
                    );
                }
            }
        }
    }
    Ok(out)
}

/// When this node admitted the row behind `e` (its own `effective_at` when no
/// served row matches — a row this node did not admit through a door).
fn admitted_at(index: &Admissions, e: &super::RosterEvent) -> chrono::DateTime<chrono::Utc> {
    index
        .get(&(e.is_add, e.member.key_id.clone(), e.effective_at))
        .copied()
        .unwrap_or(e.effective_at)
}

/// The rows a version succeeding a head of instant `floor` answers for: those
/// that take effect after it, AND those this node admitted after it (a late or
/// backdated row the held head could not have covered). No floor (the family
/// arm): every row.
fn answered_after(
    floor: Option<chrono::DateTime<chrono::Utc>>,
    index: &Admissions,
    e: &super::RosterEvent,
) -> bool {
    floor.is_none_or(|f| e.effective_at > f || admitted_at(index, e) > f)
}

/// **Consequence (i).** Refuse a new version of a witnessed lineage whose
/// roster disagrees with the fold of the roster rows effective at `as_of`.
/// Run at every door that stores a version over a held one (the local and
/// replicated family and community supersede doors and the trust-root chain
/// apply), before the write. A record that is not a witnessed lineage, and a
/// dissolved family (it has no roster), pass.
///
/// `as_of` is the version's own signer-stamped instant where the record
/// carries one (a trust-root link's `amended_at`); a family version carries
/// none, so its door judges at admission. The rows judged are those after the
/// held head's instant on the community arm, every row on the family arm
/// (`held_floor`).
///
/// # Errors
///
/// [`Error::LineageVersionDisagreesWithFold`] naming the keys; directory read
/// failures.
pub async fn check_version_covers_fold<F>(
    directory: &F,
    record: LineageRecord<'_>,
    as_of: chrono::DateTime<chrono::Utc>,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    if !record.is_witnessed() {
        return Ok(());
    }
    if let LineageRecord::Family(f) = record {
        if f.dissolved_at.is_some() {
            return Ok(());
        }
    }
    let since = held_floor(directory, record).await?;
    check_version_covers_fold_since(directory, record, since, as_of).await
}

/// [`check_version_covers_fold`] with the floor given: the instant of the
/// version the judged one succeeds. The trust-root chain apply passes the
/// final head's predecessor IN THE OFFERED CHAIN — an intermediate version of
/// that chain answered for the rows before it (a re-seat after a resignation),
/// even where this node never held it.
///
/// # Errors
///
/// As [`check_version_covers_fold`].
pub async fn check_version_covers_fold_since<F>(
    directory: &F,
    record: LineageRecord<'_>,
    since: Option<chrono::DateTime<chrono::Utc>>,
    as_of: chrono::DateTime<chrono::Utc>,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    if !record.is_witnessed() {
        return Ok(());
    }
    if let LineageRecord::Family(f) = record {
        if f.dissolved_at.is_some() {
            return Ok(());
        }
    }
    let index = admissions(directory, record).await?;
    let keys = fold_disagreement_by(
        directory,
        record,
        &|e: &super::RosterEvent| answered_after(since, &index, e),
        as_of,
    )
    .await?;
    if keys.is_empty() {
        return Ok(());
    }
    Err(Error::LineageVersionDisagreesWithFold {
        lineage_key_id: record.key_id().to_owned(),
        keys,
    })
}

/// **Consequence (ii)** — a witnessed lineage's head that lags its roster: the
/// keys a roster row older than one cadence moved and no version covers, and
/// the authorized accord roster-change decisions anchored on the head.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RosterLag {
    /// Always [`LINEAGE_HEAD_LAGS_ROSTER`].
    pub token: String,
    /// The head that lags (`persist_row_hash`).
    pub head_digest: String,
    /// The keys whose seat or role the uncovered rows moved, sorted.
    pub uncovered_keys: Vec<String>,
    /// The accord `roster_change` proposals (digests) whose authorized
    /// decision names this head as its `prior_family_digest`, with a window
    /// closed before the cutoff. Empty for every lineage but the accord.
    pub uncovered_decisions: Vec<String>,
    /// The earliest instant THIS node admitted an uncovered row (a decision
    /// counts at its window's close).
    pub since: chrono::DateTime<chrono::Utc>,
    /// The charter's `witness_cadence_secs` the lag was judged with (`0` when
    /// the charter declares none: an uncovered row lags from its effective
    /// instant).
    pub cadence_secs: u64,
}

/// **Consequence (ii).** The lag of `root`'s head at `at`, or `None` when the
/// root is not a witnessed lineage this node holds, or its head covers every
/// roster row older than one cadence.
///
/// The judgment is the held head against the fold at `at` over the rows it
/// answers for — those effective after its instant or admitted here after it —
/// that this node admitted at least one `witness_cadence_secs` (the charter in
/// force) before `at`. A row younger here than one cadence never lags, a row
/// the head reflects never does, and a backdated row does not escape.
///
/// # Errors
///
/// Directory read failures.
pub async fn roster_lag<F>(
    directory: &F,
    root: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<Option<RosterLag>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let community = directory.lookup_community(root).await?;
    let family = match &community {
        Some(_) => None,
        None => directory.lookup_family(root).await?,
    };
    let record = match (&community, &family) {
        (Some(c), _) => LineageRecord::Community(c),
        (None, Some(f)) if f.dissolved_at.is_none() => LineageRecord::Family(f),
        _ => return Ok(None),
    };
    if !record.is_witnessed() {
        return Ok(None);
    }
    let cadence_secs = super::canonical_community::charter_members_for(directory, root)
        .await?
        .and_then(|c| c.witness_cadence_secs)
        .unwrap_or(0);
    let cutoff = i64::try_from(cadence_secs)
        .ok()
        .and_then(chrono::Duration::try_seconds)
        .and_then(|d| at.checked_sub_signed(d))
        .unwrap_or(chrono::DateTime::<chrono::Utc>::MIN_UTC);
    // The fold NOW over the rows the head answers for, each counted once
    // this node has held it for one cadence (timed from its admission here,
    // never from its signer-chosen instant).
    let since = held_floor(directory, record).await?;
    let index = admissions(directory, record).await?;
    let due = |e: &super::RosterEvent| {
        answered_after(since, &index, e) && admitted_at(&index, e) <= cutoff
    };
    let uncovered_keys = fold_disagreement_by(directory, record, &due, at).await?;
    let head_digest = match record {
        LineageRecord::Family(f) => f.persist_row_hash.clone(),
        LineageRecord::Community(c) => c.persist_row_hash.clone(),
    };
    let mut first: Option<chrono::DateTime<chrono::Utc>> = None;
    let mut earliest = |t: chrono::DateTime<chrono::Utc>| {
        first = Some(first.map_or(t, |s| s.min(t)));
    };
    for ((add, key, eff), admitted) in &index {
        let row = super::RosterEvent {
            effective_at: *eff,
            is_add: *add,
            member: super::types::CommunityMember {
                key_id: key.clone(),
                joined_at: *eff,
                role: None,
            },
            signers: Default::default(),
            moderator_roots: Default::default(),
            reversed: false,
        };
        if uncovered_keys.contains(key) && due(&row) {
            earliest(*admitted);
        }
    }
    let mut uncovered_decisions = Vec::new();
    if root == super::canonical_community::accord_family_key_id() {
        for (digest, closes) in uncovered_accord_decisions(directory, &head_digest, cutoff).await? {
            uncovered_decisions.push(digest);
            earliest(closes);
        }
    }
    if uncovered_keys.is_empty() && uncovered_decisions.is_empty() {
        return Ok(None);
    }
    Ok(Some(RosterLag {
        token: LINEAGE_HEAD_LAGS_ROSTER.to_owned(),
        head_digest,
        uncovered_keys,
        uncovered_decisions,
        since: first.unwrap_or(cutoff),
        cadence_secs,
    }))
}

/// The accord `roster_change` proposals anchored on `head_digest` (CC 3.2 T6:
/// "the `prior_family_digest` an `accord_proposal` names is the digest of its
/// current head") whose stored decision is authorized and whose window closed
/// at or before `cutoff`, with the window's close. A roster change is carried
/// as a family supersede (verify-core `AccordAction::RosterChange`), so a head
/// that still IS the proposal's anchor has not been covered by it.
async fn uncovered_accord_decisions<F>(
    directory: &F,
    head_digest: &str,
    cutoff: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<(String, chrono::DateTime<chrono::Utc>)>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let action = ciris_verify_core::accord_live_quorum::AccordAction::RosterChange.as_str();
    let proposals = match directory
        .list_accord_proposals_by_anchor(action, head_digest)
        .await
    {
        Ok(p) => p,
        Err(Error::Unsupported { .. }) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for p in proposals {
        let Ok(closes) = chrono::DateTime::parse_from_rfc3339(&p.proposal.window_until)
            .map(|t| t.with_timezone(&chrono::Utc))
        else {
            continue;
        };
        if closes > cutoff {
            continue;
        }
        let digest = p.proposal.digest();
        let authorized = match directory.get_accord_decision(&digest).await {
            Ok(d) => d.is_some_and(|d| d.decision.authorized),
            Err(Error::Unsupported { .. }) => false,
            Err(e) => return Err(e),
        };
        if authorized {
            out.push((digest, closes));
        }
    }
    out.sort();
    Ok(out)
}
