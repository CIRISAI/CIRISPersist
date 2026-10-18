//! v59.0.0 (CIRISPersist#1099; CC 3.3.6.3, CIRISConstitution#178;
//! `CLM-self-roster-two-paths`) — **the two-path decision**: one actor's
//! proposal, a window, and the standing set deciding whether it stands.
//!
//! A proposal **lands** by either path (CC 3.3.6.3, `formal/self_roster`
//! `SelfRoster.tla` `Lands(p)` in its `combined` mode):
//!
//! | path | lands when |
//! |---|---|
//! | quorum | a strict majority of the live roster approves, proposer counted — at once |
//! | lone | the window has elapsed on THIS node's clock, no strict majority of the *other* members objects, and (where the door asks it) the target was silent all window |
//!
//! ```text
//! QuorumLands(p) == Majority(LiveVotes(p.approvers) \cup {p.by}, |member|)
//! LoneLands(p)   == p.age >= Window
//!                /\ ~Majority(LiveVotes(p.objectors), |member \ {p.by}|)
//!                /\ (p.kind = "add" \/ ~p.spoke)
//! ```
//!
//! `member` is the live roster at the DECISION instant, as the model's is at
//! `Execute`: `combined4_mixed` lands its second eviction by two votes of a
//! roster the first eviction shrank to three, which a roster frozen at the
//! proposal's instant (four) would refuse. A vote from a key no longer on that
//! roster is void (`LiveVotes`). Every threshold is
//! [`strict_majority`](ciris_verify_core::accord_genesis::strict_majority);
//! nothing here spells a number.
//!
//! **Pure and backend-free.** [`decide`] and [`decide_all`] read no clock, no
//! directory and no row: a door gathers the inputs (the roster fold, the
//! held votes, the target's acts, the node's clock read once) and executes
//! what the decision says. The self-roster door
//! ([`super::self_roster`]) is its first consumer; the fold survey of its
//! relatives is in the v59.0.0 CHANGELOG.
//!
//! **The window runs on the node's clock.** A proposal's age is
//! `now - received_at`, where `received_at` is the instant THIS node first
//! held it — never the signer's `asserted_at`, which the proposer chooses: a
//! backdated proposal would otherwise have closed its own window on arrival
//! (the purge-dwell precedent, [`super::steward_purge::purge_clock`]). The
//! target's silence is read from its acts' signed instants: the target is the
//! party the rule protects, and it can only move its own acts.
//!
//! **One open proposal per proposer, never a global cap.** A global cap let
//! the model's thief fill every slot so the owner could never propose
//! (`formal/self_roster` README, finding 5). [`decide_all`] orders a self's
//! proposals by `(asserted_at, id)` — a proposer orders only its own — and
//! refuses a proposer's second while its first is open.

use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use ciris_verify_core::accord_genesis::strict_majority;

/// What a proposal does to the roster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalKind {
    /// Admit `target` to the roster.
    Add,
    /// Remove `target` from the roster.
    Evict,
}

impl ProposalKind {
    /// The stable token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Evict => "evict",
        }
    }
}

/// Which proposals the lone path asks the target's silence of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SilenceRule {
    /// An eviction lands by the lone path only if the target signed nothing
    /// since the proposal arrived (CC 3.3.6.3: "for an eviction the target was
    /// silent all window"). An addition's target is not on the roster.
    EvictOnly,
    /// No silence condition.
    Never,
}

/// A door's conditions on the two paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TwoPathPolicy {
    /// The lone path's window, on the node's clock.
    pub window: Duration,
    /// The target-silence condition.
    pub silence: SilenceRule,
    /// A proposer holds at most one open proposal.
    pub one_open_per_proposer: bool,
    /// At most one open proposal of a kind names a target (the model's
    /// `~\E p \in pending : p.kind = kind /\ p.target = target`).
    pub one_open_per_target: bool,
}

/// One proposal, as a door read it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Proposal {
    /// The proposal's id (its row's `attestation_id`).
    pub id: String,
    /// Add or evict.
    pub kind: ProposalKind,
    /// The roster key that signed it.
    pub proposer: String,
    /// The key it adds or evicts.
    pub target: String,
    /// The proposer's signed instant (orders a proposer's own proposals; never
    /// the window).
    pub asserted_at: DateTime<Utc>,
    /// When THIS node first held it (the window's start).
    pub received_at: DateTime<Utc>,
}

/// The answers a proposal has, as held rows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Answers {
    /// The keys whose assent rows on the proposal are held.
    pub approvers: BTreeSet<String>,
    /// The keys whose objection rows on the proposal are held. A key that both
    /// assented and objected counts as an objector only.
    pub objectors: BTreeSet<String>,
    /// The signed instants of the target's acts (any row it signed).
    pub target_acts: Vec<DateTime<Utc>>,
}

/// Which path landed a proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LandingPath {
    /// A strict majority of the live roster approved, proposer counted.
    Quorum,
    /// The window elapsed with no strict majority of the others objecting.
    Lone,
}

/// Why a proposal cannot land as it stands. Stable snake_case tokens
/// ([`Self::as_str`]); APPEND-ONLY.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TwoPathRefusal {
    /// The proposer is not a live roster key at the decision instant (never
    /// was, or was evicted: its proposals go with it).
    ProposerNotOnRoster,
    /// An addition names a key already on the roster.
    TargetAlreadyOnRoster,
    /// An eviction names a key not on the roster.
    TargetNotOnRoster,
    /// An eviction names its own proposer.
    ProposerIsTarget,
    /// The proposer already holds an earlier open proposal.
    ProposerHasOpenProposal,
    /// An earlier open proposal of the same kind names the same target.
    TargetHasOpenProposal,
}

impl TwoPathRefusal {
    /// Every refusal, in declaration order.
    pub const ALL: [Self; 6] = [
        Self::ProposerNotOnRoster,
        Self::TargetAlreadyOnRoster,
        Self::TargetNotOnRoster,
        Self::ProposerIsTarget,
        Self::ProposerHasOpenProposal,
        Self::TargetHasOpenProposal,
    ];

    /// The stable program token, identical to the serde spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProposerNotOnRoster => "proposer_not_on_roster",
            Self::TargetAlreadyOnRoster => "target_already_on_roster",
            Self::TargetNotOnRoster => "target_not_on_roster",
            Self::ProposerIsTarget => "proposer_is_target",
            Self::ProposerHasOpenProposal => "proposer_has_open_proposal",
            Self::TargetHasOpenProposal => "target_has_open_proposal",
        }
    }
}

/// The decision on one proposal at one instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum TwoPathDecision {
    /// It lands now, by `path`.
    Lands {
        /// The path.
        path: LandingPath,
    },
    /// It stands open.
    Pending {
        /// When the lone path opens on this node's clock; `None` when it is
        /// closed (a strict majority of the others objects, or the target of
        /// an eviction has spoken) and only the quorum path remains.
        earliest_lone_at: Option<DateTime<Utc>>,
        /// Approvals the quorum path still needs.
        needs: usize,
    },
    /// It cannot land as it stands.
    Refused {
        /// Why.
        reason: TwoPathRefusal,
    },
}

impl TwoPathDecision {
    /// The stable token: `lands`, `pending`, or the refusal's.
    #[must_use]
    pub const fn token(&self) -> &'static str {
        match self {
            Self::Lands { .. } => "lands",
            Self::Pending { .. } => "pending",
            Self::Refused { reason } => reason.as_str(),
        }
    }

    /// Does it land?
    #[must_use]
    pub const fn lands(&self) -> bool {
        matches!(self, Self::Lands { .. })
    }
}

/// The open proposals ahead of this one, as [`decide_all`] computed them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OpenAhead {
    /// The proposer holds an earlier open proposal.
    pub by_proposer: bool,
    /// An earlier open proposal of the same kind names the same target.
    pub on_target: bool,
}

/// **THE two-path decision** for one proposal at `now` over the live
/// `roster`. Pure. See the module doc for the predicate.
#[must_use]
pub fn decide(
    roster: &BTreeSet<String>,
    proposal: &Proposal,
    answers: &Answers,
    ahead: OpenAhead,
    now: DateTime<Utc>,
    policy: &TwoPathPolicy,
) -> TwoPathDecision {
    let refused = |reason| TwoPathDecision::Refused { reason };
    if !roster.contains(&proposal.proposer) {
        return refused(TwoPathRefusal::ProposerNotOnRoster);
    }
    match proposal.kind {
        ProposalKind::Add if roster.contains(&proposal.target) => {
            return refused(TwoPathRefusal::TargetAlreadyOnRoster);
        }
        ProposalKind::Evict if proposal.target == proposal.proposer => {
            return refused(TwoPathRefusal::ProposerIsTarget);
        }
        ProposalKind::Evict if !roster.contains(&proposal.target) => {
            return refused(TwoPathRefusal::TargetNotOnRoster);
        }
        _ => {}
    }
    if policy.one_open_per_proposer && ahead.by_proposer {
        return refused(TwoPathRefusal::ProposerHasOpenProposal);
    }
    if policy.one_open_per_target && ahead.on_target {
        return refused(TwoPathRefusal::TargetHasOpenProposal);
    }

    // LiveVotes: a vote from a key off the roster is void; the proposer's own
    // answers are not votes (it is counted once, as the proposer).
    let live = |keys: &BTreeSet<String>| -> BTreeSet<String> {
        keys.iter()
            .filter(|k| roster.contains(*k) && **k != proposal.proposer)
            .cloned()
            .collect()
    };
    let objectors = live(&answers.objectors);
    let approvers: BTreeSet<String> = live(&answers.approvers)
        .into_iter()
        .filter(|k| !objectors.contains(k))
        .collect();

    // QuorumLands: approvers ∪ {proposer} is a strict majority of the roster.
    let quorum = strict_majority(roster.len());
    let yes = approvers.len() + 1;
    if yes >= quorum {
        return TwoPathDecision::Lands {
            path: LandingPath::Quorum,
        };
    }

    // LoneLands.
    let others = roster.len() - 1;
    let objected = objectors.len() >= strict_majority(others);
    let silence_asked = match policy.silence {
        SilenceRule::EvictOnly => proposal.kind == ProposalKind::Evict,
        SilenceRule::Never => false,
    };
    let spoke = silence_asked
        && answers
            .target_acts
            .iter()
            .any(|at| *at >= proposal.received_at);
    let opens_at = proposal.received_at + policy.window;
    let lone_open = !objected && !spoke;
    if lone_open && now >= opens_at {
        return TwoPathDecision::Lands {
            path: LandingPath::Lone,
        };
    }
    TwoPathDecision::Pending {
        earliest_lone_at: lone_open.then_some(opens_at),
        needs: quorum - yes,
    }
}

/// [`decide`] over every proposal a self holds, in `(asserted_at, id)` order:
/// a proposal that is open (pending, or landing but not yet executed) blocks
/// a later one by the same proposer and a later one of the same kind on the
/// same target. Refused proposals block nothing. Returns the decisions in the
/// sorted order, each beside its proposal.
///
/// A door executes the FIRST proposal that lands, re-reads the roster, and
/// decides again: one execution changes the roster every later decision reads
/// (the model's `Execute` drops the proposals by an evicted key and those on
/// an executed target, which the re-decision refuses as
/// [`TwoPathRefusal::ProposerNotOnRoster`] / `Target*OnRoster`).
#[must_use]
pub fn decide_all<'p>(
    roster: &BTreeSet<String>,
    proposals: &[(&'p Proposal, &'p Answers)],
    now: DateTime<Utc>,
    policy: &TwoPathPolicy,
) -> Vec<(&'p Proposal, TwoPathDecision)> {
    let mut sorted: Vec<(&Proposal, &Answers)> = proposals.to_vec();
    sorted.sort_by(|a, b| {
        (a.0.asserted_at, a.0.id.as_str()).cmp(&(b.0.asserted_at, b.0.id.as_str()))
    });
    let mut open: Vec<&Proposal> = Vec::new();
    let mut out = Vec::with_capacity(sorted.len());
    for (p, answers) in sorted {
        let ahead = OpenAhead {
            by_proposer: open.iter().any(|q| q.proposer == p.proposer),
            on_target: open
                .iter()
                .any(|q| q.kind == p.kind && q.target == p.target),
        };
        let d = decide(roster, p, answers, ahead, now, policy);
        if !matches!(d, TwoPathDecision::Refused { .. }) {
            open.push(p);
        }
        out.push((p, d));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_800_000_000 + secs, 0).expect("instant")
    }

    const W: i64 = 86_400;

    fn policy() -> TwoPathPolicy {
        TwoPathPolicy {
            window: Duration::seconds(W),
            silence: SilenceRule::EvictOnly,
            one_open_per_proposer: true,
            one_open_per_target: true,
        }
    }

    fn keys(n: usize) -> Vec<String> {
        (1..=n).map(|i| format!("d{i}")).collect()
    }

    fn roster(n: usize) -> BTreeSet<String> {
        keys(n).into_iter().collect()
    }

    fn set(ks: &[&str]) -> BTreeSet<String> {
        ks.iter().map(|k| (*k).to_owned()).collect()
    }

    fn prop(kind: ProposalKind, by: &str, target: &str, at: i64) -> Proposal {
        Proposal {
            id: format!("{}-{by}-{target}-{at}", kind.as_str()),
            kind,
            proposer: by.to_owned(),
            target: target.to_owned(),
            asserted_at: t(at),
            received_at: t(at),
        }
    }

    fn answers(approvers: &[&str], objectors: &[&str], target_acts: &[i64]) -> Answers {
        Answers {
            approvers: set(approvers),
            objectors: set(objectors),
            target_acts: target_acts.iter().map(|s| t(*s)).collect(),
        }
    }

    fn decide1(r: &BTreeSet<String>, p: &Proposal, a: &Answers, now: i64) -> TwoPathDecision {
        decide(r, p, a, OpenAhead::default(), t(now), &policy())
    }

    /// The quorum path over every roster size 1..=7: with `k` approvers beside
    /// the proposer it lands iff `k + 1 >= strict_majority(n)`, for both kinds,
    /// at the proposal's own instant (no window).
    #[test]
    fn quorum_path_every_roster_size() {
        for n in 1..=7 {
            let r = roster(n);
            for kind in [ProposalKind::Add, ProposalKind::Evict] {
                if kind == ProposalKind::Evict && n < 2 {
                    continue;
                }
                let target = if kind == ProposalKind::Add {
                    "spare".to_owned()
                } else {
                    format!("d{n}")
                };
                for k in 0..n.saturating_sub(1) {
                    // Approvers d2.. excluding the eviction target.
                    let approvers: Vec<String> = keys(n)
                        .into_iter()
                        .skip(1)
                        .filter(|d| *d != target)
                        .take(k)
                        .collect();
                    if approvers.len() < k {
                        continue;
                    }
                    let a = Answers {
                        approvers: approvers.iter().cloned().collect(),
                        ..Answers::default()
                    };
                    let p = prop(kind, "d1", &target, 0);
                    let d = decide1(&r, &p, &a, 0);
                    let want = k + 1 >= strict_majority(n);
                    assert_eq!(d.lands(), want, "n={n} kind={kind:?} approvers={k}: {d:?}");
                    if want {
                        assert_eq!(
                            d,
                            TwoPathDecision::Lands {
                                path: LandingPath::Quorum
                            }
                        );
                    } else {
                        assert_eq!(
                            d,
                            TwoPathDecision::Pending {
                                earliest_lone_at: Some(t(W)),
                                needs: strict_majority(n) - (k + 1),
                            },
                            "n={n} kind={kind:?} k={k}"
                        );
                    }
                }
            }
        }
    }

    /// The lone path over every roster size 2..=7 and every objector count:
    /// after the window it lands iff fewer than a strict majority of the
    /// OTHERS object; before the window it never lands alone.
    #[test]
    fn lone_path_every_roster_size_and_objection_count() {
        for n in 2..=7 {
            let r = roster(n);
            for kind in [ProposalKind::Add, ProposalKind::Evict] {
                let target = if kind == ProposalKind::Add {
                    "spare".to_owned()
                } else {
                    format!("d{n}")
                };
                // Objectors from d2.. (the eviction target included: "target
                // included", CC 3.3.6.3 — its objection, though, is also an
                // act, so the eviction case asks silence separately below).
                for m in 0..n {
                    let objectors: BTreeSet<String> = keys(n)
                        .into_iter()
                        .skip(1)
                        .filter(|d| kind == ProposalKind::Add || *d != target)
                        .take(m)
                        .collect();
                    if objectors.len() < m {
                        continue;
                    }
                    let a = Answers {
                        objectors: objectors.clone(),
                        ..Answers::default()
                    };
                    let p = prop(kind, "d1", &target, 0);
                    let quorum_alone = 1 >= strict_majority(n);
                    assert!(!quorum_alone, "n={n}: the proposer alone is no quorum");
                    let early = decide1(&r, &p, &a, W - 1);
                    assert!(!early.lands(), "n={n} m={m}: lands before its window");
                    let late = decide1(&r, &p, &a, W);
                    let blocked = m >= strict_majority(n - 1);
                    assert_eq!(
                        late.lands(),
                        !blocked,
                        "n={n} kind={kind:?} objectors={m}: {late:?}"
                    );
                    if blocked {
                        assert!(matches!(
                            late,
                            TwoPathDecision::Pending {
                                earliest_lone_at: None,
                                ..
                            }
                        ));
                    } else {
                        assert_eq!(
                            late,
                            TwoPathDecision::Lands {
                                path: LandingPath::Lone
                            }
                        );
                    }
                }
            }
        }
    }

    /// An eviction's target that signed anything since the proposal arrived
    /// closes the lone path, at every roster size; an act signed BEFORE the
    /// proposal arrived does not. An addition asks no silence.
    #[test]
    fn target_silence_closes_the_lone_path_for_evictions_only() {
        for n in 2..=7 {
            let r = roster(n);
            let target = format!("d{n}");
            let p = prop(ProposalKind::Evict, "d1", &target, 100);
            let spoke = answers(&[], &[], &[150]);
            assert_eq!(
                decide1(&r, &p, &spoke, 100 + W),
                TwoPathDecision::Pending {
                    earliest_lone_at: None,
                    needs: strict_majority(n) - 1,
                },
                "n={n}: a target that spoke is evictable only by quorum"
            );
            let before = answers(&[], &[], &[99]);
            assert!(
                decide1(&r, &p, &before, 100 + W).lands(),
                "n={n}: an act before the proposal does not answer it"
            );
            let add = prop(ProposalKind::Add, "d1", "spare", 100);
            assert!(decide1(&r, &add, &spoke, 100 + W).lands());
        }
    }

    /// One key: the addition is unilateral (the add-device approval); nothing
    /// else is.
    #[test]
    fn one_key_roster_is_the_only_unilateral_door() {
        let r = roster(1);
        let p = prop(ProposalKind::Add, "d1", "spare", 0);
        assert_eq!(
            decide1(&r, &p, &Answers::default(), 0),
            TwoPathDecision::Lands {
                path: LandingPath::Quorum
            }
        );
        for n in 2..=7 {
            let p = prop(ProposalKind::Add, "d1", "spare", 0);
            assert!(
                !decide1(&roster(n), &p, &Answers::default(), 0).lands(),
                "n={n}: one key's act is a proposal, not an effect"
            );
        }
    }

    /// The structural refusals, each with its token.
    #[test]
    fn structural_refusals_and_tokens() {
        let r = roster(3);
        let cases = [
            (
                prop(ProposalKind::Add, "stranger", "spare", 0),
                TwoPathRefusal::ProposerNotOnRoster,
            ),
            (
                prop(ProposalKind::Add, "d1", "d2", 0),
                TwoPathRefusal::TargetAlreadyOnRoster,
            ),
            (
                prop(ProposalKind::Evict, "d1", "spare", 0),
                TwoPathRefusal::TargetNotOnRoster,
            ),
            (
                prop(ProposalKind::Evict, "d1", "d1", 0),
                TwoPathRefusal::ProposerIsTarget,
            ),
        ];
        for (p, reason) in cases {
            assert_eq!(
                decide1(&r, &p, &Answers::default(), 0),
                TwoPathDecision::Refused { reason }
            );
        }
        for reason in TwoPathRefusal::ALL {
            let serde = serde_json::to_value(reason).expect("serde");
            assert_eq!(serde, serde_json::Value::String(reason.as_str().into()));
        }
    }

    /// A vote from a key off the roster is void, at every size: an evicted
    /// key's assent never makes a quorum, its objection never closes the lone
    /// path.
    #[test]
    fn a_vote_from_a_key_off_the_roster_is_void() {
        for n in 3..=7 {
            let r = roster(n);
            let p = prop(ProposalKind::Add, "d1", "spare", 0);
            let ghosts: Vec<String> = (0..n).map(|i| format!("evicted{i}")).collect();
            let a = Answers {
                approvers: ghosts.iter().cloned().collect(),
                ..Answers::default()
            };
            assert!(
                !decide1(&r, &p, &a, 0).lands(),
                "n={n}: ghosts made a quorum"
            );
            let o = Answers {
                objectors: ghosts.iter().cloned().collect(),
                ..Answers::default()
            };
            assert!(
                decide1(&r, &p, &o, W).lands(),
                "n={n}: ghosts closed the lone path"
            );
        }
    }

    /// The proposer is counted once: its own assent row is no second vote.
    #[test]
    fn the_proposer_is_counted_once() {
        let r = roster(4);
        let p = prop(ProposalKind::Add, "d1", "spare", 0);
        let a = answers(&["d1", "d2"], &[], &[]);
        // {d1, d2} is 2 of 4: no strict majority.
        assert!(!decide1(&r, &p, &a, 0).lands());
    }

    /// A key that both assented and objected is an objector only.
    #[test]
    fn an_objection_outweighs_the_same_keys_assent() {
        let r = roster(3);
        let p = prop(ProposalKind::Add, "d1", "spare", 0);
        let a = answers(&["d2"], &["d2"], &[]);
        assert!(!decide1(&r, &p, &a, 0).lands());
    }

    /// The window is THIS node's: a proposal the signer backdated by two
    /// windows is as young as its arrival.
    #[test]
    fn the_window_runs_on_the_nodes_clock_not_the_signers() {
        for n in 2..=7 {
            let r = roster(n);
            let mut p = prop(ProposalKind::Add, "d1", "spare", 1_000_000);
            p.asserted_at = t(1_000_000 - 2 * W);
            assert_eq!(
                decide1(&r, &p, &Answers::default(), 1_000_000),
                TwoPathDecision::Pending {
                    earliest_lone_at: Some(t(1_000_000 + W)),
                    needs: strict_majority(n) - 1,
                },
                "n={n}"
            );
        }
    }

    /// One open proposal per proposer, never a global cap: a proposer's second
    /// is refused while its first is open; another proposer's is not.
    #[test]
    fn one_open_proposal_per_proposer_never_a_global_cap() {
        for n in 3..=7 {
            let r = roster(n);
            let first = prop(ProposalKind::Add, "d1", "spare1", 0);
            let second = prop(ProposalKind::Add, "d1", "spare2", 10);
            let other = prop(ProposalKind::Add, "d2", "spare3", 20);
            let none = Answers::default();
            let ds = decide_all(
                &r,
                &[(&second, &none), (&other, &none), (&first, &none)],
                t(30),
                &policy(),
            );
            let by_id = |id: &str| ds.iter().find(|(p, _)| p.id == id).expect("decided").1;
            assert!(matches!(by_id(&first.id), TwoPathDecision::Pending { .. }));
            assert_eq!(
                by_id(&second.id),
                TwoPathDecision::Refused {
                    reason: TwoPathRefusal::ProposerHasOpenProposal
                },
                "n={n}"
            );
            assert!(
                matches!(by_id(&other.id), TwoPathDecision::Pending { .. }),
                "n={n}: another proposer is not capped"
            );
            // A refused first proposal blocks nothing.
            let stale = prop(ProposalKind::Add, "d1", "d2", 0);
            let ds = decide_all(&r, &[(&stale, &none), (&second, &none)], t(30), &policy());
            assert!(matches!(ds[1].1, TwoPathDecision::Pending { .. }), "n={n}");
        }
    }

    /// One open proposal of a kind per target.
    #[test]
    fn one_open_proposal_per_target() {
        let r = roster(3);
        let first = prop(ProposalKind::Evict, "d1", "d3", 0);
        let second = prop(ProposalKind::Evict, "d2", "d3", 10);
        let none = Answers::default();
        let ds = decide_all(&r, &[(&first, &none), (&second, &none)], t(30), &policy());
        assert_eq!(
            ds[1].1,
            TwoPathDecision::Refused {
                reason: TwoPathRefusal::TargetHasOpenProposal
            }
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    //  The six CC traces (`tests/fixtures/self_roster`), replayed as doors.
    // ─────────────────────────────────────────────────────────────────────

    mod trace_replay {
        use super::*;

        /// Half a window: the model's `Window = 2` ticks is `W_self`.
        const TICK: i64 = W / 2;

        fn load(name: &str) -> serde_json::Value {
            let text = match name {
                "unilateral3_stolen" => {
                    include_str!("../../tests/fixtures/self_roster/unilateral3_stolen.json")
                }
                "combined1_stolen" => {
                    include_str!("../../tests/fixtures/self_roster/combined1_stolen.json")
                }
                "combined2_stolen" => {
                    include_str!("../../tests/fixtures/self_roster/combined2_stolen.json")
                }
                "combined3_stolen" => {
                    include_str!("../../tests/fixtures/self_roster/combined3_stolen.json")
                }
                "combined3_lost" => {
                    include_str!("../../tests/fixtures/self_roster/combined3_lost.json")
                }
                "combined4_mixed" => {
                    include_str!("../../tests/fixtures/self_roster/combined4_mixed.json")
                }
                other => panic!("no trace {other}"),
            };
            serde_json::from_str(text).expect("trace json")
        }

        fn strs(v: &serde_json::Value) -> BTreeSet<String> {
            v.as_array()
                .expect("array")
                .iter()
                .map(|x| x.as_str().expect("string").to_owned())
                .collect()
        }

        /// One replayed state: the roster, the clock, and every open proposal
        /// as the door reads it.
        struct Replayed {
            step: String,
            member: BTreeSet<String>,
            now: DateTime<Utc>,
            open: Vec<(Proposal, Answers)>,
        }

        /// Walk a trace's states, keeping a node clock (`Tick` advances it by
        /// half a window) and each proposal's arrival instant; a proposal's
        /// answers are its `approvers` / `objectors`, and `spoke` is one act by
        /// the target at its arrival.
        fn replay(name: &str) -> (serde_json::Value, Vec<Replayed>) {
            let trace = load(name);
            let mut clock = 0;
            let mut arrived: std::collections::BTreeMap<(String, String, String), i64> =
                std::collections::BTreeMap::new();
            let mut out = Vec::new();
            for s in trace["states"].as_array().expect("states") {
                let step = s["step"].as_str().expect("step").to_owned();
                if step == "Tick" {
                    clock += TICK;
                }
                let mut open = Vec::new();
                for p in s["pending"].as_array().expect("pending") {
                    let kind = match p["kind"].as_str().expect("kind") {
                        "add" => ProposalKind::Add,
                        _ => ProposalKind::Evict,
                    };
                    let by = p["by"].as_str().expect("by").to_owned();
                    let target = p["target"].as_str().expect("target").to_owned();
                    let at = *arrived
                        .entry((kind.as_str().to_owned(), by.clone(), target.clone()))
                        .or_insert(clock);
                    let proposal = Proposal {
                        id: format!("{}-{by}-{target}", kind.as_str()),
                        kind,
                        proposer: by,
                        target,
                        asserted_at: t(at),
                        received_at: t(at),
                    };
                    let answers = Answers {
                        approvers: strs(&p["approvers"]),
                        objectors: strs(&p["objectors"]),
                        target_acts: if p["spoke"].as_bool().expect("spoke") {
                            vec![t(at)]
                        } else {
                            Vec::new()
                        },
                    };
                    open.push((proposal, answers));
                }
                out.push(Replayed {
                    step,
                    member: strs(&s["member"]),
                    now: t(clock),
                    open,
                });
            }
            (trace, out)
        }

        fn decisions(r: &Replayed) -> Vec<(Proposal, TwoPathDecision)> {
            let refs: Vec<(&Proposal, &Answers)> = r.open.iter().map(|(p, a)| (p, a)).collect();
            decide_all(&r.member, &refs, r.now, &policy())
                .into_iter()
                .map(|(p, d)| (p.clone(), d))
                .collect()
        }

        /// Every `Execute(kind target)` step, decided over the state BEFORE it
        /// at that state's clock, with the executed proposal's decision.
        fn executions(states: &[Replayed]) -> Vec<(String, TwoPathDecision)> {
            let mut out = Vec::new();
            for w in states.windows(2) {
                let (before, after) = (&w[0], &w[1]);
                let Some(rest) = after.step.strip_prefix("Execute(") else {
                    continue;
                };
                let rest = rest.trim_end_matches(')');
                let (kind, target) = rest.split_once(' ').expect("Execute(kind target)");
                let kind = if kind == "add" {
                    ProposalKind::Add
                } else {
                    ProposalKind::Evict
                };
                let ds = decisions(before);
                let (_, d) = ds
                    .iter()
                    .find(|(p, _)| p.kind == kind && p.target == target)
                    .unwrap_or_else(|| panic!("{}: no open proposal for it", after.step));
                out.push((after.step.clone(), *d));
            }
            out
        }

        fn assert_every_execute_lands(name: &str, paths: &[LandingPath]) {
            let (trace, states) = replay(name);
            assert_eq!(trace["kind"], "land");
            let ex = executions(&states);
            assert_eq!(ex.len(), paths.len(), "{name}: {ex:?}");
            for ((step, d), path) in ex.iter().zip(paths) {
                assert_eq!(
                    *d,
                    TwoPathDecision::Lands { path: *path },
                    "{name}: {step} must land by {path:?}"
                );
            }
        }

        #[test]
        fn combined3_stolen_every_execute_lands() {
            assert_every_execute_lands("combined3_stolen", &[LandingPath::Quorum]);
        }

        #[test]
        fn combined3_lost_every_execute_lands() {
            assert_every_execute_lands(
                "combined3_lost",
                &[LandingPath::Lone, LandingPath::Lone, LandingPath::Quorum],
            );
        }

        #[test]
        fn combined4_mixed_every_execute_lands() {
            assert_every_execute_lands(
                "combined4_mixed",
                &[LandingPath::Quorum, LandingPath::Quorum],
            );
        }

        /// The thief's lone eviction of an owner device, at age 0, is refused
        /// by the door (it does not land: one of three, no window); and once
        /// the owner's two devices answer it (the target speaks and both
        /// object) the lone path is closed for good.
        #[test]
        fn unilateral3_stolen_final_execute_is_refused() {
            let (trace, states) = replay("unilateral3_stolen");
            assert_eq!(trace["kind"], "refuse");
            let ex = executions(&states);
            assert_eq!(ex.len(), 1);
            let (step, d) = &ex[0];
            assert_eq!(step, "Execute(evict d2)");
            assert_eq!(
                *d,
                TwoPathDecision::Pending {
                    earliest_lone_at: Some(t(W)),
                    needs: 1,
                },
                "the thief's eviction must not land"
            );
            // The owner answers: d2 objects (and so speaks), d3 objects.
            let before = &states[states.len() - 2];
            let (p, _) = &before.open[0];
            let answered = Answers {
                approvers: BTreeSet::new(),
                objectors: set(&["d2", "d3"]),
                target_acts: vec![p.received_at],
            };
            for now in [0, W, 10 * W] {
                assert_eq!(
                    decide(
                        &before.member,
                        p,
                        &answered,
                        OpenAhead::default(),
                        t(now),
                        &policy()
                    ),
                    TwoPathDecision::Pending {
                        earliest_lone_at: None,
                        needs: 1,
                    }
                );
            }
        }

        /// BOUND (CC 3.3.6.3): one key, stolen, is the loss of the self. The
        /// door cannot tell the thief from the owner at one key: the sole
        /// key's addition lands at once, which is the trace's stated outcome
        /// (`Inv_SelfSurvives` violated, nothing on the wire recovers it).
        #[test]
        fn combined1_stolen_is_the_one_key_bound() {
            let (trace, states) = replay("combined1_stolen");
            assert_eq!(trace["kind"], "bound");
            assert_eq!(trace["tlc"], "Invariant Inv_SelfSurvives is violated");
            let last = states.last().expect("states");
            assert_eq!(last.member, set(&["d1"]));
            let p = prop(ProposalKind::Add, "d1", "d2", 0);
            assert_eq!(
                decide(
                    &last.member,
                    &p,
                    &Answers::default(),
                    OpenAhead::default(),
                    last.now,
                    &policy()
                ),
                TwoPathDecision::Lands {
                    path: LandingPath::Quorum
                },
                "at one key the add is unilateral, whoever holds the key"
            );
        }

        /// BOUND (CC 3.3.6.3): two keys, one stolen, is a stalemate. The
        /// thief's eviction of the owner's device lands in no state; at the
        /// trace's last state (the stutter) both proposals stand open with the
        /// lone path closed, and nothing the door does resolves it.
        #[test]
        fn combined2_stolen_is_the_two_key_stalemate() {
            let (trace, states) = replay("combined2_stolen");
            assert_eq!(trace["kind"], "bound");
            assert_eq!(trace["tlc"], "Temporal properties were violated");
            assert_eq!(trace["lasso_back_to_state"], "stutter");
            for s in &states {
                for (p, d) in decisions(s) {
                    if p.kind == ProposalKind::Evict && p.proposer == "d1" {
                        assert!(!d.lands(), "{}: the thief's eviction landed", s.step);
                    }
                }
            }
            let last = states.last().expect("states");
            let ds = decisions(last);
            assert_eq!(ds.len(), 2);
            for (p, d) in &ds {
                assert_eq!(
                    *d,
                    TwoPathDecision::Pending {
                        earliest_lone_at: None,
                        needs: 1,
                    },
                    "{} {}: the stalemate",
                    p.kind.as_str(),
                    p.target
                );
            }
            // And it stays one: later instants change nothing.
            for (p, a) in &last.open {
                let d = decide(
                    &last.member,
                    p,
                    a,
                    OpenAhead::default(),
                    last.now + Duration::seconds(100 * W),
                    &policy(),
                );
                assert!(!d.lands());
            }
        }
    }
}
