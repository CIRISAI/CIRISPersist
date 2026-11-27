//! v62.0.0 (LINEAGE-L3, rewritten as LINEAGE-L3.rev2 on Kernel's
//! correction, P/KERNEL-lineage-encoding.md; CC 2.7.8, CC 3.3.4) — **a
//! group's roster lineage as the kernel's seats**: who is seated at the
//! head(s) a row names, read by `ciris_kernel::seat::members_at`
//! (kernel-v0.2.2), never by an instant.
//!
//! Persist presents the nodes in the past of the heads, back to their
//! restating version(s), and the ends that act from them, as [`KRow`]s over
//! ONE object: the first restating version of the question, presented as the
//! FOUNDING row (its own object).
//!
//! - **The founding row** (the first root, by row id): an `Offer`,
//!   `Conf::Own`, object its own id, `to` every key it lists, each key a
//!   cosigner (its acceptance), signed by [`GROUP_KEY`], which is never in
//!   `to`. Its founders get the `founder` seat by a founding-like row of their
//!   own (`Conf::Own` over the founding row, signed by a founder), and the
//!   lineage's law ([`lineage_law`]) says a `founder` seat also holds
//!   `member`.
//! - **Every later node is `Conf::Group`** (an own-conferred later node
//!   seats nobody and is no tip: Kernel's probe, line 2):
//!   - a widening: an `Offer` of `member` (or `founder`, by its role) to the
//!     member, the member a cosigner (its acceptance), signed by the members
//!     who voiced it; a demotion is ended by an `Unseat` of `founder`;
//!   - a self-admission: an `Offer` signed by the joiner, `to` the joiner
//!     alone, policy `open:self_admit`;
//!   - a removal: an `Unseat` of `member` and of `founder`;
//!   - another restating version of the question: `Offer`s for the keys it
//!     ADDS and `Unseat`s for the keys it DROPS, against the founding row's
//!     list, never a re-offer of a key it carries over (that would re-seat a
//!     key a removal ended).
//!   Each names the heads it extends (`names` and `head`), carries its real
//!   voices (signer and cosigners), its policy word and the scope its policy
//!   counts (`counted`: `founder` under `founder_only`).
//! - **A resignation** is a `Withdraw` signed by the member, `target` each
//!   presented offer that seats it: not an `Unseat`, not a tip, no head. It
//!   takes effect only at a node that has it in its past, so a node names it
//!   (in `names`) to take the member out.
//!
//! The rows are presented as CONCLUDED (Kernel: `members_at` takes them so
//! and walks the seats; it does not re-count), and the ONE fold call is
//! [`seated_at`]. A later kernel pin (the tips fold, `SeatRow::regime`) adds
//! there and nowhere else. Persist's `SeatRow` for these rows is [`KRow`]'s
//! one impl (`view.rs`). The "member" of every row is a string the caller
//! hands in ([`NodeView`], [`EndView`]), never read from a key here, so the
//! private-room voice rewrite stays one upstream function.
//!
//! Not presented: a quorum's or a weighted count's threshold (`need`), owed
//! with the tips fold (it needs persist's own `quorum_need` reader), and a
//! second root's real predecessor (it is read against the founding row's
//! list: the strict fold at the pin replaces that reading).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use ciris_kernel::graph::Graph;
use ciris_kernel::layers::{self, Concluded};
use ciris_kernel::seat::{members_at, Conf, Obj, SeatKind, SeatLaw};

use super::law::{ARMS, SEAT_FOUNDER, SEAT_MEMBER};
use super::view::{KRow, NoCut, RowId, SeatFields};
use crate::federation::types::consensus_protocol as cp;

/// The founding row's signer: never in `to`, never a member, never in an
/// answer.
pub const GROUP_KEY: &str = "\u{2205}lineage-group";

/// What one lineage node is, as the fold reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeAct {
    /// A restating version the walk stops at: its listed keys, each with
    /// whether it is a founder.
    Root(Vec<(String, bool)>),
    /// A counted widening (or self-admission) of a member.
    Seat {
        /// The member seated.
        member: String,
        /// Seated as a founder.
        founder: bool,
        /// A self-admission under `open:self_admit`.
        self_admit: bool,
    },
    /// A counted removal of the member.
    Unseat(String),
}

/// One lineage node of the question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeView {
    /// The node's row id.
    pub id: [u8; 32],
    /// The heads it extends (none on a root).
    pub extends: Vec<[u8; 32]>,
    /// The ends it names (a resignation it has in its past).
    pub ends: Vec<[u8; 32]>,
    /// What it does.
    pub act: NodeAct,
    /// The members who voiced it (signer first), as handed in.
    pub voices: Vec<String>,
    /// The `consensus_protocol` in force at it.
    pub protocol: Option<String>,
}

/// One end of a seat (a resignation) of the question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndView {
    /// The end's row id.
    pub id: [u8; 32],
    /// The member whose seat it ends, as handed in.
    pub member: String,
    /// The heads it acts from.
    pub heads: Vec<[u8; 32]>,
}

/// Who is seated at the heads.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SeatedAt {
    /// The keys holding `member` (a founder seat holds it too).
    pub members: BTreeSet<String>,
    /// The keys holding `founder`.
    pub founders: BTreeSet<String>,
    /// v62.0.0 (LINEAGE-L3c) — the founder role word as the presented rows
    /// state it (set by the caller that read them), for a caller writing a
    /// seat's role: copied from the rows, never named.
    pub founder_role: Option<String>,
}

/// **The lineage's seat law**: persist's policy words (`law::ARMS`), and a
/// `founder` seat also holds `member` (Kernel: "so they are not offered
/// twice").
pub fn lineage_law() -> &'static SeatLaw {
    static LAW: OnceLock<SeatLaw> = OnceLock::new();
    LAW.get_or_init(|| SeatLaw {
        duties: Vec::new(),
        holds: BTreeMap::from([(SEAT_FOUNDER.to_owned(), vec![SEAT_MEMBER.to_owned()])]),
        confers: BTreeMap::new(),
        ends: BTreeMap::new(),
        final_scopes: Vec::new(),
        roster_seats: vec![SEAT_MEMBER.to_owned(), SEAT_FOUNDER.to_owned()],
        depth: 1,
        policy: ARMS.iter().map(|(w, p)| ((*w).to_owned(), *p)).collect(),
    })
}

/// **The policy word and the counted scope of a protocol** (the kernel's
/// table, `law::ARMS`): `founder_only` counts over `founder`, every other
/// word over `member`; `None` for a form the table has no word for.
#[must_use]
pub fn policy_of(protocol: Option<&str>) -> (Option<&'static str>, &'static str) {
    let Some(p) = protocol else {
        return (None, SEAT_MEMBER);
    };
    if p == cp::FOUNDER_ONLY {
        return (Some("founder_only"), SEAT_FOUNDER);
    }
    let word = if p == cp::OPEN_SELF_ADMIT {
        Some("open:self_admit")
    } else if p == cp::UNANIMOUS {
        Some("unanimous")
    } else if p == cp::MAJORITY {
        Some("majority")
    } else if p.starts_with(cp::QUORUM_PREFIX) {
        Some("quorum")
    } else if p.starts_with(cp::WEIGHTED_PREFIX) {
        Some("weighted")
    } else {
        None
    };
    (word, SEAT_MEMBER)
}

fn sub(node: &[u8; 32], what: &str, key: &str) -> RowId {
    RowId::of_label(&["lineage-act", &hex::encode(node), what, key])
}

/// A counted act (`Conf::Group`) over the founding object.
#[allow(clippy::too_many_arguments)]
fn counted(
    id: RowId,
    names: Vec<RowId>,
    head: Vec<RowId>,
    obj: RowId,
    kind: SeatKind,
    scope: &str,
    to: &str,
    voices: &[String],
    protocol: Option<&str>,
    accept: bool,
) -> KRow {
    let (word, counted) = policy_of(protocol);
    let signer = voices
        .first()
        .cloned()
        .unwrap_or_else(|| GROUP_KEY.to_owned());
    let mut cosigners: Vec<String> = voices.iter().skip(1).cloned().collect();
    if accept && signer != to && !cosigners.iter().any(|c| c == to) {
        cosigners.push(to.to_owned());
    }
    KRow::new(id, names, signer).with_seat(SeatFields {
        to: vec![to.to_owned()],
        scope: Some(scope.to_owned()),
        obj: Some(Obj::Row(obj)),
        conf: Some(Conf::Group),
        cosigners,
        head,
        policy: word.map(str::to_owned),
        counted: Some(counted.to_owned()),
        ..SeatFields::of(kind)
    })
}

/// **The rows** [`seated_at`] presents. Empty with no root.
#[must_use]
pub fn rows_of(nodes: &[NodeView], ends: &[EndView]) -> Vec<KRow> {
    let mut roots: Vec<&NodeView> = nodes
        .iter()
        .filter(|n| matches!(n.act, NodeAct::Root(_)))
        .collect();
    roots.sort_by_key(|n| n.id);
    let Some(first) = roots.first() else {
        return Vec::new();
    };
    let NodeAct::Root(founding_list) = &first.act else {
        return Vec::new();
    };
    let fid = RowId(first.id);
    let held: BTreeSet<[u8; 32]> = nodes.iter().map(|n| n.id).collect();
    let end_ids: BTreeSet<[u8; 32]> = ends.iter().map(|e| e.id).collect();
    let mut rows: Vec<KRow> = Vec::new();
    // every presented row that seats a key, for the ends' targets
    let mut seats_of: BTreeMap<String, Vec<RowId>> = BTreeMap::new();

    // The founding row and its founders' own row.
    let keys: Vec<String> = founding_list.iter().map(|(k, _)| k.clone()).collect();
    let founders: Vec<String> = founding_list
        .iter()
        .filter(|(_, f)| *f)
        .map(|(k, _)| k.clone())
        .collect();
    let f2 = RowId::of_label(&["lineage-founders", &hex::encode(first.id)]);
    for k in &keys {
        seats_of.entry(k.clone()).or_default().push(fid);
    }
    rows.push(
        KRow::new(
            fid,
            if founders.is_empty() {
                Vec::new()
            } else {
                vec![f2]
            },
            GROUP_KEY,
        )
        .with_seat(SeatFields {
            to: keys.clone(),
            scope: Some(SEAT_MEMBER.to_owned()),
            obj: Some(Obj::Row(fid)),
            conf: Some(Conf::Own),
            cosigners: keys.clone(),
            ..SeatFields::of(SeatKind::Offer)
        }),
    );
    if let Some((lead, rest)) = founders.split_first() {
        for k in &founders {
            seats_of.entry(k.clone()).or_default().push(f2);
        }
        rows.push(
            KRow::new(f2, Vec::new(), lead.clone()).with_seat(SeatFields {
                to: founders.clone(),
                scope: Some(SEAT_FOUNDER.to_owned()),
                obj: Some(Obj::Row(fid)),
                conf: Some(Conf::Own),
                cosigners: rest.to_vec(),
                ..SeatFields::of(SeatKind::Offer)
            }),
        );
    }
    let listed: BTreeMap<&String, bool> = founding_list.iter().map(|(k, f)| (k, *f)).collect();

    for n in nodes {
        if n.id == first.id {
            continue;
        }
        let parents: Vec<RowId> = n
            .extends
            .iter()
            .filter(|e| held.contains(*e))
            .map(|e| RowId(*e))
            .collect();
        let head = if parents.is_empty() {
            vec![fid]
        } else {
            parents.clone()
        };
        let named_ends: Vec<RowId> = n
            .ends
            .iter()
            .filter(|e| end_ids.contains(*e))
            .map(|e| RowId(*e))
            .collect();
        let proto = n.protocol.as_deref();
        let mut secondary: Vec<KRow> = Vec::new();
        let primary_kind_scope_to: Option<(SeatKind, &str, String, bool)>;
        match &n.act {
            NodeAct::Root(list) => {
                // Another restating version: what it adds and drops against
                // the founding row's list, never a carried-over re-offer.
                let now: BTreeMap<&String, bool> = list.iter().map(|(k, f)| (k, *f)).collect();
                for (k, f) in &now {
                    let was = listed.get(k).copied();
                    if was.is_none() {
                        let id = sub(&n.id, SEAT_MEMBER, k);
                        seats_of.entry((*k).clone()).or_default().push(id);
                        secondary.push(counted(
                            id,
                            head.clone(),
                            head.clone(),
                            fid,
                            SeatKind::Offer,
                            SEAT_MEMBER,
                            k,
                            &n.voices,
                            proto,
                            true,
                        ));
                    }
                    if *f && was != Some(true) {
                        let id = sub(&n.id, SEAT_FOUNDER, k);
                        seats_of.entry((*k).clone()).or_default().push(id);
                        secondary.push(counted(
                            id,
                            head.clone(),
                            head.clone(),
                            fid,
                            SeatKind::Offer,
                            SEAT_FOUNDER,
                            k,
                            &n.voices,
                            proto,
                            true,
                        ));
                    }
                    if !*f && was == Some(true) {
                        secondary.push(counted(
                            sub(&n.id, "unseat-founder", k),
                            head.clone(),
                            head.clone(),
                            fid,
                            SeatKind::Unseat,
                            SEAT_FOUNDER,
                            k,
                            &n.voices,
                            proto,
                            false,
                        ));
                    }
                }
                for (k, f) in &listed {
                    if !now.contains_key(k) {
                        secondary.push(counted(
                            sub(&n.id, "unseat", k),
                            head.clone(),
                            head.clone(),
                            fid,
                            SeatKind::Unseat,
                            SEAT_MEMBER,
                            k,
                            &n.voices,
                            proto,
                            false,
                        ));
                        if *f {
                            secondary.push(counted(
                                sub(&n.id, "unseat-founder", k),
                                head.clone(),
                                head.clone(),
                                fid,
                                SeatKind::Unseat,
                                SEAT_FOUNDER,
                                k,
                                &n.voices,
                                proto,
                                false,
                            ));
                        }
                    }
                }
                primary_kind_scope_to = None;
            }
            NodeAct::Seat {
                member,
                founder,
                self_admit,
            } => {
                seats_of
                    .entry(member.clone())
                    .or_default()
                    .push(RowId(n.id));
                if !founder {
                    secondary.push(counted(
                        sub(&n.id, "unseat-founder", member),
                        head.clone(),
                        head.clone(),
                        fid,
                        SeatKind::Unseat,
                        SEAT_FOUNDER,
                        member,
                        &n.voices,
                        proto,
                        false,
                    ));
                }
                let scope = if *founder { SEAT_FOUNDER } else { SEAT_MEMBER };
                primary_kind_scope_to = Some((SeatKind::Offer, scope, member.clone(), !self_admit));
            }
            NodeAct::Unseat(member) => {
                secondary.push(counted(
                    sub(&n.id, "unseat-founder", member),
                    head.clone(),
                    head.clone(),
                    fid,
                    SeatKind::Unseat,
                    SEAT_FOUNDER,
                    member,
                    &n.voices,
                    proto,
                    false,
                ));
                primary_kind_scope_to =
                    Some((SeatKind::Unseat, SEAT_MEMBER, member.clone(), false));
            }
        }
        // The node's own row names its predecessors, its secondary acts and
        // the ends it has in its past, so all of them are in its past.
        let mut names = parents.clone();
        names.extend(secondary.iter().map(|r| r.id));
        names.extend(named_ends);
        names.push(fid);
        let own = match primary_kind_scope_to {
            Some((kind, scope, to, accept)) => {
                let self_admit = matches!(
                    n.act,
                    NodeAct::Seat {
                        self_admit: true,
                        ..
                    }
                );
                let voices: Vec<String> = if self_admit {
                    vec![to.clone()]
                } else {
                    n.voices.clone()
                };
                let proto = if self_admit {
                    Some(cp::OPEN_SELF_ADMIT)
                } else {
                    proto
                };
                counted(
                    RowId(n.id),
                    names,
                    head,
                    fid,
                    kind,
                    scope,
                    &to,
                    &voices,
                    proto,
                    accept,
                )
            }
            None => KRow::new(RowId(n.id), names, GROUP_KEY),
        };
        rows.extend(secondary);
        rows.push(own);
    }

    // The ends: a withdrawal by the member of every presented offer that
    // seats it.
    for e in ends {
        let targets = seats_of.get(&e.member).cloned().unwrap_or_default();
        let heads: Vec<RowId> = e
            .heads
            .iter()
            .filter(|h| held.contains(*h))
            .map(|h| RowId(*h))
            .collect();
        let mut secondary: Vec<RowId> = Vec::new();
        for (i, t) in targets.iter().enumerate() {
            let id = if i == 0 {
                RowId(e.id)
            } else {
                RowId::of_label(&["lineage-end", &hex::encode(e.id), &hex::encode(t.0)])
            };
            if i > 0 {
                secondary.push(id);
            }
            let mut names = heads.clone();
            names.push(*t);
            rows.push(
                KRow::new(id, names, e.member.clone()).with_seat(SeatFields {
                    target: Some(*t),
                    ..SeatFields::of(SeatKind::Withdraw)
                }),
            );
        }
        if !secondary.is_empty() {
            if let Some(primary) = rows.iter_mut().find(|r| r.id == RowId(e.id)) {
                primary.names.extend(secondary);
            }
        }
        if targets.is_empty() {
            // nothing presented seats the member: the end is a plain row
            rows.push(KRow::new(RowId(e.id), heads, e.member.clone()));
        }
    }
    rows
}

/// **THE fold call: who is seated at `heads`** (kernel-v0.2.2
/// `seat::members_at` over [`rows_of`], the rows taken as concluded): one
/// head, every seat standing in its past; several heads, the keys common to
/// all of them. A head that is not presented seats nobody. [`GROUP_KEY`] is
/// never in the answer.
#[must_use]
pub fn seated_at(nodes: &[NodeView], ends: &[EndView], heads: &[[u8; 32]]) -> SeatedAt {
    let mut rows = rows_of(nodes, ends);
    let Some(fid) = rows.first().map(|r| r.id) else {
        return SeatedAt::default();
    };
    let q = RowId::of_label(&["lineage-question", &hex::encode(fid.0)]);
    let hs: Vec<RowId> = heads.iter().map(|h| RowId(*h)).collect();
    rows.push(KRow::new(q, hs.clone(), GROUP_KEY));
    let kept = layers::kept(&rows, |_| true);
    let c = Concluded::with(Graph::new(kept), None);
    let Some(qi) = c.g.idx(&q) else {
        return SeatedAt::default();
    };
    let mut p: Vec<usize> =
        c.g.ancestors(qi)
            .iter()
            .filter(|&a| c.concluded(a))
            .collect();
    p.sort_unstable();
    let past = layers::Past {
        g: &c.g,
        i: qi,
        p: &p,
    };
    let law = lineage_law();
    let obj = Obj::Row(fid);
    let read = |scope: &str| -> BTreeSet<String> {
        members_at(&past, law, &NoCut, &obj, &hs, scope)
            .into_iter()
            .filter(|k| k != GROUP_KEY)
            .collect()
    };
    SeatedAt {
        members: read(SEAT_MEMBER),
        founders: read(SEAT_FOUNDER),
        founder_role: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_kernel::seat::Seats;

    fn id(i: u8) -> [u8; 32] {
        [i; 32]
    }

    fn keys(ks: &[&str]) -> Vec<String> {
        ks.iter().map(|k| (*k).to_owned()).collect()
    }

    fn set(ks: &[&str]) -> BTreeSet<String> {
        ks.iter().map(|k| (*k).to_owned()).collect()
    }

    fn root(i: u8, listed: &[(&str, bool)]) -> NodeView {
        NodeView {
            id: id(i),
            extends: Vec::new(),
            ends: Vec::new(),
            act: NodeAct::Root(listed.iter().map(|(k, f)| ((*k).to_owned(), *f)).collect()),
            voices: Vec::new(),
            protocol: Some(cp::MAJORITY.to_owned()),
        }
    }

    fn widen(i: u8, extends: &[u8], member: &str, voices: &[&str]) -> NodeView {
        NodeView {
            id: id(i),
            extends: extends.iter().map(|e| id(*e)).collect(),
            ends: Vec::new(),
            act: NodeAct::Seat {
                member: member.to_owned(),
                founder: false,
                self_admit: false,
            },
            voices: keys(voices),
            protocol: Some(cp::MAJORITY.to_owned()),
        }
    }

    fn remove(i: u8, extends: &[u8], member: &str, voices: &[&str]) -> NodeView {
        NodeView {
            id: id(i),
            extends: extends.iter().map(|e| id(*e)).collect(),
            ends: Vec::new(),
            act: NodeAct::Unseat(member.to_owned()),
            voices: keys(voices),
            protocol: Some(cp::MAJORITY.to_owned()),
        }
    }

    fn at(nodes: &[NodeView], ends: &[EndView], heads: &[u8]) -> SeatedAt {
        seated_at(
            nodes,
            ends,
            &heads.iter().map(|h| id(*h)).collect::<Vec<_>>(),
        )
    }

    /// Kernel's probe over raw rows: the seats and the tips over the whole
    /// presented set, as `Seats` reads it.
    fn probe(rows: &[KRow], fid: RowId) -> (BTreeSet<String>, usize) {
        let kept = layers::kept(rows, |_| true);
        let c = Concluded::with(Graph::new(kept), None);
        let s = Seats::new(&c, lineage_law(), &NoCut, None);
        let obj = Obj::Row(fid);
        let members = s
            .holders(SEAT_MEMBER, &obj, None)
            .into_iter()
            .filter(|k| k != GROUP_KEY)
            .collect();
        (members, s.tips(&obj).len())
    }

    /// I6917 (LINEAGE-L3.rev2) — **Kernel's probe, line by line**
    /// (P/KERNEL-lineage-encoding.md "What the probe showed"): (1) the
    /// founding row alone seats abc, one tip; (2) a later node presented as
    /// `Conf::Own` seats NOBODY and is no tip (the negative that is why every
    /// later node is `Conf::Group`); (3) the same node as `Conf::Group`: abcj,
    /// one tip; (4) two concurrent `Conf::Group` nodes: abc, two tips; (5) a
    /// `Conf::Group` Unseat of b after j: acj.
    #[test]
    fn i6917_kernels_probe_line_by_line() {
        let v1 = root(1, &[("a", false), ("b", false), ("c", false)]);
        let fid = RowId(id(1));
        // (1)
        let rows = rows_of(std::slice::from_ref(&v1), &[]);
        assert_eq!(probe(&rows, fid), (set(&["a", "b", "c"]), 1), "I6917 (1)");
        // (2) the negative: an own-conferred later node by the group key
        let mut own = rows.clone();
        own.push(
            KRow::new(RowId(id(2)), vec![fid], GROUP_KEY).with_seat(SeatFields {
                to: keys(&["j"]),
                scope: Some(SEAT_MEMBER.to_owned()),
                obj: Some(Obj::Row(fid)),
                conf: Some(Conf::Own),
                cosigners: keys(&["j"]),
                ..SeatFields::of(SeatKind::Offer)
            }),
        );
        assert_eq!(
            probe(&own, fid),
            (set(&["a", "b", "c"]), 1),
            "I6917 (2): Conf::Own seats nobody and is no tip"
        );
        // (3)
        let j = widen(2, &[1], "j", &["a", "b"]);
        let rows = rows_of(&[v1.clone(), j.clone()], &[]);
        assert_eq!(
            probe(&rows, fid),
            (set(&["a", "b", "c", "j"]), 1),
            "I6917 (3)"
        );
        assert_eq!(
            at(&[v1.clone(), j.clone()], &[], &[2]).members,
            set(&["a", "b", "c", "j"])
        );
        // (4)
        let k = widen(3, &[1], "k", &["a", "b"]);
        let rows = rows_of(&[v1.clone(), j.clone(), k.clone()], &[]);
        assert_eq!(probe(&rows, fid), (set(&["a", "b", "c"]), 2), "I6917 (4)");
        assert_eq!(
            at(&[v1.clone(), j.clone(), k], &[], &[2, 3]).members,
            set(&["a", "b", "c"]),
            "I6917 (4): naming both heads, the common members"
        );
        // (5)
        let u = remove(4, &[2], "b", &["a", "c"]);
        let rows = rows_of(&[v1.clone(), j.clone(), u.clone()], &[]);
        assert_eq!(probe(&rows, fid), (set(&["a", "c", "j"]), 1), "I6917 (5)");
        assert_eq!(at(&[v1, j, u], &[], &[4]).members, set(&["a", "c", "j"]));
    }

    /// I6918 (LINEAGE-L3.rev2; Kernel's caution) — a key a removal ended is
    /// NOT re-seated by a later restating version that carries it: the
    /// second version adds and drops against the founding list, never
    /// re-offers a carried-over key.
    #[test]
    fn i6918_a_removed_key_is_not_reseated_by_a_restating_version() {
        let v1 = root(1, &[("a", false), ("b", false), ("c", false)]);
        let u = remove(2, &[1], "b", &["a", "c"]);
        // a second restating version (a roster tip) listing b as before, and j
        let mut v2 = root(3, &[("a", false), ("b", false), ("c", false), ("j", false)]);
        v2.extends = vec![id(1)];
        v2.voices = keys(&["a", "c"]);
        let join = widen(4, &[2, 3], "k", &["a", "c"]);
        let s = at(&[v1, u, v2, join], &[], &[4]);
        assert!(!s.members.contains("b"), "I6918: b stays unseated: {s:?}");
        assert_eq!(s.members, set(&["a", "c", "j", "k"]), "I6918");
    }

    /// I6919 (LINEAGE-L3.rev2) — a resignation takes effect at the next node
    /// that NAMES it, and the resigner is absent there and after; a node that
    /// does not name it still seats the resigner; the end is no head.
    #[test]
    fn i6919_a_resignation_takes_effect_where_it_is_named() {
        let v1 = root(1, &[("a", false), ("b", false), ("c", false)]);
        let j = widen(2, &[1], "j", &["a", "b"]);
        let end = EndView {
            id: id(9),
            member: "b".into(),
            heads: vec![id(2)],
        };
        let mut naming = widen(3, &[2], "k", &["a", "c"]);
        naming.ends = vec![id(9)];
        let blind = widen(4, &[2], "m", &["a", "c"]);
        let nodes = [v1.clone(), j.clone(), naming.clone(), blind.clone()];
        let ends = std::slice::from_ref(&end);
        assert!(
            at(&nodes, ends, &[2]).members.contains("b"),
            "I6919: at the head the end acts from, b still sits"
        );
        assert!(
            !at(&nodes, ends, &[3]).members.contains("b"),
            "I6919: at the node that names the end, b is out"
        );
        let later = widen(5, &[3], "n", &["a", "c"]);
        let mut more = nodes.to_vec();
        more.push(later);
        assert!(
            !at(&more, ends, &[5]).members.contains("b"),
            "I6919: and at every node after it"
        );
        assert!(
            at(&nodes, ends, &[4]).members.contains("b"),
            "I6919: a node that does not name the end still seats b"
        );
    }

    /// I6920 (LINEAGE-L3.rev2) — `founder_only` is counted over the founder
    /// scope (`counted` = `founder` on its counted rows), the founders hold
    /// the founder seat by a row of their own and `member` through it, a
    /// promotion and a demotion move the founder seat, and a self-admission
    /// is signed by the joiner alone.
    #[test]
    fn i6920_founders_and_self_admission() {
        let mut v1 = root(1, &[("a", true), ("b", false)]);
        v1.protocol = Some(cp::FOUNDER_ONLY.to_owned());
        let mut w = widen(2, &[1], "c", &["a"]);
        w.protocol = Some(cp::FOUNDER_ONLY.to_owned());
        let rows = rows_of(&[v1.clone(), w.clone()], &[]);
        let wr = rows.iter().find(|r| r.id == RowId(id(2))).expect("w");
        assert_eq!(
            wr.seat.counted.as_deref(),
            Some(SEAT_FOUNDER),
            "I6920: counted"
        );
        assert_eq!(
            wr.seat.policy.as_deref(),
            Some("founder_only"),
            "I6920: policy"
        );
        assert_eq!(wr.signer, "a", "I6920: signed by its real voice");
        assert!(
            wr.seat.cosigners.contains(&"c".to_owned()),
            "I6920: c's acceptance"
        );
        let s = at(&[v1.clone(), w.clone()], &[], &[2]);
        assert_eq!(s.founders, set(&["a"]), "I6920: the founder");
        assert_eq!(
            s.members,
            set(&["a", "b", "c"]),
            "I6920: a founder holds member"
        );
        let promote = NodeView {
            act: NodeAct::Seat {
                member: "b".into(),
                founder: true,
                self_admit: false,
            },
            ..widen(3, &[2], "b", &["a"])
        };
        let demote = widen(4, &[3], "a", &["b"]);
        let s = at(&[v1.clone(), w.clone(), promote.clone()], &[], &[3]);
        assert_eq!(s.founders, set(&["a", "b"]), "I6920: promoted");
        let s = at(&[v1, w, promote, demote], &[], &[4]);
        assert_eq!(s.founders, set(&["b"]), "I6920: demoted");
        assert!(s.members.contains("a"), "I6920: still a member");

        let open = root(5, &[("a", false)]);
        let joiner = NodeView {
            act: NodeAct::Seat {
                member: "j".into(),
                founder: false,
                self_admit: true,
            },
            protocol: Some(cp::OPEN_SELF_ADMIT.to_owned()),
            ..widen(6, &[5], "j", &["j"])
        };
        let rows = rows_of(&[open.clone(), joiner.clone()], &[]);
        let jr = rows.iter().find(|r| r.id == RowId(id(6))).expect("j");
        assert_eq!(jr.signer, "j", "I6920: the joiner signs");
        assert_eq!(jr.seat.to, keys(&["j"]), "I6920: to the joiner alone");
        assert!(jr.seat.cosigners.is_empty(), "I6920: no other voice");
        assert_eq!(jr.seat.policy.as_deref(), Some("open:self_admit"));
        assert_eq!(at(&[open, joiner], &[], &[6]).members, set(&["a", "j"]));
    }
}
