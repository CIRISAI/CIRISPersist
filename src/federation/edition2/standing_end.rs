//! v62.0.0 (R2; CC 2.4.1.1 "The end of a standing", Kernel's
//! `models/causal_kernel/conferral_end.py`) — **the ONE reader of what an end
//! does to an act**: does the act COUNT, and is it IN FORCE, decided by
//! where the act's head and the end's head stand in each other's past (CC
//! E1–E7), never by an instant. No gate computes this answer a second time:
//! a gate asks [`answers`] (the pure rule over a set of rows) or
//! [`place`] (where two held heads stand), and reads the result.
//!
//! - **The rule** ([`answers`]) is a port of the Kernel reference model's
//!   `answers()`, over the kernel's own `Graph::in_past` (kernel 0.2.0).
//!   Kernel's cautions hold: nothing here routes through `head::View`
//!   `counts_at` / `carried`, nor `seat::exercised_stands`.
//! - **Receipts** (HEAD-R5b; CC 2.4.1.1 "What stays in force", Kernel's
//!   receipt shape, `act_ack`): a receipt names ONE act (`of`; a bulk ack is
//!   one receipt per act it names) and keeps it in force (E8) when it is
//!   clean (its signer's key not cut), does not have the end in its past,
//!   and its signer is ELIGIBLE by role ([`Standing`]): the conferrer
//!   always; a co-holder of the body, or a receipter the grant names, only
//!   when the standing lets them (`who`) and the end does not lift receipts
//!   (`lifts` on a count's end); the receipter only before the body ended
//!   its seat. The grantee's own receipt keeps nothing. A receipt by the
//!   ender's own signer concurrent with the end is the ender's one say on a
//!   later-head act (E3 `one_say`: counted, never in force). The reader's
//!   line (`end_void.line`, CC 2.7.8): a head the reader acknowledged,
//!   later than the end's and without the end in its past, voids the end.
//! - **The lineage** ([`place`]): the act's head and the end's head are
//!   placed by walking the held lineage back from both, through
//!   `group:roster` versions' `refs.head` / `refs.further_heads`, or through
//!   the bundles' `prev`. A one-row record (an owner binding, a delegation)
//!   is its own head: an act under it and the end of it name the same row.
//! - **A seat's end** (a counted `membership:removal`) is applied to the
//!   typed record, and no later `group:roster` version names it (versions
//!   name only `head`, `further_heads` and `also:cites`). So an act after a
//!   removal is reached as "the act names a later head" (E3): its head has
//!   the removal's head in its past. No new edge is needed for it.
//! - **A head this node does not hold is a HOLD** (`link_unheld`), never a
//!   refusal: the row waits for the head and is re-judged when it arrives.
//!   The walk is **bounded** by [`MAX_LINEAGE_ROWS`]: a lineage longer than
//!   that is refused `standing_end_lineage_too_deep`, because an unbounded
//!   walk on a head the host supplies would be a resource door.
//! - **No memo across calls:** each call walks what it needs. A gate that
//!   asks several questions about one row passes one [`Walked`] through
//!   them.

use std::collections::{BTreeMap, BTreeSet};

use ciris_kernel::graph::Graph;

use super::names::RowId;
use crate::federation::{Error, FederationDirectory};
use crate::kernel::view::{KRow, RowId as KId};

/// The longest lineage one judgment walks: the roster's own chain bound.
pub const MAX_LINEAGE_ROWS: usize = super::group::MAX_ROSTER_CHAIN;

/// A row of the rule's input (the Kernel model's row shape).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConferralRow {
    /// The row's id.
    pub id: KId,
    /// What it is.
    pub kind: RowKind,
    /// The ids its signed bytes name.
    pub names: Vec<KId>,
    /// Who signed it (a key, or a role for a count).
    pub signer: String,
    /// The head it names (`refs.head`): an act's or an end's.
    pub head: Option<KId>,
    /// A removal's removed key.
    pub target: Option<String>,
    /// A deputy act's superior act (the edge it hangs from).
    pub via: Option<KId>,
    /// A receipt's act (the one act it receipts).
    pub of: Option<KId>,
    /// An end's `lifts` (a count's end lifting the receipts of single
    /// holders; CC 2.4.1.1).
    pub lifts: bool,
}

/// The kinds of row the rule reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowKind {
    /// A head: a roster version, a bundle, a one-row record.
    Head,
    /// An act exercised under the standing.
    Act,
    /// The end of the standing.
    End,
    /// The removal of a key.
    Removal,
    /// The grantee's own (re-)acceptance.
    Accept,
    /// A receipt of one act (an `act:ack` entry).
    Receipt,
    /// The body's end of a receipter's seat.
    ReceipterEnd,
}

/// The role a signer holds in the standing (the Kernel model's roles).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The conferrer (for a count: the count).
    Conferrer,
    /// The standing's holder.
    Grantee,
    /// A co-holder of the body the acts were done for.
    CoHolder,
    /// A receipter the grant names.
    Receipter,
    /// Anyone else (a deputy, a stranger): its receipt keeps nothing.
    Other,
}

/// Who may receipt, besides the conferrer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Who {
    /// The conferrer, a co-holder of the body, a receipter the grant names.
    All,
    /// The count's own receipts only (a root grant, ruled so).
    None,
}

/// **The standing an end is judged in**: the role of each signer, whether
/// another live standing of the grantee authorises its acts (CC "Another
/// standing"), who may receipt, and the heads the reader acknowledged (its
/// line, CC 2.7.8).
#[derive(Clone, Debug)]
pub struct Standing<'a> {
    /// The role of each signer that holds one; any other signer is
    /// [`Role::Other`].
    pub roles: &'a BTreeMap<String, Role>,
    /// Another live standing of the grantee authorises the acts.
    pub other_standing: bool,
    /// Who may receipt.
    pub who: Who,
    /// The heads the reader acknowledged.
    pub reader_acks: &'a [KId],
}

impl Standing<'_> {
    fn role(&self, signer: &str) -> Role {
        self.roles.get(signer).copied().unwrap_or(Role::Other)
    }
}

/// The answer for one act.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Judged {
    /// It counts (at its own head).
    pub counted: bool,
    /// It is in force now.
    pub in_force: bool,
    /// The rule that decided it, in the Kernel model's spelling.
    pub rule: &'static str,
}

impl Judged {
    const fn of(counted: bool, in_force: bool, rule: &'static str) -> Self {
        Self {
            counted,
            in_force,
            rule,
        }
    }
}

fn krows(rows: &[ConferralRow]) -> Vec<KRow> {
    rows.iter()
        .map(|r| KRow::new(r.id, r.names.clone(), r.signer.clone()))
        .collect()
}

/// **THE rule** (CC 2.4.1.1 E1–E8, the Kernel reference's `answers()`):
/// every act among `rows`, `{counted, in_force, rule}`, in `standing`
/// (roles, a second standing, who may receipt, the reader's line). At most
/// one end per call; a gate with several ends asks once per end and takes
/// the narrowest answer ([`narrowest`]).
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn answers(rows: &[ConferralRow], standing: &Standing<'_>) -> BTreeMap<KId, Judged> {
    let ks = krows(rows);
    let g = Graph::new(ks.iter());
    let by: BTreeMap<KId, &ConferralRow> = rows.iter().map(|r| (r.id, r)).collect();
    // `a` is in the past of `b` (by id), the reference's `a in anc(b)`.
    let in_past = |a: &KId, b: &KId| g.idx(b).is_some_and(|ib| g.id_in_past(a, ib));
    let removals: Vec<&ConferralRow> = rows.iter().filter(|r| r.kind == RowKind::Removal).collect();
    let end = rows.iter().find(|r| r.kind == RowKind::End);
    let key_cut = |r: &ConferralRow| {
        removals
            .iter()
            .any(|m| m.target.as_deref() == Some(r.signer.as_str()) && !in_past(&r.id, &m.id))
    };
    let later = |h: Option<&KId>, he: Option<&KId>| match (h, he) {
        (Some(h), Some(he)) => in_past(he, h),
        _ => false,
    };
    let void: Option<&'static str> = match end {
        None => Some("no_end"),
        Some(e) => {
            let stale = rows.iter().any(|h| {
                h.kind == RowKind::Head
                    && in_past(&h.id, &e.id)
                    && later(Some(&h.id), e.head.as_ref())
            });
            // CC 2.7.8 — the reader acknowledged a head later than the
            // end's that does not have the end in its past.
            let line = standing.reader_acks.iter().any(|h| {
                by.contains_key(h) && later(Some(h), e.head.as_ref()) && !in_past(&e.id, h)
            });
            if stale {
                Some("end_void.stale_head")
            } else if key_cut(e) {
                Some("end_void.key_removed")
            } else if line {
                Some("end_void.line")
            } else {
                None
            }
        }
    };
    let grantee = |s: &str| standing.role(s) == Role::Grantee;
    let other = |x: &ConferralRow| {
        grantee(&x.signer)
            && (standing.other_standing
                || end.is_some_and(|e| {
                    grantee(&e.signer)
                        && rows
                            .iter()
                            .any(|a| a.kind == RowKind::Accept && grantee(&a.signer))
                }))
    };
    // E8 — a count's end that lifts receipts (an end by the conferrer
    // carrying `lifts`; one's own end lifts nothing).
    let lifted = end.is_some_and(|e| e.lifts && standing.role(&e.signer) == Role::Conferrer);
    let receipter_ends: Vec<&KId> = rows
        .iter()
        .filter(|r| r.kind == RowKind::ReceipterEnd)
        .map(|r| &r.id)
        .collect();
    let eligible = |q: &ConferralRow| match standing.role(&q.signer) {
        Role::Conferrer => true,
        Role::CoHolder => standing.who == Who::All && !lifted,
        Role::Receipter => {
            standing.who == Who::All && !lifted && !receipter_ends.iter().any(|x| in_past(x, &q.id))
        }
        Role::Grantee | Role::Other => false,
    };
    let receipts = |x: &KId| {
        rows.iter()
            .filter(|q| q.kind == RowKind::Receipt && q.of.as_ref() == Some(x) && !key_cut(q))
            .collect::<Vec<_>>()
    };
    let end_rule = |x: &ConferralRow| -> Judged {
        if let Some(v) = void {
            return Judged::of(true, true, v);
        }
        let e = end.expect("a void-free answer has an end");
        if other(x) {
            return Judged::of(true, true, "E7.other_standing");
        }
        if in_past(&e.id, &x.id) {
            return Judged::of(false, false, "E4.names_end");
        }
        let held = receipts(&x.id);
        if later(x.head.as_ref(), e.head.as_ref()) {
            // E3 — the ender's one say: its own clean receipt of the act,
            // concurrent with the end.
            let say = held
                .iter()
                .any(|q| q.signer == e.signer && !in_past(&e.id, &q.id) && !in_past(&q.id, &e.id));
            return if say {
                Judged::of(true, false, "E3.one_say")
            } else {
                Judged::of(false, false, "E3.later_head")
            };
        }
        if held.iter().any(|q| eligible(q) && !in_past(&e.id, &q.id)) {
            return Judged::of(true, true, "E8.receipt");
        }
        Judged::of(true, false, "E2.forward")
    };
    let mut memo: BTreeMap<KId, Judged> = BTreeMap::new();
    let acts: Vec<&ConferralRow> = rows.iter().filter(|r| r.kind == RowKind::Act).collect();
    // A deputy's act depends on its superior act: answer superiors first
    // (the reference recurses; the depth is the deputy chain's).
    let mut pending: Vec<&ConferralRow> = acts.clone();
    let mut guard = 0usize;
    while let Some(x) = pending.first().copied() {
        guard += 1;
        if guard > acts.len() * (acts.len() + 1) + 1 {
            break;
        }
        if let Some(v) = x.via.as_ref() {
            if !memo.contains_key(v) && by.get(v).is_some_and(|r| r.kind == RowKind::Act) {
                pending.rotate_left(1);
                continue;
            }
        }
        pending.remove(0);
        let out = if key_cut(x) {
            Judged::of(false, false, "key_removed")
        } else {
            let mut j = end_rule(x);
            if let Some(u) = x.via.as_ref().and_then(|v| memo.get(v)).copied() {
                let (c, f) = (j.counted, j.in_force);
                if (c && !u.counted) || (c && f && !u.in_force) {
                    j.rule = "E6.upstream";
                }
                j.counted = c && u.counted;
                j.in_force = c && f && u.in_force;
            }
            j
        };
        memo.insert(x.id, out);
    }
    memo
}

/// The narrowest of several ends' answers for one act: it counts only if
/// every end lets it count, and is in force only if every end leaves it in
/// force. The first end that narrows it names the rule.
#[must_use]
pub fn narrowest(answers: &[Judged]) -> Option<Judged> {
    let mut it = answers.iter().copied();
    let first = it.next()?;
    Some(it.fold(first, |acc, j| {
        if (acc.counted && !j.counted) || (acc.in_force && !j.in_force) {
            Judged::of(acc.counted && j.counted, acc.in_force && j.in_force, j.rule)
        } else {
            acc
        }
    }))
}

/// Where an act's head stands against an end's head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placing {
    /// The same head.
    Same,
    /// The act's head is in the end's head's past (an older head).
    ActOlder,
    /// The end's head is in the act's head's past: the act names a LATER
    /// head (E3).
    ActLater,
    /// Neither is in the other's past.
    Concurrent,
}

/// The lineage a pair of heads is walked in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lineage {
    /// `group:roster` versions (`refs.head`, `refs.further_heads`).
    Roster,
    /// Genesis bundles (`prev`).
    Bundle,
}

/// The rows one judgment walked, kept for the next question about the same
/// row (never across calls).
#[derive(Default, Debug)]
pub struct Walked {
    /// Each walked head's parents.
    parents: BTreeMap<RowId, Vec<RowId>>,
}

fn link_unheld(head: &RowId) -> Error {
    super::fold::hold(
        super::fold::reason::LINK_UNHELD,
        Error::InvalidArgument(format!(
            "standing_end_head_unheld: the head {} an act or an end names is not held here: \
             the row waits for it (CC 2.4.1.1)",
            head.hex()
        )),
    )
}

fn too_deep(start: &RowId) -> Error {
    Error::malformed_row(
        super::door::PLANE,
        crate::federation::malformed_row::STANDING_END_LINEAGE_TOO_DEEP,
        format!(
            "the lineage under the head {} is longer than {MAX_LINEAGE_ROWS} rows: a head the \
             reader would have to walk without bound is refused",
            start.hex()
        ),
    )
}

/// Walk the roster lineage below `start` into `walked`.
async fn walk_roster<F>(dir: &F, start: &RowId, walked: &mut Walked) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut todo = vec![*start];
    while let Some(at) = todo.pop() {
        if walked.parents.contains_key(&at) {
            continue;
        }
        if walked.parents.len() >= MAX_LINEAGE_ROWS {
            return Err(too_deep(start));
        }
        let Some(st) = super::head_rule::held_statement(dir, &at).await? else {
            return Err(link_unheld(&at));
        };
        let view = super::group::roster_view_of_statement(&st)?;
        let parents = view.parents();
        todo.extend(parents.iter().copied());
        walked.parents.insert(at, parents);
    }
    Ok(())
}

/// Walk the bundle lineage (every held Valid bundle) into `walked`.
async fn walk_bundles<F>(dir: &F, walked: &mut Walked) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    for (id, prev) in super::genesis::bundle_lineage(dir).await? {
        walked
            .parents
            .insert(RowId(id), prev.map(RowId).into_iter().collect());
    }
    Ok(())
}

/// **Where `act_head` stands against `end_head`** in `lineage`, over the
/// rows this node holds (walked into `walked`). A head not held is a HOLD
/// (`link_unheld`); a lineage past [`MAX_LINEAGE_ROWS`] is refused
/// `standing_end_lineage_too_deep`.
///
/// # Errors
/// The hold and the refusal above; directory reads.
pub async fn place<F>(
    dir: &F,
    lineage: Lineage,
    act_head: &RowId,
    end_head: &RowId,
    walked: &mut Walked,
) -> Result<Placing, Error>
where
    F: FederationDirectory + ?Sized,
{
    if act_head == end_head {
        return Ok(Placing::Same);
    }
    match lineage {
        Lineage::Roster => {
            walk_roster(dir, act_head, walked).await?;
            walk_roster(dir, end_head, walked).await?;
        }
        Lineage::Bundle => {
            walk_bundles(dir, walked).await?;
            for h in [act_head, end_head] {
                if !walked.parents.contains_key(h) {
                    return Err(link_unheld(h));
                }
            }
        }
    }
    let rows: Vec<KRow> = walked
        .parents
        .iter()
        .map(|(id, ps)| {
            KRow::new(
                KId(id.0),
                ps.iter().map(|p| KId(p.0)).collect(),
                String::new(),
            )
        })
        .collect();
    let g = Graph::new(rows.iter());
    let (Some(ia), Some(ie)) = (g.idx(&KId(act_head.0)), g.idx(&KId(end_head.0))) else {
        return Ok(Placing::Concurrent);
    };
    Ok(if g.in_past(ie, ia) {
        Placing::ActLater
    } else if g.in_past(ia, ie) {
        Placing::ActOlder
    } else {
        Placing::Concurrent
    })
}

/// **One act against one end, by their heads** (E2 / E3, the persist
/// shape of [`answers`]): the act names `act_head` (or none), the end names
/// `end_head`. An act whose head is in no lineage the end's is (a one-row
/// record, or a head of another kind) reads as "no head" against it:
/// counted at its own head and not in force after the end (E2), exactly as
/// the model reads an act with no head.
#[must_use]
pub fn judge_by_heads(placing: Option<Placing>) -> Judged {
    match placing {
        Some(Placing::ActLater) => Judged::of(false, false, "E3.later_head"),
        _ => Judged::of(true, false, "E2.forward"),
    }
}

/// The ids of a set of heads, for a caller building [`ConferralRow`]s.
#[must_use]
pub fn kid(id: &RowId) -> KId {
    KId(id.0)
}

/// The set of acts in `answers` that count.
#[must_use]
pub fn counted(answers: &BTreeMap<KId, Judged>) -> BTreeSet<KId> {
    answers
        .iter()
        .filter(|(_, j)| j.counted)
        .map(|(k, _)| *k)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Kernel's conferral-end fixture (PR #22 @ 026e580, branch
    /// conferral-fixtures, NOT merged): pinned by SHA-256, re-pinned when it
    /// merges.
    const KERNEL_FIXTURE: &str = include_str!("../../../tests/vectors/kernel/conferral_end.json");
    const KERNEL_FIXTURE_SHA256: &str =
        "6db1e8b432ba9907fb2ce281b9902319a7a1320238b416d68a7cdfe74b3458c6";

    fn id(s: &str) -> KId {
        KId::of_label(&["kernel-fixture", s])
    }

    fn kind(s: &str) -> Option<RowKind> {
        Some(match s {
            "head" => RowKind::Head,
            "act" => RowKind::Act,
            "end" => RowKind::End,
            "removal" => RowKind::Removal,
            "accept" => RowKind::Accept,
            "receipt" => RowKind::Receipt,
            "receipter_end" => RowKind::ReceipterEnd,
            _ => return None,
        })
    }

    /// The fixture's roles (`roles` in the fixture): A the conferrer, B the
    /// grantee, D a co-holder, R a named receipter; C (a deputy) and
    /// anyone else hold none.
    fn roles() -> BTreeMap<String, Role> {
        [
            ("A", Role::Conferrer),
            ("B", Role::Grantee),
            ("D", Role::CoHolder),
            ("R", Role::Receipter),
        ]
        .into_iter()
        .map(|(s, r)| (s.to_owned(), r))
        .collect()
    }

    /// I6125 (R2; extended by HEAD-R5b) — **the reader answers the
    /// Kernel's cases**: EVERY case whose `refused` is null (30 of 33, 42
    /// answers, at 026e580; the receipt cases, the reader's line and
    /// `who = none` included) gives each act the fixture's `counted`,
    /// `in_force` and rule, for every arrival order the case lists (the
    /// reader reads the held set, so each order's full set gives one
    /// answer). The 3 `refused` cases are the door's (`act_names_no_head`,
    /// HEAD-2). Of the 30, 13 read receipts or the line (18 answers).
    /// Counted, so no case is lost.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn i6125_the_reader_answers_the_kernels_cases() {
        use sha2::Digest as _;
        assert_eq!(
            hex::encode(sha2::Sha256::digest(KERNEL_FIXTURE.as_bytes())),
            KERNEL_FIXTURE_SHA256,
            "I6125: the vendored Kernel fixture is the pinned one"
        );
        let f: serde_json::Value = serde_json::from_str(KERNEL_FIXTURE).unwrap();
        let (mut run, mut answers_run, mut refused, mut receipts, mut receipt_answers) =
            (0, 0, 0, 0, 0);
        let roles = roles();
        for c in f["cases"].as_array().unwrap() {
            let name = c["name"].as_str().unwrap();
            if !c["refused"].is_null() {
                refused += 1;
                continue;
            }
            let rows_j = c["rows"].as_array().unwrap();
            let reads_receipts = rows_j
                .iter()
                .any(|r| matches!(r["kind"].as_str(), Some("receipt" | "receipter_end")))
                || !c["reader_acks"].as_array().unwrap().is_empty();
            if reads_receipts {
                receipts += 1;
            }
            let who = match c["who"].as_str() {
                Some("all") => Who::All,
                Some("none") => Who::None,
                other => panic!("I6125 {name}: who {other:?}"),
            };
            let rows: Vec<ConferralRow> = rows_j
                .iter()
                .map(|r| ConferralRow {
                    id: id(r["id"].as_str().unwrap()),
                    kind: kind(r["kind"].as_str().unwrap())
                        .unwrap_or_else(|| panic!("I6125 {name}: a row kind the reader reads")),
                    names: r["names"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|n| id(n.as_str().unwrap()))
                        .collect(),
                    signer: r["signer"].as_str().unwrap().to_owned(),
                    head: r["head"].as_str().map(id),
                    target: r["target"].as_str().map(str::to_owned),
                    via: r["via"].as_str().map(id),
                    of: r["of"].as_str().map(id),
                    lifts: r["lifts"].as_bool().unwrap_or(false),
                })
                .collect();
            let acks: Vec<KId> = c["reader_acks"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| id(h.as_str().unwrap()))
                .collect();
            let got = answers(
                &rows,
                &Standing {
                    roles: &roles,
                    other_standing: c["other_standing"].as_bool().unwrap(),
                    who,
                    reader_acks: &acks,
                },
            );
            for (act, want) in c["answers"].as_object().unwrap() {
                let j = got
                    .get(&id(act))
                    .unwrap_or_else(|| panic!("I6125 {name}: no answer for {act}"));
                assert_eq!(
                    (j.counted, j.in_force, j.rule),
                    (
                        want["counted"].as_bool().unwrap(),
                        want["in_force"].as_bool().unwrap(),
                        want["rule"].as_str().unwrap()
                    ),
                    "I6125 {name}: {act}"
                );
                answers_run += 1;
                if reads_receipts {
                    receipt_answers += 1;
                }
            }
            run += 1;
        }
        assert_eq!(
            (run, answers_run, refused, receipts, receipt_answers),
            (30, 42, 3, 13, 18),
            "I6125: 30 cases (42 answers) run, 13 of them (18 answers) reading receipts or the \
             line; 3 refused at the door"
        );
    }

    /// I6126 (R2) — the persist shape: a later head is E3, every other
    /// placing (and an act with no comparable head) E2; the narrowest of
    /// several ends wins.
    #[test]
    fn i6126_judge_by_heads_and_narrowest() {
        assert_eq!(
            judge_by_heads(Some(Placing::ActLater)).rule,
            "E3.later_head"
        );
        for p in [Placing::Same, Placing::ActOlder, Placing::Concurrent] {
            let j = judge_by_heads(Some(p));
            assert!(
                j.counted && !j.in_force && j.rule == "E2.forward",
                "I6126: {p:?}"
            );
        }
        assert_eq!(judge_by_heads(None).rule, "E2.forward");
        let n = narrowest(&[
            Judged::of(true, true, "no_end"),
            Judged::of(true, false, "E2.forward"),
            Judged::of(false, false, "E3.later_head"),
        ])
        .unwrap();
        assert_eq!(
            (n.counted, n.in_force, n.rule),
            (false, false, "E3.later_head")
        );
        assert!(narrowest(&[]).is_none());
    }
}
