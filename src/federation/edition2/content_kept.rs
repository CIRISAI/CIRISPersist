//! v62.0.0 (CONTENT-K1; CC 2.4.1.1, the room-content rule R1–R12 as the
//! Constitution settled it after Kernel's run) — **room content after a
//! member's seat ends: which of the member's content rows are in the room's
//! content.**
//!
//! **A port of Kernel's rule pending its export; replaced by the crate at
//! the kernel pin.** The source is CIRISKernel PR #25, commit
//! [`KERNEL_REFERENCE_COMMIT`]:
//! - the reference `models/causal_kernel/conferral_content.py`;
//! - the fixture `crates/ciris-kernel/tests/fixtures/conferral_content.json`,
//!   which is a PROPOSAL fixture.
//!
//! The module is pure. It holds no persist type: no store, no door, no
//! `Error`, no instant, no arrival order. The answer is a function of the held
//! rows alone. Everything persist-specific lives OUTSIDE it, in the adapter:
//! - reading rows from the store;
//! - the `room_content` predicate;
//! - the stored kept set, a cache of this function's output;
//! - the door and the reads.
//!
//! The entry point is [`answers`] (a full recompute over a slice).
//! [`changed_by`] is its incremental form: the answers one arriving row
//! changes.
//!
//! The rule, as the reference states it:
//! 1. **A content row** names the roster head it is at. Its predecessors in
//!    the same author's series in the room are `refs.prev` and
//!    `refs.further_prev`, given here as one set. A series forks and may
//!    rejoin.
//! 2. **A row that ends the seat** names in `refs.trusted_through` the tips
//!    its signers hold. That row is a counted removal or the member's own
//!    resignation. A later COUNTED `membership:keeps` row adds tips to the
//!    end it cites. Tips are a set per member.
//! 3. **What is kept after an end:** a content row of the member is in the
//!    room's content when it is a tip that is read, or an ancestor of one
//!    along predecessors that are rows of the same author. An unheld
//!    predecessor is not followed until it is held.
//! 4. **An author's own retraction** of its own row takes the target out
//!    whenever it is signed. Another author's retraction is not read, and a
//!    retraction of a retraction restores nothing. An edit is a content row
//!    like any other.
//!
//! Whose tips are read is [`Merge`]. Persist builds [`Merge::CountFirst`]
//! (R7).
//!
//! `author` is the series identity the adapter supplies. In the fixture it
//! is the signing key (`B`, `B2`). Rule names are the fixture's spelling
//! ([`Rule::as_str`]).
//!
//! This is a reference shape for a test-sized slice: the causal past is
//! materialised per row.

use std::collections::{BTreeMap, BTreeSet};

/// The CIRISKernel commit whose reference and fixture this module follows
/// (PR #25, branch `conferral-content`).
pub const KERNEL_REFERENCE_COMMIT: &str = "892e4d2";

/// Who signed a row.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Signer {
    /// A counted row of the body: a roster version, a removal, a `keeps` row.
    Count,
    /// The member whose seat ends, as the series' author.
    Member(String),
}

/// What a composer content row does to its target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compose {
    /// An edit (`supersedes`): a content row like any other; no rule reads
    /// its target.
    Edit,
    /// A retraction (`withdraws` / `recants`): its author's retraction of its
    /// own row takes the target out whenever it is signed.
    Retract,
}

/// What a row is, with the members a rule reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A roster version. Its `names` are the heads it extends.
    Head,
    /// A content row of the member.
    Content {
        /// The roster head it names.
        head: String,
        /// Its predecessors: `refs.prev` and `refs.further_prev`, empty on a
        /// series' first row.
        prev: Vec<String>,
        /// For a composer, what it does and the row it composes on.
        composes: Option<(Compose, String)>,
    },
    /// An end of the member's seat: a counted removal or the member's own
    /// resignation.
    End {
        /// The roster head the end is at (h_e).
        head: String,
        /// The tips it holds good. Empty where its signers hold none. They
        /// are not in `names`: the end never waits on them.
        trusted_through: Vec<String>,
    },
    /// A `membership:keeps` row: further tips for the end it cites.
    Keeps {
        /// The roster head it is counted over. No rule here reads it.
        head: String,
        /// The end it adds to, which is also in `names`. No rule here reads
        /// it.
        cites: String,
        /// The further tips, not in `names`.
        trusted_through: Vec<String>,
    },
}

/// One held row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// The row id.
    pub id: String,
    /// Who signed it.
    pub signer: Signer,
    /// The ids it names CAUSALLY: its head, what it cites, a composer's
    /// target, and an end a row names. Predecessors and
    /// `refs.trusted_through` are not causal names here, because nothing
    /// waits on them.
    pub names: Vec<String>,
    /// What it is.
    pub kind: Kind,
}

/// Whose tips are read. Persist builds [`Merge::CountFirst`] (R7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Merge {
    /// The count's word.
    /// - Where a counted end counts, read the union of the tips of every
    ///   non-stale counted end and of every counted `keeps` row.
    /// - Where none counts, read the intersection of the member's own
    ///   counting ends, plus every counted `keeps` row. A further resignation
    ///   only narrows, and never narrows what a counted row named.
    /// - A `keeps` row signed by the member is never read.
    CountFirst,
    /// The proposal's third point read literally: the union of every
    /// counting end, the member's own included, and every counted `keeps`
    /// row.
    Union,
    /// [`Merge::CountFirst`], but where only the member's own ends speak, the
    /// union of them.
    CountFirstSelfUnion,
}

impl Merge {
    /// The fixture's token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Merge::CountFirst => "count_first",
            Merge::Union => "union",
            Merge::CountFirstSelfUnion => "count_first_self_union",
        }
    }

    /// The merge a fixture token names.
    #[must_use]
    pub fn from_token(t: &str) -> Option<Self> {
        [Merge::CountFirst, Merge::Union, Merge::CountFirstSelfUnion]
            .into_iter()
            .find(|m| m.as_str() == t)
    }
}

/// Why an end concludes nothing. Whether an end counts is decided by its own
/// causal past alone (R8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EndVoid {
    /// E1: the end has a head later than its h_e in its own past.
    StaleHead,
    /// The end has a counting end of the seat in its own past.
    SeatEnded,
}

/// The rule that decides a content row, in the order they decide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    /// E4: the row has a counting end in its past: not counted.
    NamesEnd,
    /// E3: the row names a head that has a counting end's h_e in its past.
    LaterHead,
    /// W: its author retracted it: counted, not in the room's content.
    Retracted,
    /// No end counts: counted and in force.
    NoEnd,
    /// Counted and in force: a tip that is read, or its ancestor.
    HeldGood,
    /// E2: counted at its own head, not in force: not held good.
    Forward,
}

impl Rule {
    /// The fixture's spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Rule::NamesEnd => "E4.names_end",
            Rule::LaterHead => "E3.later_head",
            Rule::Retracted => "W.retracted",
            Rule::NoEnd => "no_end",
            Rule::HeldGood => "T.held_good",
            Rule::Forward => "E2.forward",
        }
    }
}

/// One content row's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Answer {
    /// Counted at its own head.
    pub counted: bool,
    /// In the room's content now.
    pub in_force: bool,
    /// The rule that decided it.
    pub rule: Rule,
}

/// The held rows by id, with each row's causal past: every id it names,
/// transitively through the held rows. A named id that is not held is in
/// the past but adds nothing further.
struct Held<'a> {
    by: BTreeMap<&'a str, &'a Row>,
    past: BTreeMap<&'a str, BTreeSet<&'a str>>,
}

impl<'a> Held<'a> {
    fn new(rows: &'a [Row]) -> Self {
        let by: BTreeMap<&str, &Row> = rows.iter().map(|r| (r.id.as_str(), r)).collect();
        // Iterative post-order: a row's past is computed after the pasts of
        // the held rows it names. A cycle, impossible for content-addressed
        // ids, is cut where it closes.
        let mut past: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        let mut open: BTreeSet<&str> = BTreeSet::new();
        for &root in by.keys() {
            let mut stack: Vec<(&str, bool)> = vec![(root, false)];
            while let Some((i, expanded)) = stack.pop() {
                if past.contains_key(i) {
                    continue;
                }
                let row: &'a Row = by[i];
                if expanded {
                    let mut out = BTreeSet::new();
                    for n in &row.names {
                        out.insert(n.as_str());
                        if let Some(a) = past.get(n.as_str()) {
                            out.extend(a.iter().copied());
                        }
                    }
                    open.remove(i);
                    past.insert(i, out);
                } else if open.insert(i) {
                    stack.push((i, true));
                    for n in &row.names {
                        let n = n.as_str();
                        if by.contains_key(n) && !past.contains_key(n) && !open.contains(n) {
                            stack.push((n, false));
                        }
                    }
                }
            }
        }
        Self { by, past }
    }

    fn in_past(&self, of: &str, id: &str) -> bool {
        self.past.get(of).is_some_and(|p| p.contains(id))
    }

    fn ends(&self) -> impl Iterator<Item = &'a Row> + '_ {
        self.by
            .values()
            .copied()
            .filter(|r| matches!(r.kind, Kind::End { .. }))
    }
}

fn head_of(r: &Row) -> &str {
    match &r.kind {
        Kind::Content { head, .. } | Kind::End { head, .. } | Kind::Keeps { head, .. } => {
            head.as_str()
        }
        Kind::Head => "",
    }
}

fn tips_of(r: &Row) -> &[String] {
    match &r.kind {
        Kind::End {
            trusted_through, ..
        }
        | Kind::Keeps {
            trusted_through, ..
        } => trusted_through,
        Kind::Head | Kind::Content { .. } => &[],
    }
}

/// Every held end: `None` when it counts, else why it is void.
fn counting_ends(h: &Held<'_>) -> BTreeMap<String, Option<EndVoid>> {
    // The ids are content-addressed, so the names form a DAG, and an end in
    // another end's past has a strictly smaller past. Deciding ends by the
    // size of their past therefore decides every end after the ends in its
    // own past.
    let mut ends: Vec<&Row> = h.ends().collect();
    ends.sort_by_key(|e| {
        (
            h.past.get(e.id.as_str()).map_or(0, BTreeSet::len),
            e.id.clone(),
        )
    });
    let mut void: BTreeMap<String, Option<EndVoid>> = BTreeMap::new();
    for e in ends {
        let past = h.past.get(e.id.as_str()).cloned().unwrap_or_default();
        let he = head_of(e);
        let stale = past.iter().any(|&x| {
            h.by.get(x).is_some_and(|r| matches!(r.kind, Kind::Head)) && h.in_past(x, he)
        });
        let v = if stale {
            Some(EndVoid::StaleHead)
        } else if past
            .iter()
            .any(|&o| o != e.id && void.get(o).is_some_and(Option::is_none))
        {
            Some(EndVoid::SeatEnded)
        } else {
            None
        };
        void.insert(e.id.clone(), v);
    }
    void
}

/// The content rows a row's tips hold good. These are each named tip that
/// is held and is a content row of the member, and its ancestors along every
/// predecessor that is a held row of the same author.
fn held_good(h: &Held<'_>, r: &Row) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    let mut todo: Vec<&str> = tips_of(r).iter().map(String::as_str).collect();
    while let Some(t) = todo.pop() {
        let Some(x) = h.by.get(t) else { continue };
        let Kind::Content { prev, .. } = &x.kind else {
            continue;
        };
        if !matches!(x.signer, Signer::Member(_)) || !out.insert(t.to_owned()) {
            continue;
        }
        // The walk stays in one author's series; an unheld predecessor is
        // not followed until it is held.
        for q in prev {
            if h.by.get(q.as_str()).is_some_and(|p| p.signer == x.signer) {
                todo.push(q.as_str());
            }
        }
    }
    out
}

fn union_of(h: &Held<'_>, rs: &[&Row]) -> BTreeSet<String> {
    rs.iter().flat_map(|r| held_good(h, r)).collect()
}

/// The rows held good by the tips that are read under `merge`.
fn kept(h: &Held<'_>, void: &BTreeMap<String, Option<EndVoid>>, merge: Merge) -> BTreeSet<String> {
    let ends: Vec<&Row> = h.ends().collect();
    let counts: Vec<&Row> = ends
        .iter()
        .copied()
        .filter(|e| void.get(&e.id).is_some_and(Option::is_none))
        .collect();
    let c_ends: Vec<&Row> = ends
        .iter()
        .copied()
        .filter(|e| {
            e.signer == Signer::Count
                && void.get(&e.id).copied().flatten() != Some(EndVoid::StaleHead)
        })
        .collect();
    let own: Vec<&Row> = counts
        .iter()
        .copied()
        .filter(|e| matches!(e.signer, Signer::Member(_)))
        .collect();
    let adds: Vec<&Row> =
        h.by.values()
            .copied()
            .filter(|r| matches!(r.kind, Kind::Keeps { .. }) && r.signer == Signer::Count)
            .collect();
    let with_adds = |base: &[&Row]| {
        let mut all: Vec<&Row> = base.to_vec();
        all.extend(adds.iter().copied());
        union_of(h, &all)
    };
    if merge == Merge::Union {
        return with_adds(&counts);
    }
    if counts.iter().any(|e| e.signer == Signer::Count) {
        return with_adds(&c_ends);
    }
    if merge == Merge::CountFirstSelfUnion {
        return with_adds(&own);
    }
    let mut good = own.iter().map(|e| held_good(h, e));
    let mut out = match good.next() {
        Some(first) => good.fold(first, |acc, g| acc.intersection(&g).cloned().collect()),
        None => BTreeSet::new(),
    };
    out.extend(union_of(h, &adds));
    out
}

/// **THE ENTRY POINT: every content row's answer over the held `rows`.**
/// For each row it gives whether the row is counted at its own head,
/// whether it is in the room's content now, and the rule that decides it.
/// A full recompute; [`changed_by`] is the incremental form.
#[must_use]
pub fn answers(rows: &[Row], merge: Merge) -> BTreeMap<String, Answer> {
    let h = Held::new(rows);
    let void = counting_ends(&h);
    let ends: Vec<&Row> = h
        .ends()
        .filter(|e| void.get(&e.id).is_some_and(Option::is_none))
        .collect();
    let good = kept(&h, &void, merge);
    // W.retracted: an author's retraction of its own HELD row, whether or
    // not the retraction itself counts.
    let retracted: BTreeSet<&str> =
        h.by.values()
            .filter_map(|r| match &r.kind {
                Kind::Content {
                    composes: Some((Compose::Retract, target)),
                    ..
                } if h
                    .by
                    .get(target.as_str())
                    .is_some_and(|t| t.signer == r.signer) =>
                {
                    Some(target.as_str())
                }
                _ => None,
            })
            .collect();
    let mut out = BTreeMap::new();
    for r in h.by.values().copied() {
        let Kind::Content { head, .. } = &r.kind else {
            continue;
        };
        let (counted, in_force, rule) = if ends.iter().any(|e| h.in_past(&r.id, &e.id)) {
            (false, false, Rule::NamesEnd)
        } else if ends.iter().any(|e| h.in_past(head, head_of(e))) {
            (false, false, Rule::LaterHead)
        } else if retracted.contains(r.id.as_str()) {
            (true, false, Rule::Retracted)
        } else if ends.is_empty() {
            (true, true, Rule::NoEnd)
        } else if good.contains(&r.id) {
            (true, true, Rule::HeldGood)
        } else {
            (true, false, Rule::Forward)
        };
        out.insert(
            r.id.clone(),
            Answer {
                counted,
                in_force,
                rule,
            },
        );
    }
    out
}

/// **The incremental form**: the answers `arriving` changes when it joins
/// the held `rows`, with each row's new answer. The arriving row's own
/// answer is included when it is a content row. Today this is two full
/// recomputes and their difference, so it equals [`answers`] by
/// construction. Kernel's incremental step replaces it at the kernel pin.
#[must_use]
pub fn changed_by(rows: &[Row], arriving: &Row, merge: Merge) -> BTreeMap<String, Answer> {
    let before = answers(rows, merge);
    let mut with: Vec<Row> = rows.to_vec();
    with.push(arriving.clone());
    answers(&with, merge)
        .into_iter()
        .filter(|(id, a)| before.get(id) != Some(a))
        .collect()
}

#[cfg(test)]
mod tests {
    //! I6700–I6702 replay Kernel's PROPOSAL fixture for the room-content
    //! rule: CIRISKernel PR #25,
    //! `crates/ciris-kernel/tests/fixtures/conferral_content.json` at
    //! [`super::KERNEL_REFERENCE_COMMIT`]. It is vendored at
    //! `tests/vectors/kernel/conferral_content.json` and pinned by sha256. A
    //! re-pin changes the bytes, the pin and the counts together.
    use super::{answers, changed_by, Compose, Kind, Merge, Row, Signer};
    use serde_json::Value;
    use sha2::Digest as _;
    use std::collections::{BTreeMap, BTreeSet};

    const FIXTURE: &str = include_str!("../../../tests/vectors/kernel/conferral_content.json");
    const FIXTURE_SHA256: &str = "71616d724807e213e47410c877264c67e5a2ea00d34b7b5dad1e66e1a1e81964";
    const CASES: usize = 39;
    const ANSWERS: usize = 90;

    fn text(v: &Value, k: &str) -> String {
        v[k].as_str()
            .unwrap_or_else(|| panic!("{k} is not text in {v}"))
            .to_owned()
    }

    fn list(v: &Value, k: &str) -> Vec<String> {
        v[k].as_array()
            .unwrap_or_else(|| panic!("{k} is not a list in {v}"))
            .iter()
            .map(|x| x.as_str().expect("an id").to_owned())
            .collect()
    }

    fn row(v: &Value) -> Row {
        let signer = match text(v, "signer").as_str() {
            "count" => Signer::Count,
            k => Signer::Member(k.to_owned()),
        };
        let mut names = list(v, "names");
        let kind = match text(v, "kind").as_str() {
            "head" => Kind::Head,
            "act" => {
                let prev = list(v, "prev");
                // At 892e4d2 an act still lists its predecessors in `names`
                // (the door then waited on them). Here `names` is causal
                // (head, cites, target), so they are taken out.
                names.retain(|n| !prev.contains(n));
                let composes = match v["compose"].as_str() {
                    None => None,
                    Some("edit") => Some((Compose::Edit, text(v, "target"))),
                    Some("retract") => Some((Compose::Retract, text(v, "target"))),
                    Some(other) => panic!("unknown compose {other}"),
                };
                Kind::Content {
                    head: text(v, "head"),
                    prev,
                    composes,
                }
            }
            "end" => Kind::End {
                head: text(v, "head"),
                trusted_through: list(v, "trusted_through"),
            },
            "tips" => Kind::Keeps {
                head: text(v, "head"),
                cites: text(v, "extends"),
                trusted_through: list(v, "trusted_through"),
            },
            other => panic!("unknown row kind {other}"),
        };
        Row {
            id: text(v, "id"),
            signer,
            names,
            kind,
        }
    }

    struct Case {
        name: String,
        merge: Merge,
        rows: Vec<Row>,
        orders: Vec<Vec<String>>,
        want: BTreeMap<String, (bool, bool, String)>,
    }

    fn cases() -> Vec<Case> {
        assert_eq!(
            hex::encode(sha2::Sha256::digest(FIXTURE.as_bytes())),
            FIXTURE_SHA256,
            "the vendored Kernel fixture is not the pinned bytes"
        );
        let doc: Value = serde_json::from_str(FIXTURE).expect("the fixture parses");
        doc["cases"]
            .as_array()
            .expect("cases")
            .iter()
            .map(|c| {
                assert!(c["refused"].is_null(), "{}: refused is not null", c["name"]);
                Case {
                    name: text(c, "name"),
                    merge: Merge::from_token(&text(c, "merge")).expect("a known merge"),
                    rows: c["rows"]
                        .as_array()
                        .expect("rows")
                        .iter()
                        .map(row)
                        .collect(),
                    orders: c["orders"]
                        .as_array()
                        .expect("orders")
                        .iter()
                        .map(|o| {
                            o.as_array()
                                .expect("an order")
                                .iter()
                                .map(|x| x.as_str().expect("an id").to_owned())
                                .collect()
                        })
                        .collect(),
                    want: c["answers"]
                        .as_object()
                        .expect("answers")
                        .iter()
                        .map(|(id, a)| {
                            (
                                id.clone(),
                                (
                                    a["counted"].as_bool().expect("counted"),
                                    a["in_force"].as_bool().expect("in_force"),
                                    text(a, "rule"),
                                ),
                            )
                        })
                        .collect(),
                }
            })
            .collect()
    }

    fn got(rows: &[Row], merge: Merge) -> BTreeMap<String, (bool, bool, String)> {
        answers(rows, merge)
            .into_iter()
            .map(|(id, a)| (id, (a.counted, a.in_force, a.rule.as_str().to_owned())))
            .collect()
    }

    fn in_force(rows: &[Row], merge: Merge) -> BTreeSet<String> {
        answers(rows, merge)
            .into_iter()
            .filter(|(_, a)| a.in_force)
            .map(|(id, _)| id)
            .collect()
    }

    /// **I6700 (v62.0.0, CONTENT-K1.rev2; PROPOSAL)** — every answer of every
    /// case of Kernel's fixture, under the case's own merge: 39 cases and 90
    /// answers, with no divergence. Every `union` case differs from its
    /// `count_first` twin over the same rows, exactly as the twin says.
    #[test]
    fn i6700_the_kept_set_replays_kernels_conferral_content_fixture() {
        let all = cases();
        assert_eq!(all.len(), CASES, "the fixture's case count");
        assert_eq!(
            all.iter().map(|c| c.want.len()).sum::<usize>(),
            ANSWERS,
            "the fixture's answer count"
        );
        for c in &all {
            assert_eq!(got(&c.rows, c.merge), c.want, "case {}", c.name);
        }
        let unions: Vec<&Case> = all.iter().filter(|c| c.merge == Merge::Union).collect();
        assert!(!unions.is_empty(), "the fixture has a union case");
        for u in unions {
            let twin_name = u
                .name
                .strip_suffix("_union")
                .unwrap_or_else(|| panic!("{}: a union case names its twin", u.name));
            let twin = all
                .iter()
                .find(|c| c.name == twin_name && c.merge == Merge::CountFirst)
                .unwrap_or_else(|| panic!("{}: no count_first twin", u.name));
            let under_count_first = got(&u.rows, Merge::CountFirst);
            assert_eq!(
                under_count_first, twin.want,
                "{}: count_first over its rows",
                u.name
            );
            assert_ne!(under_count_first, u.want, "{}: union differs", u.name);
        }
    }

    /// **I6701 (v62.0.0, CONTENT-K1.rev2; PROPOSAL)** — two properties.
    /// - The answer is a function of the held set: it is the same in every
    ///   arrival order the fixture lists.
    /// - Tips only grow: removing any counted `keeps` row never puts a row in
    ///   the room's content that the full set leaves out.
    #[test]
    fn i6701_order_is_not_read_and_keeps_rows_only_add() {
        let mut keeps_rows = 0;
        for c in cases() {
            let full = got(&c.rows, c.merge);
            let by: BTreeMap<&str, &Row> = c.rows.iter().map(|r| (r.id.as_str(), r)).collect();
            for order in &c.orders {
                let permuted: Vec<Row> = order.iter().map(|i| by[i.as_str()].clone()).collect();
                assert_eq!(
                    permuted.len(),
                    c.rows.len(),
                    "{}: an order names every row",
                    c.name
                );
                assert_eq!(got(&permuted, c.merge), full, "{}: order {order:?}", c.name);
            }
            let with = in_force(&c.rows, c.merge);
            for (i, r) in c.rows.iter().enumerate() {
                if !matches!(r.kind, Kind::Keeps { .. }) {
                    continue;
                }
                keeps_rows += 1;
                let mut less = c.rows.clone();
                less.remove(i);
                let without = in_force(&less, c.merge);
                assert!(
                    without.is_subset(&with),
                    "{}: dropping {} shows {without:?} ⊄ {with:?}",
                    c.name,
                    r.id
                );
            }
        }
        assert!(keeps_rows > 0, "the property was exercised");
    }

    /// **I6702 (v62.0.0, CONTENT-K1.rev2)** — the incremental form equals the
    /// full recompute. For every case and every listed order, applying each
    /// arriving row's `changed_by` to the running answers gives exactly
    /// `answers` over the rows held so far.
    #[test]
    fn i6702_the_incremental_form_equals_the_full_recompute() {
        for c in cases() {
            let by: BTreeMap<&str, &Row> = c.rows.iter().map(|r| (r.id.as_str(), r)).collect();
            for order in &c.orders {
                let mut held: Vec<Row> = Vec::new();
                let mut running = answers(&held, c.merge);
                for id in order {
                    let r = by[id.as_str()];
                    running.extend(changed_by(&held, r, c.merge));
                    held.push(r.clone());
                    assert_eq!(running, answers(&held, c.merge), "{}: after {id}", c.name);
                }
            }
        }
    }
}
