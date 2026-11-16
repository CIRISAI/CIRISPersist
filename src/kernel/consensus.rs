//! v62.0.0 (slice C) — **a ballot as rows**: persist's
//! [`Ballot`](crate::federation::consensus::Ballot) presented to the kernel's
//! seat rule (`ciris_kernel::seat::seat_rule`, the `Conf::Group` arm).
//!
//! The kernel counts over the head a counted row names, never a roster read
//! at receipt (CC 6.1.8 N1). A ballot carries the roster persist resolved at
//! the change's instant; the adapter presents it as the head:
//!
//! | row | kind | what it says |
//! |---|---|---|
//! | `G` | founding offer, its own object | seats every eligible PERSON in `member`; each signs it (both consents) |
//! | `F` | offer over `G`, conferred by `G`'s own key | seats the founders in `founder` (the counted scope of `founder_only` and of an `infrastructure` group) |
//! | `C` | offer (`Add`) or unseat (`Remove`), `Conf::Group` over `G` | counted at the head `[F]` (or `[G]`), its voices the signers' persons, its `to` the person it names |
//!
//! **Persons, not keys** (KERNEL.md 7b; CC 4.5.13 `CLM-vote-once-per-person`):
//! each seat is presented as its person (`PersonsAt::seat_person`) and each
//! signature as its person's voice (`PersonsAt::voice`), so the kernel's count
//! of distinct keys is the count of persons. A person's representative seat
//! (its role, its weight) is persist's `eligible` choice: a founder's seat,
//! else the lowest key.
//!
//! **What stays persist's** — the shape of the protocol string (a malformed
//! `quorum:`, an undeclared rubric, `open:self_admit` off a `public` group),
//! which is a refusal of the record before any count (KERNEL_SEAMS §8: "the
//! right to refuse malformed input"), and the lineage's high-water latch
//! (CC 4.4.3.4.2.1), which persist folds and passes as the declared `need`.

use super::law::{seat_law, SEAT_FOUNDER, SEAT_MEMBER};
use super::view::{KRow, NoCut, RowId, SeatFields};
use super::Answer;
use crate::federation::consensus::{
    eligible_seats, quorum_need, Ballot, Direction, RUBRIC_UNIFORM_HALF,
};
use crate::federation::types::consensus_protocol as cp;
use ciris_kernel::layers;
use ciris_kernel::seat::{seat_rule, Conf, Obj, SeatKind};
use serde_json::Value;
use std::collections::BTreeSet;

/// Why the kernel has no cell for a ballot's protocol. Every one is a
/// refusal of the protocol, never a count that fell short.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoCell {
    /// `reverse_quorum:*` — CC 3.2: "Not a membership rule: reverse quorum.
    /// … It admits no one and confers no consent on anyone's behalf."
    ReverseQuorum,
    /// `custom:*` — CC 4.4.3.6's protocol table has six arms and no
    /// `custom:`; CC 3.3.4's canonical kinds are those six.
    Custom,
    /// A `weighted:` rubric whose weight or threshold is not a whole number,
    /// or that declares `threshold_fraction` — CC 3.3.4: "Each weight and the
    /// threshold is a whole number carried on the group's signed record."
    NotWhole(String),
    /// The protocol string or its declaration is malformed (persist's shape
    /// refusal, unchanged).
    Malformed(String),
}

/// The arm a ballot is counted under, with what the counted row declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arm {
    /// The policy word of the kernel's table ([`super::law::ARMS`]).
    pub word: &'static str,
    /// The scope counted: `founder` for `founder_only` and an
    /// `infrastructure` group, `member` otherwise.
    pub counted: &'static str,
    /// The declared threshold (`quorum`, `weighted`).
    pub need: Option<usize>,
    /// The whole-number weight of each eligible person (`weighted`).
    pub weights: Vec<(String, u64)>,
}

/// A JSON number as a whole number, or why not.
fn whole(v: &Value, what: &str, rubric: &str) -> Result<u64, NoCell> {
    v.as_u64().ok_or_else(|| {
        NoCell::NotWhole(format!(
            "weighted:{rubric}: the {what} {v} is not a whole number (CC 3.3.4)"
        ))
    })
}

/// The arm of a ballot's protocol, read from the string and the group's
/// signed record alone; the persons are the ballot's eligible ones.
pub fn arm_of(b: &Ballot<'_>) -> Result<Arm, NoCell> {
    arm_over(b, &eligible_seats(b))
}

/// [`arm_of`] over the eligible seats the caller already resolved.
fn arm_over(b: &Ballot<'_>, elig: &[&crate::federation::consensus::Seat]) -> Result<Arm, NoCell> {
    let p = b.protocol;
    let infra = b.subkind == Some("infrastructure");
    let counted = if infra { SEAT_FOUNDER } else { SEAT_MEMBER };
    let n = elig.len();
    let arm = |word, counted, need| {
        Ok(Arm {
            word,
            counted,
            need,
            weights: Vec::new(),
        })
    };
    if p == cp::FOUNDER_ONLY {
        return arm("founder_only", SEAT_FOUNDER, None);
    }
    if p == cp::OPEN_SELF_ADMIT {
        if b.subkind != Some(crate::federation::public_room::COHORT_SUBKIND_PUBLIC) {
            return Err(NoCell::Malformed(format!(
                "{} is admissible only on a public group (CC 4.4.3.2)",
                cp::OPEN_SELF_ADMIT
            )));
        }
        return arm("open:self_admit", counted, None);
    }
    if p == cp::UNANIMOUS {
        return arm("unanimous", counted, None);
    }
    if p == cp::MAJORITY {
        return arm("majority", counted, None);
    }
    if p.starts_with(cp::REVERSE_QUORUM_PREFIX) {
        return Err(NoCell::ReverseQuorum);
    }
    if p.starts_with(cp::CUSTOM_PREFIX) {
        return Err(NoCell::Custom);
    }
    if let Some(tail) = p.strip_prefix(cp::QUORUM_PREFIX) {
        let Some((m, _)) = crate::federation::consensus::parse_quorum_tail(tail) else {
            return Err(NoCell::Malformed(format!("malformed quorum form {p:?}")));
        };
        return arm(
            "quorum",
            counted,
            Some(quorum_need(m as usize, n, b.high_water, b.subkind)),
        );
    }
    if let Some(rubric) = p.strip_prefix(cp::WEIGHTED_PREFIX) {
        let person =
            |s: &crate::federation::consensus::Seat| b.persons.seat_person(&s.key_id).to_owned();
        if rubric == RUBRIC_UNIFORM_HALF {
            return Ok(Arm {
                word: "weighted",
                counted,
                need: Some(n.div_ceil(2)),
                weights: elig.iter().map(|s| (person(s), 1)).collect(),
            });
        }
        let Some(decl) = b
            .policy_blob
            .and_then(|pb| pb.get("rubrics"))
            .and_then(|r| r.get(rubric))
        else {
            return Err(NoCell::Malformed(format!(
                "weighted:{rubric} is not declared in the group record's policy_blob.rubrics"
            )));
        };
        if decl.get("threshold_fraction").is_some() {
            return Err(NoCell::NotWhole(format!(
                "weighted:{rubric}: threshold_fraction is not a whole-number threshold (CC 3.3.4)"
            )));
        }
        let Some(t) = decl.get("threshold") else {
            return Err(NoCell::Malformed(format!(
                "weighted:{rubric} must declare a threshold"
            )));
        };
        let t = whole(t, "threshold", rubric)?;
        if t == 0 {
            return Err(NoCell::Malformed(format!(
                "weighted:{rubric} threshold must be positive"
            )));
        }
        let weights = decl.get("weights").cloned().unwrap_or(Value::Null);
        let default = match decl.get("default_weight") {
            Some(d) => whole(d, "default_weight", rubric)?,
            None => 0,
        };
        let mut ws = Vec::with_capacity(n);
        for s in elig {
            let w = weights.get(&s.key_id).or_else(|| {
                s.role
                    .as_deref()
                    .and_then(|r| weights.get(format!("role:{r}")))
            });
            let w = match w {
                Some(w) => whole(w, "weight", rubric)?,
                None => default,
            };
            ws.push((person(s), w));
        }
        let need = usize::try_from(t)
            .map_err(|_| NoCell::Malformed(format!("weighted:{rubric} threshold overflows")))?;
        return Ok(Arm {
            word: "weighted",
            counted,
            need: Some(need),
            weights: ws,
        });
    }
    Err(NoCell::Malformed(format!(
        "{p:?} is not a canonical consensus_protocol form"
    )))
}

/// The placeholder signer of a counted row no eligible person signed: a key
/// no seat holds, so it is no voice.
const NO_VOICE: &str = "\u{2205}no-voice";

/// The rows a ballot is presented as (`G`, `F`, `C`), `C` last.
pub fn ballot_rows(b: &Ballot<'_>, arm: &Arm) -> Vec<KRow> {
    let elig = eligible_seats(b);
    let infra = b.subkind == Some("infrastructure");
    let person = |k: &str| b.persons.seat_person(k).to_owned();
    let members: Vec<String> = elig
        .iter()
        .map(|s| person(&s.key_id))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    // the founders: the eligible persons whose representative seat is a
    // founder's; under `infrastructure` the eligible set is already founders
    // that are not node-bearing (CC 3.2 "Infrastructure does not vote")
    let founders: Vec<String> = elig
        .iter()
        .filter(|s| {
            infra || s.role.as_deref() == Some(crate::federation::consensus::MEMBER_ROLE_FOUNDER)
        })
        .map(|s| person(&s.key_id))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    // the ballot's graph is the adapter's alone: synthetic ids, no digests
    let gid = RowId::synthetic(0, 0);
    let mut next: u32 = 0;
    let mut rows = Vec::with_capacity(members.len() + founders.len() + 3);
    // `G` founds the group and seats its own signer; every other seat is its
    // own offer over `G` by `G`'s key, the seated person's signature on it
    // the acceptance. One offer per seat keeps each row's signer set small:
    // the kernel's seat walk reads an offer's signers once per key it seats
    // (`seat::signers` per `accepted` call), so one offer seating every
    // member is quadratic in the roster.
    let g_signer = members
        .first()
        .cloned()
        .unwrap_or_else(|| NO_VOICE.to_owned());
    rows.push(
        KRow::new(gid, Vec::new(), g_signer.clone()).with_seat(SeatFields {
            to: vec![g_signer.clone()],
            scope: Some(SEAT_MEMBER.into()),
            obj: Some(Obj::Row(gid)),
            conf: Some(Conf::Own),
            ..SeatFields::of(SeatKind::Offer)
        }),
    );
    let mut seat_of: std::collections::BTreeMap<&str, RowId> = std::collections::BTreeMap::new();
    seat_of.insert(g_signer.as_str(), gid);
    let mut version_names = vec![gid];
    for (scope, keys) in [(SEAT_MEMBER, &members), (SEAT_FOUNDER, &founders)] {
        for k in keys.iter() {
            if scope == SEAT_MEMBER && *k == g_signer {
                continue;
            }
            next += 1;
            let id = RowId::synthetic(1, next);
            if scope == SEAT_MEMBER {
                seat_of.insert(k.as_str(), id);
            }
            version_names.push(id);
            rows.push(
                KRow::new(id, vec![gid], g_signer.clone()).with_seat(SeatFields {
                    to: vec![k.clone()],
                    scope: Some(scope.into()),
                    obj: Some(Obj::Row(gid)),
                    conf: Some(Conf::Own),
                    cosigners: if *k == g_signer {
                        Vec::new()
                    } else {
                        vec![k.clone()]
                    },
                    ..SeatFields::of(SeatKind::Offer)
                }),
            );
        }
    }
    // `V`: the roster version, the head the counted row names (it names
    // every seat, so every seat is in the head's past)
    let head = RowId::synthetic(2, 0);
    rows.push(KRow::new(head, version_names, g_signer.clone()));
    // the voices: each verified signer's person, once
    let voices: Vec<String> = b
        .signers
        .iter()
        .filter_map(|k| b.persons.voice(k))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let (c_signer, c_rest) = match voices.split_first() {
        Some((s, rest)) => (s.clone(), rest.to_vec()),
        None => (NO_VOICE.to_owned(), Vec::new()),
    };
    let to: Vec<String> = b.subject.map(|s| vec![person(s)]).unwrap_or_default();
    let cid = RowId::synthetic(3, 0);
    // a removal its subject alone signs is the member's own leaving: CC
    // 3.3.4's `membership:resignation`, a withdrawal by the member of the
    // offer that seats it, which ends its seat alone (DIFFERENCES.md 5a)
    if b.direction == Direction::Remove && to.len() == 1 && voices == to && members.contains(&to[0])
    {
        let target = seat_of.get(to[0].as_str()).copied().unwrap_or(gid);
        rows.push(
            KRow::new(cid, vec![head, target], c_signer).with_seat(SeatFields {
                target: Some(target),
                ..SeatFields::of(SeatKind::Withdraw)
            }),
        );
        return rows;
    }
    rows.push(KRow::new(cid, vec![head], c_signer).with_seat(SeatFields {
        to,
        scope: Some(SEAT_MEMBER.into()),
        obj: Some(Obj::Row(gid)),
        conf: Some(Conf::Group),
        cosigners: c_rest,
        head: vec![head],
        policy: Some(arm.word.to_owned()),
        counted: Some(arm.counted.to_owned()),
        need: arm.need,
        weights: arm.weights.clone(),
        ..SeatFields::of(if b.direction == Direction::Add {
            SeatKind::Offer
        } else {
            SeatKind::Unseat
        })
    }));
    rows
}

/// **The kernel's answer to a ballot**: does the counted row conclude under
/// the seat rule, at the head it names? `Err` when the protocol has no cell.
///
/// The answer is the seat rule's `Conf::Group` count over the roster the
/// ballot resolved ([`count`]), with the kernel's own threshold arithmetic
/// (`seat::met`). Building the ballot's row graph and walking it
/// ([`admits_by_rows`]) gives the same answer at 20–60× the cost (the
/// kernel builds a graph and a seat walk per head it counts over), so the
/// row graph is the witness, not the path: under test every call is answered
/// both ways and the two must agree (I1844).
pub fn admits(b: &Ballot<'_>) -> Result<Answer<bool>, NoCell> {
    let elig = eligible_seats(b);
    let arm = arm_over(b, &elig)?;
    Ok(Answer {
        value: count_over(b, &arm, &elig),
        rows: Vec::new(),
        rule: "seat::seat_rule/Conf::Group (count over the resolved head)",
    })
}

/// [`admits`] over the eligible seats the caller already resolved
/// (`consensus::eligible`): persist's evaluator resolves them once.
pub(crate) fn admits_over<'a>(
    b: &Ballot<'a>,
    elig: &[&'a crate::federation::consensus::Seat],
) -> Result<bool, NoCell> {
    let arm = arm_over(b, elig)?;
    Ok(count_over(b, &arm, elig))
}

/// The ballot's row graph, walked by the kernel's seat rule: the counted row
/// concludes or does not ([`ballot_rows`]).
pub fn admits_by_rows(b: &Ballot<'_>) -> Result<Answer<bool>, NoCell> {
    let arm = arm_of(b)?;
    let rows = ballot_rows(b, &arm);
    let law = seat_law();
    let c = layers::conclude(rows.iter(), |p| seat_rule(p, law, &NoCut, &|_| true), None);
    let counted = rows.last().expect("the counted row is last").id;
    Ok(Answer {
        value: c.concluded_id(&counted),
        rows: rows.iter().map(|r| r.id).collect(),
        rule: "seat::seat_rule/Conf::Group",
    })
}

/// The seat rule's `Conf::Group` arm (`ciris_kernel::seat::seat_rule`) over
/// the members the ballot resolved at the head, as persons: the counted
/// scope's members, the voices (each verified signer's person), and the
/// person the change names, who is no voice of its own count (CC 2.7.5). A
/// removal its subject alone signs is the member's own leaving (CC 3.3.4).
/// The four count cells use the kernel's `seat::met`; `unanimous`,
/// `open:self_admit` and `weighted` read as the seat rule reads them.
#[must_use]
pub fn count(b: &Ballot<'_>, arm: &Arm) -> bool {
    count_over(b, arm, &eligible_seats(b))
}

/// [`count`] over the eligible seats the caller already resolved.
fn count_over<'a>(
    b: &Ballot<'a>,
    arm: &Arm,
    elig: &[&'a crate::federation::consensus::Seat],
) -> bool {
    use ciris_kernel::seat::{met, Policy};
    let infra = b.subkind == Some("infrastructure");
    let person = |k: &'a str| -> &'a str { b.persons.seat_person(k) };
    // one seat per person already (`eligible_seats`): sorted vectors, not sets
    let sorted = |mut v: Vec<&'a str>| {
        v.sort_unstable();
        v.dedup();
        v
    };
    let members = sorted(elig.iter().map(|s| person(s.key_id.as_str())).collect());
    let founders;
    let mem: &[&str] = if arm.counted == SEAT_FOUNDER {
        founders = sorted(
            elig.iter()
                .filter(|s| {
                    infra
                        || s.role.as_deref()
                            == Some(crate::federation::consensus::MEMBER_ROLE_FOUNDER)
                })
                .map(|s| person(s.key_id.as_str()))
                .collect(),
        );
        &founders
    } else {
        &members
    };
    let seated = |k: &str| mem.binary_search(&k).is_ok();
    let v = sorted(
        b.signers
            .iter()
            .filter_map(|k| b.persons.voice(k))
            .collect(),
    );
    let voiced = |k: &str| v.binary_search(&k).is_ok();
    let to: Option<&str> = b.subject.map(person);
    let named = |k: &str| to == Some(k);
    if b.direction == Direction::Remove {
        if let Some(t) = to {
            if v.len() == 1 && v[0] == t && members.binary_search(&t).is_ok() {
                return true; // the member's own leaving
            }
        }
    }
    let is_offer = b.direction == Direction::Add;
    let pol = seat_law().policy.get(arm.word).copied();
    // the yes voices: signers' persons seated in the counted scope, the
    // person the change names not among them (CC 2.7.5)
    let yes = || v.iter().copied().filter(|k| seated(k) && !named(k));
    match pol {
        Some(Policy::SelfAdmit) => match to {
            Some(t) if is_offer && !seated(t) => voiced(t),
            _ => yes().count() >= 2,
        },
        Some(Policy::Weighted) => {
            let sum: u64 = yes()
                .map(|k| {
                    arm.weights
                        .iter()
                        .find(|(w, _)| w == k)
                        .map_or(0, |(_, x)| *x)
                })
                .sum();
            arm.need.is_some_and(|t| t > 0 && sum >= t as u64)
        }
        Some(Policy::Unanimous) => {
            let others = mem.iter().filter(|k| !named(k)).count();
            let y = yes().count();
            if is_offer {
                !mem.is_empty() && y == others && to.is_none_or(|t| !seated(t) || voiced(t))
            } else {
                y == others && 2 * y > mem.len()
            }
        }
        _ => met(pol, yes().count(), mem.len(), arm.need),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::consensus::Seat;
    use crate::federation::key_person::PersonsAt;

    fn seats(spec: &[(&str, Option<&str>, bool)]) -> Vec<Seat> {
        spec.iter()
            .map(|(k, r, node)| Seat {
                key_id: (*k).into(),
                role: r.map(str::to_owned),
                node_bearing: *node,
            })
            .collect()
    }

    fn k(
        protocol: &str,
        subkind: Option<&str>,
        blob: Option<&Value>,
        roster: &[Seat],
        signed: &[&str],
        direction: Direction,
        subject: Option<&str>,
    ) -> Result<bool, NoCell> {
        let signers: BTreeSet<String> = signed.iter().map(|s| (*s).to_owned()).collect();
        let ballot = Ballot {
            protocol,
            subkind,
            policy_blob: blob,
            roster,
            signers: &signers,
            direction,
            subject,
            persons: PersonsAt::each_key(),
            high_water: None,
        };
        let fast = admits(&ballot).map(|a| a.value);
        // I1844: the count over the resolved head is the seat rule over the rows
        assert_eq!(fast, admits_by_rows(&ballot).map(|a| a.value), "{protocol}");
        fast
    }

    /// DIFFERENCES.md's minimal case of each class, through the adapter.
    #[test]
    fn i1839_the_differences_minimal_cases_through_the_adapter() {
        use Direction::{Add, Remove};
        let abc = seats(&[("a", None, false), ("b", None, false), ("c", None, false)]);
        // 1: a unanimous removal is every member but the one named
        assert_eq!(
            k(
                "unanimous",
                None,
                None,
                &abc,
                &["a", "c"],
                Remove,
                Some("b")
            ),
            Ok(true)
        );
        assert_eq!(
            k("unanimous", None, None, &abc, &["a"], Remove, Some("b")),
            Ok(false)
        );
        // 2: an infrastructure group counts its founders that are not node-bearing
        let infra = seats(&[
            ("human", Some("founder"), false),
            ("install", Some("founder"), true),
        ]);
        assert_eq!(
            k(
                "quorum:1/2",
                Some("infrastructure"),
                None,
                &infra,
                &["install"],
                Add,
                Some("j")
            ),
            Ok(false)
        );
        assert_eq!(
            k(
                "quorum:1/2",
                Some("infrastructure"),
                None,
                &infra,
                &["human"],
                Add,
                Some("j")
            ),
            Ok(true)
        );
        // 4: no key admits itself
        let ab = seats(&[("a", Some("founder"), false), ("b", None, false)]);
        assert_eq!(
            k("quorum:1/2", None, None, &ab, &["a"], Add, Some("a")),
            Ok(false)
        );
        // 5a: founder_only is one founder's voice
        assert_eq!(
            k("founder_only", None, None, &ab, &["a"], Add, Some("j")),
            Ok(true)
        );
        assert_eq!(
            k("founder_only", None, None, &ab, &["b"], Add, Some("j")),
            Ok(false)
        );
        // 5b: open:self_admit — the joiner's own signature; a removal takes two voices
        assert_eq!(
            k(
                "open:self_admit",
                Some("public"),
                None,
                &abc,
                &["j"],
                Add,
                Some("j")
            ),
            Ok(true)
        );
        assert_eq!(
            k(
                "open:self_admit",
                Some("public"),
                None,
                &abc,
                &["a"],
                Remove,
                Some("c")
            ),
            Ok(false)
        );
        assert_eq!(
            k(
                "open:self_admit",
                Some("public"),
                None,
                &abc,
                &["a", "b"],
                Remove,
                Some("c")
            ),
            Ok(true)
        );
        assert!(matches!(
            k("open:self_admit", None, None, &abc, &["j"], Add, Some("j")),
            Err(NoCell::Malformed(_))
        ));
        // 5c: weighted, whole numbers
        let abcd = seats(&[
            ("a", None, false),
            ("b", None, false),
            ("c", None, false),
            ("d", None, false),
        ]);
        let blob = serde_json::json!({"rubrics": {"votes": {"weights": {"a": 2, "b": 1, "c": 1, "d": 1}, "threshold": 3}}});
        assert_eq!(
            k(
                "weighted:votes",
                None,
                Some(&blob),
                &abcd,
                &["a", "b"],
                Add,
                Some("j")
            ),
            Ok(true)
        );
        assert_eq!(
            k(
                "weighted:votes",
                None,
                Some(&blob),
                &abcd,
                &["b", "c"],
                Add,
                Some("j")
            ),
            Ok(false)
        );
        let frac = serde_json::json!({"rubrics": {"votes": {"weights": {"a": 2}, "threshold_fraction": 0.5}}});
        assert!(matches!(
            k(
                "weighted:votes",
                None,
                Some(&frac),
                &abcd,
                &["a"],
                Add,
                None
            ),
            Err(NoCell::NotWhole(_))
        ));
        let half =
            serde_json::json!({"rubrics": {"votes": {"weights": {"a": 1.5}, "threshold": 1}}});
        assert!(matches!(
            k(
                "weighted:votes",
                None,
                Some(&half),
                &abcd,
                &["a"],
                Add,
                None
            ),
            Err(NoCell::NotWhole(_))
        ));
        // 5d / 5e: no cell
        assert_eq!(
            k(
                "reverse_quorum:2/5:86400",
                None,
                None,
                &abcd,
                &["a"],
                Remove,
                Some("b")
            ),
            Err(NoCell::ReverseQuorum)
        );
        assert_eq!(
            k("custom:elders", None, None, &abcd, &["a"], Add, None),
            Err(NoCell::Custom)
        );
        // 5f: malformed
        assert!(matches!(
            k("whatever", None, None, &abcd, &["a"], Add, None),
            Err(NoCell::Malformed(_))
        ));
        // majority and quorum
        assert_eq!(
            k("majority", None, None, &abc, &["a", "b"], Add, Some("j")),
            Ok(true)
        );
        assert_eq!(
            k("majority", None, None, &abc, &["a"], Add, Some("j")),
            Ok(false)
        );
        assert_eq!(
            k("quorum:2/3", None, None, &abc, &["a", "b"], Add, Some("j")),
            Ok(true)
        );
        assert_eq!(
            k("quorum:2/3", None, None, &abc, &["a", "z"], Add, Some("j")),
            Ok(false)
        );
    }
}
