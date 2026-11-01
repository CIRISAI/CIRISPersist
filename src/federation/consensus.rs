//! v49.0.0 (CIRISPersist#908, `FSD/ROOM_ROSTER_AUTHORITY.md` §2) — **the one
//! `consensus_protocol` evaluator.**
//!
//! CC 4.4.3.2.3 / 4.4.3.4.2 admit a membership change by evaluating the group's
//! current `consensus_protocol` over the change's signatures. Before this
//! module the vocabulary was a stored label with three partial readers (the
//! trust-root charter threshold, `verify_membership_quorum`'s fixed strict
//! majority, and nothing at all on the roster planes). Every caller now asks
//! [`evaluate`]; none re-reads the protocol string.
//!
//! **Pure and total.** The roster fold runs on every node, so the verdict must
//! be a function of replicated, signed state only. Operator rubrics
//! (`weighted:{rubric}`) and custom predicates (`custom:{id}`) are therefore
//! *declared data* in the group record's `policy_blob`, never host callbacks —
//! a callback would let two nodes fold the same rows to different rosters.
//!
//! **Signatures are the caller's job.** This module counts *who signed*; the
//! caller has already hybrid-verified every signature it passes in.

use std::collections::BTreeSet;

use serde_json::Value;

use super::types::consensus_protocol as cp;

/// The role tag that marks a founder (CC §5.6.8.9); re-exported so the
/// evaluator and the rest of admission read one constant.
pub use super::admission::MEMBER_ROLE_FOUNDER;

/// The built-in rubric CC 4.4.3.4.2.1 describes as the way to express "M grows
/// with the roster": every eligible member weighs 1 and the threshold is
/// `ceil(roster / 2)`. Resolvable without a declaration.
pub const RUBRIC_UNIFORM_HALF: &str = "uniform_half";

/// A rubric's per-seat weight function.
type WeightFn = Box<dyn Fn(&Seat) -> f64>;

/// How deep a declared `custom:` expression may nest before it is refused.
pub const MAX_CUSTOM_DEPTH: usize = 8;

/// Which way a membership change moves the roster. Only `reverse_quorum`
/// reads it (the accord-ops invariant: *1-of-N to protect, m-of-n to undo,
/// never a 1-of-N capability grant*); every approve-to-act form treats both
/// directions alike, as the CC does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// A member joins: a capability grant (the room key is wrapped to them).
    Add,
    /// A member is removed: protective (the room key is withheld going forward).
    Remove,
}

/// One active member of the group at the change's instant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seat {
    /// The member's `key_id`.
    pub key_id: String,
    /// The member's role tag (`founder`, `member`, operator vocabulary), if any.
    pub role: Option<String>,
    /// v50.0.0 (CIRISPersist#925, CC 3.2 "Infrastructure does not vote") — the
    /// member's key is `node`-bearing: its own `identity_type` contains `node`,
    /// or it is an occurrence of an identity whose `identity_type` does. The
    /// caller resolves this from the roster reads (the evaluator stays pure);
    /// [`eligible`] drops such a seat in an `infrastructure` group whatever its
    /// role tag says.
    pub node_bearing: bool,
}

impl Seat {
    fn is_founder(&self) -> bool {
        self.role.as_deref() == Some(MEMBER_ROLE_FOUNDER)
    }
}

/// Everything [`evaluate`] reads. Borrowed, so a fold can evaluate thousands of
/// events without cloning the roster.
#[derive(Debug, Clone, Copy)]
pub struct Ballot<'a> {
    /// The group's `consensus_protocol` string.
    pub protocol: &'a str,
    /// The group's `cohort_subkind` (`infrastructure` evaluates over founders).
    pub subkind: Option<&'a str>,
    /// The group record's `policy_blob` (rubric and custom declarations).
    pub policy_blob: Option<&'a Value>,
    /// The ACTIVE members at the change's instant.
    pub roster: &'a [Seat],
    /// Every key whose signature over the change verified.
    pub signers: &'a BTreeSet<String>,
    /// Which way the change moves the roster.
    pub direction: Direction,
    /// v61 (CIRISPersist#1123) — the ONE member the change seats or
    /// removes, when it names exactly one (a widening or a revocation row);
    /// `None` for a whole-roster change (a membership-change envelope).
    /// [`consensus_protocol::OPEN_SELF_ADMIT`](cp::OPEN_SELF_ADMIT) reads it:
    /// the joiner's own signature is the group's side of their admission, and
    /// the member a removal names is never one of its voices.
    pub subject: Option<&'a str>,
}

/// v61 (CIRISPersist#1123; CC 4.5.13 "never fewer than two voices in a
/// community") — under `open:self_admit` anyone admits themselves, so the
/// guarantee that no single vote decides who is in a room attaches to
/// REMOVAL: at least this many distinct eligible members, the removed member
/// not among them, sign a removal.
pub const OPEN_SELF_ADMIT_REMOVAL_FLOOR: usize = 2;

/// The evaluator's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The protocol is met.
    Admit,
    /// The protocol is well-formed and evaluable, and not met.
    Insufficient {
        /// A human-readable account of what was needed and what was counted.
        detail: String,
    },
    /// The protocol cannot be evaluated from signed state: an undeclared
    /// rubric or custom id, a malformed declaration, or a non-canonical string.
    Unevaluable {
        /// Why.
        reason: String,
    },
}

impl Verdict {
    /// True iff [`Verdict::Admit`].
    pub fn admits(&self) -> bool {
        matches!(self, Verdict::Admit)
    }
}

/// The eligible set: founders only for `cohort_subkind: infrastructure`
/// (CC 4.4.3.2.4.1(a)), the whole active roster otherwise.
///
/// v50.0.0 (CIRISPersist#925, CC 3.2 "Infrastructure does not vote") — in an
/// `infrastructure` group a `node`-bearing seat is DROPPED even when it is
/// tagged `founder`. The admission gate refuses such a row now, but rows
/// admitted before the gate still exist; non-conformance is a reason to
/// re-mint, never a reason the fold stops applying (the CC 3.4.7.3 Clause B
/// posture). A dropped seat is not eligible, so its signature counts for
/// nothing and it does not enlarge the denominator either.
fn eligible<'a>(b: &Ballot<'a>) -> Vec<&'a Seat> {
    let founders_only = b.subkind == Some("infrastructure");
    b.roster
        .iter()
        .filter(|s| !founders_only || (s.is_founder() && !s.node_bearing))
        .collect()
}

fn counted<'a>(eligible: &[&'a Seat], signers: &BTreeSet<String>) -> Vec<&'a Seat> {
    eligible
        .iter()
        .copied()
        .filter(|s| signers.contains(&s.key_id))
        .collect()
}

fn insufficient(detail: String) -> Verdict {
    Verdict::Insufficient { detail }
}

fn unevaluable(reason: impl Into<String>) -> Verdict {
    Verdict::Unevaluable {
        reason: reason.into(),
    }
}

/// **The evaluator.** Pure and total over the `consensus_protocol` vocabulary
/// (FSD §2 table). Every arm requires at least one counted signer: no
/// protocol admits a change that no eligible member signed.
pub fn evaluate(b: &Ballot<'_>) -> Verdict {
    let elig = eligible(b);
    let got = counted(&elig, b.signers);
    let n = elig.len();
    if b.protocol == cp::OPEN_SELF_ADMIT {
        return evaluate_open_self_admit(b, &got);
    }
    // v61 (CIRISPersist#1123; CC 4.4.3.4.2) — a self-signed admission is
    // `open:self_admit`'s alone: under every other protocol a key does not
    // seat (or re-role) itself, whatever seat it already holds.
    if b.direction == Direction::Add
        && b.subject
            .is_some_and(|k| b.signers.len() == 1 && b.signers.contains(k))
    {
        return insufficient(format!(
            "a self-signed admission is admitted only under {}; {:?} needs the group's side",
            cp::OPEN_SELF_ADMIT,
            b.protocol
        ));
    }
    if got.is_empty() {
        return insufficient(format!(
            "no signer is an eligible member ({n} eligible under {:?})",
            b.protocol
        ));
    }
    let p = b.protocol;
    if p == cp::FOUNDER_ONLY {
        return if got.iter().any(|s| s.is_founder()) {
            Verdict::Admit
        } else {
            insufficient("founder_only: no signer is an active founder".into())
        };
    }
    if p == cp::UNANIMOUS {
        return if got.len() == n {
            Verdict::Admit
        } else {
            insufficient(format!("unanimous: {} of {n} signed", got.len()))
        };
    }
    if p == cp::MAJORITY {
        return if 2 * got.len() > n {
            Verdict::Admit
        } else {
            insufficient(format!(
                "majority: {} of {n} signed, more than half needed",
                got.len()
            ))
        };
    }
    if p.starts_with(cp::REVERSE_QUORUM_PREFIX) {
        let Some(policy) = super::reverse_quorum::ReverseQuorumPolicy::parse(p) else {
            return unevaluable(format!("malformed reverse_quorum form {p:?}"));
        };
        return match b.direction {
            // Protective: one member may act; the objection fold undoes it.
            Direction::Remove => Verdict::Admit,
            // A capability grant is never 1-of-N: the #574 dismissal threshold
            // (the declared m, floored at a strict majority) forward.
            Direction::Add => {
                let need = policy.dismissal_threshold(n);
                if got.len() >= need {
                    Verdict::Admit
                } else {
                    insufficient(format!(
                        "reverse_quorum addition: {} of {need} signatures",
                        got.len()
                    ))
                }
            }
        };
    }
    if let Some(tail) = p.strip_prefix(cp::QUORUM_PREFIX) {
        let Some((m, _n)) = parse_quorum_tail(tail) else {
            return unevaluable(format!("malformed quorum form {p:?}"));
        };
        // Absolute M (CC 4.4.3.4.2.1); at least one signer regardless.
        let need = (m as usize).max(1);
        return if got.len() >= need {
            Verdict::Admit
        } else {
            insufficient(format!("quorum: {} of {need} signatures", got.len()))
        };
    }
    if let Some(rubric) = p.strip_prefix(cp::WEIGHTED_PREFIX) {
        return eval_weighted(b, &elig, &got, rubric);
    }
    if let Some(id) = p.strip_prefix(cp::CUSTOM_PREFIX) {
        let Some(expr) = b
            .policy_blob
            .and_then(|pb| pb.get("custom"))
            .and_then(|c| c.get(id))
        else {
            return unevaluable(format!(
                "custom:{id} is not declared in the group record's policy_blob.custom"
            ));
        };
        return eval_expr(b, &elig, &got, expr, 0);
    }
    unevaluable(format!("{p:?} is not a canonical consensus_protocol form"))
}

/// v61 (CIRISPersist#1123; CC 4.4.3.4.2's `open:self_admit` arm, CC
/// 4.5.13's floor) — open admission, on a `public` group only:
///
/// - **a widening that seats one NEW key** is admitted on that key's own
///   signature (the joiner's acceptance of the standing proposal is the
///   growth gate's, as under every protocol);
/// - **a role change** of a seated member, and **a removal**, need at least
///   [`OPEN_SELF_ADMIT_REMOVAL_FLOOR`] distinct eligible signers, the member
///   the change names not counted: one voice never decides who is in a room;
/// - a whole-roster change (no single subject) gains no one by itself.
fn evaluate_open_self_admit(b: &Ballot<'_>, got: &[&Seat]) -> Verdict {
    if b.subkind != Some(super::public_room::COHORT_SUBKIND_PUBLIC) {
        return unevaluable(format!(
            "{} is admissible only on a public group (CC 4.4.3.2)",
            cp::OPEN_SELF_ADMIT
        ));
    }
    let seated = |k: &str| b.roster.iter().any(|s| s.key_id == k);
    if b.direction == Direction::Add {
        match b.subject {
            Some(k) if !seated(k) => {
                return if b.signers.contains(k) {
                    Verdict::Admit
                } else {
                    insufficient(format!(
                        "{}: the joiner {k} did not sign their own admission",
                        cp::OPEN_SELF_ADMIT
                    ))
                };
            }
            Some(_) => {}
            None => {
                return insufficient(format!(
                    "{}: a change naming no one joiner admits no one",
                    cp::OPEN_SELF_ADMIT
                ))
            }
        }
    }
    let voices = got
        .iter()
        .filter(|s| Some(s.key_id.as_str()) != b.subject)
        .count();
    if voices >= OPEN_SELF_ADMIT_REMOVAL_FLOOR {
        Verdict::Admit
    } else {
        insufficient(format!(
            "{}: {voices} distinct voice(s) besides the member named; one vote never \
             decides who is in a room (at least {OPEN_SELF_ADMIT_REMOVAL_FLOOR})",
            cp::OPEN_SELF_ADMIT
        ))
    }
}

fn parse_quorum_tail(tail: &str) -> Option<(u32, u32)> {
    let (m, n) = tail.split_once('/')?;
    let (m, n) = (m.parse::<u32>().ok()?, n.parse::<u32>().ok()?);
    (n > 0 && m <= n).then_some((m, n))
}

/// A declared rubric: `{ "weights": {key_id | "role:{r}" → w}, "default_weight": w,
/// "threshold": x }` or `"threshold_fraction": f` (of the eligible total).
fn eval_weighted(b: &Ballot<'_>, elig: &[&Seat], got: &[&Seat], rubric: &str) -> Verdict {
    let (weight_of, threshold): (WeightFn, f64) = if rubric == RUBRIC_UNIFORM_HALF {
        (Box::new(|_| 1.0), (elig.len() as f64 / 2.0).ceil())
    } else {
        let Some(decl) = b
            .policy_blob
            .and_then(|pb| pb.get("rubrics"))
            .and_then(|r| r.get(rubric))
        else {
            return unevaluable(format!(
                "weighted:{rubric} is not declared in the group record's policy_blob.rubrics"
            ));
        };
        let weights = decl.get("weights").cloned().unwrap_or(Value::Null);
        let default = decl
            .get("default_weight")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let w = move |s: &Seat| -> f64 {
            weights
                .get(&s.key_id)
                .and_then(Value::as_f64)
                .or_else(|| {
                    s.role
                        .as_deref()
                        .and_then(|r| weights.get(format!("role:{r}")))
                        .and_then(Value::as_f64)
                })
                .unwrap_or(default)
        };
        let total: f64 = elig.iter().map(|s| w(s)).sum();
        let threshold = match (
            decl.get("threshold").and_then(Value::as_f64),
            decl.get("threshold_fraction").and_then(Value::as_f64),
        ) {
            (Some(t), None) => t,
            (None, Some(f)) if (0.0..=1.0).contains(&f) => (f * total).max(f64::MIN_POSITIVE),
            _ => {
                return unevaluable(format!(
                    "weighted:{rubric} must declare exactly one of threshold / threshold_fraction (0..=1)"
                ))
            }
        };
        if !threshold.is_finite() || threshold <= 0.0 {
            return unevaluable(format!("weighted:{rubric} threshold must be positive"));
        }
        (Box::new(w), threshold)
    };
    let sum: f64 = got.iter().map(|s| weight_of(s)).sum();
    if sum >= threshold {
        Verdict::Admit
    } else {
        insufficient(format!("weighted:{rubric}: {sum} of {threshold} weight"))
    }
}

/// A declared `custom:` expression (FSD §2 table).
fn eval_expr(b: &Ballot<'_>, elig: &[&Seat], got: &[&Seat], expr: &Value, depth: usize) -> Verdict {
    if depth > MAX_CUSTOM_DEPTH {
        return unevaluable(format!(
            "custom expression nests deeper than {MAX_CUSTOM_DEPTH}"
        ));
    }
    let Some(obj) = expr.as_object().filter(|o| o.len() == 1) else {
        return unevaluable("a custom expression node is an object with exactly one key");
    };
    let (op, arg) = obj.iter().next().expect("one key");
    let sub = |proto: &str| -> Verdict {
        evaluate(&Ballot {
            protocol: proto,
            ..*b
        })
    };
    match op.as_str() {
        "any_of" | "all_of" => {
            let Some(items) = arg.as_array().filter(|a| !a.is_empty()) else {
                return unevaluable(format!("{op} takes a non-empty array"));
            };
            let mut last_insufficient = None;
            for item in items {
                match eval_expr(b, elig, got, item, depth + 1) {
                    Verdict::Admit if op == "any_of" => return Verdict::Admit,
                    Verdict::Admit => {}
                    v @ Verdict::Unevaluable { .. } => return v,
                    v @ Verdict::Insufficient { .. } => {
                        if op == "all_of" {
                            return v;
                        }
                        last_insufficient = Some(v);
                    }
                }
            }
            if op == "all_of" {
                Verdict::Admit
            } else {
                last_insufficient.unwrap_or_else(|| insufficient("any_of: nothing admitted".into()))
            }
        }
        "founder" => sub(cp::FOUNDER_ONLY),
        "majority" => sub(cp::MAJORITY),
        "unanimous" => sub(cp::UNANIMOUS),
        "quorum" => match arg.as_u64() {
            Some(m) => sub(&format!(
                "{}{m}/{}",
                cp::QUORUM_PREFIX,
                elig.len().max(m as usize).max(1)
            )),
            None => unevaluable("quorum takes an absolute integer M"),
        },
        "weighted" => match arg.as_str() {
            Some(r) => sub(&format!("{}{r}", cp::WEIGHTED_PREFIX)),
            None => unevaluable("weighted takes a rubric name"),
        },
        "role" => {
            let (Some(name), Some(min)) = (
                arg.get("name").and_then(Value::as_str),
                arg.get("min").and_then(Value::as_u64),
            ) else {
                return unevaluable("role takes {\"name\": r, \"min\": M}");
            };
            let have = got
                .iter()
                .filter(|s| s.role.as_deref() == Some(name))
                .count();
            let need = (min as usize).max(1);
            if have >= need {
                Verdict::Admit
            } else {
                insufficient(format!("role {name}: {have} of {need} signatures"))
            }
        }
        other => unevaluable(format!("unknown custom expression node {other:?}")),
    }
}

/// How many distinct eligible signatures a protocol demands of a roster of
/// `roster_size`, for callers that tally elsewhere (the trust-root charter,
/// which applies its own #557 floor on top). `None` for forms whose answer is
/// not a count (`founder_only` — a founder, not a number; `weighted:`;
/// `custom:`) or that do not parse; such callers read `None` FAIL-SECURE.
pub fn required_signatures(protocol: &str, roster_size: usize) -> Option<usize> {
    if protocol == cp::UNANIMOUS {
        return Some(roster_size.max(1));
    }
    if protocol == cp::MAJORITY {
        return Some(roster_size / 2 + 1);
    }
    if protocol.starts_with(cp::REVERSE_QUORUM_PREFIX) {
        return super::reverse_quorum::ReverseQuorumPolicy::parse(protocol)
            .map(|p| p.dismissal_threshold(roster_size));
    }
    if let Some(tail) = protocol.strip_prefix(cp::QUORUM_PREFIX) {
        return parse_quorum_tail(tail).map(|(m, _)| (m as usize).max(1));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seats(spec: &[(&str, Option<&str>)]) -> Vec<Seat> {
        spec.iter()
            .map(|(k, r)| Seat {
                key_id: (*k).into(),
                role: r.map(str::to_owned),
                node_bearing: false,
            })
            .collect()
    }
    fn signers(ks: &[&str]) -> BTreeSet<String> {
        ks.iter().map(|k| (*k).to_owned()).collect()
    }
    fn eval(p: &str, roster: &[Seat], s: &[&str], blob: Option<&Value>, d: Direction) -> Verdict {
        evaluate(&Ballot {
            protocol: p,
            subkind: None,
            policy_blob: blob,
            roster,
            signers: &signers(s),
            direction: d,
            subject: None,
        })
    }

    fn eval_about(
        p: &str,
        sub: Option<&str>,
        roster: &[Seat],
        s: &[&str],
        subject: &str,
        d: Direction,
    ) -> Verdict {
        evaluate(&Ballot {
            protocol: p,
            subkind: sub,
            policy_blob: None,
            roster,
            signers: &signers(s),
            direction: d,
            subject: Some(subject),
        })
    }

    /// v61 (CIRISPersist#1123) — `open:self_admit`: a new key admits itself;
    /// a removal or a role change needs two voices besides the member named;
    /// the protocol is unevaluable outside a public group.
    #[test]
    fn open_self_admit_admits_the_joiner_and_floors_removal_at_two() {
        use Direction::{Add, Remove};
        let p = cp::OPEN_SELF_ADMIT;
        let pubk = Some("public");
        let r = seats(&[("a", Some("founder")), ("b", None), ("c", None)]);
        // The joiner's own signature is the group's side.
        assert!(eval_about(p, pubk, &r, &["j"], "j", Add).admits());
        // Somebody else's signature is not the joiner's consent.
        assert!(!eval_about(p, pubk, &r, &["a"], "j", Add).admits());
        // One voice never excludes; two do; the member named is no voice.
        assert!(!eval_about(p, pubk, &r, &["a"], "c", Remove).admits());
        assert!(!eval_about(p, pubk, &r, &["a", "c"], "c", Remove).admits());
        assert!(eval_about(p, pubk, &r, &["a", "b"], "c", Remove).admits());
        // A non-member's signature is no voice.
        assert!(!eval_about(p, pubk, &r, &["a", "x"], "c", Remove).admits());
        // A seated member's self-promotion is a role change: two voices.
        assert!(!eval_about(p, pubk, &r, &["b"], "b", Add).admits());
        assert!(eval_about(p, pubk, &r, &["a", "c"], "b", Add).admits());
        // A whole-roster change admits no joiner by itself.
        assert!(!evaluate(&Ballot {
            protocol: p,
            subkind: pubk,
            policy_blob: None,
            roster: &r,
            signers: &signers(&["a", "b", "c"]),
            direction: Add,
            subject: None,
        })
        .admits());
        // Off a public group the protocol cannot be evaluated.
        assert!(matches!(
            eval_about(p, None, &r, &["j"], "j", Add),
            Verdict::Unevaluable { .. }
        ));
    }

    /// v61 (CIRISPersist#1123; CC 4.4.3.4.2) — every protocol but
    /// `open:self_admit` refuses a self-signed admission, even from a seat.
    #[test]
    fn a_self_signed_admission_is_refused_by_every_other_protocol() {
        let r = seats(&[("a", Some("founder")), ("b", None)]);
        for p in [cp::FOUNDER_ONLY, cp::MAJORITY, cp::UNANIMOUS, "quorum:1/2"] {
            assert!(
                !eval_about(p, None, &r, &["a"], "a", Direction::Add).admits(),
                "{p}: a founder re-seating itself alone"
            );
            assert!(
                !eval_about(p, None, &r, &["j"], "j", Direction::Add).admits(),
                "{p}: a stranger seating itself"
            );
        }
        // The same signer seating someone else still admits where it did.
        assert!(eval_about(cp::FOUNDER_ONLY, None, &r, &["a"], "j", Direction::Add).admits());
        // A removal by the removed member is not an admission (resignation is
        // the fold's own rule).
        assert!(eval_about(cp::FOUNDER_ONLY, None, &r, &["a"], "a", Direction::Remove).admits());
    }

    #[test]
    fn every_arm_admits_and_refuses() {
        use Direction::Add;
        let r = seats(&[
            ("a", Some("founder")),
            ("b", None),
            ("c", None),
            ("d", None),
            ("e", None),
        ]);
        assert!(eval("founder_only", &r, &["a"], None, Add).admits());
        assert!(!eval("founder_only", &r, &["b", "c"], None, Add).admits());
        assert!(eval("unanimous", &r, &["a", "b", "c", "d", "e"], None, Add).admits());
        assert!(!eval("unanimous", &r, &["a", "b", "c", "d"], None, Add).admits());
        assert!(eval("majority", &r, &["a", "b", "c"], None, Add).admits());
        assert!(!eval("majority", &r, &["a", "b"], None, Add).admits());
        assert!(eval("quorum:2/5", &r, &["b", "c"], None, Add).admits());
        assert!(!eval("quorum:2/5", &r, &["b"], None, Add).admits());
        // quorum:0/N still needs one eligible signer.
        assert!(!eval("quorum:0/5", &r, &["stranger"], None, Add).admits());
        // Strangers never count.
        assert!(!eval("majority", &r, &["x", "y", "z"], None, Add).admits());
    }

    #[test]
    fn weighted_uniform_half_and_declared() {
        use Direction::Add;
        let r = seats(&[
            ("a", Some("founder")),
            ("b", None),
            ("c", None),
            ("d", None),
        ]);
        assert!(eval("weighted:uniform_half", &r, &["a", "b"], None, Add).admits());
        assert!(!eval("weighted:uniform_half", &r, &["a"], None, Add).admits());
        let blob = serde_json::json!({"rubrics": {"votes": {
            "weights": {"a": 3, "role:member": 1}, "default_weight": 1, "threshold": 4}}});
        assert!(eval("weighted:votes", &r, &["a", "b"], Some(&blob), Add).admits());
        assert!(!eval("weighted:votes", &r, &["b", "c", "d"], Some(&blob), Add).admits());
        assert!(matches!(
            eval("weighted:missing", &r, &["a"], Some(&blob), Add),
            Verdict::Unevaluable { .. }
        ));
    }

    #[test]
    fn custom_composes_the_primitives() {
        use Direction::Add;
        let r = seats(&[
            ("a", Some("founder")),
            ("b", Some("elder")),
            ("c", Some("elder")),
            ("d", None),
        ]);
        let blob = serde_json::json!({"custom": {"council": {"all_of": [
            {"founder": {}}, {"role": {"name": "elder", "min": 1}}]}}});
        assert!(eval("custom:council", &r, &["a", "b"], Some(&blob), Add).admits());
        assert!(!eval("custom:council", &r, &["a", "d"], Some(&blob), Add).admits());
        assert!(matches!(
            eval("custom:nope", &r, &["a"], Some(&blob), Add),
            Verdict::Unevaluable { .. }
        ));
        let bad = serde_json::json!({"custom": {"x": {"launch": {}}}});
        assert!(matches!(
            eval("custom:x", &r, &["a"], Some(&bad), Add),
            Verdict::Unevaluable { .. }
        ));
    }

    #[test]
    fn reverse_quorum_protects_cheaply_and_grants_expensively() {
        let r = seats(&[
            ("a", None),
            ("b", None),
            ("c", None),
            ("d", None),
            ("e", None),
        ]);
        let p = "reverse_quorum:2/5:86400";
        assert!(eval(p, &r, &["a"], None, Direction::Remove).admits());
        // Addition: m=2 floored at a strict majority of 5 = 3.
        assert!(!eval(p, &r, &["a", "b"], None, Direction::Add).admits());
        assert!(eval(p, &r, &["a", "b", "c"], None, Direction::Add).admits());
    }

    #[test]
    fn infrastructure_counts_founders_only() {
        let r = seats(&[
            ("a", Some("founder")),
            ("b", Some("founder")),
            ("c", None),
            ("d", None),
        ]);
        let v = evaluate(&Ballot {
            protocol: "majority",
            subkind: Some("infrastructure"),
            policy_blob: None,
            roster: &r,
            signers: &signers(&["a", "c", "d"]),
            direction: Direction::Add,
            subject: None,
        });
        assert!(
            !v.admits(),
            "one of two founders is not a majority of founders: {v:?}"
        );
    }

    #[test]
    fn non_canonical_is_unevaluable() {
        let r = seats(&[("a", Some("founder"))]);
        assert!(matches!(
            eval("whatever", &r, &["a"], None, Direction::Add),
            Verdict::Unevaluable { .. }
        ));
    }

    /// v50.0.0 (CIRISPersist#925) — a `node`-bearing key tagged `founder` in an
    /// `infrastructure` group is not an eligible seat: it neither votes nor
    /// counts in the denominator.
    #[test]
    fn node_founder_seat_is_not_eligible() {
        let mut r = seats(&[("human", Some("founder")), ("install", Some("founder"))]);
        r[1].node_bearing = true;
        let b = Ballot {
            protocol: "quorum:1/2",
            subkind: Some("infrastructure"),
            policy_blob: None,
            roster: &r,
            signers: &signers(&["install"]),
            direction: Direction::Add,
            subject: None,
        };
        let elig: Vec<&str> = eligible(&b).iter().map(|s| s.key_id.as_str()).collect();
        assert_eq!(
            elig,
            vec!["human"],
            "the node seat is dropped from the eligible set"
        );
        let v = evaluate(&b);
        assert!(
            !v.admits(),
            "quorum:1/2 over one human founder + one node 'founder': the node's scrub \
             does not admit: {v:?}"
        );
        assert!(
            evaluate(&Ballot {
                signers: &signers(&["human"]),
                ..b
            })
            .admits(),
            "the human founder's scrub still admits"
        );
        // Outside infrastructure the rule does not apply (CC 3.2 scopes it).
        assert!(evaluate(&Ballot { subkind: None, ..b }).admits());
    }
}
