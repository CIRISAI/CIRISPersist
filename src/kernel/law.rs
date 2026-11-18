//! v62.0.0 (slice C) — **the tables the kernel reads**, loaded from what
//! persist already vendors. None of it is code (`ciris_kernel::seat::SeatLaw`,
//! `ciris_kernel::window::WindowSpec`).
//!
//! - [`seat_law`]: the closed `consensus_protocol` vocabulary of CC 4.4.3.6
//!   (six arms: `founder_only`, `open:self_admit`, `unanimous`, `majority`,
//!   `quorum:M/N`, `weighted:{rubric}`) as the kernel's policy cells, plus the
//!   seats the adapter places (`member`, `founder`, `owner`).
//! - [`window_specs`]: one `WindowSpec` per two-path row of the vendored
//!   `governance_policy.json` (CC 4.5.13): enact and cancel clauses, the
//!   at-window default, the length in [`Micros`].
//!
//! `reverse_quorum:*` and `custom:*` have NO cell: CC 3.2 "Not a membership
//! rule: reverse quorum … It admits no one", and CC 4.4.3.6's protocol table
//! has no `custom:` arm (I1832).

use super::view::Micros;
use ciris_kernel::seat::{Policy, SeatLaw};
use ciris_kernel::window::{Base, Clause, How, WindowSpec};
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// The seat a group's roster places.
pub const SEAT_MEMBER: &str = "member";
/// The seat a founder holds beside `member`.
pub const SEAT_FOUNDER: &str = "founder";
/// The single-valued seat over a node's key (CC 3.2, the first binding).
pub const SEAT_OWNER: &str = "owner";

/// The policy cell of each arm of the closed vocabulary, by its arm word.
/// `quorum` reads its threshold from the counted row (`Declared`: persist
/// supplies `quorum_need`, the CC 4.4.3.4.2.1 latch included), `weighted`
/// its weights and threshold from the group's signed record.
pub const ARMS: &[(&str, Policy)] = &[
    ("founder_only", Policy::One),
    ("open:self_admit", Policy::SelfAdmit),
    ("unanimous", Policy::Unanimous),
    ("majority", Policy::Strict(1, 2)),
    ("quorum", Policy::Declared),
    ("weighted", Policy::Weighted),
];

/// The seat law the adapter's answers read. Built once.
pub fn seat_law() -> &'static SeatLaw {
    static LAW: OnceLock<SeatLaw> = OnceLock::new();
    LAW.get_or_init(|| SeatLaw {
        duties: Vec::new(),
        holds: BTreeMap::new(),
        confers: BTreeMap::new(),
        ends: BTreeMap::new(),
        final_scopes: Vec::new(),
        roster_seats: vec![SEAT_MEMBER.to_owned(), SEAT_FOUNDER.to_owned()],
        depth: 1,
        policy: ARMS.iter().map(|(w, p)| ((*w).to_owned(), *p)).collect(),
    })
}

/// A rule of the vendored table as a window clause count.
fn how_of(rule: &serde_json::Value) -> Option<How> {
    let num = rule.get("num").and_then(serde_json::Value::as_u64);
    let den = rule.get("den").and_then(serde_json::Value::as_u64);
    match rule.get("kind").and_then(serde_json::Value::as_str)? {
        "fraction" => Some(How::AtLeast(num?, den?, 1)),
        "strict_majority" | "strict_majority_of_others" => Some(How::Strict),
        "one_of_n" => Some(How::One),
        _ => None,
    }
}

/// The window table of every two-path row of the vendored
/// `governance_policy.json`, by family. A row whose enact rule is not a
/// count the kernel's clauses state (a ranked election, a role cell) is not
/// in the map: its window stays persist's until the cell is typed.
pub fn window_specs() -> &'static BTreeMap<String, WindowSpec<Micros>> {
    static SPECS: OnceLock<BTreeMap<String, WindowSpec<Micros>>> = OnceLock::new();
    SPECS.get_or_init(|| {
        let table: serde_json::Value = serde_json::from_str(
            crate::federation::namespace::cc_manifests::GOVERNANCE_POLICY_JSON,
        )
        .expect("the vendored governance_policy.json parses (pinned by its sha256)");
        let mut out = BTreeMap::new();
        for f in table["families"].as_array().into_iter().flatten() {
            let (Some(family), Some(enact)) =
                (f["family"].as_str(), f.get("enact_rule").and_then(how_of))
            else {
                continue;
            };
            if f["kind"].as_str() != Some("two_path") {
                continue;
            }
            let others = f["cancel_over"].as_str() == Some("others");
            let mut at_once = vec![Clause {
                value: "yes".into(),
                how: enact,
                over: if others { Base::Others } else { Base::All },
                out: "enacted".into(),
            }];
            if let Some(cancel) = f.get("cancel_rule").and_then(how_of) {
                at_once.push(Clause {
                    value: "no".into(),
                    how: cancel,
                    over: if others { Base::Others } else { Base::All },
                    out: "cancelled".into(),
                });
            }
            out.insert(
                family.to_owned(),
                WindowSpec {
                    counted: SEAT_MEMBER.into(),
                    concluder: SEAT_MEMBER.into(),
                    opener_says: Some("yes".into()),
                    at_once,
                    silent: None,
                    at_close: Vec::new(),
                    default: f["at_window"].as_str().unwrap_or("lapsed").to_owned(),
                    target_votes: false,
                    secs: f["window_secs"]
                        .as_i64()
                        .unwrap_or(0)
                        .saturating_mul(1_000_000),
                },
            );
        }
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn i1832_the_seat_law_has_a_cell_for_the_six_arms_and_none_for_reverse_quorum_or_custom() {
        let law = seat_law();
        assert_eq!(law.policy.len(), 6);
        for w in [
            "founder_only",
            "open:self_admit",
            "unanimous",
            "majority",
            "quorum",
            "weighted",
        ] {
            assert!(law.policy.contains_key(w), "{w}");
        }
        assert!(law
            .policy
            .keys()
            .all(|w| !w.starts_with("reverse_quorum") && !w.starts_with("custom")));
    }

    #[test]
    fn i1833_every_fraction_two_path_row_loads_as_a_window_with_its_length() {
        let specs = window_specs();
        let standing = &specs["default_standing"];
        assert_eq!(standing.secs, 259_200 * 1_000_000);
        assert_eq!(standing.default, "cancelled");
        assert!(matches!(standing.at_once[0].how, How::AtLeast(2, 3, 1)));
        let add = &specs["self_roster_add"];
        assert_eq!(add.default, "stay_open");
        assert!(matches!(add.at_once[1].how, How::Strict));
        assert!(matches!(add.at_once[0].over, Base::Others));
        // a ranked or a mirror row is not a two-path window here
        assert!(!specs.contains_key("moderator_election"));
        assert!(!specs.contains_key("moderation_action"));
        // v62.0.0 (CC rc20): `community_remove` is a `cosigned` row (enact =
        // the room's protocol), not a two-path window; six remain.
        assert!(!specs.contains_key("community_remove"));
        assert_eq!(specs.len(), 6);
    }
}
