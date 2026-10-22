//! v60.0.0 (S6v; CC 4.5.13 `CLM-governance-policy-table`, CC 4.2.1.1
//! `CLM-policy-corridor`; CIRISPersist#1100, CIRISConstitution#180) — **the
//! two-path policy table as runtime data, and the corridor at admission.**
//!
//! CC publishes the policy every window-opening door runs as one table
//! (`manifests/governance_policy.json`, vendored at the `v1.0-rc9` tag in
//! [`cc_manifests`](super::namespace::cc_manifests)): per family the five
//! numbers (enact, cancel, floor, window, irreversible) over a named standing
//! set, what CANCEL runs over, what the window's close does, and which
//! corridor the row lives in. A two-path door no longer spells its policy: it
//! asks [`PolicyTable::admit`] for its family's row, which builds the
//! [`TwoPathPolicy`] from the row and runs the corridor over it, and the door
//! refuses with [`Error::GovernancePolicyRefused`] when the row is outside
//! its corridor (or unreadable). The self-roster door
//! ([`super::self_roster::policy`]) is the first: its policy is the table's
//! `self_roster_add` / `self_roster_evict` rows.
//!
//! **The corridor, as CC checks the table** (`tools/build_governance_policy.py`
//! `check_corridor` at the tag, ported): a community row with a reverse path
//! is checked with [`TwoPathPolicy::check_corridor`] (`PolicyCorridor.lean`
//! `inCorridor`) at the bases 6, 7, 10 and the expected-active base of a
//! 10 000-member community (CC checks the fraction alone from base 6 up: at 3
//! the count minimum lifts a tiny community's floor and cancel); a
//! forward-only community row must not enact on one voice, must enact on at
//! least half, and must keep its window floor, at 3, 6, 7, 10 and that base; a
//! self row is checked in its own corridor (no floor clause,
//! [`FloorClass::SameIdentity`]) at three keys with the 24 h floor. A row's
//! window floor is its class's: `content_24h` → 86 400 s, irreversible →
//! 604 800 s, anything else → `standing_72h` 259 200 s.
//!
//! **What is not built.** Only [`Base::StandingRoster`] is built: a
//! community row's `active` base (the provisional expected-active law, #180
//! item 2) resolves only over a base count a caller supplies (the vectors);
//! [`PolicyTable::admit`] refuses such a row for a door
//! (`base_not_built`). The `mirror` and `cosigned` rows (moderation's
//! fallback, the halt's fuse, the custodian replacement) are recorded under
//! their own rules and are not two-path policies (`not_two_path`).

use std::collections::BTreeMap;
use std::sync::OnceLock;

use super::namespace::cc_manifests;
use super::two_path::{
    AtWindow, Base, CancelOver, Cmp, CorridorRefusal, FloorClass, SilenceRule, Threshold,
    TwoPathPolicy,
};
use super::Error;

/// The table's `kind` for a row the generic two-path machine decides.
pub const KIND_TWO_PATH: &str = "two_path";
/// The community corridor.
pub const CORRIDOR_COMMUNITY: &str = "community";
/// The self corridor (one person's own keys).
pub const CORRIDOR_SELF: &str = "self";
/// The self roster's two rows.
pub const FAMILY_SELF_ROSTER_ADD: &str = "self_roster_add";
/// See [`FAMILY_SELF_ROSTER_ADD`].
pub const FAMILY_SELF_ROSTER_EVICT: &str = "self_roster_evict";

/// The bases CC checks a reverse-path community row at, beside the
/// expected-active base of [`EXPECTED_ACTIVE_PROBE_N`] members.
pub const COMMUNITY_CORRIDOR_BASES: [usize; 3] = [6, 7, 10];
/// The bases CC checks a forward-only community row at (beside the same
/// expected-active base).
pub const FORWARD_ONLY_BASES: [usize; 4] = [3, 6, 7, 10];
/// The community size whose expected-active base CC checks (base 344 under
/// the table's provisional law).
pub const EXPECTED_ACTIVE_PROBE_N: usize = 10_000;
/// The roster size CC checks a self row's own corridor at.
pub const SELF_CORRIDOR_BASE: usize = 3;

/// Why a door refused to decide under its family's policy row. Stable
/// snake_case tokens; APPEND-ONLY. A corridor refusal carries the
/// [`CorridorRefusal`] token itself.
pub mod refusal {
    /// The table has no row for the family the door asked for.
    pub const ROW_MISSING: &str = "policy_row_missing";
    /// The row is not a two-path policy (a `mirror` or `cosigned` row).
    pub const NOT_TWO_PATH: &str = "policy_not_two_path";
    /// A member of the row is in a form persist does not read (an unknown
    /// threshold phrase, an unknown `cancel_over` / `at_window` / corridor,
    /// a window that is not its class's, a zero denominator).
    pub const ROW_UNREADABLE: &str = "policy_row_unreadable";
    /// The row's base is not built (the expected-active law, #180 item 2).
    pub const BASE_NOT_BUILT: &str = "policy_base_not_built";
    /// Two rows one door decides under as one policy disagree.
    pub const ROWS_DISAGREE: &str = "policy_rows_disagree";
}

/// The table's `_meta`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct TableMeta {
    /// CC's hash over the rows (the vectors carry it too).
    pub policy_sha256: String,
    /// The CC section (`4.5.13`).
    pub cc_section: String,
}

/// The table's provisional base law (`base(N) = N if N <= k else max(min,
/// k + (N - k) // tail)`).
#[derive(Debug, Clone, Copy, serde::Deserialize)]
pub struct BaseLaw {
    /// The small-community size at or below which every member counts.
    pub k: usize,
    /// One in `tail` members beyond `k` counts.
    pub tail: usize,
    /// The floor the base never falls below.
    pub min: usize,
}

impl BaseLaw {
    /// The expected-active base of an `n`-member community.
    #[must_use]
    pub fn expected_active(self, n: usize) -> usize {
        if n <= self.k {
            n
        } else {
            (self.k + (n - self.k) / self.tail.max(1)).max(self.min)
        }
    }
}

/// One row of the table, as CC writes it. The threshold members are raw:
/// a `{num, den}` object, `null`, or one of the phrases
/// [`PolicyTable::policy_of`] reads.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PolicyRow {
    /// The door family (`self_roster_add`, `default_content`, …).
    pub family: String,
    /// `two_path`, `mirror` or `cosigned`.
    pub kind: String,
    /// `standing` or `active`.
    pub base: String,
    /// ENACT.
    pub enact: serde_json::Value,
    /// CANCEL.
    pub cancel: serde_json::Value,
    /// FLOOR.
    pub floor: serde_json::Value,
    /// `base`, `others`, or `—` (no cancel).
    pub cancel_over: String,
    /// `cancelled`, `stay_open`, `lapsed`, `tallied`, `—`.
    pub at_window: String,
    /// The window, in seconds.
    pub window_secs: i64,
    /// The window's sensitivity class (a key of `window_classes`).
    pub window_class: String,
    /// No instant landing.
    pub irreversible: bool,
    /// The door has a reverse path.
    pub reverse_path: bool,
    /// `community`, `self`, `role`, `halt`, `cosign`.
    pub corridor: String,
}

/// The vendored table (CC 4.5.13).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PolicyTable {
    /// The pin and section.
    #[serde(rename = "_meta")]
    pub meta: TableMeta,
    /// One row per door family.
    pub families: Vec<PolicyRow>,
    /// The count minimum per corridor (`community` 2, `self` 1).
    pub min_count: BTreeMap<String, usize>,
    /// Window class → seconds.
    pub window_classes: BTreeMap<String, i64>,
    /// The provisional base law.
    pub base_law: BaseLaw,
}

/// What the table does not say and a door does: the silence condition and
/// the one-open rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DoorRule {
    /// The target-silence condition.
    pub silence: SilenceRule,
    /// A proposer holds at most one open proposal.
    pub one_open_per_proposer: bool,
    /// At most one open proposal of a kind names a target.
    pub one_open_per_target: bool,
}

impl DoorRule {
    /// The self-roster door's rule (CC 3.3.6.3): an eviction's target silent
    /// all window; one open proposal per proposer and per target.
    pub const SELF_ROSTER: Self = Self {
        silence: SilenceRule::EvictOnly,
        one_open_per_proposer: true,
        one_open_per_target: true,
    };
}

fn refused(family: &str, reason: &'static str) -> Error {
    Error::GovernancePolicyRefused {
        family: family.to_owned(),
        reason,
    }
}

/// `{num, den}` with a non-zero denominator.
fn fraction(v: &serde_json::Value, cmp: Cmp) -> Option<Threshold> {
    let num = u32::try_from(v.get("num")?.as_u64()?).ok()?;
    let den = u32::try_from(v.get("den")?.as_u64()?).ok()?;
    (den > 0).then_some(Threshold::Fraction { num, den, cmp })
}

/// The CANCEL phrase of a self row ("more than 1/2 of the others (strict
/// majority)").
const CANCEL_STRICT_MAJORITY_OF_OTHERS: &str = "more than 1/2 of the others (strict majority)";
/// The FLOOR phrase of a self row: one key.
const FLOOR_ONE_VOTER: &str = "one_voter";

impl PolicyTable {
    /// Parse a table (the vendored one is [`table`]).
    ///
    /// # Errors
    ///
    /// [`Error::GovernancePolicyRefused`] (`policy_row_unreadable`, family
    /// `*`) when the bytes are not a table.
    pub fn parse(json: &str) -> Result<Self, Error> {
        serde_json::from_str(json).map_err(|_| refused("*", refusal::ROW_UNREADABLE))
    }

    /// The row for `family`.
    ///
    /// # Errors
    ///
    /// `policy_row_missing`.
    pub fn row(&self, family: &str) -> Result<&PolicyRow, Error> {
        self.families
            .iter()
            .find(|r| r.family == family)
            .ok_or_else(|| refused(family, refusal::ROW_MISSING))
    }

    /// A row's count-minimum class: [`FloorClass::SameIdentity`] for the self
    /// corridor, [`FloorClass::Voters`] for a community; the table's own
    /// `min_count` must say the same number.
    fn floor_class(&self, row: &PolicyRow) -> Result<FloorClass, Error> {
        let class = match row.corridor.as_str() {
            CORRIDOR_SELF => FloorClass::SameIdentity,
            CORRIDOR_COMMUNITY => FloorClass::Voters,
            _ => return Err(refused(&row.family, refusal::ROW_UNREADABLE)),
        };
        if self.min_count.get(&row.corridor) != Some(&class.min_count()) {
            return Err(refused(&row.family, refusal::ROW_UNREADABLE));
        }
        Ok(class)
    }

    /// **The row as a [`TwoPathPolicy`]**, with the door's own rule. No
    /// corridor: [`Self::admit`] is the door's call. The base is
    /// [`Base::StandingRoster`] whatever the row names; a caller deciding an
    /// `active` row supplies the base count ([`TwoPathPolicy::resolve_over`]).
    ///
    /// # Errors
    ///
    /// `policy_not_two_path`, or `policy_row_unreadable` for a member in a
    /// form persist does not read or a window that is not its class's.
    pub fn policy_of(&self, row: &PolicyRow, door: DoorRule) -> Result<TwoPathPolicy, Error> {
        let bad = || refused(&row.family, refusal::ROW_UNREADABLE);
        if row.kind != KIND_TWO_PATH {
            return Err(refused(&row.family, refusal::NOT_TWO_PATH));
        }
        if self.window_classes.get(&row.window_class) != Some(&row.window_secs) {
            return Err(bad());
        }
        let floor_class = self.floor_class(row)?;
        let enact = fraction(&row.enact, Cmp::MoreThan).ok_or_else(bad)?;
        let cancel = match &row.cancel {
            serde_json::Value::Null => None,
            serde_json::Value::String(s) if s == CANCEL_STRICT_MAJORITY_OF_OTHERS => {
                Some(Threshold::StrictMajority)
            }
            v => Some(fraction(v, Cmp::AtLeast).ok_or_else(bad)?),
        };
        let floor = match &row.floor {
            serde_json::Value::Null => None,
            serde_json::Value::String(s) if s == FLOOR_ONE_VOTER => Some(Threshold::Fraction {
                num: 0,
                den: 1,
                cmp: Cmp::AtLeast,
            }),
            v => Some(fraction(v, Cmp::AtLeast).ok_or_else(bad)?),
        };
        let cancel_over = match (row.cancel_over.as_str(), cancel.is_some()) {
            ("base", true) => CancelOver::Base,
            ("others", true) => CancelOver::Others,
            // A row with no cancel names no denominator for it.
            (_, false) => CancelOver::Base,
            _ => return Err(bad()),
        };
        let at_window = match row.at_window.as_str() {
            "cancelled" => AtWindow::Cancel,
            "stay_open" => AtWindow::StayOpen,
            _ => return Err(bad()),
        };
        Ok(TwoPathPolicy {
            base: Base::StandingRoster,
            enact,
            cancel,
            cancel_over,
            floor,
            floor_class,
            reverse_path: row.reverse_path,
            at_window,
            irreversible: row.irreversible,
            window_secs: row.window_secs,
            silence: door.silence,
            one_open_per_proposer: door.one_open_per_proposer,
            one_open_per_target: door.one_open_per_target,
        })
    }

    /// A row's window floor, by its class (CC's `check_corridor`).
    fn window_floor(&self, row: &PolicyRow) -> Result<i64, Error> {
        let class = if row.irreversible {
            "irreversible_7d"
        } else if row.window_class == "content_24h" {
            "content_24h"
        } else {
            "standing_72h"
        };
        self.window_classes
            .get(class)
            .copied()
            .ok_or_else(|| refused(&row.family, refusal::ROW_UNREADABLE))
    }

    /// **The corridor over a row**, as CC checks the table (module doc): the
    /// first clause that fails, at the first base it fails at.
    ///
    /// # Errors
    ///
    /// The [`CorridorRefusal`]; `policy_row_unreadable` for a row whose
    /// corridor or window class persist does not read.
    pub fn check_corridor(
        &self,
        row: &PolicyRow,
        policy: &TwoPathPolicy,
    ) -> Result<Result<(), CorridorRefusal>, Error> {
        match row.corridor.as_str() {
            CORRIDOR_SELF => Ok(policy.check_corridor(
                SELF_CORRIDOR_BASE,
                self.window_classes
                    .get("ruled_24h")
                    .copied()
                    .ok_or_else(|| refused(&row.family, refusal::ROW_UNREADABLE))?,
            )),
            CORRIDOR_COMMUNITY => {
                let floor = self.window_floor(row)?;
                let probe = self.base_law.expected_active(EXPECTED_ACTIVE_PROBE_N);
                if policy.reverse_path {
                    for base in COMMUNITY_CORRIDOR_BASES.into_iter().chain([probe]) {
                        if let Err(r) = policy.check_corridor(base, floor) {
                            return Ok(Err(r));
                        }
                    }
                    return Ok(Ok(()));
                }
                for base in FORWARD_ONLY_BASES.into_iter().chain([probe]) {
                    if policy.enact.votes(base) <= 1 {
                        return Ok(Err(CorridorRefusal::EnactBySingleVoter));
                    }
                    if let Threshold::Fraction { num, den, .. } = policy.enact {
                        if 2 * num < den {
                            return Ok(Err(CorridorRefusal::EnactBelowStrictMajority));
                        }
                    }
                    if policy.window_secs < floor {
                        return Ok(Err(CorridorRefusal::WindowBelowFloor));
                    }
                }
                Ok(Ok(()))
            }
            _ => Err(refused(&row.family, refusal::ROW_UNREADABLE)),
        }
    }

    /// **THE door's call**: the policy a door decides `family` under — the
    /// row, built, with its base built, inside its corridor.
    ///
    /// # Errors
    ///
    /// [`Error::GovernancePolicyRefused`]: the corridor token, or one of
    /// [`refusal`]'s.
    pub fn admit(&self, family: &str, door: DoorRule) -> Result<TwoPathPolicy, Error> {
        let row = self.row(family)?;
        let policy = self.policy_of(row, door)?;
        if row.base != "standing" {
            return Err(refused(family, refusal::BASE_NOT_BUILT));
        }
        self.check_corridor(row, &policy)?
            .map_err(|r| refused(family, r.as_str()))?;
        Ok(policy)
    }

    /// **The self roster's policy** (CC 3.3.6.3): its two rows admitted, and
    /// one policy, since one decision orders a self's additions and evictions
    /// together.
    ///
    /// # Errors
    ///
    /// As [`Self::admit`], or `policy_rows_disagree`.
    pub fn self_roster(&self) -> Result<TwoPathPolicy, Error> {
        let add = self.admit(FAMILY_SELF_ROSTER_ADD, DoorRule::SELF_ROSTER)?;
        let evict = self.admit(FAMILY_SELF_ROSTER_EVICT, DoorRule::SELF_ROSTER)?;
        if add != evict {
            return Err(refused(FAMILY_SELF_ROSTER_EVICT, refusal::ROWS_DISAGREE));
        }
        Ok(add)
    }
}

/// The vendored table, parsed once.
///
/// # Errors
///
/// `policy_row_unreadable` when the compiled-in bytes are not a table (a
/// re-vendor that changed the shape; I1303 holds it).
pub fn table() -> Result<&'static PolicyTable, Error> {
    #[cfg(test)]
    if let Some(t) = test_table::get() {
        return Ok(t);
    }
    static TABLE: OnceLock<Option<PolicyTable>> = OnceLock::new();
    TABLE
        .get_or_init(|| PolicyTable::parse(cc_manifests::GOVERNANCE_POLICY_JSON).ok())
        .as_ref()
        .ok_or_else(|| refused("*", refusal::ROW_UNREADABLE))
}

/// The test seam: a door reads this table instead of the vendored one on
/// the current thread (the purge clock's precedent). Test builds only.
#[cfg(test)]
pub(crate) mod test_table {
    use super::PolicyTable;
    use std::cell::Cell;

    thread_local! {
        static TABLE: Cell<Option<&'static PolicyTable>> = const { Cell::new(None) };
    }

    /// Read `table` on this thread (`None`: the vendored one). The table is
    /// leaked: a test's lifetime.
    pub(crate) fn set(table: Option<PolicyTable>) {
        let leaked = table.map(|t| &*Box::leak(Box::new(t)));
        TABLE.with(|c| c.set(leaked));
    }

    pub(super) fn get() -> Option<&'static PolicyTable> {
        TABLE.with(Cell::get)
    }
}

#[cfg(test)]
mod tests {
    //! **I1303–I1306** — the vendored table, read as runtime data, and the
    //! corridor as CC checks it.
    use super::*;

    fn vendored() -> PolicyTable {
        PolicyTable::parse(cc_manifests::GOVERNANCE_POLICY_JSON).expect("the vendored table")
    }

    fn with_row(family: &str, f: impl Fn(&mut serde_json::Value)) -> PolicyTable {
        let mut v: serde_json::Value =
            serde_json::from_str(cc_manifests::GOVERNANCE_POLICY_JSON).expect("json");
        let row = v["families"]
            .as_array_mut()
            .expect("families")
            .iter_mut()
            .find(|r| r["family"] == family)
            .expect("row");
        f(row);
        PolicyTable::parse(&v.to_string()).expect("table")
    }

    /// A mutation of one table row.
    type Mutate = dyn Fn(&mut serde_json::Value);

    fn reason(e: Error) -> &'static str {
        match e {
            Error::GovernancePolicyRefused { reason, .. } => reason,
            other => panic!("expected a policy refusal, got {other:?}"),
        }
    }

    /// **I1303** — the vendored table parses, its pin is the table's, and
    /// every two-path row CC built is inside its corridor as persist checks
    /// it; the three rows under their own rule are not two-path policies.
    #[test]
    fn i1303_every_two_path_row_of_the_vendored_table_is_in_its_corridor() {
        let t = table().expect("the compiled-in table");
        assert_eq!(
            t.meta.policy_sha256,
            cc_manifests::VENDORED_GOVERNANCE_POLICY_SHA256
        );
        assert_eq!(t.meta.cc_section, "4.5.13");
        assert_eq!(t.base_law.expected_active(EXPECTED_ACTIVE_PROBE_N), 344);
        assert_eq!(t.base_law.expected_active(10), 10);
        assert_eq!(
            t.base_law.expected_active(12),
            12,
            "at k every member counts"
        );
        assert_eq!(t.base_law.expected_active(42), 13);
        // At or below k the base is N even under a floor above k (the floor
        // lifts only the tail).
        let tiny = BaseLaw {
            k: 2,
            tail: 30,
            min: 3,
        };
        assert_eq!((tiny.expected_active(2), tiny.expected_active(3)), (2, 3));
        let (mut two_path, mut other) = (Vec::new(), Vec::new());
        for row in &t.families {
            let door = DoorRule::SELF_ROSTER;
            match t.policy_of(row, door) {
                Ok(p) => {
                    assert_eq!(
                        t.check_corridor(row, &p).expect("readable"),
                        Ok(()),
                        "{} is outside its corridor",
                        row.family
                    );
                    two_path.push(row.family.as_str());
                }
                Err(e) => {
                    assert_eq!(reason(e), refusal::NOT_TWO_PATH, "{}", row.family);
                    other.push(row.family.as_str());
                }
            }
        }
        assert_eq!(
            two_path,
            [
                "default_content",
                "default_standing",
                "default_irreversible",
                "community_invite",
                "community_remove",
                "self_roster_add",
                "self_roster_evict"
            ]
        );
        assert_eq!(
            other,
            ["moderation_action", "accord_halt", "custodian_replace"]
        );
        // A door may decide only a standing-base row: the community rows'
        // expected-active base is not built.
        for fam in ["default_content", "community_invite"] {
            assert_eq!(
                reason(t.admit(fam, DoorRule::SELF_ROSTER).unwrap_err()),
                refusal::BASE_NOT_BUILT
            );
        }
        assert_eq!(
            reason(t.admit("no_such_door", DoorRule::SELF_ROSTER).unwrap_err()),
            refusal::ROW_MISSING
        );
    }

    /// **I1304** — the self roster's policy is the table's: the ruled
    /// thresholds at every roster size 1..=12 (ENACT a strict majority of the
    /// roster, CANCEL of the others, FLOOR one key), the 24 h window, the
    /// window leaving a proposal open, reversible, and the door's own rule.
    #[test]
    fn i1304_the_self_roster_policy_is_the_tables() {
        let p = vendored().self_roster().expect("admitted");
        assert_eq!(p.window_secs, 86_400);
        assert_eq!(p.window_secs, crate::federation::self_roster::W_SELF_SECS);
        assert_eq!(p.at_window, AtWindow::StayOpen);
        assert_eq!(p.cancel_over, CancelOver::Others);
        assert_eq!(p.floor_class, FloorClass::SameIdentity);
        assert!(p.reverse_path && !p.irreversible);
        assert_eq!(
            (p.silence, p.one_open_per_proposer, p.one_open_per_target),
            (SilenceRule::EvictOnly, true, true)
        );
        for n in 1..=12usize {
            let roster: std::collections::BTreeSet<String> =
                (1..=n).map(|i| format!("d{i}")).collect();
            let r = p.resolve(&roster, "d1");
            let sm = ciris_verify_core::accord_genesis::strict_majority;
            assert_eq!(r.enact, sm(n), "enact at {n}");
            assert_eq!(r.cancel, Some(sm(n - 1).max(1)), "cancel at {n}");
            assert_eq!(r.floor, Some(1), "floor at {n}");
        }
    }

    /// **I1305** — the corridor refuses a row outside it, by its token, at
    /// the door's call: each self-row and community-row mutation below is
    /// one clause.
    #[test]
    fn i1305_a_row_outside_its_corridor_is_refused_by_its_token() {
        let self_cases: [(&Mutate, &str); 4] = [
            // A self window under its 24 h floor (class kept honest).
            (
                &|r| {
                    r["window_class"] = "none".into();
                    r["window_secs"] = 0.into();
                },
                "window_below_floor",
            ),
            // ENACT one key of three.
            (
                &|r| r["enact"] = serde_json::json!({"num": 1, "den": 7}),
                "enact_by_single_voter",
            ),
            // ENACT every key of three.
            (
                &|r| r["enact"] = serde_json::json!({"num": 5, "den": 6}),
                "enact_needs_everyone",
            ),
            // FLOOR above ENACT.
            (
                &|r| r["floor"] = serde_json::json!({"num": 1, "den": 1}),
                "floor_above_enact",
            ),
        ];
        for (f, want) in self_cases {
            for fam in [FAMILY_SELF_ROSTER_ADD, FAMILY_SELF_ROSTER_EVICT] {
                let t = with_row(fam, f);
                assert_eq!(reason(t.self_roster().unwrap_err()), want, "{fam}");
            }
        }
        // Community rows, through `check_corridor` (no community door is built).
        let community: [(&str, &Mutate, CorridorRefusal); 6] = [
            (
                "default_standing",
                &|r| r["cancel"] = serde_json::json!({"num": 1, "den": 7}),
                CorridorRefusal::CancelBySingleVoter,
            ),
            (
                "default_standing",
                &|r| r["floor"] = serde_json::json!({"num": 0, "den": 1}),
                CorridorRefusal::FloorBelowTwoVoters,
            ),
            (
                "default_content",
                &|r| {
                    r["window_class"] = "none".into();
                    r["window_secs"] = 0.into();
                },
                CorridorRefusal::WindowBelowFloor,
            ),
            (
                "default_irreversible",
                &|r| {
                    r["window_class"] = "standing_72h".into();
                    r["window_secs"] = 259_200.into();
                },
                CorridorRefusal::WindowBelowFloor,
            ),
            (
                "community_remove",
                &|r| r["enact"] = serde_json::json!({"num": 1, "den": 7}),
                CorridorRefusal::EnactBySingleVoter,
            ),
            (
                "community_remove",
                &|r| r["enact"] = serde_json::json!({"num": 1, "den": 3}),
                CorridorRefusal::EnactBelowStrictMajority,
            ),
        ];
        for (fam, f, want) in community {
            let t = with_row(fam, f);
            let row = t.row(fam).unwrap();
            let p = t.policy_of(row, DoorRule::SELF_ROSTER).unwrap();
            assert_eq!(t.check_corridor(row, &p).unwrap(), Err(want), "{fam}");
        }
        // A forward-only row enacting on exactly half (strictly more than
        // 1/2) is at the strict-majority floor, inside.
        let t = with_row("community_remove", |r| {
            r["enact"] = serde_json::json!({"num": 1, "den": 2});
        });
        let row = t.row("community_remove").unwrap();
        let p = t.policy_of(row, DoorRule::SELF_ROSTER).unwrap();
        assert_eq!(t.check_corridor(row, &p).unwrap(), Ok(()));
        // The forward-only row's window floor is checked too.
        let t = with_row("community_remove", |r| {
            r["window_class"] = "content_24h".into();
            r["window_secs"] = 86_400.into();
        });
        let row = t.row("community_remove").unwrap();
        let p = t.policy_of(row, DoorRule::SELF_ROSTER).unwrap();
        assert_eq!(
            t.check_corridor(row, &p).unwrap(),
            Ok(()),
            "a content-class row's floor is 24 h"
        );
        let t = with_row("community_remove", |r| {
            r["window_class"] = "ruled_24h".into();
            r["window_secs"] = 86_400.into();
        });
        let row = t.row("community_remove").unwrap();
        let p = t.policy_of(row, DoorRule::SELF_ROSTER).unwrap();
        assert_eq!(
            t.check_corridor(row, &p).unwrap(),
            Err(CorridorRefusal::WindowBelowFloor),
            "any other class's floor is 72 h"
        );
    }

    /// **I1306** — a row persist cannot read is refused, never guessed: an
    /// unknown threshold phrase, a window that is not its class's, an
    /// unknown `cancel_over` / `at_window` / corridor, a `min_count` that
    /// disagrees with the class, two self rows that disagree.
    #[test]
    fn i1306_an_unreadable_row_is_refused_not_guessed() {
        let cases: [&dyn Fn(&mut serde_json::Value); 7] = [
            &|r| r["cancel"] = "more than half".into(),
            &|r| r["floor"] = "two_voters".into(),
            &|r| r["enact"] = serde_json::json!({"num": 1, "den": 0}),
            &|r| r["window_secs"] = 86_401.into(),
            &|r| r["cancel_over"] = "all".into(),
            &|r| r["at_window"] = "lapsed".into(),
            &|r| r["corridor"] = "role".into(),
        ];
        for f in cases {
            let t = with_row(FAMILY_SELF_ROSTER_ADD, f);
            assert_eq!(
                reason(t.self_roster().unwrap_err()),
                refusal::ROW_UNREADABLE
            );
        }
        let mut v: serde_json::Value =
            serde_json::from_str(cc_manifests::GOVERNANCE_POLICY_JSON).unwrap();
        v["min_count"]["self"] = 2.into();
        let t = PolicyTable::parse(&v.to_string()).unwrap();
        assert_eq!(
            reason(t.self_roster().unwrap_err()),
            refusal::ROW_UNREADABLE,
            "min_count must be the class's"
        );
        let t = with_row(FAMILY_SELF_ROSTER_EVICT, |r| {
            r["at_window"] = "cancelled".into();
        });
        assert_eq!(reason(t.self_roster().unwrap_err()), refusal::ROWS_DISAGREE);
        assert_eq!(
            reason(PolicyTable::parse("{}").unwrap_err()),
            refusal::ROW_UNREADABLE
        );
        let t = with_row(FAMILY_SELF_ROSTER_ADD, |r| r["kind"] = "mirror".into());
        assert_eq!(reason(t.self_roster().unwrap_err()), refusal::NOT_TWO_PATH);
    }
}
