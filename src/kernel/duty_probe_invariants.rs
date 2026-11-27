//! v62.0.0 (SEAT-K0; the lead's ask of 11-24) — **the Kernel crate's duty
//! seat, as it is on kernel-v0.2.2, presented through persist's own
//! `KRow`.** Pure; no store.
//!
//! Two kinds of test, kept apart on purpose:
//!
//! - **I7165–I7169 — Kernel's own duty fixtures** (the crate's
//!   `tests/fixtures/seat.json`, scenarios 1, 8, 9, 10 and 31), transcribed
//!   row for row and run through persist's `KRow` / `NoCut` and the
//!   crate's reference law (the fixture's `law`). These ASSERT the crate's
//!   own expected answer: a red one means persist's presentation of a row
//!   (the `SeatRow` fields `KRow` carries) does not read as Kernel's does.
//!   Scenario 1 is transcribed without its moderation-window rows (they bear
//!   on the window, not on the seat), so its withdrawal names `md` alone.
//! - **I7170–I7172 — the three questions sent to Kernel (P/SEAT-plan.md
//!   §2c, KQ1–KQ3) as PROBES.** Each prints `WANTED … GOT …` for every line
//!   of its question and asserts nothing: it is a REPORT, run by name
//!   (`#[ignore]`d so it gates nothing), so the questions' "wanted" lines get
//!   a measured "got" beside them. They are deleted when Kernel answers and
//!   SEAT-2's witnesses replace them.
//!
//! Not presentable on this base (READ): `KRow` carries no `sub()` (v62-pre4's
//! R2-delegation adds `SeatFields::sub`, on another line), so no row here
//! grants sub-delegation; Kernel's nine delegation lines that turn on it are
//! v62-pre4's I6421–I6429, not repeated here.

use std::collections::{BTreeMap, BTreeSet};

use ciris_kernel::layers;
use ciris_kernel::seat::{seat_rule, Conf, Obj, Over, Policy, SeatKind, SeatLaw, Seats};

use super::view::{KRow, NoCut, RowId, SeatFields};

fn id(s: &str) -> RowId {
    RowId::of_label(&["seat-probe", s])
}

fn ids(v: &[&str]) -> Vec<RowId> {
    v.iter().map(|s| id(s)).collect()
}

fn keys(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_owned()).collect()
}

fn set(v: &[&str]) -> BTreeSet<String> {
    v.iter().map(|s| (*s).to_owned()).collect()
}

/// The crate's reference law (`tests/fixtures/seat.json` `law`), the parts a
/// duty seat reads.
fn kernel_law() -> SeatLaw {
    SeatLaw {
        duties: keys(&["moderate", "review", "slash", "takedown"]),
        holds: BTreeMap::from([
            (
                "duty".to_owned(),
                keys(&["member", "moderate", "review", "slash", "takedown"]),
            ),
            ("founder".to_owned(), keys(&["member"])),
        ]),
        confers: BTreeMap::from([(
            "duty".to_owned(),
            (
                keys(&["duty", "moderate", "review", "slash", "takedown"]),
                Over::Same,
            ),
        )]),
        ends: BTreeMap::new(),
        final_scopes: Vec::new(),
        roster_seats: keys(&["member"]),
        depth: 5,
        policy: BTreeMap::from([
            ("duty_confer".to_owned(), Policy::DutyConfer),
            ("duty_withdraw".to_owned(), Policy::DutyWithdraw),
            ("community_invite".to_owned(), Policy::AtLeast(2, 3)),
            ("community_remove".to_owned(), Policy::AtLeast(2, 3)),
        ]),
    }
}

/// One row, as the fixture states it. Every row is over the room `g`
/// unless `obj` is false.
#[derive(Default)]
struct F<'a> {
    names: &'a [&'a str],
    to: &'a [&'a str],
    cosigners: &'a [&'a str],
    scope: Option<&'a str>,
    conf: Option<Conf>,
    under: Option<&'a str>,
    head: &'a [&'a str],
    policy: Option<&'a str>,
    counted: Option<&'a str>,
    of: Option<&'a str>,
    target: Option<&'a str>,
    no_obj: bool,
}

fn row(name: &str, signer: &str, kind: SeatKind, f: F<'_>) -> KRow {
    KRow::new(id(name), ids(f.names), signer).with_seat(SeatFields {
        to: keys(f.to),
        scope: f.scope.map(str::to_owned),
        obj: (!f.no_obj).then(|| Obj::Row(id("g"))),
        conf: f.conf,
        under: f.under.map(id),
        cosigners: keys(f.cosigners),
        head: ids(f.head),
        policy: f.policy.map(str::to_owned),
        counted: f.counted.map(str::to_owned),
        of: f.of.map(id),
        target: f.target.map(id),
        ..SeatFields::of(kind)
    })
}

/// The answers a probe reads, over `rows` under `law`.
struct Read {
    concluded: BTreeMap<String, bool>,
    holders: BTreeMap<&'static str, BTreeSet<String>>,
}

const SCOPES: &[&str] = &["duty", "moderate", "review", "member"];

fn read(rows: &[KRow], names: &[&str], law: &SeatLaw) -> Read {
    let kept = layers::kept(rows, |_| true);
    let c = layers::conclude(kept, |p| seat_rule(p, law, &NoCut, &|_| true), None);
    let seats = Seats::new(&c, law, &NoCut, None);
    let room = Obj::Row(id("g"));
    Read {
        concluded: names
            .iter()
            .map(|n| ((*n).to_owned(), c.concluded_id(&id(n))))
            .collect(),
        holders: SCOPES
            .iter()
            .map(|s| (*s, seats.holders(s, &room, None)))
            .collect(),
    }
}

fn founding(signer: &str, to: &[&str], cosigners: &[&str], scope: &str) -> KRow {
    row(
        "g",
        signer,
        SeatKind::Offer,
        F {
            to,
            cosigners,
            scope: Some(scope),
            conf: Some(Conf::Own),
            ..F::default()
        },
    )
}

// ── Kernel's own fixtures (asserting) ─────────────────────────────────────

/// **I7165 — seat.json scenario 9**: a seat conferred by two of three
/// founding holders survives its conferrer's unseating by the other two.
#[test]
fn i7165_kernel_scenario_9_a_seat_survives_its_conferrer() {
    let law = kernel_law();
    let rows = vec![
        founding("f1", &["f1", "f2", "f3"], &["f2", "f3"], "duty"),
        row(
            "d",
            "f1",
            SeatKind::Offer,
            F {
                names: &["g"],
                to: &["K"],
                cosigners: &["f2"],
                scope: Some("moderate"),
                conf: Some(Conf::Group),
                head: &["g"],
                policy: Some("duty_confer"),
                counted: Some("duty"),
                ..F::default()
            },
        ),
        row(
            "ak",
            "K",
            SeatKind::Accept,
            F {
                names: &["d"],
                of: Some("d"),
                no_obj: true,
                ..F::default()
            },
        ),
        row(
            "c3",
            "f3",
            SeatKind::Cosign,
            F {
                names: &["g"],
                of: Some("xf"),
                no_obj: true,
                ..F::default()
            },
        ),
        row(
            "xf",
            "f2",
            SeatKind::Unseat,
            F {
                names: &["g", "c3", "ak"],
                to: &["f1"],
                scope: Some("duty"),
                conf: Some(Conf::Group),
                head: &["g"],
                policy: Some("duty_withdraw"),
                counted: Some("duty"),
                ..F::default()
            },
        ),
    ];
    let r = read(&rows, &["g", "d", "ak", "c3", "xf"], &law);
    assert!(
        r.concluded.values().all(|c| *c),
        "I7165: every row concludes: {:?}",
        r.concluded
    );
    assert_eq!(
        r.holders["duty"],
        set(&["K", "f2", "f3"]),
        "I7165: duty holders"
    );
}

/// **I7166 — seat.json scenario 10**: the same rows, but the unseating does
/// not name K's acceptance: two tips, and K is not common to them.
#[test]
fn i7166_kernel_scenario_10_tips_wait() {
    let law = kernel_law();
    let rows = vec![
        founding("f1", &["f1", "f2", "f3"], &["f2", "f3"], "duty"),
        row(
            "d",
            "f1",
            SeatKind::Offer,
            F {
                names: &["g"],
                to: &["K"],
                cosigners: &["f2"],
                scope: Some("moderate"),
                conf: Some(Conf::Group),
                head: &["g"],
                policy: Some("duty_confer"),
                counted: Some("duty"),
                ..F::default()
            },
        ),
        row(
            "ak",
            "K",
            SeatKind::Accept,
            F {
                names: &["d"],
                of: Some("d"),
                no_obj: true,
                ..F::default()
            },
        ),
        row(
            "c3",
            "f3",
            SeatKind::Cosign,
            F {
                names: &["g"],
                of: Some("xf"),
                no_obj: true,
                ..F::default()
            },
        ),
        row(
            "xf",
            "f2",
            SeatKind::Unseat,
            F {
                names: &["g", "c3"],
                to: &["f1"],
                scope: Some("duty"),
                conf: Some(Conf::Group),
                head: &["g"],
                policy: Some("duty_withdraw"),
                counted: Some("duty"),
                ..F::default()
            },
        ),
    ];
    let r = read(&rows, &["g", "d", "ak", "c3", "xf"], &law);
    assert!(
        r.concluded.values().all(|c| *c),
        "I7166: every row concludes: {:?}",
        r.concluded
    );
    assert_eq!(r.holders["duty"], set(&["f2", "f3"]), "I7166: duty holders");
}

/// **I7167 — seat.json scenario 8**: among three holders, one holder's own
/// conferral (`Conf::Seat` under the founding) concludes nothing.
#[test]
fn i7167_kernel_scenario_8_no_lone_conferral_among_three() {
    let law = kernel_law();
    let rows = vec![
        founding("f1", &["f1", "f2", "f3"], &["f2", "f3"], "duty"),
        row(
            "d1",
            "f1",
            SeatKind::Offer,
            F {
                names: &["g"],
                to: &["K"],
                scope: Some("moderate"),
                conf: Some(Conf::Seat),
                under: Some("g"),
                ..F::default()
            },
        ),
        row(
            "ak",
            "K",
            SeatKind::Accept,
            F {
                names: &["d1"],
                of: Some("d1"),
                no_obj: true,
                ..F::default()
            },
        ),
    ];
    let r = read(&rows, &["g", "d1", "ak"], &law);
    assert_eq!(
        r.concluded,
        BTreeMap::from([
            ("g".to_owned(), true),
            ("d1".to_owned(), false),
            ("ak".to_owned(), false)
        ]),
        "I7167"
    );
    assert_eq!(
        r.holders["duty"],
        set(&["f1", "f2", "f3"]),
        "I7167: duty holders"
    );
}

/// **I7168 — seat.json scenario 31**: a lone holder's conferral, withdrawn
/// by the holder's acceptance and offered again, seats again.
#[test]
fn i7168_kernel_scenario_31_a_lone_holder_confers_again() {
    let law = kernel_law();
    let seat = |name: &str, names: &'static [&'static str]| {
        row(
            name,
            "A",
            SeatKind::Offer,
            F {
                names,
                to: &["K"],
                scope: Some("moderate"),
                conf: Some(Conf::Seat),
                under: Some("g"),
                ..F::default()
            },
        )
    };
    let accept = |name: &str, of: &'static [&'static str]| {
        row(
            name,
            "K",
            SeatKind::Accept,
            F {
                names: of,
                of: of.first().copied(),
                no_obj: true,
                ..F::default()
            },
        )
    };
    let withdraw = |name: &str, target: &'static [&'static str]| {
        row(
            name,
            "K",
            SeatKind::Withdraw,
            F {
                names: target,
                target: target.first().copied(),
                no_obj: true,
                ..F::default()
            },
        )
    };
    let rows = vec![
        founding("A", &["A"], &[], "duty"),
        seat("o1", &["g"]),
        accept("a1", &["o1"]),
        withdraw("wd1", &["a1"]),
        seat("o2", &["wd1"]),
        accept("a2", &["o2"]),
        withdraw("wd3", &["o1"]),
    ];
    let r = read(&rows, &["g", "o1", "a1", "wd1", "o2", "a2", "wd3"], &law);
    assert!(
        r.concluded.values().all(|c| *c),
        "I7168: every row concludes: {:?}",
        r.concluded
    );
    assert_eq!(r.holders["duty"], set(&["A", "K"]), "I7168: duty holders");
}

/// **I7169 — seat.json scenario 1, without its window rows**: a counted
/// conferral is not ended by its proposer's lone withdrawal (CC 2.7.7 "an
/// offer conferred by a count is ended by its holder or by a count, never by
/// its proposer alone"; G7).
#[test]
fn i7169_kernel_scenario_1_a_proposer_cannot_end_a_counted_seat() {
    let law = kernel_law();
    let rows = vec![
        founding("m1", &["m1", "m2", "m3"], &["m2", "m3"], "duty"),
        row(
            "md",
            "m1",
            SeatKind::Offer,
            F {
                names: &["g"],
                to: &["MOD"],
                cosigners: &["m3", "MOD"],
                scope: Some("moderate"),
                conf: Some(Conf::Group),
                head: &["g"],
                policy: Some("duty_confer"),
                counted: Some("duty"),
                ..F::default()
            },
        ),
        row(
            "um",
            "m1",
            SeatKind::Withdraw,
            F {
                names: &["md"],
                target: Some("md"),
                no_obj: true,
                ..F::default()
            },
        ),
    ];
    let r = read(&rows, &["g", "md", "um"], &law);
    assert!(
        r.concluded.values().all(|c| *c),
        "I7169: every row concludes: {:?}",
        r.concluded
    );
    assert_eq!(
        r.holders["duty"],
        set(&["MOD", "m1", "m2", "m3"]),
        "I7169: MOD still holds"
    );
}

// ── The Kernel questions (reports; run by name) ───────────────────────────

fn report(q: &str, line: &str, wanted: &str, got: &dyn std::fmt::Debug) {
    eprintln!("PROBE {q} {line}: WANTED {wanted} | GOT {got:?}");
}

/// **I7170 — KQ1**: per-duty founding holders beside the members, over one
/// object. Founding lists a, b, c (all sign), `duty_holders = {moderate:
/// [a, b], review: [a]}`; then a counted widening of d; then a counted
/// `duty_confer` of `moderate` to c (c a cosigner); then a's lone withdrawal
/// of c's offer; then a counted `Unseat` of `member` of c. Presented two
/// ways: (A) persist's lineage today (founding scope `member` by a synthetic
/// signer, the duty holders by founding-like `Conf::Own` rows of their own,
/// one per duty); (B) Kernel's scenarios (founding scope `duty` to the
/// holders, the other members by a founding-like `member` row).
#[test]
#[ignore = "SEAT-K0 report: run by name; prints WANTED | GOT for KQ1"]
fn i7170_kq1_per_duty_founding_holders() {
    let law = kernel_law();
    let tail = |extra_names: &'static [&'static str]| -> Vec<KRow> {
        vec![
            row(
                "wd",
                "a",
                SeatKind::Offer,
                F {
                    names: extra_names,
                    to: &["d"],
                    cosigners: &["b", "c", "d"],
                    scope: Some("member"),
                    conf: Some(Conf::Group),
                    head: &["g"],
                    policy: Some("community_invite"),
                    counted: Some("member"),
                    ..F::default()
                },
            ),
            row(
                "cc",
                "a",
                SeatKind::Offer,
                F {
                    names: &["wd"],
                    to: &["c"],
                    cosigners: &["b", "c"],
                    scope: Some("moderate"),
                    conf: Some(Conf::Group),
                    head: &["wd"],
                    policy: Some("duty_confer"),
                    counted: Some("duty"),
                    ..F::default()
                },
            ),
            row(
                "aw",
                "a",
                SeatKind::Withdraw,
                F {
                    names: &["cc"],
                    target: Some("cc"),
                    no_obj: true,
                    ..F::default()
                },
            ),
            row(
                "rc",
                "a",
                SeatKind::Unseat,
                F {
                    names: &["aw"],
                    to: &["c"],
                    cosigners: &["b", "d"],
                    scope: Some("member"),
                    conf: Some(Conf::Group),
                    head: &["wd"],
                    policy: Some("community_remove"),
                    counted: Some("member"),
                    ..F::default()
                },
            ),
        ]
    };
    let own = |name: &str, signer: &str, scope: &str, to: &'static [&'static str]| {
        row(
            name,
            signer,
            SeatKind::Offer,
            F {
                names: &["g"],
                to,
                cosigners: to,
                scope: Some(scope),
                conf: Some(Conf::Own),
                ..F::default()
            },
        )
    };
    for (way, mut rows) in [
        (
            "A (lineage today)",
            vec![
                founding(
                    "\u{2205}group",
                    &["a", "b", "c"],
                    &["a", "b", "c"],
                    "member",
                ),
                own("hm", "a", "moderate", &["a", "b"]),
                own("hr", "a", "review", &["a"]),
            ],
        ),
        (
            "B (Kernel's scenarios)",
            vec![
                founding("a", &["a", "b"], &["b"], "duty"),
                own("mm", "a", "member", &["c"]),
            ],
        ),
    ] {
        let first = rows.len();
        rows.extend(tail(&["g"]));
        for upto in [first + 2, first + 3, first + 4] {
            let at = match upto - first {
                2 => "after c's conferral",
                3 => "after a's lone withdrawal",
                _ => "after c's removal",
            };
            let r = read(&rows[..upto], &["g", "wd", "cc", "aw", "rc"], &law);
            let q = format!("KQ1 {way} {at}");
            report(&q, "concluded", "all", &r.concluded);
            report(
                &q,
                "holders(moderate)",
                "{a, b, c} (removal: {a, b})",
                &r.holders["moderate"],
            );
            report(&q, "holders(review)", "{a}", &r.holders["review"]);
            report(
                &q,
                "holders(duty)",
                "{a, b, c} (removal: {a, b})",
                &r.holders["duty"],
            );
            report(
                &q,
                "holders(member)",
                "{a, b, c, d} (removal: {a, b, d})",
                &r.holders["member"],
            );
        }
    }
}

/// **I7171 — KQ2**: a deputy. a holds `moderate` by a counted conferral
/// (founding holders f1, f2); a deputizes d (`Conf::Seat` under a's offer,
/// `moderate`, no sub-delegation: this base cannot present one); then a is
/// unseated by f1 and f2.
#[test]
#[ignore = "SEAT-K0 report: run by name; prints WANTED | GOT for KQ2"]
fn i7171_kq2_a_deputy() {
    let law = kernel_law();
    let rows = vec![
        founding("f1", &["f1", "f2"], &["f2"], "duty"),
        row(
            "sa",
            "f1",
            SeatKind::Offer,
            F {
                names: &["g"],
                to: &["a"],
                cosigners: &["f2", "a"],
                scope: Some("moderate"),
                conf: Some(Conf::Group),
                head: &["g"],
                policy: Some("duty_confer"),
                counted: Some("duty"),
                ..F::default()
            },
        ),
        row(
            "dd",
            "a",
            SeatKind::Offer,
            F {
                names: &["sa"],
                to: &["d"],
                cosigners: &["d"],
                scope: Some("moderate"),
                conf: Some(Conf::Seat),
                under: Some("sa"),
                ..F::default()
            },
        ),
        row(
            "ua",
            "f1",
            SeatKind::Unseat,
            F {
                names: &["dd"],
                to: &["a"],
                cosigners: &["f2"],
                scope: Some("moderate"),
                conf: Some(Conf::Group),
                head: &["sa"],
                policy: Some("duty_withdraw"),
                counted: Some("duty"),
                ..F::default()
            },
        ),
    ];
    for (upto, at) in [(3, "with the deputy"), (4, "after a's unseating")] {
        let r = read(&rows[..upto], &["g", "sa", "dd", "ua"], &law);
        let q = format!("KQ2 {at}");
        report(&q, "concluded", "g sa dd (ua) all", &r.concluded);
        report(
            &q,
            "holders(duty)",
            "{f1, f2, a} then {f1, f2}: never d",
            &r.holders["duty"],
        );
        report(
            &q,
            "holders(moderate)",
            "d may act under a's seat, not after (no seat of its own)",
            &r.holders["moderate"],
        );
    }
}

/// **I7172 — KQ3**: leaving ends duty seats. Founding holders a, b; b
/// resigns its MEMBERSHIP (a `Withdraw` by b of the offer seating it as a
/// member). (A) persist's lineage today: the member seat is the founding
/// row (scope `member`), the duty seat a founding-like row of its own; (B)
/// Kernel's scenarios: the founding row IS the duty seat.
#[test]
#[ignore = "SEAT-K0 report: run by name; prints WANTED | GOT for KQ3"]
fn i7172_kq3_leaving_ends_a_duty_seat() {
    let law = kernel_law();
    let leave = row(
        "lb",
        "b",
        SeatKind::Withdraw,
        F {
            names: &["g"],
            target: Some("g"),
            no_obj: true,
            ..F::default()
        },
    );
    let a = vec![
        founding("\u{2205}group", &["a", "b"], &["a", "b"], "member"),
        row(
            "hd",
            "a",
            SeatKind::Offer,
            F {
                names: &["g"],
                to: &["a", "b"],
                cosigners: &["a", "b"],
                scope: Some("duty"),
                conf: Some(Conf::Own),
                ..F::default()
            },
        ),
        leave.clone(),
    ];
    let b = vec![founding("a", &["a", "b"], &["b"], "duty"), leave];
    for (way, rows) in [("A (lineage today)", a), ("B (Kernel's scenarios)", b)] {
        let r = read(&rows, &["g", "hd", "lb"], &law);
        let q = format!("KQ3 {way}");
        report(&q, "concluded", "all", &r.concluded);
        report(&q, "holders(duty)", "{a}", &r.holders["duty"]);
        report(&q, "holders(member)", "{a}", &r.holders["member"]);
    }
}
