//! v62.0.0 (CONTENT-A1) — witnesses of **the adapter to
//! `ciris_kernel::content`**. The crate's own fixture replay is Kernel's
//! (`tests/content.rs`) and is not re-run here; these witness that persist's
//! rows, keys and past reach the crate as its rules mean them.
//!
//! - **I6707** (pure) — the member's keys:
//!   - a person's SECOND device (`iss` the device, `author` the person)
//!     retracting the person's row is the author's own: the row is
//!     `W.retracted`;
//!   - for an AGENT member, the owner's withdrawal of the agent's row is not
//!     the author's: the row stays held good;
//!   - [`kernel_in_play`] is false with no End.
//! - **I6708** (sqlite + pg) — the store replay of Kernel's
//!   `removal_in_flight_row`, `removed_member_keeps_posting` and
//!   `kept_post_retracted_after_end`. Member `x` posts c1 → c2 → c3 in a room
//!   (through the statement door). The count removes `x`, naming `c2` (through
//!   the door). `x` then posts c4 and retracts c1; A7 will admit these, and
//!   the adapter is handed their bytes. The answers:
//!   - c1 `W.retracted`;
//!   - c2 `T.held_good`;
//!   - c3 `E2.forward` (in flight);
//!   - c4 `E2.forward` (after the end);
//!   - the retraction `E2.forward`.
//!
//! **Not witnessed here.** Re-admission (`seat_at` is BLOCKED) and a
//! resignation (needs v62-resign's leaf: after RESIGN).

use std::collections::{BTreeMap, BTreeSet};

use ciris_kernel::content::{Answer, Kind, Rule, SeatAt};
use ciris_verify_core::cde::{self, Value};

use super::content::{
    answers, kernel_in_play, member_keys, rows_of, HeldPast, Room, RoomRow, COUNT,
};
use crate::federation::edition2::fixture_switch as e2;
use crate::federation::edition2::group::MembershipRecord;
use crate::federation::edition2::group_fixtures::{
    held_head, membership_voices, put_voices, sign_group_payload,
};
use crate::federation::edition2::ingest::{put_statement, StatementOutcome, INGEST_TIER};
use crate::federation::edition2::names::RowId;
use crate::federation::types::{identity_type, CommunityMembershipRevocation};
use crate::federation::FederationDirectory;

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

fn det_map(mut m: Vec<(&str, Value)>) -> Value {
    m.sort_by_key(|(k, _)| cde::encode(&t(k)));
    Value::Map(m.into_iter().map(|(k, v)| (t(k), v)).collect())
}

fn rref(id: &RowId) -> Value {
    ciris_verify_core::edition2::row_ref(&id.0)
}

fn now_ms() -> u64 {
    e2::ms(crate::host::clock::now())
}

/// `signer`'s chat message authored as `author` in `room` over `head`,
/// following `prev`.
fn post(
    signer: &str,
    author: &str,
    room: &str,
    head: &RowId,
    prev: Option<&RowId>,
    at: u64,
) -> Vec<u8> {
    let mut refs = vec![("head", rref(head))];
    if let Some(p) = prev {
        refs.push(("prev", rref(p)));
    }
    let p = det_map(vec![
        ("asserted_at", Value::Uint(at)),
        ("author", t(author)),
        ("dimension", t("chat:message:v1")),
        ("cohort_scope", t("community")),
        ("community_id", t(room)),
        ("refs", det_map(refs)),
    ]);
    sign(signer, author, "scores", &p)
}

/// `signer`'s withdrawal authored as `author` of `target`, over `head`.
fn retract(signer: &str, author: &str, target: &RowId, head: &RowId, at: u64) -> Vec<u8> {
    let p = det_map(vec![
        ("asserted_at", Value::Uint(at)),
        ("author", t(author)),
        (
            "refs",
            det_map(vec![("head", rref(head)), ("target", rref(target))]),
        ),
    ]);
    sign(signer, author, "withdraws", &p)
}

fn sign(signer: &str, sub: &str, row_type: &str, p: &Value) -> Vec<u8> {
    ciris_verify_core::edition2::sign_row_statement(
        &e2::signing_key(signer),
        &e2::kid(signer),
        sub,
        row_type,
        &ciris_verify_core::namespace_match::family_id("chat:*"),
        p,
        vec![],
    )
    .expect("A1: sign a statement")
}

fn id_of(st: &[u8]) -> RowId {
    RowId::of_statement(st).expect("A1: a row")
}

fn judged(a: Option<&Answer<RowId>>) -> Option<(bool, bool, Rule)> {
    match a {
        Some(Answer::Judged(j)) => Some((j.counted, j.in_force, j.rule)),
        _ => None,
    }
}

/// A synthetic Head and a counted End naming `tips`, both over `head`.
fn head_and_end(head: RowId, end: RowId, tips: &[RowId]) -> [RoomRow; 2] {
    let base = RoomRow {
        id: head,
        kind: Kind::Head,
        signer: COUNT.to_owned(),
        head: None,
        prev: Vec::new(),
        tips: Vec::new(),
        retracts: None,
        extends: None,
        seat: SeatAt::Sits,
    };
    let mut e = base.clone();
    e.id = end;
    e.kind = Kind::End;
    e.head = Some(head);
    e.tips = tips.to_vec();
    [base, e]
}

/// The past of a slice where every row names `head` alone.
fn flat_past(rows: &[RoomRow], head: RowId) -> HeldPast {
    HeldPast::of(
        rows.iter()
            .map(|r| {
                let reach = if r.id == head {
                    BTreeSet::new()
                } else {
                    BTreeSet::from([head])
                };
                (r.id, (reach, None))
            })
            .collect::<BTreeMap<_, _>>(),
    )
}

/// **I6707 (v62.0.0, CONTENT-A1; pure)** — the member's keys.
#[test]
fn i6707_the_member_is_the_person_across_keys_and_an_agent_alone() {
    let room = Room {
        scope: "community".into(),
        group: "a1-room".into(),
    };
    let head = RowId([0x11; 32]);
    let end = RowId([0x12; 32]);
    let at = 5_000;
    // A person P posts from its own key and retracts from its second device D.
    let (p, d) = ("a1-person", "a1-device");
    let c1 = post(p, &e2::kid(p), &room.group, &head, None, at);
    let w = retract(d, &e2::kid(p), &id_of(&c1), &head, at + 1);
    let sts = vec![c1.clone(), w];
    let keys = member_keys(&sts, &e2::kid(p));
    assert!(
        keys.contains(&e2::kid(d)),
        "I6707 the device is the person's key"
    );
    let mut rows = rows_of(&sts, &room, &e2::kid(p));
    assert!(
        !kernel_in_play(&rows),
        "I6707 no End: the crate is not in play"
    );
    rows.extend(head_and_end(head, end, &[id_of(&c1)]));
    assert!(kernel_in_play(&rows));
    let past = flat_past(&rows, head);
    let got = answers(&rows, &keys, &past);
    assert_eq!(
        judged(got.get(&id_of(&c1))),
        Some((true, false, Rule::Retracted)),
        "I6707 a second device's retraction is the author's own: {got:?}"
    );

    // An agent member A; its owner O withdraws A's row.
    let (a, o) = ("a1-agent", "a1-owner");
    let a1 = post(a, &e2::kid(a), &room.group, &head, None, at);
    let wo = retract(o, &e2::kid(o), &id_of(&a1), &head, at + 1);
    let sts = vec![a1.clone(), wo];
    let keys = member_keys(&sts, &e2::kid(a));
    assert!(
        !keys.contains(&e2::kid(o)),
        "I6707 the owner's key is never the agent member's"
    );
    let mut rows = rows_of(&sts, &room, &e2::kid(a));
    rows.extend(head_and_end(head, end, &[id_of(&a1)]));
    let past = flat_past(&rows, head);
    let got = answers(&rows, &keys, &past);
    assert_eq!(
        judged(got.get(&id_of(&a1))),
        Some((true, true, Rule::HeldGood)),
        "I6707 the owner's withdrawal is not the agent's own: {got:?}"
    );
}

/// The removal of `x` from `gid` over `head`, naming `tips`, voiced by
/// `voters`.
fn removal_naming_tips(
    gid: &str,
    x: &str,
    head: &RowId,
    tips: &[RowId],
    voters: &[&str],
    at: u64,
) -> Vec<Vec<u8>> {
    use chrono::TimeZone as _;
    let instant = chrono::Utc
        .timestamp_millis_opt(i64::try_from(at).unwrap())
        .single()
        .unwrap();
    let removal = MembershipRecord::CommunityRemoval(CommunityMembershipRevocation {
        community_key_id: gid.to_owned(),
        removed_identity_key_id: x.to_owned(),
        removed_at: instant,
        effective_at: instant,
        reason: None,
        witness_set: Vec::new(),
        persist_row_hash: String::new(),
    });
    // The fixtures' voices, re-signed with `refs.trusted_through` added.
    let keys: Vec<_> = voters.iter().map(|s| e2::signing_key(s)).collect();
    let signers: Vec<&_> = keys.iter().collect();
    let base = membership_voices(&removal, Some(head), &signers);
    let (_, payload) = crate::federation::edition2::liveness::statement_parts(&base[0])
        .expect("A1: the removal statement");
    let Value::Map(mut m) = payload else {
        unreachable!("a payload is a map")
    };
    for (k, v) in &mut m {
        if k.as_text() == Some("refs") {
            if let Value::Map(refs) = v {
                let mut set: Vec<Value> = tips.iter().map(rref).collect();
                set.sort_by_key(cde::encode);
                refs.push((t("trusted_through"), Value::Array(set)));
                refs.sort_by_key(|(k, _)| cde::encode(k));
            }
        }
    }
    let p = Value::Map(m);
    keys.iter()
        .map(|k| {
            sign_group_payload(
                k,
                x,
                crate::federation::edition2::group::MEMBERSHIP_PREFIX,
                &p,
            )
        })
        .collect()
}

/// I6708: the store replay.
pub(crate) async fn replay_body(d: &dyn FederationDirectory) {
    let (m1, m2, m3, x) = ("a1-r-m1", "a1-r-m2", "a1-r-m3", "a1-r-x");
    for s in [m1, m2, m3, x] {
        e2::put_key(d, s, &[identity_type::USER]).await;
    }
    let c = crate::federation::edition2::voices_invariants::found_community(
        d,
        "a1-r-g",
        &[m1, m2, m3, x],
        "majority",
        None,
    )
    .await;
    let gid = c.community_key_id.clone();
    let (head, _) = held_head(d, &gid)
        .await
        .expect("I6708: the room's roster head");
    let at = now_ms() - 60_000;
    let xk = e2::kid(x);
    let c1 = post(x, &xk, &gid, &head, None, at);
    let c2 = post(x, &xk, &gid, &head, Some(&id_of(&c1)), at + 1);
    let c3 = post(x, &xk, &gid, &head, Some(&id_of(&c2)), at + 2);
    for st in [&c1, &c2, &c3] {
        let o = put_statement(d, st, None, INGEST_TIER)
            .await
            .unwrap_or_else(|e| panic!("I6708: x's post: {e:?}"));
        assert!(
            matches!(o, StatementOutcome::Row { .. }),
            "I6708: a seated member's post lands: {o:?}"
        );
    }
    let voices = removal_naming_tips(&gid, &xk, &head, &[id_of(&c2)], &[m1, m2, m3], at + 3);
    let o = put_voices(d, &voices)
        .await
        .expect("I6708: the removal naming c2");
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "I6708: the removal lands on three of four: {o:?}"
    );
    let end = id_of(&voices[0]);
    let c4 = post(x, &xk, &gid, &head, Some(&id_of(&c3)), at + 4);
    let w = retract(x, &xk, &id_of(&c1), &head, at + 5);

    let mut sts: Vec<Vec<u8>> = Vec::new();
    for id in [head, id_of(&c1), id_of(&c2), id_of(&c3), end] {
        sts.extend(d.edition2_voices(&id).await.unwrap());
    }
    let offered = vec![c4.clone(), w.clone()];
    sts.extend(offered.iter().cloned());
    let room = Room {
        scope: "community".into(),
        group: gid.clone(),
    };
    let rows = rows_of(&sts, &room, &xk);
    assert!(kernel_in_play(&rows), "I6708: the end is held");
    for (id, kind) in [
        (head, Kind::Head),
        (end, Kind::End),
        (id_of(&w), Kind::Content),
    ] {
        assert_eq!(
            rows.iter().find(|r| r.id == id).map(|r| r.kind),
            Some(kind),
            "I6708: {id:?} maps to {kind:?}"
        );
    }
    let roots: Vec<RowId> = rows.iter().map(|r| r.id).collect();
    let past = HeldPast::preload(d, &roots, &offered)
        .await
        .expect("I6708: the past");
    let keys = member_keys(&sts, &xk);
    let got = answers(&rows, &keys, &past);
    for (what, id, want) in [
        (
            "c1, retracted after the end",
            id_of(&c1),
            (true, false, Rule::Retracted),
        ),
        (
            "c2, the named tip",
            id_of(&c2),
            (true, true, Rule::HeldGood),
        ),
        ("c3, in flight", id_of(&c3), (true, false, Rule::Forward)),
        (
            "c4, after the end",
            id_of(&c4),
            (true, false, Rule::Forward),
        ),
        ("the retraction", id_of(&w), (true, false, Rule::Forward)),
    ] {
        assert_eq!(judged(got.get(&id)), Some(want), "I6708 {what}: {got:?}");
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i6708_the_store_reaches_the_crate_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(replay_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i6708_the_store_reaches_the_crate_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(replay_body(&b)).await;
}
