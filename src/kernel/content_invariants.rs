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
//! - v62.0.0 (CONTENT-A1.rev2) — I6708 reads its head from the lineage
//!   ([`head_rows`]): the founding version admits `x`.
//! - **I6729** (pure) — the member's own removal is presented as its End and
//!   a Head marked `Out` under a second id ([`present_own_removals`]): a row
//!   naming the removal as its head is `no_seat`; without the presentation
//!   it waits on the removal (`Undecided`).
//! - **I6730** (sqlite + pg) — RE-ADMISSION is a new seat, read from the
//!   lineage ([`seat_mark`] over `edition2::lineage::members_at`). In a
//!   family, `bob` posts at the founding version; a counted removal; a post
//!   naming the removal; a counted re-widening; a post naming it:
//!   `E2.forward`, `no_seat`, `no_end`.
//! - **I6731** (pure) — in a private room the member is the VOICE: a row
//!   signed by a room key under `iss` = the voice maps to the voice (signer
//!   and member keys), never to the room key.
//! - **I6732** (pure) — a content row naming several heads is NOT JUDGED
//!   YET ([`not_judged`]) and is never handed to the crate; a retraction
//!   naming several heads still takes effect.
//!
//! **Not witnessed here.** A resignation (v62-resign's door; the crate reads
//! it as the member's own End, I6708's shape).

use std::collections::{BTreeMap, BTreeSet};

use ciris_kernel::content::{Answer, Kind, Rule, SeatAt};
use ciris_verify_core::cde::{self, Value};

use super::content::{
    answers, head_rows, kernel_in_play, member_keys, named_heads, not_judged, own_removal_head_id,
    present_own_removals, rows_of, HeldPast, Room, RoomRow, COUNT,
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
pub(crate) fn post(
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

pub(crate) fn id_of(st: &[u8]) -> RowId {
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
        several_heads: false,
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
pub(crate) fn removal_naming_tips(
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
    let mut rows = rows_of(&sts, &room, &xk);
    assert!(kernel_in_play(&rows), "I6708: the end is held");
    // v62.0.0 (CONTENT-A1.rev2) — the heads are the lineage's.
    let (heads, own) = head_rows(d, &room, &xk, &named_heads(&rows))
        .await
        .expect("I6708: the lineage heads");
    assert!(own.contains(&end), "I6708: x's removal is x's own");
    assert_eq!(
        heads.iter().find(|r| r.id == head).map(|r| r.seat),
        Some(SeatAt::Admits),
        "I6708: the founding version admits x (from the lineage)"
    );
    rows.extend(heads);
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
    let mut past = HeldPast::preload(d, &roots, &offered)
        .await
        .expect("I6708: the past");
    present_own_removals(&mut rows, &own, &mut past);
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

/// **I6729 (v62.0.0, CONTENT-A1.rev2; pure)** — the member's own removal,
/// presented twice (KERNEL on tips 11-23, item 3).
#[test]
fn i6729_a_row_naming_its_members_removal_is_no_seat() {
    let (m, room) = ("a1r-m", "a1r-room");
    let mk = e2::kid(m);
    let h0 = RowId([0x21; 32]);
    let end = RowId([0x22; 32]);
    let at = 7_000;
    let c1 = post(m, &mk, room, &h0, None, at);
    let c2 = post(m, &mk, room, &end, Some(&id_of(&c1)), at + 2);
    let room_r = Room {
        scope: "community".into(),
        group: room.into(),
    };
    let base = || {
        let mut rows = rows_of(&[c1.clone(), c2.clone()], &room_r, &mk);
        let [mut head, e] = head_and_end(h0, end, &[id_of(&c1)]);
        head.seat = SeatAt::Admits;
        rows.push(head);
        rows.push(e);
        rows
    };
    let reach = |rows: &[RoomRow]| {
        let mut m: BTreeMap<RowId, (BTreeSet<RowId>, Option<RowId>)> = BTreeMap::new();
        for r in rows {
            let set = if r.id == h0 {
                BTreeSet::new()
            } else if r.id == id_of(&c2) {
                BTreeSet::from([end, h0])
            } else {
                BTreeSet::from([h0])
            };
            m.insert(r.id, (set, None));
        }
        HeldPast::of(m)
    };
    let keys = BTreeSet::from([mk.clone()]);
    // Premise: handed in once, as the End only, the row naming it waits.
    let rows = base();
    let got = answers(&rows, &keys, &reach(&rows));
    assert_eq!(
        got.get(&id_of(&c2)),
        Some(&Answer::Undecided(end)),
        "I6729 premise: without the Head presentation the crate waits on the removal: {got:?}"
    );
    // Presented twice: the End, and a Head `Out` under the second id.
    let mut rows = base();
    let mut past = reach(&rows);
    present_own_removals(&mut rows, &BTreeSet::from([end]), &mut past);
    let second = own_removal_head_id(&end);
    assert_eq!(
        rows.iter()
            .find(|r| r.id == id_of(&c2))
            .and_then(|r| r.head),
        Some(second),
        "I6729 the member's row naming its removal names the second id"
    );
    assert_eq!(
        rows.iter()
            .find(|r| r.id == second)
            .map(|r| (r.kind, r.seat, r.head)),
        Some((Kind::Head, SeatAt::Out, Some(h0))),
        "I6729 the Head presentation is Out, naming the removal's own head"
    );
    assert_eq!(
        past.in_past(&end, &second),
        Ok(true),
        "I6729 the End is in its past"
    );
    assert_eq!(
        past.in_past(&second, &end),
        Ok(false),
        "I6729 and not the reverse"
    );
    assert_eq!(
        past.in_past(&h0, &second),
        Ok(true),
        "I6729 as for the row itself"
    );
    let got = answers(&rows, &keys, &past);
    assert_eq!(
        judged(got.get(&id_of(&c2))),
        Some((false, false, Rule::NoSeat)),
        "I6729 a row naming the member's own removal as its head is no_seat: {got:?}"
    );
    assert_eq!(
        judged(got.get(&id_of(&c1))),
        Some((true, true, Rule::HeldGood)),
        "I6729 the named tip is still held good: {got:?}"
    );
}

/// `signer`'s chat message authored as `author` in the FAMILY `group` over
/// `head`.
fn family_post(signer: &str, author: &str, group: &str, head: &RowId, at: u64) -> Vec<u8> {
    let p = det_map(vec![
        ("asserted_at", Value::Uint(at)),
        ("author", t(author)),
        ("dimension", t("chat:message:v1")),
        ("cohort_scope", t("family")),
        ("family_key_id", t(group)),
        ("refs", det_map(vec![("head", rref(head))])),
    ]);
    sign(signer, author, "scores", &p)
}

/// I6730: re-admission is a new seat, from the lineage.
pub(crate) async fn readmission_body(d: &dyn FederationDirectory, tag: &str) {
    use crate::federation::membership_acceptance::test_support::{acceptance_row, proposal_row};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        consensus_protocol, Family, FamilyMember, FamilyMembershipRevocation,
        FamilyMembershipWidening,
    };
    let landed = |r: &Result<StatementOutcome, crate::federation::Error>| {
        matches!(r, Ok(StatementOutcome::Row { .. }))
    };
    let at_ago = |mins: i64| {
        crate::federation::admission::truncate_to_substrate_resolution(
            chrono::Utc::now() - chrono::Duration::minutes(mins),
        )
    };
    let fam = format!("a1r-fam-{tag}");
    let (alice, bob) = (format!("a1r-alice-{tag}"), format!("a1r-bob-{tag}"));
    for k in [&alice, &bob] {
        e2::put_key(d, k, &[identity_type::USER]).await;
    }
    let founded = at_ago(60);
    let family = Family {
        prev_head_digest: String::new(),
        charter_digest: String::new(),
        family_key_id: fam.clone(),
        family_name: "a1r".into(),
        members: [&alice, &bob]
            .iter()
            .enumerate()
            .map(|(i, k)| FamilyMember {
                key_id: (*k).clone(),
                joined_at: founded,
                role: (i == 0).then(|| "founder".to_owned()),
            })
            .collect(),
        founded_at: founded,
        consensus_protocol: consensus_protocol::FOUNDER_ONLY.to_owned(),
        consensus_protocol_entrenched: false,
        dissolved_at: None,
        persist_row_hash: String::new(),
    };
    let founding = e2::family_voices(&ts::sign_family(&alice, family), 1, None, e2::ms(founded));
    let v1 = e2::row_id_of(&founding[0]);
    let r = e2::put_voices(d, &founding).await;
    assert!(landed(&r), "{tag} I6730: the founding: {r:?}");
    let group = e2::kid(&fam);

    // The counted removal of bob, over the founding version.
    let removal = e2::family_revocation_voices(
        &ts::sign_family_membership_revocation(
            &alice,
            FamilyMembershipRevocation {
                family_key_id: fam.clone(),
                removed_identity_key_id: bob.clone(),
                removed_at: at_ago(40),
                effective_at: at_ago(40),
                reason: None,
                witness_set: vec![],
                persist_row_hash: String::new(),
            },
        ),
        Some(&v1),
    );
    let rm = e2::row_id_of(&removal[0]);
    let r = e2::put_voices(d, &removal).await;
    assert!(landed(&r), "{tag} I6730: the removal: {r:?}");
    let bk = d
        .group_lineage_node(&rm)
        .await
        .unwrap()
        .and_then(|n| n.subject)
        .expect("I6730: the removal is a node of bob");

    // The counted re-widening of bob, extending the removal.
    let p = proposal_row(
        &alice,
        crate::federation::types::cohort_scope::FAMILY,
        &group,
        &bob,
        None,
        at_ago(30),
    );
    e2::put_signed(d, &p).await.expect("I6730: the proposal");
    let acc = acceptance_row(&bob, &p, at_ago(30));
    e2::put_signed(d, &acc)
        .await
        .expect("I6730: the acceptance");
    let widening = e2::family_widening_voices(
        &ts::sign_family_membership_widening(
            &alice,
            FamilyMembershipWidening {
                family_key_id: fam.clone(),
                member_key_id: bob.clone(),
                joined_at: at_ago(20),
                effective_at: at_ago(20),
                role: None,
                persist_row_hash: String::new(),
            },
        ),
        Some(&rm),
    );
    let w = e2::row_id_of(&widening[0]);
    let r = e2::put_voices(d, &widening).await;
    assert!(landed(&r), "{tag} I6730: the re-widening: {r:?}");

    // bob's three posts, handed in as bytes (the present read is A7's).
    let base = e2::ms(at_ago(50));
    let p1 = family_post(&bob, &bk, &group, &v1, base);
    let p2 = family_post(&bob, &bk, &group, &rm, base + 1);
    let p3 = family_post(&bob, &bk, &group, &w, base + 2);
    let offered = vec![p1.clone(), p2.clone(), p3.clone()];
    let mut sts = offered.clone();
    sts.extend(d.edition2_voices(&rm).await.unwrap());
    let room = Room {
        scope: "family".into(),
        group: group.clone(),
    };
    let mut rows = rows_of(&sts, &room, &bk);
    assert!(
        kernel_in_play(&rows),
        "{tag} I6730: the removal is bob's End"
    );
    let (heads, own) = head_rows(d, &room, &bk, &named_heads(&rows))
        .await
        .expect("I6730: the lineage heads");
    let mark = |id: &RowId| heads.iter().find(|r| r.id == *id).map(|r| r.seat);
    assert_eq!(
        mark(&v1),
        Some(SeatAt::Admits),
        "{tag} I6730: v1 admits bob"
    );
    assert_eq!(
        mark(&w),
        Some(SeatAt::Admits),
        "{tag} I6730: the re-widening admits bob again (a new seat)"
    );
    assert!(
        own.contains(&rm) && mark(&rm).is_none(),
        "{tag} I6730: bob's removal is presented by the two-id function, not as a head"
    );
    rows.extend(heads);
    let roots: Vec<RowId> = rows.iter().map(|r| r.id).collect();
    let mut past = HeldPast::preload(d, &roots, &offered)
        .await
        .expect("I6730: the past");
    present_own_removals(&mut rows, &own, &mut past);
    let keys = member_keys(&sts, &bk);
    let got = answers(&rows, &keys, &past);
    for (what, id, want) in [
        (
            "p1, at the founding seat, not a tip",
            id_of(&p1),
            (true, false, Rule::Forward),
        ),
        (
            "p2, naming bob's removal",
            id_of(&p2),
            (false, false, Rule::NoSeat),
        ),
        ("p3, in the new seat", id_of(&p3), (true, true, Rule::NoEnd)),
    ] {
        assert_eq!(
            judged(got.get(&id)),
            Some(want),
            "{tag} I6730 {what}: {got:?}"
        );
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i6730_readmission_is_a_new_seat_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(readmission_body(&b, "sqlite")).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i6730_readmission_is_a_new_seat_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(readmission_body(&b, "postgres")).await;
}

/// **I6731 (v62.0.0, CONTENT-A1.rev2; pure)** — in a private room the
/// member is the VOICE, never the room key.
#[test]
fn i6731_in_a_private_room_the_member_is_the_voice() {
    let (voice, room_key) = ("a1r-voice", "a1r-room-key");
    let vk = e2::kid(voice);
    let room = Room {
        scope: "community".into(),
        group: "a1r-private".into(),
    };
    let head = RowId([0x31; 32]);
    // Signed by the ROOM key, `iss` the voice, `author` the voice.
    let p = det_map(vec![
        ("asserted_at", Value::Uint(9_000)),
        ("author", t(&vk)),
        ("dimension", t("chat:message:v1")),
        ("cohort_scope", t("community")),
        ("community_id", t(&room.group)),
        ("refs", det_map(vec![("head", rref(&head))])),
    ]);
    let st = ciris_verify_core::edition2::sign_row_statement(
        &e2::signing_key(room_key),
        &vk,
        &vk,
        "scores",
        &ciris_verify_core::namespace_match::family_id("chat:*"),
        &p,
        vec![],
    )
    .expect("I6731: sign");
    let rows = rows_of(std::slice::from_ref(&st), &room, &vk);
    assert_eq!(
        rows.iter()
            .map(|r| (r.kind, r.signer.clone()))
            .collect::<Vec<_>>(),
        vec![(Kind::Content, vk.clone())],
        "I6731 the row is the voice's"
    );
    let keys = member_keys(std::slice::from_ref(&st), &vk);
    assert_eq!(
        keys,
        BTreeSet::from([vk.clone()]),
        "I6731 the member's keys are the voice alone, never the room key ({})",
        e2::kid(room_key)
    );
}

/// **I6732 (v62.0.0, CONTENT-A1.rev2; pure)** — a content row naming
/// several heads is not judged yet; a retraction naming several still acts.
#[test]
fn i6732_a_row_naming_several_heads_is_not_judged_yet() {
    let (m, room) = ("a1r-sh", "a1r-sh-room");
    let mk = e2::kid(m);
    let (h1, h2, end) = (RowId([0x41; 32]), RowId([0x42; 32]), RowId([0x43; 32]));
    let two_heads = |at: u64, row_type: &str, extra: Vec<(&str, Value)>| {
        let mut refs = vec![
            ("head", rref(&h1)),
            ("further_heads", Value::Array(vec![rref(&h2)])),
        ];
        refs.extend(extra);
        let mut p = vec![
            ("asserted_at", Value::Uint(at)),
            ("author", t(&mk)),
            ("refs", det_map(refs)),
        ];
        if row_type == "scores" {
            p.push(("dimension", t("chat:message:v1")));
            p.push(("cohort_scope", t("community")));
            p.push(("community_id", t(room)));
        }
        sign(m, &mk, row_type, &det_map(p))
    };
    let c0 = post(m, &mk, room, &h1, None, 8_000);
    let c1 = two_heads(8_001, "scores", Vec::new());
    let w = two_heads(8_002, "withdraws", vec![("target", rref(&id_of(&c0)))]);
    let room_r = Room {
        scope: "community".into(),
        group: room.into(),
    };
    let mut rows = rows_of(&[c0.clone(), c1.clone(), w.clone()], &room_r, &mk);
    assert_eq!(
        not_judged(&rows),
        vec![id_of(&c1)],
        "I6732 the content row naming two heads is not judged yet; the retraction is not so marked"
    );
    rows.extend(head_and_end(h1, end, &[id_of(&c0)]));
    let keys = BTreeSet::from([mk.clone()]);
    let got = answers(&rows, &keys, &flat_past(&rows, h1));
    assert!(
        !got.contains_key(&id_of(&c1)),
        "I6732 the crate is never handed a several-heads row: {got:?}"
    );
    assert_eq!(
        judged(got.get(&id_of(&c0))),
        Some((true, false, Rule::Retracted)),
        "I6732 a retraction naming several heads still takes effect: {got:?}"
    );
}
