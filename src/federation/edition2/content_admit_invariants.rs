//! v62.0.0 (CONTENT-A7; CC rc22 3.1.3.2; P/CONTENT-design.rev3.md
//! "admit-and-mark") — witnesses of **a removed member's room content,
//! admitted and marked**, sqlite + postgres, through the statement door.
//!
//! - **I6734** — the count removes `x`, naming `c2` as its tip. Then `x`
//!   posts `c3`:
//!   - it is ADMITTED (`Row`), never held on the write scope;
//!   - its cached answer is `E2.forward` (out of the room's content);
//!   - it takes one place in the ended buffer;
//!   - the present filter (`content_cache::present`) drops it and keeps the
//!     held tip `c2` and a co-member's row.
//! - **I6740** — the VIEW of a room read (through the read wrapper, the
//!   in-process half of `ExecuteAttestationQuery`): `Present` drops `c3`
//!   and keeps `c2` and the co-member's row; `Record` keeps `c3`; a room
//!   query with no view is refused (no default either way).
//! - **I6744** (A7b) — `list_attestations_referencing_in_view`: x's own
//!   post-end retraction of c1 is returned by `Record` and withheld by
//!   `Present` (it is `E2.forward`: counted, not in force).
//! - **I6745** (A7b) — a CROSS-ROOM `by(member)` query: x seated in room A and
//!   removed from room B. `Present` returns A's post and withholds B's
//!   post-end row, judged per row by each row's room; `Record` returns
//!   both; a row placed in no room (no statement) is kept under `Present`.
//! - **I6735** — the ended buffer's ceiling (2 rows): `x`'s third post-end
//!   row is declined `NotKept` and its statement is not kept. A re-offer of
//!   an admitted row is never declined.
//!
//! Not witnessed here: a member SEATED AGAIN writes as any member and takes
//! no place in the buffer (the write scope admits it first); that needs a
//! re-widening through the community door. I6730 witnesses the seat.

use super::content_cache::present;
use super::fixture_switch as e2;
use super::group_fixtures::{held_head, put_voices};
use super::hold_bound::{with_bounds, HoldBounds};
use super::ingest::{put_statement, StatementOutcome, INGEST_TIER};
use crate::federation::types::identity_type;
use crate::federation::{Error, FederationDirectory};
use crate::kernel::content_invariants::{id_of, post, removal_naming_tips};

async fn ended_rows(d: &dyn FederationDirectory, gid: &str, member: &str) -> u64 {
    d.edition2_held_bound_usage("community", gid, "ended", Some(member), 1_000)
        .await
        .expect("A7: the ledger reads")
        .0
}

/// I6734 + I6735.
pub(crate) async fn admit_body(d: &dyn FederationDirectory) {
    let (m1, m2, m3, x) = ("a7-m1", "a7-m2", "a7-m3", "a7-x");
    for s in [m1, m2, m3, x] {
        e2::put_key(d, s, &[identity_type::USER]).await;
    }
    let c =
        super::voices_invariants::found_community(d, "a7-g", &[m1, m2, m3, x], "majority", None)
            .await;
    let gid = c.community_key_id.clone();
    let (head, _) = held_head(d, &gid).await.expect("A7: the head");
    let at = e2::ms(crate::host::clock::now()) - 60_000;
    let (xk, m1k) = (e2::kid(x), e2::kid(m1));
    let c1 = post(x, &xk, &gid, &head, None, at);
    let c2 = post(x, &xk, &gid, &head, Some(&id_of(&c1)), at + 1);
    let other = post(m1, &m1k, &gid, &head, None, at + 2);
    for st in [&c1, &c2, &other] {
        let o = put_statement(d, st, None, INGEST_TIER).await.unwrap();
        assert!(
            matches!(o, StatementOutcome::Row { .. }),
            "A7: lands: {o:?}"
        );
    }
    let voices = removal_naming_tips(&gid, &xk, &head, &[id_of(&c2)], &[m1, m2, m3], at + 3);
    let o = put_voices(d, &voices).await.expect("A7: the removal");
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "A7: it lands: {o:?}"
    );
    assert_eq!(
        ended_rows(d, &gid, &xk).await,
        0,
        "I6734 premise: the buffer is empty"
    );

    // I6734 — admitted and marked.
    let c3 = post(x, &xk, &gid, &head, Some(&id_of(&c2)), at + 4);
    let o = put_statement(d, &c3, None, INGEST_TIER)
        .await
        .expect("I6734: the post-end row");
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "I6734 a removed member's post is admitted, not held: {o:?}"
    );
    let a = d
        .edition2_content_answer(&id_of(&c3))
        .await
        .unwrap()
        .expect("I6734: it is answered");
    assert!(
        !a.in_force && a.rule == "E2.forward",
        "I6734 marked out of the room's content: {a:?}"
    );
    assert_eq!(
        ended_rows(d, &gid, &xk).await,
        1,
        "I6734 one place in the ended buffer"
    );
    let mut rows = Vec::new();
    for st in [&c2, &c3, &other] {
        rows.push(
            d.get_attestation(&id_of(st).hex())
                .await
                .unwrap()
                .expect("A7: the row is held"),
        );
    }
    let shown: Vec<String> = present(d, rows)
        .await
        .expect("I6734: the present read")
        .into_iter()
        .map(|r| r.attestation_id)
        .collect();
    assert_eq!(
        shown,
        vec![id_of(&c2).hex(), id_of(&other).hex()],
        "I6734 the present read drops the post-end row, keeps the tip and a co-member's row"
    );

    // I6740 — the view, through the read wrapper (the in-process half of
    // `ExecuteAttestationQuery`): a room query states it; Present drops the
    // post-end row, Record keeps it, and a room query with no view is refused.
    {
        use crate::federation::attestation_query::{
            AttestationQuery, AttestationReads, ContentView, NotServedReason, ReadOutcome,
        };
        let room_q = AttestationQuery::in_room(
            "community",
            &gid,
            std::num::NonZeroU32::new(100).expect("a page"),
        );
        let ids = |o: ReadOutcome| -> Vec<String> {
            let mut v: Vec<String> = o
                .served()
                .expect("I6740: served")
                .rows
                .into_iter()
                .map(|r| r.attestation_id)
                .collect();
            v.sort();
            v
        };
        let present_ids = ids(d
            .query_attestations(&room_q.clone().view(ContentView::Present))
            .await);
        let record_ids = ids(d
            .query_attestations(&room_q.clone().view(ContentView::Record))
            .await);
        assert!(
            record_ids.contains(&id_of(&c3).hex()) && !present_ids.contains(&id_of(&c3).hex()),
            "I6740 Present drops the post-end row, Record keeps it: {present_ids:?} / \
             {record_ids:?}"
        );
        assert!(
            present_ids.contains(&id_of(&c2).hex()) && present_ids.contains(&id_of(&other).hex()),
            "I6740 Present keeps the held tip and a co-member's row: {present_ids:?}"
        );
        assert!(
            matches!(
                d.query_attestations(&room_q).await,
                ReadOutcome::NotServed(NotServedReason::Refused(Error::InvalidArgument(_)))
            ),
            "I6740 a room query with no view is refused (no default)"
        );
    }

    // I6744 (CONTENT-A7b) — the referencing read in a stated view (Edge's
    // row_lifecycle: Present; blob placement: Record). x, removed, retracts
    // c1 (its own row: admitted without a seat, KR-fix17). Under the ruled
    // present rule the retraction counts at its head and is not in force
    // after the end (`E2.forward`), so Present does NOT return it: a
    // departed member's delete / rename composer is withheld from the room
    // view, while c1 itself is `W.retracted` (the author's retraction takes
    // effect whenever signed) and also out of the room's content.
    {
        use crate::federation::attestation_query::ContentView;
        use crate::kernel::content_invariants::retract;
        let w = retract(x, &xk, &id_of(&c1), &head, at + 10);
        let o = put_statement(d, &w, None, INGEST_TIER)
            .await
            .expect("I6744: x's own retraction");
        assert!(
            matches!(o, StatementOutcome::Row { .. }),
            "I6744 premise: an author retracts its own row with no seat: {o:?}"
        );
        let c1_att = id_of(&c1).hex();
        let ids = |v: Vec<crate::federation::types::Attestation>| -> Vec<String> {
            v.into_iter().map(|r| r.attestation_id).collect()
        };
        let record = ids(d
            .list_attestations_referencing_in_view(&c1_att, ContentView::Record)
            .await
            .expect("I6744: the record"));
        let shown = ids(d
            .list_attestations_referencing_in_view(&c1_att, ContentView::Present)
            .await
            .expect("I6744: the present"));
        assert!(
            record.contains(&id_of(&w).hex()),
            "I6744 Record returns the departed member's retraction: {record:?}"
        );
        assert!(
            !shown.contains(&id_of(&w).hex()),
            "I6744 Present withholds it (E2.forward after the end): {shown:?}"
        );
    }

    // I6735 — the ceiling (2 rows): c4 takes the last place, c5 is declined.
    let bounds = HoldBounds {
        ended_rows: 2,
        ..HoldBounds::default()
    };
    let c4 = post(x, &xk, &gid, &head, Some(&id_of(&c3)), at + 5);
    let c5 = post(x, &xk, &gid, &head, Some(&id_of(&c4)), at + 6);
    with_bounds(bounds, async {
        let o = put_statement(d, &c4, None, INGEST_TIER).await.unwrap();
        assert!(
            matches!(o, StatementOutcome::Row { .. }),
            "I6735 c4 fits: {o:?}"
        );
        let e = put_statement(d, &c5, None, INGEST_TIER)
            .await
            .expect_err("I6735 over the ended ceiling");
        assert!(
            matches!(
                &e,
                Error::NotKept {
                    bucket: "ended",
                    ..
                }
            ),
            "I6735 declined, never Invalid: {e:?}"
        );
        assert!(
            d.edition2_voices(&id_of(&c5)).await.unwrap().is_empty(),
            "I6735 a declined statement is not kept"
        );
        let again = put_statement(d, &c3, None, INGEST_TIER)
            .await
            .expect("I6735 a re-offer of an admitted row");
        assert!(
            !matches!(again, StatementOutcome::Pending { .. }),
            "I6735 an admitted row is never declined again: {again:?}"
        );
    })
    .await;
    assert_eq!(
        ended_rows(d, &gid, &xk).await,
        2,
        "I6735 the buffer holds its ceiling"
    );
}

/// I6745: the cross-room by(member) query, Present judged per row.
pub(crate) async fn cross_room_body(d: &dyn FederationDirectory) {
    use crate::federation::attestation_query::{AttestationQuery, AttestationReads, ContentView};
    let (m1, m2, m3, x) = ("a7b-m1", "a7b-m2", "a7b-m3", "a7b-x");
    for s in [m1, m2, m3, x] {
        e2::put_key(d, s, &[identity_type::USER]).await;
    }
    let room_a =
        super::voices_invariants::found_community(d, "a7b-A", &[m1, m2, m3, x], "majority", None)
            .await
            .community_key_id;
    let room_b =
        super::voices_invariants::found_community(d, "a7b-B", &[m1, m2, m3, x], "majority", None)
            .await
            .community_key_id;
    let (head_a, _) = held_head(d, &room_a).await.expect("I6745: A's head");
    let (head_b, _) = held_head(d, &room_b).await.expect("I6745: B's head");
    let at = e2::ms(crate::host::clock::now()) - 60_000;
    let xk = e2::kid(x);
    let b1 = post(x, &xk, &room_b, &head_b, None, at);
    put_statement(d, &b1, None, INGEST_TIER).await.unwrap();
    let voices = removal_naming_tips(&room_b, &xk, &head_b, &[id_of(&b1)], &[m1, m2, m3], at + 1);
    let o = put_voices(d, &voices)
        .await
        .expect("I6745: x removed from B");
    assert!(matches!(o, StatementOutcome::Row { .. }), "I6745: {o:?}");
    let a1 = post(x, &xk, &room_a, &head_a, None, at + 2);
    let b2 = post(x, &xk, &room_b, &head_b, Some(&id_of(&b1)), at + 3);
    for st in [&a1, &b2] {
        let o = put_statement(d, st, None, INGEST_TIER).await.unwrap();
        assert!(
            matches!(o, StatementOutcome::Row { .. }),
            "I6745: x's post lands: {o:?}"
        );
    }
    let by_x = AttestationQuery::by(&xk, std::num::NonZeroU32::new(100).expect("a page"));
    let read = |v: ContentView| {
        let q = by_x.clone().view(v);
        async move {
            d.query_attestations(&q)
                .await
                .served()
                .expect("I6745: served")
                .rows
                .into_iter()
                .map(|r| r.attestation_id)
                .collect::<Vec<String>>()
        }
    };
    let present_ids = read(ContentView::Present).await;
    let record_ids = read(ContentView::Record).await;
    for (what, st) in [("A's post", &a1), ("B's post-end row", &b2)] {
        assert!(
            record_ids.contains(&id_of(st).hex()),
            "I6745 Record returns {what}"
        );
    }
    assert!(
        present_ids.contains(&id_of(&a1).hex()),
        "I6745 Present returns x's post in room A, where x sits: {present_ids:?}"
    );
    assert!(
        !present_ids.contains(&id_of(&b2).hex()),
        "I6745 Present withholds x's post-end row in room B, by B's rule: {present_ids:?}"
    );
    // A row placed in no room: no statement, no cached answer, kept.
    let mut bare = d
        .get_attestation(&id_of(&a1).hex())
        .await
        .unwrap()
        .expect("I6745: a1 is held");
    if let Some(m) = bare.attestation_envelope.as_object_mut() {
        m.remove(super::ingest::STATEMENT_MEMBER);
    }
    let kept = super::content_cache::present(d, vec![bare]).await.unwrap();
    assert_eq!(
        kept.len(),
        1,
        "I6745 a row with no room placement is returned under Present"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i6745_a_cross_room_query_judges_present_per_row_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(cross_room_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i6745_a_cross_room_query_judges_present_per_row_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(cross_room_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i6734_i6735_a_removed_members_post_is_admitted_and_marked_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(admit_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i6734_i6735_a_removed_members_post_is_admitted_and_marked_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(admit_body(&b)).await;
}
