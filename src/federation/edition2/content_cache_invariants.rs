//! v62.0.0 (CONTENT-A6) — witnesses of **the answer cache**. sqlite +
//! postgres; they pass once the V300 edit carries the content tables
//! (P/CONTENT-V300.rev3.sql).
//!
//! - **I6711** — the door keeps the cache.
//!   - Before any end, a member's rows have no cache row (in force by the
//!     crate's no-end property).
//!   - Once the count's removal of `x` naming `c2` lands: c1 and c2 are
//!     `T.held_good` (in force), and c3 is `E2.forward` (out).
//!   - A later post c4 by `x` (held at the door by the write scope) is
//!     cached `E2.forward`.
//!   - The removal is RETAINED with its head and its tip
//!     (`edition2_content_ends`).
//! - **I6713** (CONTENT-A6b) — no O(n²) for an ended member. Through the
//!   counting double (`FaultInjectingDirectory::calls`):
//!   - each of the removed member's posts p1..p6 after the end (a chain, no
//!     tip) costs the SAME number of store calls at the door, for k = 2..6
//!     (bounded, not growing with k);
//!   - the series is never read (`edition2_room_series` 0), nothing is
//!     replaced wholesale (`edition2_put_content_answers` 0), and one row is
//!     written (`edition2_put_content_answer` 1);
//!   - every post is cached `E2.forward`.
//!   - The fallback: a post that an end ALREADY names as its tip (the leaver
//!     named it before publishing it) takes the full recompute, and it and
//!     its ancestor come back `T.held_good`.

use super::fixture_switch as e2;
use super::group_fixtures::{held_head, put_voices};
use super::ingest::{put_statement, StatementOutcome, INGEST_TIER};
use super::names::RowId;
use crate::federation::types::identity_type;
use crate::federation::FederationDirectory;
use crate::kernel::content_invariants::{id_of, post, removal_naming_tips};

async fn answer(d: &dyn FederationDirectory, id: &RowId) -> Option<(bool, String)> {
    d.edition2_content_answer(id)
        .await
        .expect("I6711: the cache reads")
        .map(|a| (a.in_force, a.rule))
}

/// I6711.
pub(crate) async fn cache_body(d: &dyn FederationDirectory) {
    let (m1, m2, m3, x) = ("a6-m1", "a6-m2", "a6-m3", "a6-x");
    for s in [m1, m2, m3, x] {
        e2::put_key(d, s, &[identity_type::USER]).await;
    }
    let c =
        super::voices_invariants::found_community(d, "a6-g", &[m1, m2, m3, x], "majority", None)
            .await;
    let gid = c.community_key_id.clone();
    let (head, _) = held_head(d, &gid).await.expect("I6711: the head");
    let at = e2::ms(crate::host::clock::now()) - 60_000;
    let xk = e2::kid(x);
    let c1 = post(x, &xk, &gid, &head, None, at);
    let c2 = post(x, &xk, &gid, &head, Some(&id_of(&c1)), at + 1);
    let c3 = post(x, &xk, &gid, &head, Some(&id_of(&c2)), at + 2);
    for st in [&c1, &c2, &c3] {
        let o = put_statement(d, st, None, INGEST_TIER).await.unwrap();
        assert!(
            matches!(o, StatementOutcome::Row { .. }),
            "I6711: lands: {o:?}"
        );
    }
    assert_eq!(
        answer(d, &id_of(&c1)).await,
        None,
        "I6711 no end: not cached"
    );

    let voices = removal_naming_tips(&gid, &xk, &head, &[id_of(&c2)], &[m1, m2, m3], at + 3);
    let o = put_voices(d, &voices).await.expect("I6711: the removal");
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "I6711: it lands: {o:?}"
    );
    for (what, st, want) in [
        ("c1", &c1, (true, "T.held_good")),
        ("c2", &c2, (true, "T.held_good")),
        ("c3", &c3, (false, "E2.forward")),
    ] {
        assert_eq!(
            answer(d, &id_of(st)).await,
            Some((want.0, want.1.to_owned())),
            "I6711 {what}"
        );
    }

    let c4 = post(x, &xk, &gid, &head, Some(&id_of(&c3)), at + 4);
    let _ = put_statement(d, &c4, None, INGEST_TIER).await;
    assert_eq!(
        answer(d, &id_of(&c4)).await,
        Some((false, "E2.forward".to_owned())),
        "I6711 a post after the end is out"
    );

    let ends = d
        .edition2_content_ends("community", &gid, &xk)
        .await
        .expect("I6711: the retained ends");
    assert_eq!(ends.len(), 1, "I6711 one retained end");
    assert_eq!(ends[0].source, id_of(&voices[0]));
    assert_eq!(ends[0].head, head);
    assert_eq!(ends[0].tips, vec![id_of(&c2)]);
    assert!(ends[0].counted, "I6711 a removal is the count's");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i6711_the_door_keeps_the_answer_cache_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(cache_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i6711_the_door_keeps_the_answer_cache_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(cache_body(&b)).await;
}

/// I6713.
pub(crate) async fn bounded_body(backend: std::sync::Arc<dyn FederationDirectory>) {
    use crate::federation::directory_double::FaultInjectingDirectory;
    let dd = FaultInjectingDirectory::new(backend);
    let d: &dyn FederationDirectory = &dd;
    let (m1, m2, m3, x, y) = ("a6b-m1", "a6b-m2", "a6b-m3", "a6b-x", "a6b-y");
    for s in [m1, m2, m3, x, y] {
        e2::put_key(d, s, &[identity_type::USER]).await;
    }
    let c = super::voices_invariants::found_community(
        d,
        "a6b-g",
        &[m1, m2, m3, x, y],
        "majority",
        None,
    )
    .await;
    let gid = c.community_key_id.clone();
    let (head, _) = held_head(d, &gid).await.expect("I6713: the head");
    let at = e2::ms(crate::host::clock::now()) - 60_000;
    let xk = e2::kid(x);
    let c1 = post(x, &xk, &gid, &head, None, at);
    let c2 = post(x, &xk, &gid, &head, Some(&id_of(&c1)), at + 1);
    for st in [&c1, &c2] {
        put_statement(d, st, None, INGEST_TIER).await.unwrap();
    }
    let voices = removal_naming_tips(&gid, &xk, &head, &[id_of(&c2)], &[m1, m2, m3, y], at + 2);
    let o = put_voices(d, &voices).await.expect("I6713: the removal");
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "I6713: it lands: {o:?}"
    );
    let mut prev = id_of(&c2);
    let mut totals: Vec<u64> = Vec::new();
    for k in 1..=6u64 {
        let p = post(x, &xk, &gid, &head, Some(&prev), at + 2 + k);
        dd.reset_calls();
        let _ = put_statement(d, &p, None, INGEST_TIER).await;
        let calls = dd.calls();
        let n = |m: &str| calls.get(m).copied().unwrap_or(0);
        if k >= 2 {
            assert_eq!(
                n("edition2_room_series"),
                0,
                "I6713 post {k}: the series is not read"
            );
            assert_eq!(
                n("edition2_put_content_answers"),
                0,
                "I6713 post {k}: nothing replaced"
            );
            assert_eq!(
                n("edition2_put_content_answer"),
                1,
                "I6713 post {k}: one row written"
            );
            totals.push(calls.values().sum());
        }
        assert_eq!(
            answer(d, &id_of(&p)).await,
            Some((false, "E2.forward".to_owned())),
            "I6713 post {k} is out"
        );
        prev = id_of(&p);
    }
    assert!(
        totals.windows(2).all(|w| w[0] == w[1]),
        "I6713 the k-th post's store calls do not grow with k: {totals:?}"
    );

    // The fallback: y's end names t2 before t2 is published.
    let yk = e2::kid(y);
    let t1 = post(y, &yk, &gid, &head, None, at + 20);
    put_statement(d, &t1, None, INGEST_TIER).await.unwrap();
    let t2 = post(y, &yk, &gid, &head, Some(&id_of(&t1)), at + 21);
    let yv = removal_naming_tips(&gid, &yk, &head, &[id_of(&t2)], &[m1, m2, m3], at + 22);
    put_voices(d, &yv).await.expect("I6713: y's removal");
    assert_eq!(
        answer(d, &id_of(&t1)).await,
        Some((false, "E2.forward".to_owned())),
        "I6713 before its tip arrives, t1 is out"
    );
    dd.reset_calls();
    let _ = put_statement(d, &t2, None, INGEST_TIER).await;
    assert!(
        dd.calls().get("edition2_room_series").copied().unwrap_or(0) >= 1,
        "I6713 a named tip takes the full recompute"
    );
    for (what, st) in [("t1", &t1), ("t2", &t2)] {
        assert_eq!(
            answer(d, &id_of(st)).await,
            Some((true, "T.held_good".to_owned())),
            "I6713 {what} is kept once the named tip lands"
        );
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i6713_an_ended_members_post_is_answered_alone_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(bounded_body(std::sync::Arc::new(b))).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i6713_an_ended_members_post_is_answered_alone_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(bounded_body(std::sync::Arc::new(b))).await;
}
