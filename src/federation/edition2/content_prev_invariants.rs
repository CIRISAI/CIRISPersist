//! v62.0.0 (CONTENT-A4) — witnesses of **the producer's predecessors**.
//! sqlite + postgres. They pass once the V300 edit carries
//! `ceg_room_content` (P/CONTENT-V300.rev3.sql, PRE4-V300-a).
//!
//! - **I6709** — the series and the draft:
//!   - a member's posts in a room join its series, through the statement
//!     door;
//!   - `state_prev` names the newest tip: after c1 → c1; after c2 (prev c1)
//!     → c2;
//!   - with a fork (x2 also after c1), the tips are {c2, x2}, newest first by
//!     admission, and the draft names x2;
//!   - until the Verify pin no `further_prev` is stated;
//!   - a payload that already names `prev`, a row at `self`, and a composer
//!     are unchanged.
//! - **I6714** (CONTENT-A4b) — tips are read off the series index:
//!   - through the counting double, `author_tips` after each of 8 chained
//!     posts makes exactly ONE store call (`edition2_room_tips`), whatever
//!     the series' length, and never walks the series
//!     (`edition2_room_series` / `edition2_rows_naming` 0);
//!   - it answers the newest post;
//!   - a successor that arrives BEFORE its predecessor leaves the
//!     predecessor followed once it lands: the tips are {the successor}.
//! - **I6710** (CONTENT-A5) — the end's tips:
//!   - `state_tips` on x's removal names x's tips in the room in
//!     `refs.trusted_through` (c2, x2);
//!   - a removal already naming tips, and a widening, are unchanged;
//!   - `keeps_draft` is counted (no `author`), cites exactly one end, and
//!     names its tips;
//!   - with no tips, or with 65, it is refused (`trusted_through_too_many`).

use ciris_verify_core::cde::{self, Value};

use super::content_prev::{author_tips, state_prev, FURTHER_PREV_ON_THE_WIRE};
use super::fixture_switch as e2;
use super::group_fixtures::held_head;
use super::ingest::{put_statement, StatementOutcome, INGEST_TIER};
use super::names::{names_of, single, RowId};
use crate::federation::types::identity_type;
use crate::federation::FederationDirectory;

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

fn det_map(mut m: Vec<(&str, Value)>) -> Value {
    m.sort_by_key(|(k, _)| cde::encode(&t(k)));
    Value::Map(m.into_iter().map(|(k, v)| (t(k), v)).collect())
}

fn chat_payload(
    author: &str,
    scope: &str,
    room: &str,
    head: &RowId,
    prev: Option<&RowId>,
    at: u64,
) -> Value {
    let mut refs = vec![("head", ciris_verify_core::edition2::row_ref(&head.0))];
    if let Some(p) = prev {
        refs.push(("prev", ciris_verify_core::edition2::row_ref(&p.0)));
    }
    det_map(vec![
        ("asserted_at", Value::Uint(at)),
        ("author", t(author)),
        ("dimension", t("chat:message:v1")),
        ("cohort_scope", t(scope)),
        ("community_id", t(room)),
        ("refs", det_map(refs)),
    ])
}

fn family() -> String {
    ciris_verify_core::namespace_match::family_id("chat:*")
}

async fn post(d: &dyn FederationDirectory, seed: &str, p: &Value) -> RowId {
    let st = ciris_verify_core::edition2::sign_row_statement(
        &e2::signing_key(seed),
        &e2::kid(seed),
        &e2::kid(seed),
        "scores",
        &family(),
        p,
        vec![],
    )
    .expect("I6709: sign");
    let o = put_statement(d, &st, None, INGEST_TIER)
        .await
        .unwrap_or_else(|e| panic!("I6709: the post: {e:?}"));
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "I6709: lands: {o:?}"
    );
    RowId::of_statement(&st).expect("I6709: a row")
}

fn named(p: &Value, role: &str) -> Option<RowId> {
    single(&names_of(p).expect("I6709: refs read"), role)
}

/// I6709.
pub(crate) async fn prev_body(d: &dyn FederationDirectory) {
    let (m1, x) = ("a4-m1", "a4-x");
    for s in [m1, x] {
        e2::put_key(d, s, &[identity_type::USER]).await;
    }
    let c = super::voices_invariants::found_community(d, "a4-g", &[m1, x], "majority", None).await;
    let gid = c.community_key_id.clone();
    let (head, _) = held_head(d, &gid).await.expect("I6709: the head");
    let xk = e2::kid(x);
    let at = e2::ms(crate::host::clock::now()) - 60_000;
    let draft = |at: u64| chat_payload(&xk, "community", &gid, &head, None, at);

    let fresh = state_prev(d, "scores", &family(), draft(at)).await.unwrap();
    assert_eq!(
        named(&fresh, "prev"),
        None,
        "I6709 the first row names none"
    );

    let c1 = post(d, x, &chat_payload(&xk, "community", &gid, &head, None, at)).await;
    let p = state_prev(d, "scores", &family(), draft(at + 1))
        .await
        .unwrap();
    assert_eq!(named(&p, "prev"), Some(c1), "I6709 after c1");

    let c2 = post(
        d,
        x,
        &chat_payload(&xk, "community", &gid, &head, Some(&c1), at + 2),
    )
    .await;
    let p = state_prev(d, "scores", &family(), draft(at + 3))
        .await
        .unwrap();
    assert_eq!(named(&p, "prev"), Some(c2), "I6709 after c2");

    let x2 = post(
        d,
        x,
        &chat_payload(&xk, "community", &gid, &head, Some(&c1), at + 4),
    )
    .await;
    assert_eq!(
        author_tips(d, "community", &gid, &xk).await.unwrap(),
        vec![x2, c2],
        "I6709 two tips, newest first by admission"
    );
    let p = state_prev(d, "scores", &family(), draft(at + 5))
        .await
        .unwrap();
    assert_eq!(named(&p, "prev"), Some(x2), "I6709 the newest tip");
    let further = names_of(&p)
        .unwrap()
        .iter()
        .filter(|n| n.role == "further_prev")
        .count();
    assert_eq!(
        further,
        usize::from(FURTHER_PREV_ON_THE_WIRE),
        "I6709 further_prev only from the Verify pin"
    );

    // Unchanged: a payload naming its own prev, a row at self, a composer.
    let own = chat_payload(&xk, "community", &gid, &head, Some(&c1), at + 6);
    assert_eq!(
        state_prev(d, "scores", &family(), own.clone())
            .await
            .unwrap(),
        own
    );
    let selfp = chat_payload(&xk, "self", &gid, &head, None, at + 7);
    assert_eq!(
        state_prev(d, "scores", &family(), selfp.clone())
            .await
            .unwrap(),
        selfp
    );
    let comp = det_map(vec![
        ("asserted_at", Value::Uint(at + 8)),
        ("author", t(&xk)),
        (
            "refs",
            det_map(vec![(
                "target",
                ciris_verify_core::edition2::row_ref(&c1.0),
            )]),
        ),
    ]);
    assert_eq!(
        state_prev(d, "withdraws", &family(), comp.clone())
            .await
            .unwrap(),
        comp
    );
}

/// I6710 (runs after I6709's rows: c1, c2, x2 by x).
pub(crate) async fn tips_body(d: &dyn FederationDirectory) {
    use super::content_prev::state_tips;
    use super::group::{keeps_draft, membership_payload, MembershipRecord, MEMBERSHIP_PREFIX};
    use crate::federation::types::{CommunityMembershipRevocation, CommunityMembershipWidening};
    Box::pin(prev_body(d)).await;
    let gid = e2::kid("a4-g");
    let gid = d
        .lookup_community(&gid)
        .await
        .unwrap()
        .map_or(gid, |c| c.community_key_id);
    let (head, _) = held_head(d, &gid).await.expect("I6710: the head");
    let xk = e2::kid("a4-x");
    let fam = ciris_verify_core::namespace_match::family_id(MEMBERSHIP_PREFIX);
    let now = crate::host::clock::now();
    let removal = MembershipRecord::CommunityRemoval(CommunityMembershipRevocation {
        community_key_id: gid.clone(),
        removed_identity_key_id: xk.clone(),
        removed_at: now,
        effective_at: now,
        reason: None,
        witness_set: Vec::new(),
        persist_row_hash: String::new(),
    });
    let p = membership_payload(&removal, Some(&head)).unwrap();
    let tips = author_tips(d, "community", &gid, &xk).await.unwrap();
    assert_eq!(tips.len(), 2, "I6710 x's two tips");
    let stated = state_tips(d, "scores", &fam, p.clone()).await.unwrap();
    let named: Vec<RowId> = names_of(&stated)
        .unwrap()
        .into_iter()
        .filter(|n| n.role == "trusted_through")
        .map(|n| n.row)
        .collect();
    let mut want = tips.clone();
    want.sort();
    let mut got = named.clone();
    got.sort();
    assert_eq!(got, want, "I6710 the removal names x's tips");
    assert_eq!(
        state_tips(d, "scores", &fam, stated.clone()).await.unwrap(),
        stated,
        "I6710 tips already named are kept"
    );
    let widening = MembershipRecord::CommunityWidening(CommunityMembershipWidening {
        community_key_id: gid.clone(),
        member_key_id: xk.clone(),
        joined_at: now,
        effective_at: now,
        role: None,
        persist_row_hash: String::new(),
    });
    let w = membership_payload(&widening, Some(&head)).unwrap();
    assert_eq!(state_tips(d, "scores", &fam, w.clone()).await.unwrap(), w);

    let end = RowId([0x5e; 32]);
    let signer = e2::kid("a4-m1");
    let at = e2::ms(now);
    let draft = keeps_draft("community", &gid, &xk, &head, &end, &tips, at, &signer)
        .expect("I6710 a keeps draft");
    let payload: Value = cde::decode(&draft.payload).expect("I6710 the payload decodes");
    assert!(
        payload.get_text("author").is_none(),
        "I6710 counted: no author"
    );
    let ns = names_of(&payload).unwrap();
    assert_eq!(
        ns.iter().filter(|n| n.role == "also:cites").count(),
        1,
        "I6710 cites one end"
    );
    assert_eq!(ns.iter().filter(|n| n.role == "trusted_through").count(), 2);
    assert!(keeps_draft("community", &gid, &xk, &head, &end, &[], at, &signer).is_err());
    let many: Vec<RowId> = (0u8..65).map(|i| RowId([i; 32])).collect();
    let e = keeps_draft("community", &gid, &xk, &head, &end, &many, at, &signer)
        .expect_err("I6710 65 tips");
    assert!(
        e.to_string().contains("trusted_through_too_many"),
        "I6710 the token: {e}"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i6710_an_end_names_the_members_tips_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(tips_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i6710_an_end_names_the_members_tips_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(tips_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i6709_the_draft_names_the_newest_tip_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(prev_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i6709_the_draft_names_the_newest_tip_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(prev_body(&b)).await;
}

/// I6714.
pub(crate) async fn tips_read_body(backend: std::sync::Arc<dyn FederationDirectory>) {
    use crate::federation::directory_double::FaultInjectingDirectory;
    let dd = FaultInjectingDirectory::new(backend);
    let d: &dyn FederationDirectory = &dd;
    let (m1, x) = ("a4b-m1", "a4b-x");
    for s in [m1, x] {
        e2::put_key(d, s, &[identity_type::USER]).await;
    }
    let c = super::voices_invariants::found_community(d, "a4b-g", &[m1, x], "majority", None).await;
    let gid = c.community_key_id.clone();
    let (head, _) = held_head(d, &gid).await.expect("I6714: the head");
    let xk = e2::kid(x);
    let at = e2::ms(crate::host::clock::now()) - 60_000;
    let mut prev: Option<RowId> = None;
    for k in 0..8u64 {
        let id = post(
            d,
            x,
            &chat_payload(&xk, "community", &gid, &head, prev.as_ref(), at + k),
        )
        .await;
        dd.reset_calls();
        let tips = author_tips(d, "community", &gid, &xk).await.unwrap();
        let calls = dd.calls();
        assert_eq!(
            tips,
            vec![id],
            "I6714 after post {k}: the newest is the one tip"
        );
        assert_eq!(
            calls.get("edition2_room_tips").copied(),
            Some(1),
            "I6714 one indexed read: {calls:?}"
        );
        assert_eq!(
            calls.values().sum::<u64>(),
            1,
            "I6714 nothing else read: {calls:?}"
        );
        prev = Some(id);
    }
    // Out of order: y2 (naming y1) lands before y1.
    let y1p = chat_payload(&xk, "community", &gid, &head, prev.as_ref(), at + 20);
    let y1 = ciris_verify_core::edition2::sign_row_statement(
        &e2::signing_key(x),
        &e2::kid(x),
        &e2::kid(x),
        "scores",
        &family(),
        &y1p,
        vec![],
    )
    .expect("I6714: sign y1");
    let y1_id = RowId::of_statement(&y1).unwrap();
    let y2 = post(
        d,
        x,
        &chat_payload(&xk, "community", &gid, &head, Some(&y1_id), at + 21),
    )
    .await;
    let o = put_statement(d, &y1, None, INGEST_TIER).await.unwrap();
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "I6714: y1 lands: {o:?}"
    );
    assert_eq!(
        author_tips(d, "community", &gid, &xk).await.unwrap(),
        vec![y2],
        "I6714 a predecessor that lands after its successor is followed"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i6714_tips_are_read_off_the_index_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(tips_read_body(std::sync::Arc::new(b))).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i6714_tips_are_read_off_the_index_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(tips_read_body(std::sync::Arc::new(b))).await;
}
