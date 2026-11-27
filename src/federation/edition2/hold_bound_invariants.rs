//! v62.0.0 (HOLD-1a; CC 2.7.3 as ruled 11-23) — witnesses of **this node's
//! own bound on rows held for a writer's standing**. Store bodies run on
//! sqlite and postgres, under small bounds (`hold_bound::with_bounds`).
//!
//! - **I6715** (pure) — `takes_out` is the exemption list:
//!   - true for `withdraws`, `recants`, `membership` removal and
//!     resignation, `takedown_notice`, `key:revocation`,
//!     `identity:occurrence_revocation`, `revocation:*`;
//!   - false for a chat message, a `supersedes`, a `keeps` row and a
//!     widening.
//! - **I6716** — the flood and the exemption. Three fresh keys (registered,
//!   seated nowhere) post into a room:
//!   - each key's third row is declined `Error::NotKept` (writer ceiling 2);
//!     the room stops growing at its ceiling of 5;
//!   - a declined statement is not kept;
//!   - the replicated door answers the same offer `Refused { NotKept }`;
//!   - past every ceiling, a key's withdrawal of its own held row is still
//!     kept.
//! - **I6717** — the race. A joiner's first post arrives BEFORE the widening
//!   that seats it (at an instant before the post):
//!   - it is held inside the bound;
//!   - once the widening lands, it concludes and leaves the ledger.
//! - **I6718** — the dwell. With a dwell of 0, the next row's check drops the
//!   older held row (its statement is gone); re-sent, it is kept again.
//!
//! Owed: a dropped TIP later named by a `keeps` row, re-sent, kept. That
//! goes through the door at the pre4 re-vendor, as I6705's note says.
//! HOLD-1b witnesses the re-fold count.

use ciris_verify_core::cde::{self, Value};

use super::fixture_switch as e2;
use super::group_fixtures::held_head;
use super::hold_bound::{takes_out, with_bounds, HoldBounds};
use super::ingest::{
    apply_replicated_statement, put_statement, ReplicatedStatementOutcome, StatementOutcome,
    INGEST_TIER,
};
use super::names::RowId;
use crate::federation::attestation_apply::AttestationRefusalReason;
use crate::federation::types::identity_type;
use crate::federation::{Error, FederationDirectory};

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

fn det_map(mut m: Vec<(&str, Value)>) -> Value {
    m.sort_by_key(|(k, _)| cde::encode(&t(k)));
    Value::Map(m.into_iter().map(|(k, v)| (t(k), v)).collect())
}

fn fid(p: &str) -> String {
    ciris_verify_core::namespace_match::family_id(p)
}

/// **I6715 (v62.0.0, HOLD-1a; pure)**.
#[test]
fn i6715_takes_out_is_the_exemption_list() {
    let dim = |d: &str| det_map(vec![("dimension", t(d))]);
    let empty = det_map(vec![]);
    for (what, rt, fam, p) in [
        ("withdraws", "withdraws", fid("chat:*"), empty.clone()),
        ("recants", "recants", fid("chat:*"), empty.clone()),
        (
            "removal",
            "scores",
            fid("membership:{stage}"),
            dim("membership:removal:v1"),
        ),
        (
            "resignation",
            "scores",
            fid("membership:{stage}"),
            dim("membership:resignation:v1"),
        ),
        (
            "takedown",
            "scores",
            fid("takedown_notice:{basis}"),
            dim("takedown_notice:dmca:v1"),
        ),
        (
            "key revocation",
            "scores",
            fid("key:revocation"),
            empty.clone(),
        ),
        (
            "occurrence revocation",
            "scores",
            fid("identity:occurrence_revocation"),
            empty.clone(),
        ),
        (
            "entity revocation",
            "scores",
            fid("revocation:{entity_type}:{reason}"),
            dim("revocation:key:compromise:v1"),
        ),
    ] {
        assert!(takes_out(rt, &fam, &p), "I6715 {what} takes something out");
    }
    for (what, rt, fam, p) in [
        ("chat", "scores", fid("chat:*"), dim("chat:message:v1")),
        (
            "supersedes",
            "supersedes",
            fid("chat:*"),
            dim("chat:message:v1"),
        ),
        (
            "keeps",
            "scores",
            fid("membership:{stage}"),
            dim("membership:keeps:v1"),
        ),
        (
            "widening",
            "scores",
            fid("membership:{stage}"),
            dim("membership:widening:v1"),
        ),
    ] {
        assert!(!takes_out(rt, &fam, &p), "I6715 {what} only adds");
    }
}

/// `seed`'s chat message in `room` over `head`, at `at`.
fn chat(seed: &str, room: &str, head: &RowId, at: u64) -> Vec<u8> {
    let p = det_map(vec![
        ("asserted_at", Value::Uint(at)),
        ("author", t(&e2::kid(seed))),
        ("dimension", t("chat:message:v1")),
        ("cohort_scope", t("community")),
        ("community_id", t(room)),
        (
            "refs",
            det_map(vec![(
                "head",
                ciris_verify_core::edition2::row_ref(&head.0),
            )]),
        ),
    ]);
    ciris_verify_core::edition2::sign_row_statement(
        &e2::signing_key(seed),
        &e2::kid(seed),
        &e2::kid(seed),
        "scores",
        &fid("chat:*"),
        &p,
        vec![],
    )
    .expect("HOLD: sign")
}

fn withdraw(seed: &str, target: &RowId, head: &RowId, at: u64) -> Vec<u8> {
    let p = det_map(vec![
        ("asserted_at", Value::Uint(at)),
        ("author", t(&e2::kid(seed))),
        (
            "refs",
            det_map(vec![
                ("head", ciris_verify_core::edition2::row_ref(&head.0)),
                ("target", ciris_verify_core::edition2::row_ref(&target.0)),
            ]),
        ),
    ]);
    ciris_verify_core::edition2::sign_row_statement(
        &e2::signing_key(seed),
        &e2::kid(seed),
        &e2::kid(seed),
        "withdraws",
        &fid("chat:*"),
        &p,
        vec![],
    )
    .expect("HOLD: sign a withdrawal")
}

fn id(st: &[u8]) -> RowId {
    RowId::of_statement(st).expect("HOLD: a row")
}

fn not_kept(r: &Result<StatementOutcome, Error>) -> bool {
    matches!(r, Err(Error::NotKept { .. }))
}

fn small() -> HoldBounds {
    HoldBounds {
        unseated_room_rows: 5,
        unseated_writer_rows: 2,
        ..HoldBounds::default()
    }
}

async fn room(d: &dyn FederationDirectory, seed: &str, members: &[&str]) -> (String, RowId) {
    let c = super::voices_invariants::found_community(d, seed, members, "majority", None).await;
    let (head, _) = held_head(d, &c.community_key_id)
        .await
        .expect("HOLD: the head");
    (c.community_key_id, head)
}

fn now_ms() -> u64 {
    e2::ms(crate::host::clock::now())
}

/// I6716.
pub(crate) async fn flood_body(d: &dyn FederationDirectory) {
    let m1 = "hold-m1";
    let keys = ["hold-s1", "hold-s2", "hold-s3"];
    for s in std::iter::once(&m1).chain(keys.iter()) {
        e2::put_key(d, s, &[identity_type::USER]).await;
    }
    let (gid, head) = room(d, "hold-g", &[m1]).await;
    let at = now_ms() - 60_000;
    let mut kept: Vec<RowId> = Vec::new();
    for (i, s) in keys.iter().enumerate() {
        for j in 0..3u64 {
            let st = chat(s, &gid, &head, at + (i as u64) * 10 + j);
            let r = put_statement(d, &st, None, INGEST_TIER).await;
            let room_full = kept.len() >= 5;
            if j < 2 && !room_full {
                assert!(
                    matches!(r, Ok(StatementOutcome::Pending { .. })),
                    "I6716 {s} row {j}: held inside the bound: {r:?}"
                );
                kept.push(id(&st));
            } else {
                assert!(not_kept(&r), "I6716 {s} row {j}: declined: {r:?}");
                assert!(
                    d.edition2_voices(&id(&st)).await.unwrap().is_empty(),
                    "I6716 a declined statement is not kept"
                );
                let rep = apply_replicated_statement(d, &st, &id(&st).0)
                    .await
                    .unwrap();
                assert!(
                    matches!(
                        rep,
                        ReplicatedStatementOutcome::Refused {
                            reason: AttestationRefusalReason::NotKept
                        }
                    ),
                    "I6716 the replicated door answers NotKept: {rep:?}"
                );
            }
        }
    }
    let (rows, _) = d
        .edition2_held_bound_usage("community", &gid, "unseated", None, 100)
        .await
        .unwrap();
    assert_eq!(rows, 5, "I6716 the room stops at its ceiling");
    // Past every ceiling: a withdrawal of one's own held row is kept.
    let w = withdraw(keys[0], &kept[0], &head, at + 100);
    let r = put_statement(d, &w, None, INGEST_TIER).await;
    assert!(!not_kept(&r), "I6716 a withdrawal is never declined: {r:?}");
    if r.is_ok() {
        assert!(
            !d.edition2_voices(&id(&w)).await.unwrap().is_empty(),
            "I6716 the withdrawal is kept"
        );
    }
}

/// I6717.
pub(crate) async fn race_body(d: &dyn FederationDirectory) {
    use crate::federation::edition2::group::MembershipRecord;
    use crate::federation::edition2::group_fixtures::{membership_voices, put_voices};
    use crate::federation::membership_acceptance::test_support::{acceptance_row, proposal_row};
    use crate::federation::types::{cohort_scope::COMMUNITY, CommunityMembershipWidening};
    let (m1, z) = ("hold-r-m1", "hold-r-z");
    for s in [m1, z] {
        e2::put_key(d, s, &[identity_type::USER]).await;
    }
    let (gid, head) = room(d, "hold-r-g", &[m1]).await;
    let joined = crate::host::clock::now() - chrono::Duration::minutes(2);
    let joined = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(joined.timestamp_millis())
        .expect("an instant");
    let post = chat(z, &gid, &head, e2::ms(joined) + 30_000);
    let r = put_statement(d, &post, None, INGEST_TIER).await.unwrap();
    assert!(
        matches!(r, StatementOutcome::Pending { .. }),
        "I6717 the post before its widening is held: {r:?}"
    );
    let zk = e2::kid(z);
    assert_eq!(
        d.edition2_held_bound_usage("community", &gid, "unseated", Some(&zk), 100)
            .await
            .unwrap()
            .0,
        1,
        "I6717 inside the bound"
    );
    let p = proposal_row(&e2::kid(m1), COMMUNITY, &gid, &zk, None, joined);
    e2::put_signed(d, &p).await.expect("I6717 the proposal");
    e2::put_signed(d, &acceptance_row(&zk, &p, joined))
        .await
        .expect("I6717 the acceptance");
    let w = MembershipRecord::CommunityWidening(CommunityMembershipWidening {
        community_key_id: gid.clone(),
        member_key_id: zk.clone(),
        joined_at: joined,
        effective_at: joined,
        role: None,
        persist_row_hash: String::new(),
    });
    let k = e2::signing_key(m1);
    put_voices(d, &membership_voices(&w, Some(&head), &[&k]))
        .await
        .expect("I6717 the widening");
    assert!(
        d.get_attestation(&id(&post).hex()).await.unwrap().is_some(),
        "I6717 the post concludes once the widening lands"
    );
    assert_eq!(
        d.edition2_held_bound_usage("community", &gid, "unseated", Some(&zk), 100)
            .await
            .unwrap()
            .0,
        0,
        "I6717 a concluded row leaves the ledger"
    );
}

/// I6718.
pub(crate) async fn dwell_body(d: &dyn FederationDirectory) {
    let (m1, s) = ("hold-d-m1", "hold-d-s");
    for k in [m1, s] {
        e2::put_key(d, k, &[identity_type::USER]).await;
    }
    let (gid, head) = room(d, "hold-d-g", &[m1]).await;
    let at = now_ms() - 60_000;
    let q1 = chat(s, &gid, &head, at);
    let q2 = chat(s, &gid, &head, at + 1);
    put_statement(d, &q1, None, INGEST_TIER).await.unwrap();
    put_statement(d, &q2, None, INGEST_TIER).await.unwrap();
    assert!(
        d.edition2_voices(&id(&q1)).await.unwrap().is_empty(),
        "I6718 the older row past the dwell is dropped"
    );
    let again = put_statement(d, &q1, None, INGEST_TIER).await;
    assert!(
        matches!(again, Ok(StatementOutcome::Pending { .. })),
        "I6718 re-sent, it is kept again: {again:?}"
    );
}

#[cfg(feature = "sqlite")]
async fn sqlite() -> crate::store::sqlite::SqliteBackend {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b
}

#[cfg(feature = "postgres")]
async fn postgres() -> Option<crate::store::postgres::PostgresBackend> {
    use crate::store::Backend as _;
    let dsn = crate::test_pg::empty_dsn()?;
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Some(b)
}

fn zero_dwell() -> HoldBounds {
    HoldBounds {
        unseated_dwell_us: 0,
        ..HoldBounds::default()
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i6716_a_flood_stops_at_the_ceiling_sqlite() {
    let b = sqlite().await;
    with_bounds(small(), Box::pin(flood_body(&b))).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i6716_a_flood_stops_at_the_ceiling_postgres() {
    let Some(b) = postgres().await else { return };
    with_bounds(small(), Box::pin(flood_body(&b))).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i6717_the_race_lands_sqlite() {
    let b = sqlite().await;
    with_bounds(small(), Box::pin(race_body(&b))).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i6717_the_race_lands_postgres() {
    let Some(b) = postgres().await else { return };
    with_bounds(small(), Box::pin(race_body(&b))).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i6718_past_the_dwell_a_row_is_dropped_and_comes_back_sqlite() {
    let b = sqlite().await;
    with_bounds(zero_dwell(), Box::pin(dwell_body(&b))).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i6718_past_the_dwell_a_row_is_dropped_and_comes_back_postgres() {
    let Some(b) = postgres().await else { return };
    with_bounds(zero_dwell(), Box::pin(dwell_body(&b))).await;
}
