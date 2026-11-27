//! v62.0.0 (HOLD-1b; CC 2.7.3 as ruled 11-23: "do not re-fold every held row
//! in a room on each membership change; a held row is re-read when the row
//! it waits on arrives") — witnesses, sqlite + postgres, through the counting
//! double.
//!
//! - **I6719** — a seat GAINED by a roster version still changes the answer.
//!   A joiner `z`'s post, held before version 2 lists it, CONCLUDES once
//!   version 2 (adding `z`) lands.
//! - **I6720** — the cost does not grow with unrelated held rows. The store
//!   calls one roster version's admission makes are EQUAL with 1 and with 5
//!   strangers' held rows in the room (the strangers are not re-folded).
//! - **I6721** — a seat LOST by a roster version is still re-checked. Version
//!   2 drops `m2`; the calls its admission makes GROW with `m2`'s concluded
//!   rows (1 → 3): `m2`'s rows are re-folded, member-scoped, as before.

use ciris_verify_core::cde::{self, Value};

use super::fixture_switch as e2;
use super::group::GroupRecord;
use super::group_fixtures::{held_head, put_voices, roster_voices};
use super::ingest::{put_statement, StatementOutcome, INGEST_TIER};
use super::names::RowId;
use crate::federation::directory_double::FaultInjectingDirectory;
use crate::federation::types::{identity_type, Community, CommunityMember};
use crate::federation::FederationDirectory;

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

fn det_map(mut m: Vec<(&str, Value)>) -> Value {
    m.sort_by_key(|(k, _)| cde::encode(&t(k)));
    Value::Map(m.into_iter().map(|(k, v)| (t(k), v)).collect())
}

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
        &ciris_verify_core::namespace_match::family_id("chat:*"),
        &p,
        vec![],
    )
    .expect("HOLD-1b: sign")
}

fn ms_of(t: chrono::DateTime<chrono::Utc>) -> u64 {
    e2::ms(t)
}

/// Version 2 of `c`: its members, less `drop`, plus `add` joined at
/// `joined`, voiced by `voters`.
fn version2(
    c: &Community,
    add: Option<&str>,
    drop: Option<&str>,
    joined: chrono::DateTime<chrono::Utc>,
    head: &RowId,
    voters: &[&str],
) -> Vec<Vec<u8>> {
    let mut next = c.clone();
    if let Some(d) = drop {
        let dk = e2::kid(d);
        next.members.retain(|m| m.key_id != dk);
    }
    if let Some(a) = add {
        next.members.push(CommunityMember {
            key_id: e2::kid(a),
            joined_at: joined,
            role: None,
        });
    }
    let keys: Vec<_> = voters.iter().map(|s| e2::signing_key(s)).collect();
    let signers: Vec<&_> = keys.iter().collect();
    roster_voices(
        &GroupRecord::Community(next),
        2,
        Some(head),
        ms_of(joined) + 1_000,
        &signers,
    )
}

struct Room {
    community: Community,
    head: RowId,
}

async fn room(d: &dyn FederationDirectory, seed: &str, members: &[&str]) -> Room {
    for s in members {
        e2::put_key(d, s, &[identity_type::USER]).await;
    }
    let community =
        super::voices_invariants::found_community(d, seed, members, "majority", None).await;
    let (head, _) = held_head(d, &community.community_key_id)
        .await
        .expect("HOLD-1b: the head");
    Room { community, head }
}

/// I6719.
pub(crate) async fn gained_body(d: &dyn FederationDirectory) {
    let (m1, m2, z) = ("h1b-g-m1", "h1b-g-m2", "h1b-g-z");
    let r = room(d, "h1b-g", &[m1, m2]).await;
    e2::put_key(d, z, &[identity_type::USER]).await;
    let joined = crate::host::clock::now() - chrono::Duration::minutes(5);
    let post = chat(
        z,
        &r.community.community_key_id,
        &r.head,
        ms_of(joined) + 60_000,
    );
    let o = put_statement(d, &post, None, INGEST_TIER).await.unwrap();
    assert!(
        matches!(o, StatementOutcome::Pending { .. }),
        "I6719 held before z is listed: {o:?}"
    );
    put_voices(
        d,
        &version2(&r.community, Some(z), None, joined, &r.head, &[m1, m2]),
    )
    .await
    .expect("I6719 version 2");
    let id = RowId::of_statement(&post).unwrap();
    assert!(
        d.get_attestation(&id.hex()).await.unwrap().is_some(),
        "I6719 the seat a roster version gives concludes the held post"
    );
}

/// I6720: the store calls version 2's admission makes, with `strangers`
/// strangers' held rows in the room.
pub(crate) async fn bounded_calls(
    backend: std::sync::Arc<dyn FederationDirectory>,
    strangers: usize,
) -> u64 {
    let dd = FaultInjectingDirectory::new(backend);
    let d: &dyn FederationDirectory = &dd;
    let (m1, m2, z) = ("h1b-b-m1", "h1b-b-m2", "h1b-b-z");
    let r = room(d, "h1b-b", &[m1, m2]).await;
    e2::put_key(d, z, &[identity_type::USER]).await;
    let joined = crate::host::clock::now() - chrono::Duration::minutes(5);
    let gid = r.community.community_key_id.clone();
    for i in 0..strangers {
        let s = format!("h1b-b-s{i}");
        e2::put_key(d, &s, &[identity_type::USER]).await;
        let st = chat(&s, &gid, &r.head, ms_of(joined) + 10_000);
        let _ = put_statement(d, &st, None, INGEST_TIER).await.unwrap();
    }
    let zp = chat(z, &gid, &r.head, ms_of(joined) + 60_000);
    let _ = put_statement(d, &zp, None, INGEST_TIER).await.unwrap();
    let v2 = version2(&r.community, Some(z), None, joined, &r.head, &[m1, m2]);
    dd.reset_calls();
    put_voices(d, &v2).await.expect("I6720 version 2");
    dd.calls().values().sum()
}

/// I6721: the store calls version 2 (dropping `m2`) makes, with `posts`
/// concluded rows of `m2` in the room.
pub(crate) async fn lost_calls(
    backend: std::sync::Arc<dyn FederationDirectory>,
    posts: u64,
) -> u64 {
    let dd = FaultInjectingDirectory::new(backend);
    let d: &dyn FederationDirectory = &dd;
    let (m1, m2, m3) = ("h1b-l-m1", "h1b-l-m2", "h1b-l-m3");
    let r = room(d, "h1b-l", &[m1, m2, m3]).await;
    let gid = r.community.community_key_id.clone();
    let at = e2::ms(crate::host::clock::now()) - 120_000;
    for k in 0..posts {
        let st = chat(m2, &gid, &r.head, at + k);
        let o = put_statement(d, &st, None, INGEST_TIER).await.unwrap();
        assert!(
            matches!(o, StatementOutcome::Row { .. }),
            "I6721 a member's post lands: {o:?}"
        );
    }
    let joined = crate::host::clock::now() - chrono::Duration::minutes(1);
    let v2 = version2(&r.community, None, Some(m2), joined, &r.head, &[m1, m3]);
    dd.reset_calls();
    put_voices(d, &v2).await.expect("I6721 version 2");
    dd.calls().values().sum()
}

#[cfg(feature = "sqlite")]
async fn sqlite() -> std::sync::Arc<dyn FederationDirectory> {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    std::sync::Arc::new(b)
}

#[cfg(feature = "postgres")]
async fn postgres() -> Option<std::sync::Arc<dyn FederationDirectory>> {
    use crate::store::Backend as _;
    let dsn = crate::test_pg::empty_dsn()?;
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Some(std::sync::Arc::new(b))
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i6719_a_seat_gained_by_a_roster_version_concludes_sqlite() {
    Box::pin(gained_body(&*sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i6719_a_seat_gained_by_a_roster_version_concludes_postgres() {
    let Some(b) = postgres().await else { return };
    Box::pin(gained_body(&*b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i6720_a_roster_version_does_not_refold_strangers_sqlite() {
    let one = Box::pin(bounded_calls(sqlite().await, 1)).await;
    let five = Box::pin(bounded_calls(sqlite().await, 5)).await;
    assert_eq!(
        one, five,
        "I6720 1 vs 5 strangers' held rows: {one} vs {five}"
    );
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i6720_a_roster_version_does_not_refold_strangers_postgres() {
    let (Some(a), Some(b)) = (postgres().await, postgres().await) else {
        return;
    };
    let one = Box::pin(bounded_calls(a, 1)).await;
    let five = Box::pin(bounded_calls(b, 5)).await;
    assert_eq!(
        one, five,
        "I6720 1 vs 5 strangers' held rows: {one} vs {five}"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i6721_a_seat_lost_is_still_rechecked_sqlite() {
    let one = Box::pin(lost_calls(sqlite().await, 1)).await;
    let three = Box::pin(lost_calls(sqlite().await, 3)).await;
    assert!(
        three > one,
        "I6721 m2's rows are re-folded: {one} vs {three}"
    );
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i6721_a_seat_lost_is_still_rechecked_postgres() {
    let (Some(a), Some(b)) = (postgres().await, postgres().await) else {
        return;
    };
    let one = Box::pin(lost_calls(a, 1)).await;
    let three = Box::pin(lost_calls(b, 3)).await;
    assert!(
        three > one,
        "I6721 m2's rows are re-folded: {one} vs {three}"
    );
}
