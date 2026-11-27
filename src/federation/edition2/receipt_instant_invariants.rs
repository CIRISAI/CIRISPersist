//! v62.0.0 (HOLD-1c; the lead's ruling 11-23: "a verdict must not depend on
//! when a re-fold happens to run") — witnesses, sqlite + postgres, under an
//! installed `FixedClock` (process-global: run under nextest, one process per
//! test).
//!
//! - **I6722** — a member's row RECEIVED inside W (3 days) and concluded
//!   stays concluded when its member's removal, four days later, re-folds
//!   it. The write scope reads the row's first-held instant, not now. The
//!   mutation (`received_at = now` in `attestation_admit::held_receipt`
//!   or the write-scope gate) turns this red: the row un-concludes
//!   `asserted_at_stale`.
//! - **I6728** (HOLD-1d) — inside a re-judgement (`attestation_admit::
//!   at_original_receipt`), a gate's "currently a member" read
//!   (`active_community_members`) reads the room at the row's receipt.
//! - **I6723** — a row the removed member signed while seated but that this
//!   node FIRST receives after the removal, outside W, is held
//!   `asserted_at_stale` at first receipt, and stays held when a later
//!   re-fold runs.

use std::sync::Arc;

use ciris_verify_core::cde::{self, Value};

use super::fixture_switch as e2;
use super::group::MembershipRecord;
use super::group_fixtures::{held_head, membership_voices, put_voices};
use super::ingest::{put_statement, StatementOutcome, INGEST_TIER};
use super::names::RowId;
use crate::federation::types::{identity_type, CommunityMembershipRevocation};
use crate::federation::FederationDirectory;
use crate::host::clock::{self, FixedClock};

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
    .expect("HOLD-1c: sign")
}

const FOUR_DAYS: std::time::Duration = std::time::Duration::from_secs(4 * 86_400);

/// The body: `late` = I6723's row (signed now, first received after the
/// removal four days on).
pub(crate) async fn body(d: &dyn FederationDirectory, fixed: &FixedClock) {
    let (m1, m2, m3) = ("h1c-m1", "h1c-m2", "h1c-m3");
    for s in [m1, m2, m3] {
        e2::put_key(d, s, &[identity_type::USER]).await;
    }
    let c = super::voices_invariants::found_community(d, "h1c-g", &[m1, m2, m3], "majority", None)
        .await;
    let gid = c.community_key_id.clone();
    let (head, _) = held_head(d, &gid).await.expect("HOLD-1c: the head");
    let at = e2::ms(clock::now()) - 60_000;
    let early = chat(m2, &gid, &head, at);
    let late = chat(m2, &gid, &head, at + 1);
    let o = put_statement(d, &early, None, INGEST_TIER).await.unwrap();
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "HOLD-1c a seated member's row concludes: {o:?}"
    );
    // Four days on, m2 is removed by the count; the removal touches
    // `key:<m2>` and re-folds m2's rows.
    fixed.advance(FOUR_DAYS);
    let now = clock::now();
    let removal = MembershipRecord::CommunityRemoval(CommunityMembershipRevocation {
        community_key_id: gid.clone(),
        removed_identity_key_id: e2::kid(m2),
        removed_at: now,
        effective_at: now,
        reason: None,
        witness_set: Vec::new(),
        persist_row_hash: String::new(),
    });
    let keys: Vec<_> = [m1, m3].iter().map(|s| e2::signing_key(s)).collect();
    let signers: Vec<&_> = keys.iter().collect();
    put_voices(d, &membership_voices(&removal, Some(&head), &signers))
        .await
        .expect("HOLD-1c the removal");
    let early_id = RowId::of_statement(&early).unwrap();
    assert!(
        d.get_attestation(&early_id.hex()).await.unwrap().is_some(),
        "I6722 a row received inside W stays concluded when a later re-fold runs"
    );
    // v62.0.0 (HOLD-1d) — I6728: a gate's "currently a member" read
    // (`active_community_members`) inside a RE-JUDGEMENT of a row first held
    // four days ago reads the room at that receipt: m2 is a member there. At
    // the clock m2 is out (the premise). Kills: the read taking
    // `clock::now()` inside a re-fold.
    let m2_kid = e2::kid(m2);
    let at_clock = d.active_community_members(&gid).await.unwrap();
    assert!(
        !at_clock.iter().any(|m| m.key_id == m2_kid),
        "I6728 premise: at the clock the removal has taken m2 out"
    );
    let at_receipt = crate::federation::attestation_admit::at_original_receipt(
        Some(now - chrono::Duration::days(4)),
        d.active_community_members(&gid),
    )
    .await
    .unwrap();
    assert!(
        at_receipt.iter().any(|m| m.key_id == m2_kid),
        "I6728 (HOLD-1d): judged at the receipt four days ago, m2 is still a member"
    );
    // I6723 — first received NOW, outside W, from a removed member: stale.
    let o = put_statement(d, &late, None, INGEST_TIER).await.unwrap();
    assert!(
        matches!(o, StatementOutcome::Pending { .. }),
        "I6723 held at first receipt: {o:?}"
    );
    let late_id = RowId::of_statement(&late).unwrap();
    let why = super::fold::why_held(d, &late_id)
        .await
        .unwrap()
        .map(|h| h.reason);
    assert_eq!(
        why.as_deref(),
        Some(super::fold::reason::ASSERTED_AT_STALE),
        "I6723 stale at first receipt"
    );
    // A later re-fold of m2's rows (a second removal voice re-offered is no
    // change; re-fold the row itself) keeps it held.
    fixed.advance(FOUR_DAYS);
    super::fold::refold_rows(d, [late_id].into_iter().collect())
        .await
        .unwrap();
    assert!(
        d.get_attestation(&late_id.hex()).await.unwrap().is_none(),
        "I6723 stays held"
    );
}

async fn with_fixed_clock<F, Fut>(f: F)
where
    F: FnOnce(Arc<FixedClock>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let fixed = Arc::new(FixedClock::new(chrono::Utc::now()));
    let prev = clock::install(fixed.clone());
    f(fixed).await;
    match prev {
        Some(p) => {
            clock::install(p);
        }
        None => {
            clock::uninstall();
        }
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i6722_i6723_the_write_scope_reads_the_receipt_instant_sqlite() {
    use crate::store::Backend as _;
    with_fixed_clock(|fixed| async move {
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(body(&b, &fixed)).await;
    })
    .await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i6722_i6723_the_write_scope_reads_the_receipt_instant_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    with_fixed_clock(|fixed| async move {
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(body(&b, &fixed)).await;
    })
    .await;
}
