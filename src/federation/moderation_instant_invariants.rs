//! v62.0.0 (SD-fix1; CC 4.5.5 "Authority is judged over the act's own
//! causal past", CC 2.7.7, CC 2.4.1.3) — **a room's duty walk reads its
//! edges AT THE ACT'S INSTANT**, sqlite and pg. Before SD-fix1
//! `is_named_moderator`, `moderators_of` and `check_moderation_admission`
//! passed the act's instant only as the minor-band instant: the lens had
//! `as_of: None`, so an EXPIRED appointment still conferred and a
//! withdrawal dated AFTER an act un-made it. CW-fix1's room scoping
//! (`DutyHolders`, `CommunityWalk::In`) is unchanged and is exercised by every
//! leg (each edge names its room).
//!
//! The edges and the withdrawal land through the edition-2 statement door
//! (`land_with_voices`, `put_signed`). The act is a `moderation:spam`
//! `scores` row judged by `check_delegated_duty_scores_admission`, the duty
//! gate `attestation_admit` runs with the row's own `asserted_at` (as I2168
//! judges its quarantine row); `is_named_moderator` / `moderators_of` are read
//! at the same instant.
//!
//! - **I5300** an appointment whose signed term had CLOSED before the act
//!   confers nothing; an act dated inside the term is admitted. Both arrival
//!   orders: the acts judged before and after the edge lands.
//! - **I5301** a withdrawal dated AFTER the act does not reach back: the act
//!   stays admitted. Both orders: judged before the withdrawal lands, and
//!   after.
//! - **I5302** a withdrawal dated BEFORE the act refuses it. Both orders:
//!   an act dated after the withdrawal, judged before the withdrawal lands
//!   (admitted then) and again after (refused).

use crate::federation::admission::{
    check_delegated_duty_scores_admission, is_named_moderator, moderators_of, with_test_term,
    DELEGATION_SCOPE_MODERATE,
};
use crate::federation::edition2::fixture_switch as e2;
use crate::federation::edition2::ingest::StatementOutcome;
use crate::federation::tier_ingest::test_support as ts;
use crate::federation::types::{attestation_type, identity_type};
use crate::federation::{Attestation, Error, FederationDirectory};
use chrono::{DateTime, Duration, Utc};

/// `placer`'s `moderate` appointment of `to`, NAMING `room`, signed at `at`,
/// with an explicit term end when `until` is given (else the test term).
fn edge(
    placer: &str,
    to: &str,
    room: &str,
    at: DateTime<Utc>,
    until: Option<DateTime<Utc>>,
) -> Attestation {
    let id = uuid::Uuid::new_v4().to_string();
    let mut env = serde_json::json!({
        "id": id,
        "scope": [DELEGATION_SCOPE_MODERATE],
        "community_id": room,
    });
    if let Some(u) = until {
        env[crate::federation::admission::DELEGATION_VALID_UNTIL_FIELD] =
            serde_json::json!(u.to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
    }
    with_test_term(&mut env, at);
    let mut row = ts::bare_attestation(&id, placer, to, &env);
    row.attestation_type = attestation_type::DELEGATES_TO.to_owned();
    row.asserted_at = at;
    row.scrub_timestamp = at;
    ts::seal_row_in_place(placer, &mut row);
    row
}

/// `by`'s `moderation:spam` act in `room`, signed at `at`.
fn act(by: &str, room: &str, at: DateTime<Utc>) -> Attestation {
    let id = uuid::Uuid::new_v4().to_string();
    let env = serde_json::json!({
        "id": id,
        "dimension": "moderation:spam",
        "community_id": room,
    });
    let mut row = ts::bare_attestation(&id, by, by, &env);
    row.attestation_type = attestation_type::SCORES.to_owned();
    row.asserted_at = at;
    row.scrub_timestamp = at;
    ts::seal_row_in_place(by, &mut row);
    row
}

async fn lands(d: &dyn FederationDirectory, row: &Attestation, voice: &str, label: &str) {
    assert!(
        matches!(
            e2::land_with_voices(d, row, &[voice]).await,
            Ok(StatementOutcome::Row { .. })
        ),
        "{label}: the edge lands"
    );
}

async fn withdraw(
    d: &dyn FederationDirectory,
    target: &Attestation,
    by: &str,
    label: &str,
) -> DateTime<Utc> {
    let w = e2::composer_of(attestation_type::WITHDRAWS, target, by);
    let at = w.asserted_at;
    let out = e2::put_signed(d, &w)
        .await
        .unwrap_or_else(|e| panic!("{label}: the placer's withdraws: {e}"));
    assert!(
        matches!(out, StatementOutcome::Row { .. }),
        "{label}: the placer's withdraws lands: {out:?}"
    );
    at
}

/// Is `by`'s act at `at` admitted by the duty gate, and is `by` a named
/// moderator (and in `moderators_of`) at `at`? The three must agree.
async fn admitted(
    d: &dyn FederationDirectory,
    by: &str,
    room: &str,
    at: DateTime<Utc>,
    label: &str,
) -> bool {
    let gate = match check_delegated_duty_scores_admission(d, &act(by, room, at)).await {
        Ok(()) => true,
        Err(Error::DelegatedScopeUnauthorized { .. }) => false,
        Err(e) => panic!("{label}: the duty gate errs: {e}"),
    };
    let k = e2::kid(by);
    let named = is_named_moderator(d, &k, room, DELEGATION_SCOPE_MODERATE, at)
        .await
        .expect("is_named_moderator");
    let listed = moderators_of(d, room, DELEGATION_SCOPE_MODERATE, at)
        .await
        .expect("moderators_of")
        .contains(&k);
    assert_eq!(
        gate, named,
        "{label}: the gate and is_named_moderator agree"
    );
    assert_eq!(
        named, listed,
        "{label}: is_named_moderator and moderators_of agree"
    );
    gate
}

async fn room(d: &dyn FederationDirectory, name: &str, founder: &str) -> String {
    crate::federation::edition2::voices_invariants::found_community(
        d,
        name,
        &[founder],
        "majority",
        None,
    )
    .await
    .community_key_id
}

pub(crate) async fn i5300_i5302_the_walk_reads_the_act_instant(d: &dyn FederationDirectory) {
    let t0 = Utc::now() - Duration::hours(2);
    // ---- I5300: the term closed before the act.
    for (order, edge_first) in [("edge-first", true), ("acts-first", false)] {
        let (f, m) = (format!("sd0-f-{order}"), format!("sd0-m-{order}"));
        let (f, m) = (f.as_str(), m.as_str());
        for k in [f, m] {
            e2::put_key(d, k, &[identity_type::USER]).await;
        }
        let r = room(d, &format!("sd0-room-{order}"), f).await;
        let e = edge(f, m, &r, t0, Some(t0 + Duration::minutes(30)));
        let (inside, after) = (t0 + Duration::minutes(10), t0 + Duration::minutes(60));
        if !edge_first {
            assert!(
                !admitted(d, m, &r, inside, "I5300").await,
                "I5300 {order}: no edge yet"
            );
        }
        lands(d, &e, m, "I5300").await;
        assert!(
            admitted(d, m, &r, inside, "I5300").await,
            "I5300 {order}: an act inside the term is admitted"
        );
        assert!(
            !admitted(d, m, &r, after, "I5300").await,
            "I5300 {order}: an act after the term closed is REFUSED (the expired appointment confers nothing)"
        );
    }
    // ---- I5301: a withdrawal dated AFTER the act does not reach back.
    for (order, judge_first) in [("judged-first", true), ("withdrawn-first", false)] {
        let (f, m) = (format!("sd1-f-{order}"), format!("sd1-m-{order}"));
        let (f, m) = (f.as_str(), m.as_str());
        for k in [f, m] {
            e2::put_key(d, k, &[identity_type::USER]).await;
        }
        let r = room(d, &format!("sd1-room-{order}"), f).await;
        let e = edge(f, m, &r, t0, None);
        lands(d, &e, m, "I5301").await;
        let the_act = t0 + Duration::minutes(10);
        if judge_first {
            assert!(
                admitted(d, m, &r, the_act, "I5301").await,
                "I5301 {order}: admitted before the withdrawal"
            );
        }
        let w_at = withdraw(d, &e, f, "I5301").await;
        assert!(
            w_at > the_act,
            "I5301: the withdrawal is dated after the act"
        );
        assert!(
            admitted(d, m, &r, the_act, "I5301").await,
            "I5301 {order}: a withdrawal dated after the act does NOT reach back"
        );
        assert!(
            !admitted(d, m, &r, crate::host::clock::now(), "I5301").await,
            "I5301 {order}: and an act now, after it, is refused"
        );
    }
    // ---- I5302: a withdrawal dated BEFORE the act refuses it.
    for (order, judge_first) in [("judged-first", true), ("withdrawn-first", false)] {
        let (f, m) = (format!("sd2-f-{order}"), format!("sd2-m-{order}"));
        let (f, m) = (f.as_str(), m.as_str());
        for k in [f, m] {
            e2::put_key(d, k, &[identity_type::USER]).await;
        }
        let r = room(d, &format!("sd2-room-{order}"), f).await;
        let e = edge(f, m, &r, t0, None);
        lands(d, &e, m, "I5302").await;
        // The act is dated after the withdrawal will be (the withdrawal is
        // signed at the host clock when it is made).
        let the_act = Utc::now() + Duration::minutes(10);
        if judge_first {
            assert!(
                admitted(d, m, &r, the_act, "I5302").await,
                "I5302 {order}: admitted while no withdrawal is held"
            );
        }
        let w_at = withdraw(d, &e, f, "I5302").await;
        assert!(
            w_at < the_act,
            "I5302: the withdrawal is dated before the act"
        );
        assert!(
            !admitted(d, m, &r, the_act, "I5302").await,
            "I5302 {order}: a withdrawal dated before the act REFUSES it"
        );
        assert!(
            admitted(d, m, &r, t0 + Duration::minutes(10), "I5302").await,
            "I5302 {order}: an act before the withdrawal still stands"
        );
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i5300_i5302_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(i5300_i5302_the_walk_reads_the_act_instant(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i5300_i5302_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(i5300_i5302_the_walk_reads_the_act_instant(&b)).await;
}
