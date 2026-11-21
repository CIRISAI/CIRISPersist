//! v62.0.0 (CW-fix1; CC 4.5.4 — a moderator appointment is
//! `delegates_to(authority → K, scope ⊇ {moderate}, community_id: C)`) —
//! **I2167: an appointment in room A confers nothing in room B, nor outside
//! rooms**, on the edge level, sqlite and pg (I2168 drives the same through
//! `Engine::add_moderator`). F founds A and B (a holder of both):
//!
//! - F appoints D by an edge naming A: D moderates A, NOT B
//!   (`is_named_moderator`, `moderators_of`, the chokepoint
//!   `check_moderation_admission`);
//! - a DEPUTY chain: D (granted `sub_delegation`) appoints E by an edge
//!   naming A: E moderates A, NOT B; an edge from D naming B confers nothing
//!   in B (D holds no seat there);
//! - an UNSCOPED edge F→U confers nothing in A or B (a community walk follows
//!   only edges naming it);
//! - the federation-scope walk follows only UNSCOPED edges: with F as a
//!   federation holder, the room appointment F→D gives D no federation duty,
//!   the unscoped F→U does.
//!
//! Before CW-fix1 every leg above that says NOT was true.

use crate::federation::admission::{
    check_moderation_admission, is_named_moderator, moderators_of, with_test_term, DutyHolders,
    DELEGATION_SCOPE_MODERATE,
};
use crate::federation::edition2::fixture_switch as e2;
use crate::federation::edition2::ingest::StatementOutcome;
use crate::federation::tier_ingest::test_support as ts;
use crate::federation::types::{attestation_type, identity_type};
use crate::federation::{Attestation, FederationDirectory};
use chrono::{Duration, Utc};

fn edge(placer: &str, to: &str, community: Option<&str>, sub_delegation: bool) -> Attestation {
    let at = Utc::now() - Duration::hours(2);
    let id = uuid::Uuid::new_v4().to_string();
    let mut env = serde_json::json!({
        "id": id,
        "scope": [DELEGATION_SCOPE_MODERATE],
        "sub_delegation": sub_delegation,
    });
    if let Some(c) = community {
        env["community_id"] = serde_json::json!(c);
    }
    with_test_term(&mut env, at);
    let mut row = ts::bare_attestation(&id, placer, to, &env);
    row.attestation_type = attestation_type::DELEGATES_TO.to_owned();
    row.asserted_at = at;
    row.scrub_timestamp = at;
    ts::seal_row_in_place(placer, &mut row);
    row
}

async fn lands(d: &dyn FederationDirectory, row: &Attestation, voice: &str) {
    assert!(
        matches!(
            e2::land_with_voices(d, row, &[voice]).await,
            Ok(StatementOutcome::Row { .. })
        ),
        "I2167: the edge lands"
    );
}

pub(crate) async fn i2167_an_appointment_in_a_confers_nothing_in_b(d: &dyn FederationDirectory) {
    let (f, dm, em, u, x) = ("cx-f", "cx-d", "cx-e", "cx-u", "cx-x");
    for k in [f, dm, em, u, x] {
        e2::put_key(d, k, &[identity_type::USER]).await;
    }
    let a = crate::federation::edition2::voices_invariants::found_community(
        d,
        "cx-room-a",
        &[f],
        "majority",
        None,
    )
    .await
    .community_key_id;
    let b = crate::federation::edition2::voices_invariants::found_community(
        d,
        "cx-room-b",
        &[f],
        "majority",
        None,
    )
    .await
    .community_key_id;
    let now = Utc::now();
    let named = |room: String, k: &'static str| async move {
        is_named_moderator(d, &e2::kid(k), &room, DELEGATION_SCOPE_MODERATE, now)
            .await
            .expect("is_named_moderator")
    };
    // F appoints D in A (granting sub_delegation).
    lands(d, &edge(f, dm, Some(&a), true), dm).await;
    assert!(named(a.clone(), dm).await, "I2167: D moderates A");
    assert!(!named(b.clone(), dm).await, "I2167: D does NOT moderate B");
    let in_b = moderators_of(d, &b, DELEGATION_SCOPE_MODERATE, now)
        .await
        .unwrap();
    assert!(
        !in_b.contains(&e2::kid(dm)),
        "I2167: B's moderators exclude D: {in_b:?}"
    );
    let f_roots: std::collections::HashSet<String> = std::iter::once(e2::kid(f)).collect();
    let act = |holders: DutyHolders, k: &'static str| async move {
        check_moderation_admission(
            d,
            &e2::kid(k),
            &holders,
            DELEGATION_SCOPE_MODERATE,
            "content:i2167",
            now,
        )
        .await
    };
    assert!(
        matches!(
            act(DutyHolders::of_community(&b, f_roots.clone()), dm).await,
            Err(crate::federation::Error::DelegatedScopeUnauthorized { .. })
        ),
        "I2167: D's act in B is refused at the chokepoint"
    );
    assert!(
        act(DutyHolders::of_community(&a, f_roots.clone()), dm)
            .await
            .is_ok(),
        "I2167: and admitted in A"
    );
    // A deputy chain: D appoints E in A; D's edge naming B confers nothing.
    lands(d, &edge(dm, em, Some(&a), false), em).await;
    assert!(named(a.clone(), em).await, "I2167: E moderates A through D");
    assert!(!named(b.clone(), em).await, "I2167: E does NOT moderate B");
    lands(d, &edge(dm, x, Some(&b), false), x).await;
    assert!(
        !named(b.clone(), x).await,
        "I2167: D holds nothing in B to pass on"
    );
    // An unscoped edge confers nothing in any room.
    lands(d, &edge(f, u, None, false), u).await;
    assert!(
        !named(a.clone(), u).await && !named(b.clone(), u).await,
        "I2167: an unscoped edge confers nothing in a room"
    );
    // The federation-scope walk follows only unscoped edges.
    assert!(
        act(DutyHolders::unscoped(f_roots.clone()), u).await.is_ok(),
        "I2167: an unscoped delegation from a federation holder carries its federation duty"
    );
    assert!(
        matches!(
            act(DutyHolders::unscoped(f_roots), dm).await,
            Err(crate::federation::Error::DelegatedScopeUnauthorized { .. })
        ),
        "I2167: a ROOM appointment confers no federation-scope duty"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2167_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(i2167_an_appointment_in_a_confers_nothing_in_b(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2167_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(i2167_an_appointment_in_a_confers_nothing_in_b(&b)).await;
}
