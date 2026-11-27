//! v62.0.0 (BIND-1b; the lead's ruling 11-23: `delegation_valid_from` /
//! `delegation_valid_until` are ms-time on EVERY `delegates_to`, CC 2.4 and
//! Constitution's `owner-binding` rule) — **I6627–I6628: a delegation's term
//! round-trips statement → row → statement, ms-time in the payload, RFC 3339
//! text on the row.**
//!
//! One witness per family that carries a term:
//!
//! - **I6627** — `self:delegates_to`: a founder's termed `moderate` edge in
//!   a room.
//! - **I6628** — `ownership:{relation}:{target_kind}:{version}`: an owner
//!   binding with a term.
//!
//! Each row lands through the real door. Each leg then asserts three things:
//!
//! 1. the KEPT statement's payload states both members as POSIX ms (a CBOR
//!    unsigned integer);
//! 2. the stored row's envelope projects them as the CC 2.6.3 text
//!    (`YYYY-MM-DDTHH:MM:SS.sssZ`) of the same instants: the form persist's
//!    JSON readers and the hosts read today;
//! 3. the producer's payload (`emit::payload_from_envelope`) over that stored
//!    envelope states them as the same ms again.

use chrono::{DateTime, SecondsFormat, Utc};
use ciris_verify_core::cde::Value;

use super::fixture_switch as e2;
use super::ingest::StatementOutcome;
use crate::federation::admission::{DELEGATION_VALID_FROM_FIELD, DELEGATION_VALID_UNTIL_FIELD};
use crate::federation::types::{identity_type, Attestation};
use crate::federation::FederationDirectory;

const TERM: [&str; 2] = [DELEGATION_VALID_FROM_FIELD, DELEGATION_VALID_UNTIL_FIELD];

fn ms(t: DateTime<Utc>) -> u64 {
    u64::try_from(t.timestamp_millis()).expect("after 1970")
}

fn text(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// The three legs over `row` (landed), whose term is `[from, until]`.
async fn round_trip(
    d: &dyn FederationDirectory,
    row: &Attestation,
    from: DateTime<Utc>,
    until: DateTime<Utc>,
    what: &str,
) {
    let want = [from, until];
    // The stored row (by the fixtures' id: a re-headed statement is followed,
    // `fixture_switch::rid`), and the statement it carries: the kept one.
    let stored = d
        .get_attestation(&e2::rid(row))
        .await
        .expect("the row reads")
        .unwrap_or_else(|| panic!("{what}: the row is stored"));
    let kept = e2::carried_statement(&stored)
        .unwrap_or_else(|| panic!("{what}: the stored row carries its statement"));
    // (1) The kept statement.
    let (_, payload) = super::liveness::statement_parts(&kept).expect("a COSE_Sign1 statement");
    for (member, at) in TERM.iter().zip(want) {
        assert_eq!(
            payload.get_text(member),
            Some(&Value::Uint(ms(at))),
            "{what}: the kept statement states {member} as POSIX ms"
        );
    }
    // (2) The stored row.
    for (member, at) in TERM.iter().zip(want) {
        assert_eq!(
            stored.attestation_envelope.get(*member),
            Some(&serde_json::json!(text(at))),
            "{what}: the row projects {member} as RFC 3339 text"
        );
    }
    // (3) The producer over the stored row.
    let family = e2::family_of(&stored);
    let again = super::emit::payload_from_envelope(
        &stored.attestation_envelope,
        &family,
        ms(stored.asserted_at),
        None,
        &[],
    )
    .unwrap_or_else(|e| panic!("{what}: the producer states the stored envelope: {e}"));
    for (member, at) in TERM.iter().zip(want) {
        assert_eq!(
            again.get_text(member),
            Some(&Value::Uint(ms(at))),
            "{what}: the producer states {member} as the same ms again"
        );
    }
}

/// A term `[at, at + days]`, at millisecond precision.
fn term(at: DateTime<Utc>, days: i64) -> (DateTime<Utc>, DateTime<Utc>) {
    let from = DateTime::<Utc>::from_timestamp_millis(at.timestamp_millis()).expect("an instant");
    (from, from + chrono::Duration::days(days))
}

/// **I6627** — a `self:delegates_to` with a term.
pub(crate) async fn i6627_a_delegation_term_round_trips(d: &dyn FederationDirectory, tag: &str) {
    use crate::federation::admission::DELEGATION_SCOPE_MODERATE;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::attestation_type;
    let (f, x) = (format!("tm-f-{tag}"), format!("tm-x-{tag}"));
    for k in [&f, &x] {
        let _ = e2::put_key(d, k, &[identity_type::USER]).await;
    }
    let c = super::voices_invariants::found_community(
        d,
        &format!("tm-g-{tag}"),
        &[f.as_str()],
        "majority",
        None,
    )
    .await;
    let at = Utc::now() - chrono::Duration::hours(2);
    let (from, until) = term(at, 30);
    let id = uuid::Uuid::new_v4().to_string();
    let env = serde_json::json!({
        "id": id,
        "scope": [DELEGATION_SCOPE_MODERATE],
        "community_id": c.community_key_id,
        DELEGATION_VALID_FROM_FIELD: text(from),
        DELEGATION_VALID_UNTIL_FIELD: text(until),
    });
    let mut edge = ts::bare_attestation(&id, &f, &x, &env);
    edge.attestation_type = attestation_type::DELEGATES_TO.to_owned();
    edge.asserted_at = from;
    edge.scrub_timestamp = from;
    ts::seal_row_in_place(&f, &mut edge);
    assert_eq!(
        e2::family_of(&edge),
        super::emit::DELEGATES_TO_FAMILY,
        "I6627: the family under test"
    );
    let out = e2::land_with_voices(d, &edge, &[x.as_str()])
        .await
        .unwrap_or_else(|e| panic!("I6627: the termed edge lands: {e}"));
    assert!(
        matches!(out, StatementOutcome::Row { .. }),
        "I6627: the termed edge lands: {out:?}"
    );
    round_trip(d, &edge, from, until, "I6627 self:delegates_to").await;
}

/// **I6628** — an owner binding (`ownership:*`) with a term.
pub(crate) async fn i6628_an_owner_binding_term_round_trips(
    d: &dyn FederationDirectory,
    tag: &str,
) {
    let (owner, node) = (format!("tm-o-{tag}"), format!("tm-n-{tag}"));
    let _ = e2::put_key(d, &owner, &[identity_type::USER]).await;
    let _ = e2::put_key(d, &node, &[identity_type::NODE]).await;
    let mut a = crate::federation::tier_ingest::test_support::owner_binding_attestation(
        &uuid::Uuid::new_v4().to_string(),
        &owner,
        &node,
    );
    let (from, until) = term(Utc::now() - chrono::Duration::minutes(5), 90);
    a.asserted_at = from;
    a.scrub_timestamp = from;
    a.attestation_envelope[DELEGATION_VALID_FROM_FIELD] = serde_json::json!(text(from));
    a.attestation_envelope[DELEGATION_VALID_UNTIL_FIELD] = serde_json::json!(text(until));
    let row = e2::row_of(&a, &owner);
    assert!(
        e2::family_of(&row).starts_with("ownership:"),
        "I6628: the family under test"
    );
    let out = e2::land_owner_binding(d, &row, &node)
        .await
        .unwrap_or_else(|e| panic!("I6628: the termed binding lands: {e}"));
    assert!(
        matches!(out, StatementOutcome::Row { .. }),
        "I6628: the termed binding lands: {out:?}"
    );
    round_trip(d, &row, from, until, "I6628 ownership").await;
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend as _;

    async fn fresh() -> SqliteBackend {
        let b = SqliteBackend::open_in_memory().await.unwrap();
        b.run_migrations().await.unwrap();
        b
    }

    #[tokio::test]
    async fn i6627_a_delegation_term_round_trips_sqlite() {
        let d = fresh().await;
        Box::pin(i6627_a_delegation_term_round_trips(&d, "s")).await;
    }

    #[tokio::test]
    async fn i6628_an_owner_binding_term_round_trips_sqlite() {
        let d = fresh().await;
        Box::pin(i6628_an_owner_binding_term_round_trips(&d, "s")).await;
    }
}

#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use crate::store::postgres::PostgresBackend;
    use crate::store::Backend as _;

    async fn fresh() -> Option<PostgresBackend> {
        let dsn = crate::test_pg::empty_dsn()?;
        let b = PostgresBackend::connect(&dsn).await.unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    }

    #[tokio::test]
    async fn i6627_a_delegation_term_round_trips_postgres() {
        let Some(d) = fresh().await else { return };
        Box::pin(i6627_a_delegation_term_round_trips(&d, "p")).await;
    }

    #[tokio::test]
    async fn i6628_an_owner_binding_term_round_trips_postgres() {
        let Some(d) = fresh().await else { return };
        Box::pin(i6628_an_owner_binding_term_round_trips(&d, "p")).await;
    }
}
