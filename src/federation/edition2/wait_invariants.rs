//! v62.0.0 (CC 2.7, wave P9) — **a wait is a wait on every surface.**
//!
//! Under CC 2.7 a link that is not held answers WAITING (retryable), never a
//! terminal refusal. [`Error::is_wait`] is the one classification; the
//! directory capsule, the edition-2 HTTP door and the Python mapper read it,
//! never a list of their own.
//!
//! - **I3600 (the classification).** Every wait arm answers `is_wait()`
//!   (the key record not held, a named row not held, a held roster change,
//!   a held self-roster proposal, a licensure short of its quorum, an
//!   unresolved membership or write scope, a missing delegation edge, a
//!   retryable key-grant / acceptance / purge reason, a relayed wait); their
//!   terminal siblings do not (an evicted genesis key, a refused proposal, a
//!   retracted delegation, a malformed row, an invalid argument, a backend
//!   failure, a row waiting for its actor, no constitutional root yet).
//! - **I3601 (the door, sqlite and postgres).** A row signed by a key whose
//!   record this node does not hold is the wait
//!   `federation_attester_key_unknown` on BOTH backends, with the same kind,
//!   and nothing is stored.
//! - **I3603 (HTTP, sqlite and postgres; `server` feature).** The same bytes
//!   at `POST /v1/edition2/statements` answer `424` with that kind and
//!   `retryable: true`; a JSON body answers `422`, `retryable: false`.
//!
//! The capsule leg (I3602) is in `ffi::directory_capsule::wait_relay`, the
//! status table (I3606) in `server::edition2`, the Python leg (I3607) in
//! `ffi::pyo3::wait_taxonomy_tests`, and the drivers' foreign-key legs
//! (I3604, I3605) in `store::link_not_held_invariants`.

use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::sign_row_statement;

use super::door_invariants::fixture::*;
use super::ingest::{put_statement, INGEST_TIER};
use super::names::RowId;
use crate::federation::{Error, FederationDirectory, SignerNotActingReason};

/// An authored score row by `k`: `ingest_invariants`'s shape, byte for byte
/// (it admits it from a held key, and answers the wait for a stranger's).
fn score_row(k: &ciris_crypto::composite::CompositeSigningKey, at: u64) -> Vec<u8> {
    let payload = map(vec![
        ("asserted_at", Value::Uint(at)),
        ("author", Value::Text(iref(k))),
        ("score", Value::Uint(750_000)),
        ("confidence", Value::Uint(900_000)),
        (
            "dimension",
            Value::Text("evidence:safety_battery:capture:a:b:v1".into()),
        ),
        (
            "refs",
            map(vec![(
                "also",
                map(vec![("cites", Value::Array(vec![ref2(&[0x31; 32])]))]),
            )]),
        ),
    ]);
    sign_row_statement(
        k,
        &iref(k),
        &iref(k),
        "scores",
        "evidence:.suite:.kind:.cell:.prefix",
        &payload,
        vec![],
    )
    .unwrap()
}

/// I3600 — the one classification, arm by arm.
#[test]
fn i3600_is_wait_classifies_every_wait_arm() {
    use crate::federation::tier_ingest::{
        LOCATION_AUTHORITY_RULE_DELEGATION_RETRACTED, LOCATION_AUTHORITY_RULE_NO_DELEGATION_EDGE,
    };
    let s = |x: &str| x.to_owned();
    let waits: Vec<Error> = vec![
        Error::AttesterKeyUnknown {
            attesting_key_id: s("k"),
            plane: "attestation",
        },
        Error::link_not_held("family", "insert family: FOREIGN KEY constraint failed"),
        Error::WithdrawsTargetUnheld {
            attestation_id: s("w"),
            target_attestation_id: s("t"),
        },
        Error::RosterChangeNotLanded {
            group_key_id: s("g"),
            member_key_id: s("m"),
            direction: "widening",
            quorum_key: s("q"),
            signers: 1,
        },
        Error::LicensureShortOfAuthorityQuorum {
            attesting_key_id: s("k"),
            authority_id: s("a"),
            signers: 1,
        },
        Error::SignerDoesNotActFor {
            attesting_key_id: s("k"),
            identity_key_id: s("i"),
            plane: "identity_occurrence",
            reason: SignerNotActingReason::NotBound,
        },
        Error::SelfRosterNotLanded {
            identity_key_id: s("i"),
            target_key_id: s("t"),
            kind: "add",
            proposal_id: s("p"),
            decision: "pending",
            earliest_lone_at: None,
            needs: 1,
        },
        Error::WriteScopeRefused(crate::scope::ScopeRefusalReason::MembershipUnresolved),
        Error::LocationAuthorityUnauthorized {
            subject_key_id: s("s"),
            offered_authority_key_id: s("a"),
            rule: LOCATION_AUTHORITY_RULE_NO_DELEGATION_EDGE,
        },
        Error::RosterAuthorityUnauthorized {
            group_key_id: s("g"),
            offered_authority_key_id: s("a"),
            rule: crate::federation::ROSTER_AUTHORITY_RULE_NOT_ESTABLISHED,
            shortfall: None,
        },
        Error::MembershipAcceptanceRefused {
            group_key_id: s("g"),
            member_key_id: s("m"),
            rule: crate::federation::membership_acceptance::RULE_ACCEPTANCE_UNRESOLVED,
        },
        Error::Relayed {
            kind: "federation_attester_key_unknown",
            wait: true,
            message: s("relayed"),
        },
    ];
    for e in &waits {
        assert!(e.is_wait(), "I3600: {} must say WAIT", e.kind());
    }
    let terminal: Vec<Error> = vec![
        Error::SignerDoesNotActFor {
            attesting_key_id: s("k"),
            identity_key_id: s("i"),
            plane: "identity_occurrence",
            reason: SignerNotActingReason::GenesisEvicted,
        },
        Error::SelfRosterNotLanded {
            identity_key_id: s("i"),
            target_key_id: s("t"),
            kind: "add",
            proposal_id: s("p"),
            decision: "majority_objected",
            earliest_lone_at: None,
            needs: 0,
        },
        Error::WriteScopeRefused(crate::scope::ScopeRefusalReason::NoCommunityMembership),
        Error::LocationAuthorityUnauthorized {
            subject_key_id: s("s"),
            offered_authority_key_id: s("a"),
            rule: LOCATION_AUTHORITY_RULE_DELEGATION_RETRACTED,
        },
        Error::malformed_row(
            "attestation",
            crate::federation::malformed_row::NO_SIGNER,
            "x",
        ),
        Error::InvalidArgument(s("bad")),
        Error::Backend(s("database is locked")),
        Error::NoActorSignature {
            attestation_id: s("a"),
            attesting_key_id: s("k"),
        },
        Error::Relayed {
            kind: "federation_malformed_row",
            wait: false,
            message: s("relayed"),
        },
    ];
    for e in &terminal {
        assert!(!e.is_wait(), "I3600: {} must NOT say wait", e.kind());
    }
    assert_eq!(
        Error::link_not_held("family", "x").kind(),
        "federation_link_not_held",
        "I3600: the link wait's stable token"
    );
}

/// I3601 + I3603 over one migrated store.
async fn body(dir: std::sync::Arc<dyn FederationDirectory>) {
    // Signed before any await: no signing key crosses one.
    let row = {
        let stranger = key(97);
        score_row(&stranger, 5_000)
    };
    let row_id = RowId::of_statement(&row).expect("a row statement");

    // ── I3601 ──
    let e = put_statement(dir.as_ref(), &row, None, INGEST_TIER)
        .await
        .expect_err("I3601: a key not held is not admitted");
    assert_eq!(
        e.kind(),
        "federation_attester_key_unknown",
        "I3601: the same kind on every backend: {e}"
    );
    assert!(e.is_wait(), "I3601: a wait: {e}");
    assert!(
        dir.get_attestation(&row_id.hex())
            .await
            .expect("I3601: read")
            .is_none(),
        "I3601: nothing stored behind a wait"
    );

    // ── I3603 ──
    #[cfg(feature = "server")]
    {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        use crate::server::edition2::{router, Edition2ErrorBody, Edition2State, STATEMENTS_PATH};

        let app = router(Edition2State::new(dir.clone()));
        let send = |body: Vec<u8>| {
            let app = app.clone();
            async move {
                let req = Request::post(STATEMENTS_PATH)
                    .header("Content-Type", "application/cose")
                    .body(Body::from(body))
                    .expect("request");
                let resp = app.oneshot(req).await.expect("infallible");
                let status = resp.status();
                let bytes = resp
                    .into_body()
                    .collect()
                    .await
                    .expect("body")
                    .to_bytes()
                    .to_vec();
                (status, bytes)
            }
        };
        let (st, b) = send(row.clone()).await;
        assert_eq!(
            st,
            StatusCode::FAILED_DEPENDENCY,
            "I3603: a wait is 424: {}",
            String::from_utf8_lossy(&b)
        );
        let body: Edition2ErrorBody = serde_json::from_slice(&b).expect("I3603: body");
        assert_eq!(body.kind, "federation_attester_key_unknown", "I3603");
        assert!(body.retryable, "I3603: retryable");

        let (st, b) = send(br#"{"attestation":{}}"#.to_vec()).await;
        assert_eq!(
            st,
            StatusCode::UNPROCESSABLE_ENTITY,
            "I3603: malformed is 422"
        );
        let body: Edition2ErrorBody = serde_json::from_slice(&b).expect("I3603: body");
        assert_eq!(body.kind, "federation_malformed_row", "I3603");
        assert!(!body.retryable, "I3603: terminal");
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3601_i3603_a_missing_link_waits_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(std::sync::Arc::new(b))).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3601_i3603_a_missing_link_waits_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::isolated_dsn() else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(std::sync::Arc::new(b))).await;
}
