//! v62.0.0 (v62 P8) — **I3546–I3547: the erasure withdraws is the
//! producer's edition-2 statement, and the authority is unchanged.** sqlite
//! and postgres.
//!
//! - **I3546** — over an edition-2 `detection:*` row (P4's conferred
//!   detector, P8's detection parts), the PRODUCER's `withdraws`
//!   (`subject_erasure::withdraws_statement_parts`: P1's composer payload,
//!   `refs.target`, the target's family) is admitted through the statement
//!   door, and `subject_erasure::erasing_withdraws` reads it as the
//!   producer's RULE-1 withdraws: the authority the DSAR door cites. A second
//!   node holding the row and the conferral admits the same bytes and reads
//!   the same authority (`apply_replicated_erasure`'s re-derivation).
//! - **I3547** — the CC 2.4.1.1 carve-out, in the edition-2 form: a
//!   `withdraws` of the same adverse row by ANOTHER key (the scored subject's
//!   or any non-producer's) is refused at the door, and no erasing authority
//!   appears.

use super::fixture_switch as e2;
use super::ingest::{put_statement, INGEST_TIER};
use crate::derived::detection_row::detection_statement_parts;
use crate::derived::types::{ConformityVariant, DetectionSeverity};
use crate::derived::DetectionEvent;
use crate::federation::subject_erasure::{erasing_withdraws, withdraws_statement_parts};
use crate::federation::FederationDirectory;

fn event(signing_key_id: &str) -> DetectionEvent {
    let ts = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        (crate::host::clock::now() - chrono::Duration::minutes(1)).timestamp_millis(),
    )
    .expect("ms");
    DetectionEvent {
        detection_id: uuid::Uuid::new_v4(),
        trace_id: format!("p8-erasure-trace-{}", uuid::Uuid::new_v4().simple()),
        body_sha256: vec![7u8; 32],
        detector: "hash_chain_integrity".into(),
        severity: DetectionSeverity::Warning,
        cohort_cell: serde_json::json!({"agent_role": "x"}),
        conformity_variant: ConformityVariant::Numeric,
        conformity_payload: serde_json::json!({"score": 0.5}),
        lens_core_version: "1.0.0".into(),
        ratchet_calibration_version: 3,
        canonical_bytes: b"{\"a\":1}".to_vec(),
        ed25519_sig: Vec::new(),
        ml_dsa_65_sig: Vec::new(),
        signing_key_id: signing_key_id.to_owned(),
        ts,
    }
}

fn sign(
    seed: &str,
    row_type: &str,
    parts: (String, String, ciris_verify_core::cde::Value),
) -> Vec<u8> {
    let (sub, family, payload) = parts;
    ciris_verify_core::edition2::sign_row_statement(
        &e2::signing_key(seed),
        &e2::kid(seed),
        &sub,
        row_type,
        &family,
        &payload,
        vec![],
    )
    .expect("signed")
}

fn now_ms() -> u64 {
    e2::ms(crate::host::clock::now())
}

async fn body<B>(a: &B, b: &B)
where
    B: FederationDirectory + Sync,
{
    Box::pin(super::standing_invariants::conferred_detector_body(a)).await;
    Box::pin(super::standing_invariants::conferred_detector_body(b)).await;
    let det = "p4-detector";
    let ev = event(&e2::kid(det));
    let detection = sign(
        det,
        "scores",
        detection_statement_parts(&ev, None).expect("parts"),
    );
    for d in [a, b] {
        put_statement(d, &detection, None, INGEST_TIER)
            .await
            .expect("the detection is admitted");
    }
    let rid = super::names::RowId::of_statement(&detection)
        .expect("a row")
        .hex();
    let target = a.get_attestation(&rid).await.unwrap().expect("held");

    // I3547 — another key's withdraws of an adverse row is refused first.
    let other = "p8-erasure-subject";
    e2::put_key(a, other, &["user"]).await;
    let theirs = sign(
        other,
        "withdraws",
        withdraws_statement_parts(&target, &e2::kid(other), now_ms()).expect("parts"),
    );
    assert!(
        put_statement(a, &theirs, None, INGEST_TIER).await.is_err(),
        "I3547: no subject-authority path reaches a detection row"
    );
    assert!(
        erasing_withdraws(a, &target).await.unwrap().is_none(),
        "I3547: no erasing authority"
    );

    // I3546 — the producer's own withdraws: rule 1.
    let mine = sign(
        det,
        "withdraws",
        withdraws_statement_parts(&target, &e2::kid(det), now_ms()).expect("parts"),
    );
    let wid = super::names::RowId::of_statement(&mine)
        .expect("a row")
        .hex();
    for (node, d) in [("A", a), ("B", b)] {
        put_statement(d, &mine, None, INGEST_TIER)
            .await
            .unwrap_or_else(|e| panic!("I3546: {node} admits the producer's withdraws: {e:?}"));
        let target = d.get_attestation(&rid).await.unwrap().expect("held");
        let w = erasing_withdraws(d, &target)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("I3546: {node} reads the rule-1 authority"));
        assert_eq!(
            w.attestation_id, wid,
            "I3546: {node}: the producer's statement"
        );
        assert!(
            super::emit::carried_statement(&w).is_some(),
            "I3546: an edition-2 statement, nothing JCS-signed"
        );
    }
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
    let dsn = crate::test_pg::isolated_dsn()?;
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Some(b)
}

#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread")]
async fn i3546_erasure_withdraws_sqlite() {
    let (a, b) = (sqlite().await, sqlite().await);
    Box::pin(body(&a, &b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn i3546_erasure_withdraws_postgres() {
    let (Some(a), Some(b)) = (postgres().await, postgres().await) else {
        eprintln!("i3546 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
        return;
    };
    Box::pin(body(&a, &b)).await;
    eprintln!("i3546 postgres: RAN");
}
