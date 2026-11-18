//! v62.0.0 (v62 P8) — **I3535–I3537: a detection is a `detection:{detector}`
//! edition-2 statement, standing by conferral, admitted on a SECOND node.**
//! sqlite and postgres.
//!
//! - **I3535** — a detector conferred `infra:detect` (P4's
//!   `conferred_detector_body`: a root this node trusts confers it; the
//!   detector's key states only `agent`) states a detection
//!   (`derived::detection_row::detection_statement_parts`, signed by its
//!   key). Node A admits it under the NODE-COMPUTED row id (not the
//!   uuid-derived `detection_attestation_id`) and projects it into
//!   `detection_events`, the two signature columns the statement's
//!   composite halves (64 / 3309 bytes), its reals fixed-scale integers
//!   (`0.25` → `250000`, CC 2.6.1.5). Node B, with the same conferral,
//!   admits the same bytes and projects the same detection.
//! - **I3536** — a key that only DECLARES `lenscore_detector` is refused
//!   (`ReservedPrefixEmitterMismatch`): standing is never a self-declared
//!   type.
//! - **I3537** — the earlier-form door (`put_detection_event`, a detection
//!   hybrid-signed over its canonical bytes) refuses `earlier_form_object`
//!   once the doors are shut.

use super::fixture_switch as e2;
use super::ingest::{put_statement, INGEST_TIER};
use crate::derived::detection_row::{detection_attestation_id, detection_statement_parts};
use crate::derived::types::{ConformityVariant, DetectionSeverity};
use crate::derived::{DerivedSchema, DetectionEvent, EventFilter};
use crate::federation::FederationDirectory;

const DETECTOR: &str = "hash_chain_integrity";

fn event(signing_key_id: &str) -> DetectionEvent {
    let ts = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        (crate::host::clock::now() - chrono::Duration::minutes(1)).timestamp_millis(),
    )
    .expect("ms");
    DetectionEvent {
        detection_id: uuid::Uuid::new_v4(),
        trace_id: format!("p8-trace-{}", uuid::Uuid::new_v4().simple()),
        body_sha256: vec![7u8; 32],
        detector: DETECTOR.into(),
        severity: DetectionSeverity::Warning,
        cohort_cell: serde_json::json!({"agent_role": "x"}),
        conformity_variant: ConformityVariant::Numeric,
        conformity_payload: serde_json::json!({"score": 0.25}),
        lens_core_version: "1.0.0".into(),
        ratchet_calibration_version: 3,
        canonical_bytes: b"{\"a\":1}".to_vec(),
        ed25519_sig: Vec::new(),
        ml_dsa_65_sig: Vec::new(),
        signing_key_id: signing_key_id.to_owned(),
        ts,
    }
}

fn sign(seed: &str, ev: &DetectionEvent) -> Vec<u8> {
    let (sub, family, payload) = detection_statement_parts(ev).expect("the detection's parts");
    ciris_verify_core::edition2::sign_row_statement(
        &e2::signing_key(seed),
        &sub,
        &sub,
        "scores",
        &family,
        &payload,
        vec![],
    )
    .expect("sign the detection")
}

async fn projected<B: DerivedSchema>(b: &B, ev: &DetectionEvent) -> Option<DetectionEvent> {
    b.get_detection_events(EventFilter {
        detector: Some(DETECTOR.into()),
        ..EventFilter::default()
    })
    .await
    .expect("read detection_events")
    .into_iter()
    .find(|e| e.detection_id == ev.detection_id)
}

async fn body<B>(a: &B, b: &B)
where
    B: FederationDirectory + DerivedSchema + Sync,
{
    // I3535 — the conferral (P4's fixture) on both nodes.
    Box::pin(super::standing_invariants::conferred_detector_body(a)).await;
    Box::pin(super::standing_invariants::conferred_detector_body(b)).await;
    let det = "p4-detector";
    let ev = event(&e2::kid(det));
    let st = sign(det, &ev);
    let rid = super::names::RowId::of_statement(&st).expect("a row statement");
    assert_ne!(
        rid.hex(),
        detection_attestation_id(&ev.detection_id),
        "I3535: the row id is node-computed"
    );
    for (node, d) in [("A", a), ("B", b)] {
        put_statement(d, &st, None, INGEST_TIER)
            .await
            .unwrap_or_else(|e| panic!("I3535: {node} admits the detection: {e:?}"));
        let row = d
            .get_attestation(&rid.hex())
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("I3535: {node} holds it under its row id"));
        assert_eq!(row.attesting_key_id, e2::kid(det), "I3535: by the detector");
        let p = projected(d, &ev)
            .await
            .unwrap_or_else(|| panic!("I3535: {node} projects the detection"));
        assert_eq!(
            p.ed25519_sig.len(),
            64,
            "I3535: the statement's Ed25519 half"
        );
        assert_eq!(p.ml_dsa_65_sig.len(), 3309, "I3535: its ML-DSA-65 half");
        assert_eq!(p.trace_id, ev.trace_id, "I3535");
        assert_eq!(
            p.conformity_payload,
            serde_json::json!({"score": 250_000}),
            "I3535: a real is a fixed-scale integer, never text"
        );
    }

    // I3536 — a declared type confers nothing.
    let rogue = "p8-rogue-detector";
    e2::put_key(a, rogue, &["lenscore_detector"]).await;
    let rogue_ev = event(&e2::kid(rogue));
    let e = put_statement(a, &sign(rogue, &rogue_ev), None, INGEST_TIER)
        .await
        .expect_err("I3536: a self-declared detector is refused");
    assert!(
        matches!(
            e,
            crate::federation::Error::ReservedPrefixEmitterMismatch { .. }
        ),
        "I3536: {e:?}"
    );
    assert!(
        projected(a, &rogue_ev).await.is_none(),
        "I3536: nothing projected"
    );

    // I3537 — the earlier-form door, shut.
    let mut earlier = event(&e2::kid(det));
    earlier.ed25519_sig = vec![1u8; 64];
    earlier.ml_dsa_65_sig = vec![2u8; 3309];
    let refused =
        super::door::with_earlier_form_doors_shut(a.put_detection_event(earlier.clone())).await;
    assert!(
        matches!(&refused, Err(e) if e.to_string().contains("earlier_form_object")),
        "I3537: {refused:?}"
    );
    assert!(
        projected(a, &earlier).await.is_none(),
        "I3537: nothing written"
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
    let dsn = crate::test_pg::isolated_dsn()?;
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Some(b)
}

#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread")]
async fn i3535_detection_statement_sqlite() {
    let (a, b) = (sqlite().await, sqlite().await);
    Box::pin(body(&a, &b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn i3535_detection_statement_postgres() {
    let (Some(a), Some(b)) = (postgres().await, postgres().await) else {
        eprintln!("i3535 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
        return;
    };
    Box::pin(body(&a, &b)).await;
    eprintln!("i3535 postgres: RAN");
}
