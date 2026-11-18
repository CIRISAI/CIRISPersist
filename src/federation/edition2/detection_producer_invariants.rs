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
//!   composite halves (64 / 3309 bytes); a body real is a CBOR tag-4
//!   decimal fraction (`0.25` → `4([-2, 25])`, P1's `body_number`). Node B, with the same conferral,
//!   admits the same bytes and projects the same detection.
//! - **I3539** — the detection KEEPS its trace as evidence
//!   (`evidence_refs` = `[[-16, trace_evidence_ref(trace)]]`): a purge
//!   selecting the trace (`PurgeSelection::ByActor` of its signer) reaches
//!   the detection row (in the selection or its withheld list), the Art. 17
//!   route.
//! - **I3549** — the detection names the scored agent's canonical subject
//!   (`subject_key_ids`): with no trace held, the DSAR door's by-subject
//!   reach finds it, and with the producer's withdraws the plan cites it.
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
    sign_naming(seed, ev, None)
}

fn sign_naming(seed: &str, ev: &DetectionEvent, subject: Option<&str>) -> Vec<u8> {
    let (sub, family, payload) =
        detection_statement_parts(ev, subject).expect("the detection's parts");
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
    B: FederationDirectory
        + DerivedSchema
        + crate::federation::steward_purge_invariants::bodies::Seams
        + crate::federation::attestation_admit::AttestationStore
        + Sync,
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
    // I3535 — a non-integral body real is a CBOR tag-4 decimal fraction
    // (CC ruling, P1's `body_number`): 0.25 → 4([-2, 25]); never a float,
    // never text.
    {
        use ciris_verify_core::cde::{encode, Value};
        let (_, payload) = super::liveness::statement_parts(&st).expect("decodes");
        let score = payload
            .get_text(crate::derived::detection_row::BODY_MEMBER)
            .and_then(|b| b.get_text("conformity_payload"))
            .and_then(|c| c.get_text("score"))
            .expect("I3535: the body's score");
        assert_eq!(
            encode(score),
            encode(&Value::Tag(
                4,
                Box::new(Value::Array(vec![Value::int(-2), Value::int(25)]))
            )),
            "I3535: 0.25 is 4([-2, 25])"
        );
    }
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
    }

    // I3539 — the trace is the detection's evidence: a purge selecting the
    // trace (by its signer) reaches the detection row through its
    // `evidence_refs` digest (`detection_row::trace_evidence_ref`).
    let tracer = "p8-tracer";
    let tracer_id = e2::put_key(a, tracer, &["agent"]).await;
    let traced = event(&e2::kid(det));
    crate::federation::steward_purge_invariants::bodies::seed_trace(
        a,
        &traced.trace_id,
        &tracer_id,
        "p8-model",
    )
    .await;
    let traced_st = sign(det, &traced);
    put_statement(a, &traced_st, None, INGEST_TIER)
        .await
        .expect("I3539: the traced detection is admitted");
    let traced_rid = super::names::RowId::of_statement(&traced_st)
        .expect("a row")
        .hex();
    let resolved = crate::federation::steward_purge::resolve_selection(
        a,
        &crate::federation::steward_purge::PurgeSelection::ByActor {
            key_id: tracer_id.clone(),
        },
    )
    .await
    .expect("I3539: resolved");
    assert!(
        format!("{resolved:?}").contains(&traced_rid),
        "I3539: the purge of the trace reaches its detection row: {resolved:?}"
    );

    // I3549 — the detection NAMES the scored agent's canonical subject
    // (`subject_key_ids`), so a DSAR erasure by subject reaches it after its
    // trace is gone: no trace is held for this agent, and the door's
    // by-agent reach (`detection_row_ids_for_agent`, its `attestation_subjects`
    // arm) still finds the row; with the producer's withdraws held, the
    // erasure plan cites it.
    {
        let agent = format!("p8-agent-{}", uuid::Uuid::new_v4().simple());
        let subject = crate::federation::subject_erasure::agent_subject(&agent).expect("subject");
        let named = event(&e2::kid(det));
        let named_st = sign_naming(det, &named, Some(&subject));
        put_statement(a, &named_st, None, INGEST_TIER)
            .await
            .expect("I3549: the detection naming its subject is admitted");
        let named_rid = super::names::RowId::of_statement(&named_st)
            .expect("a row")
            .hex();
        let row = a.get_attestation(&named_rid).await.unwrap().expect("held");
        assert_eq!(row.subject_key_ids, vec![subject.clone()], "I3549: named");
        // No trace is held for this detection: the trace-join arm of the
        // door's reach can find nothing.
        assert!(
            a.trace_agent_id_hash(&named.trace_id)
                .await
                .expect("trace lookup")
                .is_none(),
            "I3549: the trace is gone"
        );
        // The key-scoped reach runs ONLY the trace join (the subject arm is
        // the full erasure's): it does not reach the row ...
        let by_trace = a
            .detection_row_ids_for_agent(&agent, Some(&e2::kid(det)))
            .await
            .expect("I3549: the key-scoped reach");
        assert!(
            !by_trace.contains(&named_rid),
            "I3549: no trace, so the trace join reaches nothing: {by_trace:?}"
        );
        // ... and the full erasure's by-SUBJECT arm (`attestation_subjects`
        // WHERE subject_key_id = agent_subject, projected from the edition-2
        // row's `subject_key_ids` at the put) does.
        let reached = a
            .detection_row_ids_for_agent(&agent, None)
            .await
            .expect("I3549: the full reach");
        assert!(
            reached.contains(&named_rid),
            "I3549: erasure by subject reaches the detection with no trace held: {reached:?}"
        );
        let (w_sub, w_family, w_payload) =
            crate::federation::subject_erasure::withdraws_statement_parts(
                &row,
                &e2::kid(det),
                e2::ms(crate::host::clock::now()),
            )
            .expect("parts");
        let w = ciris_verify_core::edition2::sign_row_statement(
            &e2::signing_key(det),
            &e2::kid(det),
            &w_sub,
            "withdraws",
            &w_family,
            &w_payload,
            vec![],
        )
        .expect("signed");
        put_statement(a, &w, None, INGEST_TIER)
            .await
            .expect("I3549: the producer's withdraws");
        let plan = crate::federation::subject_erasure::plan_store_erasure(
            a,
            &agent,
            None,
            crate::host::clock::now(),
        )
        .await
        .expect("I3549: the erasure plan");
        assert!(
            plan.citations.iter().any(|c| c.target == named_rid),
            "I3549: the erasure cites the detection by subject"
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
