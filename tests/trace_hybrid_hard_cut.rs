//! v7.2.0 (CIRISPersist#225) — the trace-tier hybrid hard cut, proven
//! on BOTH durable backends (Postgres + SQLite).
//!
//! CEG 1.0-RC7 §10.1.5.1.1 + the hard cut on CIRISVerify#75: the
//! producer's per-trace envelope signature must carry + verify
//! ML-DSA-65 (HNDL forge-later against the durable, replicated,
//! kept-for-posterity trace corpus). The MemoryBackend mirror of these
//! assertions lives in `src/ingest.rs` (the four lib proof tests); this
//! file proves the same cut survives the V083 schema + the SQL
//! round-trip on the two backends that actually persist.
//!
//! Project rule (NO pg/sqlite asymmetry): the schema + gate + verify
//! path are identical on both backends; only the SQL dialect differs.
//! Each backend runs the SAME four assertions via a shared body.
//!
//! - Postgres is gated on `CIRIS_PERSIST_TEST_PG_URL` (plain
//!   `postgres:16`), self-isolating via uuid-suffixed ids.
//! - SQLite uses an in-memory database.

#![cfg(all(feature = "postgres", feature = "sqlite"))]

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ed25519_dalek::{Signer as _, SigningKey};

use ciris_persist::federation::{FederationDirectory, KeyRecord, SignedKeyRecord};
use ciris_persist::ingest::{IngestError, IngestPipeline, VerifyMode};
use ciris_persist::schema::{
    CompleteTrace, ComponentType, ReasoningEventType, TraceComponent, TraceLevel,
};
use ciris_persist::scrub::NullScrubber;
use ciris_persist::store::Backend;
use ciris_persist::verify::ed25519::canonical_bytes_for_trace;
use ciris_persist::verify::Error as VerifyError;
use ciris_persist::verify::{
    verify_hybrid, HybridPolicy, PythonJsonDumpsCanonicalizer, VerifyOutcome,
};

/// The producer's deterministic Ed25519 key + the (key_id, pubkey_b64)
/// the caller must register before running the body.
fn producer_key(suffix: &str) -> (SigningKey, String, String) {
    let ed_sk = SigningKey::from_bytes(&[0x42; 32]);
    let ed_pk_b64 = BASE64.encode(ed_sk.verifying_key().to_bytes());
    (ed_sk, format!("hard-cut-agent-key:{suffix}"), ed_pk_b64)
}

/// Register the producer's Ed25519 pubkey in `federation_keys` (the
/// directory `Backend::lookup_public_key` — the trace verify path —
/// reads). `put_public_key` is on `FederationDirectory`, implemented by
/// all backends, so this stays dialect-agnostic.
async fn register_producer<D: FederationDirectory>(dir: &D, key_id: &str, ed_pk_b64: &str) {
    dir.put_public_key(SignedKeyRecord {
        record: KeyRecord {
            key_id: key_id.to_owned(),
            pubkey_ed25519_base64: ed_pk_b64.to_owned(),
            pubkey_ml_dsa_65_base64: None,
            algorithm: ciris_persist::federation::types::algorithm::HYBRID.to_owned(),
            identity_type: ciris_persist::federation::types::identity_type::AGENT.to_owned(),
            identity_ref: key_id.to_owned(),
            valid_from: "2026-01-01T00:00:00Z".parse().unwrap(),
            valid_until: None,
            registration_envelope: serde_json::json!({ "key_id": key_id }),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.to_owned(),
            scrub_timestamp: "2026-01-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
        },
    })
    .await
    .expect("register producer key in federation_keys");
}

/// Deterministic scrub signer (the unconditional per-row scrub key).
fn scrub_signer() -> Box<dyn HardwareSigner> {
    let mut s = Ed25519SoftwareSigner::new("hard-cut-scrub-signer");
    s.import_key(&[0xA5u8; 32]).expect("import_key");
    Box::new(s) as Box<dyn HardwareSigner>
}

/// Build a single-component CompleteTrace with the given ids + schema
/// version + cohort, classical-only (no PQC half yet). `agent_id_hash`
/// is the per-run suffix so PG read-backs self-isolate.
fn base_trace(
    trace_id: &str,
    key_id: &str,
    schema_version: &str,
    agent_hash: &str,
) -> CompleteTrace {
    let mut data = serde_json::Map::new();
    data.insert("attempt_index".into(), 0.into());
    CompleteTrace {
        trace_id: trace_id.to_owned(),
        thought_id: "th-1".into(),
        task_id: None,
        agent_id_hash: agent_hash.to_owned(),
        started_at: "2026-04-30T00:15:53.123456Z".parse().unwrap(),
        completed_at: "2026-04-30T00:16:12.789012Z".parse().unwrap(),
        trace_level: TraceLevel::Generic,
        trace_schema_version: serde_json::from_str(&format!("\"{schema_version}\"")).unwrap(),
        components: vec![TraceComponent {
            component_type: ComponentType::Observation,
            event_type: ReasoningEventType::ThoughtStart,
            timestamp: "2026-04-30T00:15:53.123Z".parse().unwrap(),
            data,
            agent_id_hash: None,
        }],
        deployment_profile: None,
        cohort_scope: "federation".into(),
        cohort_target_id: None,
        signature: String::new(),
        signature_key_id: key_id.to_owned(),
        signature_ml_dsa_65: None,
        pubkey_ml_dsa_65: None,
        pqc_key_id: None,
    }
}

/// Ed25519-only sign (the classical / legacy provenance shape).
fn classical_sign(trace: &mut CompleteTrace, ed_sk: &SigningKey) {
    let canonical = canonical_bytes_for_trace(trace, &PythonJsonDumpsCanonicalizer).unwrap();
    trace.signature = BASE64.encode(ed_sk.sign(&canonical).to_bytes());
}

/// Hybrid sign: Ed25519 over canonical + ML-DSA-65 over the bound input
/// `canonical || classical_sig`, plus the asserted ML-DSA-65 pubkey.
async fn hybrid_sign(trace: &mut CompleteTrace, ed_sk: &SigningKey) {
    let canonical = canonical_bytes_for_trace(trace, &PythonJsonDumpsCanonicalizer).unwrap();
    let ed_sig = ed_sk.sign(&canonical).to_bytes();
    let mldsa = MlDsa65SoftwareSigner::from_seed_bytes(&[0x77; 32], "hard-cut-mldsa").unwrap();
    let mut bound = Vec::with_capacity(canonical.len() + ed_sig.len());
    bound.extend_from_slice(&canonical);
    bound.extend_from_slice(&ed_sig);
    let pqc_sig = mldsa.sign(&bound).await.unwrap();
    let pqc_pk = mldsa.public_key().await.unwrap();
    trace.signature = BASE64.encode(ed_sig);
    trace.signature_ml_dsa_65 = Some(BASE64.encode(&pqc_sig));
    trace.pubkey_ml_dsa_65 = Some(BASE64.encode(&pqc_pk));
    trace.pqc_key_id = Some("hard-cut-mldsa".to_owned());
}

fn envelope_bytes(trace: &CompleteTrace, schema_version: &str) -> Vec<u8> {
    serde_json::json!({
        "events": [{
            "event_type": "complete_trace",
            "trace_level": "generic",
            "trace": serde_json::to_value(trace).unwrap(),
        }],
        "batch_timestamp": "2026-04-30T15:00:00+00:00",
        "consent_timestamp": "2025-01-01T00:00:00Z",
        "trace_level": "generic",
        "trace_schema_version": schema_version,
    })
    .to_string()
    .into_bytes()
}

/// The shared body: runs assertions (a)-(e) against a migrated backend.
/// `suffix` keeps PG ids self-isolating across concurrent runs.
async fn run_hard_cut_assertions<B: Backend>(backend: &B, suffix: &str) {
    let (ed_sk, key_id, ed_pk_b64) = producer_key(suffix);
    // Per-run agent_id_hash so PG read-backs (filtered on agent_id_hash)
    // never see another concurrent run's rows.
    let agent_hash = format!("ah-{suffix}");
    // The producer's Ed25519 key was registered by the caller (the
    // concrete `register_accord_public_key` is inherent per backend, not
    // on the `Backend` trait, so it can't be called through `B`).

    let scrub = scrub_signer();
    let pipeline = IngestPipeline {
        backend,
        canonicalizer: &PythonJsonDumpsCanonicalizer,
        scrubber: &NullScrubber,
        signer: &*scrub,
        signer_key_id: "hard-cut-scrub-signer",
    };

    // (a) Full-mode VALID hybrid trace → ADMITTED, both halves stored.
    let mut hyb = base_trace(
        &format!("trace-hyb-{suffix}"),
        &key_id,
        "2.7.0",
        &agent_hash,
    );
    hybrid_sign(&mut hyb, &ed_sk).await;
    let summary = pipeline
        .receive_and_persist(&envelope_bytes(&hyb, "2.7.0"))
        .await
        .expect("(a) valid hybrid trace MUST be admitted");
    assert_eq!(
        summary.signatures_verified, 1,
        "(a) persist verified hybrid"
    );
    assert_eq!(
        summary.trace_events_inserted, 1,
        "(a) one component → one row"
    );

    // (d)+(e) Read the stored row back and verify BOTH halves on read.
    let page = backend
        .fetch_trace_events_page(0, 100, Some(agent_hash.as_str()))
        .await
        .expect("(d) read back");
    let stored = page
        .iter()
        .find(|(_, r)| r.trace_id == hyb.trace_id)
        .map(|(_, r)| r)
        .expect("(d) stored hybrid row present");
    assert!(
        stored.signature_ml_dsa_65.is_some(),
        "(d) ML-DSA-65 half stored on {} backend",
        suffix
    );
    assert!(
        stored.pubkey_ml_dsa_65.is_some(),
        "(d) producer PQC pubkey stored"
    );
    assert_eq!(stored.pqc_key_id.as_deref(), Some("hard-cut-mldsa"));
    let canonical = canonical_bytes_for_trace(&hyb, &PythonJsonDumpsCanonicalizer).unwrap();
    let outcome = verify_hybrid(
        &canonical,
        &stored.signature,
        stored.signature_ml_dsa_65.as_deref(),
        &ed_pk_b64,
        stored.pubkey_ml_dsa_65.as_deref(),
        HybridPolicy::Strict,
        None,
    )
    .expect("(e) the STORED hybrid signature MUST verify both halves on read");
    assert_eq!(outcome, VerifyOutcome::HybridVerified);

    // (b) Full-mode CLASSICAL-ONLY trace → REJECTED at admission.
    let mut classical = base_trace(
        &format!("trace-classical-{suffix}"),
        &key_id,
        "2.7.0",
        &agent_hash,
    );
    classical_sign(&mut classical, &ed_sk);
    let err = pipeline
        .receive_and_persist(&envelope_bytes(&classical, "2.7.0"))
        .await
        .expect_err("(b) Full-mode classical-only MUST be rejected (the hard cut)");
    assert!(
        matches!(err, IngestError::Verify(VerifyError::HybridRequired)),
        "(b) classical-only reject MUST be HybridRequired, got {err:?}"
    );
    // Verify-before-mutation: the rejected classical-only trace wrote no
    // row (its trace_id never lands).
    let page2 = backend
        .fetch_trace_events_page(0, 1000, Some(agent_hash.as_str()))
        .await
        .unwrap();
    assert!(
        !page2.iter().any(|(_, r)| r.trace_id == classical.trace_id),
        "(b) rejected classical-only trace MUST write zero rows"
    );

    // (c) Legacy `2.7.legacy` classical-only import under
    // TrustPreVerified → ADMITTED (the carve-out).
    let mut legacy = base_trace(
        &format!("trace-legacy-{suffix}"),
        &key_id,
        "2.7.legacy",
        &agent_hash,
    );
    classical_sign(&mut legacy, &ed_sk);
    let summary_legacy = pipeline
        .receive_and_persist_with(
            &envelope_bytes(&legacy, "2.7.legacy"),
            VerifyMode::TrustPreVerified,
        )
        .await
        .expect("(c) legacy pre-verified classical-only import MUST be admitted");
    assert_eq!(
        summary_legacy.trace_events_inserted, 1,
        "(c) legacy import landed"
    );
    let page3 = backend
        .fetch_trace_events_page(0, 1000, Some(agent_hash.as_str()))
        .await
        .unwrap();
    let legacy_row = page3
        .iter()
        .find(|(_, r)| r.trace_id == legacy.trace_id)
        .map(|(_, r)| r)
        .expect("(c) legacy row present");
    assert!(
        legacy_row.signature_ml_dsa_65.is_none(),
        "(c) legacy carve-out row is classical-only (no PQC half)"
    );
}

#[tokio::test]
async fn sqlite_trace_tier_hybrid_hard_cut() {
    let backend = ciris_persist::store::SqliteBackend::open_in_memory()
        .await
        .expect("open sqlite");
    backend
        .run_migrations()
        .await
        .expect("sqlite migrations (incl. V083)");
    // Register the producer Ed25519 key (inherent method, per backend).
    let (_sk, key_id, ed_pk_b64) = producer_key("sqlite");
    register_producer(&backend, &key_id, &ed_pk_b64).await;
    run_hard_cut_assertions(&backend, "sqlite").await;
}

#[tokio::test]
async fn postgres_trace_tier_hybrid_hard_cut() {
    let Some(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok() else {
        eprintln!("postgres_trace_tier_hybrid_hard_cut skipped: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let backend = ciris_persist::store::PostgresBackend::connect(&dsn)
        .await
        .expect("connect postgres");
    backend
        .run_migrations()
        .await
        .expect("pg migrations (incl. V083)");
    // uuid-suffixed ids so concurrent / repeated PG runs self-isolate.
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let (_sk, key_id, ed_pk_b64) = producer_key(&suffix);
    register_producer(&backend, &key_id, &ed_pk_b64).await;
    run_hard_cut_assertions(&backend, &suffix).await;
}
