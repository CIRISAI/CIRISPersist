//! Shared fixtures for bench harnesses.
//!
//! v0.1.7 — used by `benches/{ingest_pipeline,canonicalize,sign,
//! dedup_key,queue}.rs`. Same shape as `tests/qa_harness.rs` but
//! pulled out so each bench binary can include via `#[path]` without
//! pulling the full QA harness module.

#![allow(dead_code)]

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ed25519_dalek::{Signer as _, SigningKey};

use ciris_persist::schema::{
    CompleteTrace, ComponentType, ReasoningEventType, SchemaVersion, TraceComponent, TraceLevel,
};
use ciris_persist::verify::canonical::Canonicalizer;
use ciris_persist::verify::{ed25519::canonical_payload_value, PythonJsonDumpsCanonicalizer};

pub fn test_signer() -> Box<dyn HardwareSigner> {
    let mut s = Ed25519SoftwareSigner::new("bench-signer");
    s.import_key(&[0x42u8; 32]).expect("import_key");
    Box::new(s) as Box<dyn HardwareSigner>
}

pub fn make_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// Build an unsigned CompleteTrace fixture (n components, deterministic
/// shape). Shared by the classical + hybrid batch builders so the two
/// can't drift.
fn build_unsigned_trace(
    key_id: &str,
    agent_id_hash: &str,
    trace_id: &str,
    thought_id: &str,
    n_components: usize,
) -> CompleteTrace {
    let mut components = Vec::with_capacity(n_components);
    for i in 0..n_components {
        let mut data = serde_json::Map::new();
        data.insert("attempt_index".into(), serde_json::json!(i));
        data.insert("seq".into(), serde_json::json!(i));
        data.insert(
            "rationale".into(),
            serde_json::json!(format!("step {i} reasoning text fragment")),
        );
        components.push(TraceComponent {
            component_type: ComponentType::Conscience,
            event_type: ReasoningEventType::ConscienceResult,
            timestamp: format!("2026-05-01T00:{:02}:{:02}Z", i / 60, i % 60)
                .parse()
                .unwrap(),
            data,
            agent_id_hash: None,
        });
    }

    CompleteTrace {
        trace_id: trace_id.into(),
        thought_id: thought_id.into(),
        task_id: Some("task-bench".into()),
        agent_id_hash: agent_id_hash.into(),
        started_at: "2026-05-01T00:00:00Z".parse().unwrap(),
        completed_at: "2026-05-01T00:01:00Z".parse().unwrap(),
        trace_level: TraceLevel::Generic,
        trace_schema_version: SchemaVersion::parse("2.7.0").unwrap(),
        components,
        deployment_profile: None,
        signature: String::new(),
        signature_key_id: key_id.into(),
        cohort_scope: "federation".into(),
        cohort_target_id: None,
        signature_ml_dsa_65: None,
        pubkey_ml_dsa_65: None,
        pqc_key_id: None,
    }
}

/// Wrap a (signed) trace as a single-event batch envelope.
fn envelope_bytes(trace: &CompleteTrace) -> Vec<u8> {
    let trace_json = serde_json::to_value(trace).unwrap();
    serde_json::json!({
        "events": [{ "event_type": "complete_trace", "trace_level": "generic", "trace": trace_json }],
        "batch_timestamp": "2026-05-01T00:00:00Z",
        "consent_timestamp": "2025-01-01T00:00:00Z",
        "trace_level": "generic",
        "trace_schema_version": "2.7.0",
    })
    .to_string()
    .into_bytes()
}

/// Build a classical (Ed25519-only) signed CompleteTrace + serialize as
/// a batch envelope. For benches that DON'T run the Full-mode ingest
/// gate (dedup-key extraction, queue enqueue) — the per-trace hybrid
/// hard cut (#225) is not exercised on these paths.
/// Same shape as `tests/qa_harness.rs::build_signed_batch`.
pub fn build_signed_batch(
    sk: &SigningKey,
    key_id: &str,
    agent_id_hash: &str,
    trace_id: &str,
    thought_id: &str,
    n_components: usize,
) -> Vec<u8> {
    let mut trace = build_unsigned_trace(key_id, agent_id_hash, trace_id, thought_id, n_components);
    let payload = canonical_payload_value(&trace);
    let bytes = PythonJsonDumpsCanonicalizer
        .canonicalize_value(&payload)
        .unwrap();
    trace.signature = BASE64.encode(sk.sign(&bytes).to_bytes());
    envelope_bytes(&trace)
}

/// Build a HYBRID (Ed25519 + ML-DSA-65) signed batch — the shape the
/// trace-tier hard cut (#225) requires for `VerifyMode::Full` admission.
/// The PQC half signs the bound input `canonical || ed25519_sig` and the
/// producer's ML-DSA-65 pubkey rides the envelope, mirroring the lib
/// fixture `ingest::tests::hybrid_sign_trace`. Async because the
/// `PqcSigner` API is async; bench call sites drive it via `block_on`.
pub async fn build_signed_batch_hybrid(
    sk: &SigningKey,
    key_id: &str,
    agent_id_hash: &str,
    trace_id: &str,
    thought_id: &str,
    n_components: usize,
) -> Vec<u8> {
    let mut trace = build_unsigned_trace(key_id, agent_id_hash, trace_id, thought_id, n_components);
    let payload = canonical_payload_value(&trace);
    let canonical = PythonJsonDumpsCanonicalizer
        .canonicalize_value(&payload)
        .unwrap();

    // Classical half.
    let ed_sig = sk.sign(&canonical).to_bytes();

    // PQC half over the bound input (canonical || classical_sig).
    let mldsa =
        MlDsa65SoftwareSigner::from_seed_bytes(&[0x77; 32], "bench-mldsa").expect("ml-dsa seed");
    let mut bound = Vec::with_capacity(canonical.len() + ed_sig.len());
    bound.extend_from_slice(&canonical);
    bound.extend_from_slice(&ed_sig);
    let pqc_sig = mldsa.sign(&bound).await.expect("ml-dsa sign");
    let pqc_pk = mldsa.public_key().await.expect("ml-dsa pk");

    trace.signature = BASE64.encode(ed_sig);
    trace.signature_ml_dsa_65 = Some(BASE64.encode(&pqc_sig));
    trace.pubkey_ml_dsa_65 = Some(BASE64.encode(&pqc_pk));
    trace.pqc_key_id = Some("bench-mldsa".to_owned());
    envelope_bytes(&trace)
}
