//! Shared fixtures for bench harnesses.
//!
//! v0.1.7 — used by `benches/{ingest_pipeline,canonicalize,sign,
//! dedup_key,queue}.rs`. Same shape as `tests/qa_harness.rs` but
//! pulled out so each bench binary can include via `#[path]` without
//! pulling the full QA harness module.

#![allow(dead_code)]

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner};
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

/// Build a signed CompleteTrace + serialize as a batch envelope.
/// Same shape as `tests/qa_harness.rs::build_signed_batch`.
pub fn build_signed_batch(
    sk: &SigningKey,
    key_id: &str,
    agent_id_hash: &str,
    trace_id: &str,
    thought_id: &str,
    n_components: usize,
) -> Vec<u8> {
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

    let mut trace = CompleteTrace {
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
    };
    let payload = canonical_payload_value(&trace);
    let bytes = PythonJsonDumpsCanonicalizer
        .canonicalize_value(&payload)
        .unwrap();
    trace.signature = BASE64.encode(sk.sign(&bytes).to_bytes());

    let trace_json = serde_json::to_value(&trace).unwrap();
    let envelope = serde_json::json!({
        "events": [{ "event_type": "complete_trace", "trace_level": "generic", "trace": trace_json }],
        "batch_timestamp": "2026-05-01T00:00:00Z",
        "consent_timestamp": "2025-01-01T00:00:00Z",
        "trace_level": "generic",
        "trace_schema_version": "2.7.0",
    });
    envelope.to_string().into_bytes()
}
