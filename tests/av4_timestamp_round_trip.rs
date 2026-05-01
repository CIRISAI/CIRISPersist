//! THREAT_MODEL.md AV-4 regression — verify on real Python-isoformat
//! timestamps, including the zero-microsecond shape that broke the
//! lens production cutover at v0.1.x ≤ 0.1.7.
//!
//! Pre-v0.1.8: persist parsed wire timestamps into `chrono::DateTime`
//! and re-formatted them via `format!("%Y-%m-%dT%H:%M:%S%.6f%:z")`,
//! which always emitted six microsecond digits. Python's
//! `datetime.isoformat()` drops the microsecond fraction entirely
//! when microseconds == 0. Result: `2026-04-30T00:15:53+00:00`
//! (Python wire bytes) became `2026-04-30T00:15:53.000000+00:00`
//! (persist canonicalization), the canonical bytes diverged, and
//! `verify_strict` rejected every batch matching the shape.
//!
//! v0.1.8: `WireDateTime` preserves wire bytes. This test
//! constructs a JSON envelope with zero-microsecond timestamps,
//! signs it byte-correctly (over the wire-string canonical input),
//! pushes it through the ingest pipeline, and asserts verify
//! passes.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner};
use ed25519_dalek::{Signer as _, SigningKey};

use ciris_persist::ingest::IngestPipeline;
use ciris_persist::scrub::NullScrubber;
use ciris_persist::store::MemoryBackend;
use ciris_persist::verify::canonical::Canonicalizer;
use ciris_persist::verify::PythonJsonDumpsCanonicalizer;

fn test_signer() -> Box<dyn HardwareSigner> {
    let mut s = Ed25519SoftwareSigner::new("av4-signer");
    s.import_key(&[0x42u8; 32]).expect("import_key");
    Box::new(s) as Box<dyn HardwareSigner>
}

/// Build a signed CompleteTrace JSON envelope using the *exact*
/// timestamp wire shape the agent ships. Critically: sort keys,
/// ensure_ascii, no-whitespace separators (Python json.dumps
/// defaults), and use the wire timestamps verbatim as the
/// canonical input — same way the Python agent builds its
/// signature input per TRACE_WIRE_FORMAT.md §8.
fn build_signed_trace_with_wire_timestamps(
    sk: &SigningKey,
    key_id: &str,
    started_at: &str,
    completed_at: &str,
    component_timestamp: &str,
) -> Vec<u8> {
    // Build the canonical payload as a serde_json::Value with
    // *string* timestamps — the same way agent code does, and the
    // same way persist's canonical_payload_value now does.
    let canonical = serde_json::json!({
        "trace_id": "trace-av4",
        "thought_id": "th-av4",
        "task_id": null,
        "agent_id_hash": "deadbeef",
        "started_at": started_at,
        "completed_at": completed_at,
        "trace_level": "generic",
        "trace_schema_version": "2.7.0",
        "components": [{
            "component_type": "observation",
            "data": { "attempt_index": 0 },
            "event_type": "THOUGHT_START",
            "timestamp": component_timestamp,
        }],
    });

    // Canonicalize and sign — this is what the agent does on its
    // side to produce the signature.
    let bytes = PythonJsonDumpsCanonicalizer
        .canonicalize_value(&canonical)
        .unwrap();
    let sig = sk.sign(&bytes);

    // Build the wire-format trace + envelope. The trace JSON needs
    // signature + signature_key_id added; fields are in any order
    // because deserialization is order-agnostic. (The CANONICAL
    // bytes the agent signed are the ones above; that's what
    // verify must reproduce.)
    let trace_json = serde_json::json!({
        "trace_id": "trace-av4",
        "thought_id": "th-av4",
        "agent_id_hash": "deadbeef",
        "started_at": started_at,
        "completed_at": completed_at,
        "trace_level": "generic",
        "trace_schema_version": "2.7.0",
        "components": [{
            "component_type": "observation",
            "data": { "attempt_index": 0 },
            "event_type": "THOUGHT_START",
            "timestamp": component_timestamp,
        }],
        "signature": BASE64.encode(sig.to_bytes()),
        "signature_key_id": key_id,
    });

    let envelope = serde_json::json!({
        "events": [{ "event_type": "complete_trace", "trace_level": "generic", "trace": trace_json }],
        "batch_timestamp": "2026-05-01T00:00:00Z",
        "consent_timestamp": "2025-01-01T00:00:00Z",
        "trace_level": "generic",
        "trace_schema_version": "2.7.0",
    });
    envelope.to_string().into_bytes()
}

async fn run(bytes: &[u8], key_id: &str, sk: &SigningKey) -> Result<usize, String> {
    let backend = MemoryBackend::new();
    backend.add_public_key(key_id, sk.verifying_key());
    let signer = test_signer();
    let pipeline = IngestPipeline {
        backend: &backend,
        canonicalizer: &PythonJsonDumpsCanonicalizer,
        scrubber: &NullScrubber,
        signer: &*signer,
        signer_key_id: "av4-signer",
    };
    pipeline
        .receive_and_persist(bytes)
        .await
        .map(|s| s.trace_events_inserted)
        .map_err(|e| format!("kind={} display={e}", e.kind()))
}

/// **The production-bug shape.** Python `datetime.isoformat()`
/// drops the microsecond fraction entirely when microseconds is 0.
/// Pre-v0.1.8 persist re-formatted to include `.000000` and
/// signature verify failed. This test confirms v0.1.8 round-trips.
#[tokio::test]
async fn av4_zero_microseconds_no_fraction_verifies() {
    let sk = SigningKey::from_bytes(&[0xAA; 32]);
    let bytes = build_signed_trace_with_wire_timestamps(
        &sk,
        "agent-av4",
        // No `.ffffff` — the production-bug shape. Pre-v0.1.8
        // persist re-formatted to "...53.000000+00:00" and verify
        // mismatched.
        "2026-04-30T00:15:53+00:00",
        "2026-04-30T00:16:12+00:00",
        "2026-04-30T00:15:53+00:00",
    );
    let inserted = run(&bytes, "agent-av4", &sk)
        .await
        .expect("AV-4 (zero micros) MUST verify post-v0.1.8");
    assert_eq!(inserted, 1, "one component → one row");
}

/// Microsecond-precision shape (Python isoformat with non-zero
/// microseconds). Worked pre-v0.1.8 too because the re-format
/// happened to produce identical bytes for this input shape, but
/// confirm v0.1.8 hasn't regressed it.
#[tokio::test]
async fn av4_six_digit_microseconds_verifies() {
    let sk = SigningKey::from_bytes(&[0xBB; 32]);
    let bytes = build_signed_trace_with_wire_timestamps(
        &sk,
        "agent-av4",
        "2026-04-30T00:15:53.123456+00:00",
        "2026-04-30T00:16:12.789012+00:00",
        "2026-04-30T00:15:53.123456+00:00",
    );
    let inserted = run(&bytes, "agent-av4", &sk)
        .await
        .expect("six-digit microseconds must verify");
    assert_eq!(inserted, 1);
}

/// Z-suffix form (some agent paths emit this — if/when we encounter
/// it we want it to round-trip too).
#[tokio::test]
async fn av4_z_suffix_form_verifies() {
    let sk = SigningKey::from_bytes(&[0xCC; 32]);
    let bytes = build_signed_trace_with_wire_timestamps(
        &sk,
        "agent-av4",
        "2026-04-30T00:15:53.123456Z",
        "2026-04-30T00:16:12.789012Z",
        "2026-04-30T00:15:53.123456Z",
    );
    let inserted = run(&bytes, "agent-av4", &sk)
        .await
        .expect("Z-suffix form must verify");
    assert_eq!(inserted, 1);
}

/// Millisecond precision (3-digit fraction). Python's isoformat
/// emits this when sub-millisecond precision is dropped (e.g. via
/// some clock sources or explicit truncation).
#[tokio::test]
async fn av4_three_digit_milliseconds_verifies() {
    let sk = SigningKey::from_bytes(&[0xDD; 32]);
    let bytes = build_signed_trace_with_wire_timestamps(
        &sk,
        "agent-av4",
        "2026-04-30T00:15:53.123+00:00",
        "2026-04-30T00:16:12.789+00:00",
        "2026-04-30T00:15:53.123+00:00",
    );
    let inserted = run(&bytes, "agent-av4", &sk)
        .await
        .expect("millisecond-precision form must verify");
    assert_eq!(inserted, 1);
}

/// Tampering still fails — confirm the verify gate didn't widen
/// while we were closing AV-4.
#[tokio::test]
async fn av4_tampered_timestamp_still_rejected() {
    let sk = SigningKey::from_bytes(&[0xEE; 32]);
    // Sign over one timestamp; corrupt the wire to a different
    // (but valid) timestamp before submitting.
    let bytes = build_signed_trace_with_wire_timestamps(
        &sk,
        "agent-av4",
        "2026-04-30T00:15:53+00:00",
        "2026-04-30T00:16:12+00:00",
        "2026-04-30T00:15:53+00:00",
    );
    // Corrupt the bytes: change started_at to a different valid
    // wire timestamp. Since we're rewriting JSON, do this by
    // round-tripping through Value.
    let mut env: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    env["events"][0]["trace"]["started_at"] =
        serde_json::Value::String("2026-04-30T00:15:54+00:00".into());
    let tampered = serde_json::to_vec(&env).unwrap();

    let err = run(&tampered, "agent-av4", &sk).await.unwrap_err();
    assert!(
        err.contains("verify_signature_mismatch") || err.contains("verify_"),
        "tampered timestamp must reject — got: {err}"
    );
}
