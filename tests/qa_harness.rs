//! v0.1.3 post-tag QA harness — stress-test the pipeline against
//! the threats the threat model catalogs and confirm the
//! mission-aligned guarantees hold under load.
//!
//! Run: `cargo test --test qa_harness --release -- --test-threads=1 --nocapture`
//!
//! Each scenario is a single `#[tokio::test]` so harness output
//! groups cleanly. Some scenarios stress concurrency and need
//! `--test-threads=1` to avoid noisy interactions; release mode
//! exercises the v0.1.3 hardening profile (panic=abort,
//! overflow-checks=true) the production binary uses.
//!
//! Findings → v0.1.4 fixes.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner};
use ed25519_dalek::{Signer as _, SigningKey};

use ciris_persist::ingest::{IngestError, IngestPipeline};
use ciris_persist::schema::{
    CompleteTrace, ComponentType, ReasoningEventType, SchemaVersion, TraceComponent, TraceLevel,
};
use ciris_persist::scrub::NullScrubber;
use ciris_persist::store::MemoryBackend;
use ciris_persist::verify::canonical::Canonicalizer;
use ciris_persist::verify::{ed25519::canonical_payload_value, PythonJsonDumpsCanonicalizer};

// ─── shared fixtures ───────────────────────────────────────────────

fn test_signer() -> Box<dyn HardwareSigner> {
    let mut s = Ed25519SoftwareSigner::new("qa-harness-signer");
    s.import_key(&[0x42u8; 32]).expect("import_key");
    Box::new(s) as Box<dyn HardwareSigner>
}

/// Mint an agent keypair + register in the backend's accord_public_keys
/// directory so verify_trace passes. Returns (signing_key, key_id).
fn agent_with_registered_key(backend: &MemoryBackend, key_id: &str, seed: u8) -> SigningKey {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    backend.add_public_key(key_id, sk.verifying_key());
    sk
}

/// Build a signed CompleteTrace + serialize as a batch envelope.
fn build_signed_batch(
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
        components.push(TraceComponent {
            component_type: ComponentType::Conscience,
            event_type: ReasoningEventType::ConscienceResult,
            timestamp: format!("2026-05-01T00:{:02}:{:02}Z", i / 60, i % 60)
                .parse()
                .unwrap(),
            data,
        });
    }

    let mut trace = CompleteTrace {
        trace_id: trace_id.into(),
        thought_id: thought_id.into(),
        task_id: Some("task-qa".into()),
        agent_id_hash: agent_id_hash.into(),
        started_at: "2026-05-01T00:00:00Z".parse().unwrap(),
        completed_at: "2026-05-01T00:01:00Z".parse().unwrap(),
        trace_level: TraceLevel::Generic,
        trace_schema_version: SchemaVersion::parse("2.7.0").unwrap(),
        components,
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

// ─── Scenario A: high-volume concurrent agents ─────────────────────

/// THREAT_MODEL.md AV-9 stress: N parallel agents each submit M
/// distinct batches; assert no cross-agent dedup collisions and
/// every persisted row carries a valid scrub envelope.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn high_volume_concurrent_agents() {
    const N_AGENTS: usize = 8;
    const N_BATCHES_PER_AGENT: usize = 16;
    const COMPONENTS_PER_BATCH: usize = 6;

    let backend = Arc::new(MemoryBackend::new());
    let signer = Arc::<dyn HardwareSigner>::from(test_signer());
    let signer_key_id = "qa-harness-signer".to_owned();

    // Register one keypair per simulated agent.
    let mut agents = Vec::new();
    for i in 0..N_AGENTS {
        let key_id = format!("agent-{i:02}");
        let agent_id_hash = format!("hash-{i:02}");
        let sk = agent_with_registered_key(&backend, &key_id, (i + 1) as u8);
        agents.push((key_id, agent_id_hash, sk));
    }

    let start = Instant::now();
    let inserted = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for (a_idx, (key_id, agent_id_hash, sk)) in agents.iter().enumerate() {
        for b in 0..N_BATCHES_PER_AGENT {
            let bytes = build_signed_batch(
                sk,
                key_id,
                agent_id_hash,
                &format!("trace-{a_idx:02}-{b:04}"),
                &format!("th-{a_idx:02}-{b:04}"),
                COMPONENTS_PER_BATCH,
            );
            let backend = backend.clone();
            let signer = signer.clone();
            let signer_key_id = signer_key_id.clone();
            let inserted = inserted.clone();
            tasks.push(tokio::spawn(async move {
                let pipeline = IngestPipeline {
                    backend: &*backend,
                    canonicalizer: &PythonJsonDumpsCanonicalizer,
                    scrubber: &NullScrubber,
                    signer: &*signer,
                    signer_key_id: &signer_key_id,
                };
                let s = pipeline
                    .receive_and_persist(&bytes)
                    .await
                    .expect("happy path");
                inserted.fetch_add(s.trace_events_inserted, Ordering::Relaxed);
            }));
        }
    }
    for t in tasks {
        t.await.unwrap();
    }
    let elapsed = start.elapsed();

    let total = inserted.load(Ordering::Relaxed);
    let expected = N_AGENTS * N_BATCHES_PER_AGENT * COMPONENTS_PER_BATCH;
    assert_eq!(
        total, expected,
        "all rows persisted across concurrent agents"
    );

    // Snapshot: every row populated envelope columns.
    let snap = backend.snapshot_events();
    assert_eq!(snap.len(), expected);
    for row in &snap {
        assert!(row.original_content_hash.is_some());
        assert!(row.scrub_signature.is_some());
        assert_eq!(row.scrub_key_id.as_deref(), Some("qa-harness-signer"));
    }
    println!(
        "scenario A: {N_AGENTS} agents × {N_BATCHES_PER_AGENT} batches × {COMPONENTS_PER_BATCH} components = {total} rows in {elapsed:?}"
    );
}

// ─── Scenario B: AV-5 schema-version flood ─────────────────────────

/// THREAT_MODEL.md AV-5 stress: 10k malformed bodies, assert pipeline
/// rejects each typed without unbounded memory growth (the v0.1.2
/// `Cow<'static, str>` fix should hold).
#[tokio::test]
async fn av5_schema_version_flood() {
    const N: usize = 10_000;
    let backend = MemoryBackend::new();
    let signer = test_signer();

    let pipeline = IngestPipeline {
        backend: &backend,
        canonicalizer: &PythonJsonDumpsCanonicalizer,
        scrubber: &NullScrubber,
        signer: &*signer,
        signer_key_id: "qa-harness-signer",
    };

    for i in 0..N {
        let body = serde_json::json!({
            "events": [],
            "batch_timestamp": "2026-05-01T00:00:00Z",
            "consent_timestamp": "2025-01-01T00:00:00Z",
            "trace_level": "generic",
            "trace_schema_version": format!("99.{i}.0"),
        });
        let err = pipeline
            .receive_and_persist(body.to_string().as_bytes())
            .await
            .expect_err("malformed version must reject");
        assert!(matches!(err, IngestError::Schema(_)));
    }
    // Backend untouched.
    assert!(backend.snapshot_events().is_empty());
    println!("scenario B: {N} malformed schema-version submissions, all rejected, no rows");
}

// ─── Scenario C: AV-6 JSON-bomb depth ──────────────────────────────

/// THREAT_MODEL.md AV-6: 64-deep nested data blob → typed
/// DataTooDeep rejection.
#[tokio::test]
async fn av6_json_bomb_depth() {
    let mut nested = serde_json::Value::Null;
    for _ in 0..64 {
        let mut m = serde_json::Map::new();
        m.insert("a".into(), nested);
        nested = serde_json::Value::Object(m);
    }
    let body = serde_json::json!({
        "events": [{
            "event_type": "complete_trace", "trace_level": "generic",
            "trace": {
                "trace_id": "trace-bomb", "thought_id": "th-bomb",
                "agent_id_hash": "deadbeef",
                "started_at": "2026-05-01T00:00:00Z",
                "completed_at": "2026-05-01T00:01:00Z",
                "trace_level": "generic", "trace_schema_version": "2.7.0",
                "components": [{
                    "component_type": "observation", "event_type": "THOUGHT_START",
                    "timestamp": "2026-05-01T00:00:00Z", "data": nested
                }],
                "signature": "AAAA", "signature_key_id": "k",
            }
        }],
        "batch_timestamp": "2026-05-01T00:00:00Z",
        "consent_timestamp": "2025-01-01T00:00:00Z",
        "trace_level": "generic", "trace_schema_version": "2.7.0",
    });
    let backend = MemoryBackend::new();
    let signer = test_signer();
    let pipeline = IngestPipeline {
        backend: &backend,
        canonicalizer: &PythonJsonDumpsCanonicalizer,
        scrubber: &NullScrubber,
        signer: &*signer,
        signer_key_id: "qa",
    };
    let err = pipeline
        .receive_and_persist(body.to_string().as_bytes())
        .await
        .expect_err("64-deep blob must be rejected");
    match err {
        IngestError::Schema(ciris_persist::schema::Error::DataTooDeep(_)) => {}
        other => panic!("expected DataTooDeep, got {other:?}"),
    }
    println!("scenario C: 64-deep JSON blob rejected with typed DataTooDeep");
}

// ─── Scenario D: AV-9 cross-agent dedup-key collision ──────────────

/// Two agents submit traces with identical
/// `(trace_id, thought_id, event_type, attempt_index, ts)` shape.
/// Pre-v0.1.2 this would have collided; v0.1.2 added agent_id_hash
/// as the dedup-key prefix. Both rows must persist.
#[tokio::test]
async fn av9_cross_agent_dedup() {
    let backend = MemoryBackend::new();
    let signer = test_signer();
    let sk_a = agent_with_registered_key(&backend, "agent-A", 0xAA);
    let sk_b = agent_with_registered_key(&backend, "agent-B", 0xBB);

    let bytes_a = build_signed_batch(&sk_a, "agent-A", "hash-A", "trace-collide", "th-collide", 1);
    let bytes_b = build_signed_batch(
        &sk_b,
        "agent-B",
        "hash-B",
        "trace-collide", // SAME trace_id
        "th-collide",    // SAME thought_id
        1,
    );

    let pipeline = IngestPipeline {
        backend: &backend,
        canonicalizer: &PythonJsonDumpsCanonicalizer,
        scrubber: &NullScrubber,
        signer: &*signer,
        signer_key_id: "qa",
    };
    let s_a = pipeline.receive_and_persist(&bytes_a).await.unwrap();
    let s_b = pipeline.receive_and_persist(&bytes_b).await.unwrap();
    assert_eq!(s_a.trace_events_inserted, 1, "agent A's row persists");
    assert_eq!(
        s_b.trace_events_inserted, 1,
        "agent B's row persists despite same trace_id/thought_id"
    );
    assert_eq!(backend.snapshot_events().len(), 2);
    println!("scenario D: cross-agent dedup — both agents persisted distinct rows");
}

// ─── Scenario E: AV-24 sign-verify round-trip on every row ─────────

/// Every persisted row's scrub_signature ed25519_verifies against
/// the signer's public key + canonical(payload). Tests at scale.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn av24_sign_verify_round_trip_all_rows() {
    const N_BATCHES: usize = 32;
    const COMPONENTS: usize = 8;

    let backend = Arc::new(MemoryBackend::new());
    let signer = Arc::<dyn HardwareSigner>::from(test_signer());
    let signer_key_id = "qa-harness-signer".to_owned();
    let sk = agent_with_registered_key(&backend, "agent-qa", 0x42);

    let mut tasks = Vec::new();
    for b in 0..N_BATCHES {
        let bytes = build_signed_batch(
            &sk,
            "agent-qa",
            "hash-qa",
            &format!("trace-{b:04}"),
            &format!("th-{b:04}"),
            COMPONENTS,
        );
        let backend = backend.clone();
        let signer = signer.clone();
        let signer_key_id = signer_key_id.clone();
        tasks.push(tokio::spawn(async move {
            let pipeline = IngestPipeline {
                backend: &*backend,
                canonicalizer: &PythonJsonDumpsCanonicalizer,
                scrubber: &NullScrubber,
                signer: &*signer,
                signer_key_id: &signer_key_id,
            };
            pipeline.receive_and_persist(&bytes).await.unwrap();
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }

    // Verify each row's scrub_signature against the signer's pubkey.
    let pubkey_bytes = signer.public_key().await.unwrap();
    let pubkey_arr: [u8; 32] = pubkey_bytes.as_slice().try_into().unwrap();
    let pubkey = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_arr).unwrap();

    let snap = backend.snapshot_events();
    assert_eq!(snap.len(), N_BATCHES * COMPONENTS);
    for row in &snap {
        let payload = serde_json::Value::Object(row.payload.clone());
        let canon = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&payload)
            .unwrap();
        let sig_bytes = BASE64
            .decode(row.scrub_signature.as_ref().unwrap())
            .unwrap();
        let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        pubkey
            .verify_strict(&canon, &sig)
            .unwrap_or_else(|_| panic!("scrub_signature must verify on every row"));
    }
    println!(
        "scenario E: {} rows, all scrub_signatures ed25519_verified",
        snap.len()
    );
}

// ─── Scenario F: graceful shutdown drain under load ────────────────

/// AV-19: spawn_persister processes a steady stream, then we drop the
/// producer mid-stream. PersisterHandle.shutdown() drains the queue
/// without losing rows.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn av19_graceful_shutdown_under_load() {
    use ciris_persist::{spawn_persister, Journal, DEFAULT_QUEUE_DEPTH};
    let dir = tempfile::tempdir().unwrap();
    let journal = Arc::new(Journal::open(dir.path().join("j.redb")).unwrap());
    let backend = Arc::new(MemoryBackend::new());
    let sk = agent_with_registered_key(&backend, "agent-shutdown", 0xC0);
    let signer = Arc::<dyn HardwareSigner>::from(test_signer());

    let (handle, persister) = spawn_persister(
        DEFAULT_QUEUE_DEPTH,
        backend.clone(),
        Arc::new(PythonJsonDumpsCanonicalizer),
        Arc::new(NullScrubber),
        journal,
        signer,
        "qa-harness-signer".to_owned(),
    );

    // Submit a stream of batches. Don't await between submits — let
    // the persister catch up async.
    const N: usize = 64;
    for i in 0..N {
        let bytes = build_signed_batch(
            &sk,
            "agent-shutdown",
            "hash-shut",
            &format!("trace-{i:04}"),
            &format!("th-{i:04}"),
            4,
        );
        // Must allow a brief yield — queue is size DEFAULT_QUEUE_DEPTH
        // so this should never block; sanity on the API.
        let _ = handle
            .submit_with_timeout(bytes, Duration::from_secs(2))
            .await;
    }

    // Drop handle → queue close → persister drains.
    drop(handle);
    persister
        .shutdown_with_timeout(Duration::from_secs(15))
        .await
        .unwrap();

    let snap = backend.snapshot_events();
    let expected = N * 4;
    assert_eq!(
        snap.len(),
        expected,
        "all submitted rows landed despite mid-load shutdown"
    );
    println!("scenario F: {N} batches submitted under load, all {expected} rows drained on graceful shutdown");
}

// ─── Scenario G: AV-17 attempt_index out-of-range ──────────────────

/// MAX_ATTEMPT_INDEX bound holds; values above the cap reject typed.
#[tokio::test]
async fn av17_attempt_index_out_of_range() {
    let backend = MemoryBackend::new();
    let signer = test_signer();
    let sk = agent_with_registered_key(&backend, "agent-av17", 0x17);

    // Build a trace with attempt_index = 4_294_967_296 (u32::MAX + 1).
    // Pre-v0.1.3 this would have wrapped to 0 via `as u32`.
    let mut data = serde_json::Map::new();
    data.insert(
        "attempt_index".into(),
        serde_json::Value::Number(serde_json::Number::from(4_294_967_296i64)),
    );
    let component = TraceComponent {
        component_type: ComponentType::Conscience,
        event_type: ReasoningEventType::ConscienceResult,
        timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
        data,
    };
    let mut trace = CompleteTrace {
        trace_id: "trace-av17".into(),
        thought_id: "th-av17".into(),
        task_id: None,
        agent_id_hash: "hash-av17".into(),
        started_at: "2026-05-01T00:00:00Z".parse().unwrap(),
        completed_at: "2026-05-01T00:01:00Z".parse().unwrap(),
        trace_level: TraceLevel::Generic,
        trace_schema_version: SchemaVersion::parse("2.7.0").unwrap(),
        components: vec![component],
        signature: String::new(),
        signature_key_id: "agent-av17".into(),
    };
    let payload = canonical_payload_value(&trace);
    let canon = PythonJsonDumpsCanonicalizer
        .canonicalize_value(&payload)
        .unwrap();
    trace.signature = BASE64.encode(sk.sign(&canon).to_bytes());
    let envelope = serde_json::json!({
        "events": [{ "event_type": "complete_trace", "trace_level": "generic",
                     "trace": serde_json::to_value(&trace).unwrap() }],
        "batch_timestamp": "2026-05-01T00:00:00Z",
        "consent_timestamp": "2025-01-01T00:00:00Z",
        "trace_level": "generic",
        "trace_schema_version": "2.7.0",
    });
    let bytes = envelope.to_string().into_bytes();

    let pipeline = IngestPipeline {
        backend: &backend,
        canonicalizer: &PythonJsonDumpsCanonicalizer,
        scrubber: &NullScrubber,
        signer: &*signer,
        signer_key_id: "qa",
    };
    let err = pipeline.receive_and_persist(&bytes).await.unwrap_err();
    // The decompose step calls component.attempt_index() which
    // surfaces AttemptIndexOutOfRange wrapped through Store.
    let kind = err.kind();
    assert!(
        kind == "schema_attempt_index_out_of_range" || kind == "store_backend",
        "expected typed rejection, got kind={kind}"
    );
    assert!(backend.snapshot_events().is_empty());
    println!("scenario G: attempt_index=2^32 rejected with kind={kind}");
}
