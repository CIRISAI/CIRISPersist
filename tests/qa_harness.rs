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
async fn agent_with_registered_key(backend: &MemoryBackend, key_id: &str, seed: u8) -> SigningKey {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    backend.add_public_key(key_id, sk.verifying_key());
    // CIRISPersist#789 — the producer's ML-DSA-65 key must be IN THE
    // DIRECTORY. Admission resolves it by `pqc_key_id` and refuses when it is
    // absent; the payload's own copy is no longer trusted, because a key the
    // submitter nominates proves nothing about who they are. The fleet is
    // 100% PQC, so a registered PQC key is the normal state of the world.
    {
        use ciris_keyring::PqcSigner as _;
        let mldsa = ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(&[0x77; 32], "qa-mldsa")
            .expect("ml-dsa seed");
        let pk = mldsa.public_key().await.expect("ml-dsa pk");
        backend.add_pqc_public_key(
            "qa-mldsa",
            &base64::engine::general_purpose::STANDARD.encode(&pk),
        );
    }
    sk
}

/// Build a signed CompleteTrace + serialize as a batch envelope.
/// v7.2.0 (#225): hybrid-signed (Ed25519 + ML-DSA-65) so the Full-mode
/// trace-tier hard cut admits.
async fn build_signed_batch(
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
            agent_id_hash: None,
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
        deployment_profile: None,
        cohort_scope: "federation".into(),
        cohort_target_id: None,
        signature: String::new(),
        signature_key_id: key_id.into(),
        signature_ml_dsa_65: None,
        pubkey_ml_dsa_65: None,
        pqc_key_id: None,
    };
    let payload = canonical_payload_value(&trace);
    let bytes = PythonJsonDumpsCanonicalizer
        .canonicalize_value(&payload)
        .unwrap();
    let ed_sig = sk.sign(&bytes).to_bytes();
    // Hybrid half: ML-DSA-65 over (canonical || classical_sig).
    {
        use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner};
        let mldsa = MlDsa65SoftwareSigner::from_seed_bytes(&[0x77; 32], "qa-mldsa").unwrap();
        let mut bound = Vec::with_capacity(bytes.len() + ed_sig.len());
        bound.extend_from_slice(&bytes);
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = mldsa.sign(&bound).await.unwrap();
        let pqc_pk = mldsa.public_key().await.unwrap();
        trace.signature = BASE64.encode(ed_sig);
        trace.signature_ml_dsa_65 = Some(BASE64.encode(&pqc_sig));
        trace.pubkey_ml_dsa_65 = Some(BASE64.encode(&pqc_pk));
        trace.pqc_key_id = Some("qa-mldsa".to_owned());
    }

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
        let sk = agent_with_registered_key(&backend, &key_id, (i + 1) as u8).await;
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
            )
            .await;
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
    let sk_a = agent_with_registered_key(&backend, "agent-A", 0xAA).await;
    let sk_b = agent_with_registered_key(&backend, "agent-B", 0xBB).await;

    let bytes_a =
        build_signed_batch(&sk_a, "agent-A", "hash-A", "trace-collide", "th-collide", 1).await;
    let bytes_b = build_signed_batch(
        &sk_b,
        "agent-B",
        "hash-B",
        "trace-collide", // SAME trace_id
        "th-collide",    // SAME thought_id
        1,
    )
    .await;

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
    let sk = agent_with_registered_key(&backend, "agent-qa", 0x42).await;

    let mut tasks = Vec::new();
    for b in 0..N_BATCHES {
        let bytes = build_signed_batch(
            &sk,
            "agent-qa",
            "hash-qa",
            &format!("trace-{b:04}"),
            &format!("th-{b:04}"),
            COMPONENTS,
        )
        .await;
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
    // v32.0.0 (CIRISPersist#690) — the preimage is the whole envelope, and it
    // is rebuilt here ENTIRELY from persisted columns. Verifying against
    // `canonical(payload)` alone stopped being correct when the signature
    // widened to cover the treatment claims; verifying against a preimage
    // assembled from the in-memory envelope would be a restatement rather than
    // a check, because the envelope holds fields the row may not.
    //
    // Every row, not a sample: `scenario E` exists to prove the property holds
    // across the whole batch set, and a per-row `expect` here is what would
    // localise a partial write path (one door stamping the columns, another
    // not) rather than reporting "some row failed".
    for (i, row) in snap.iter().enumerate() {
        let payload = serde_json::Value::Object(row.payload.clone());
        let canon = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&payload)
            .unwrap();
        let post_sha = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&canon));
        let preimage = ciris_persist::ingest::scrub_preimage(
            &post_sha,
            row.original_content_hash
                .as_deref()
                .unwrap_or_else(|| panic!("row {i}: original_content_hash not persisted")),
            row.scrub_ner_ran
                .unwrap_or_else(|| panic!("row {i}: scrub_ner_ran not persisted")),
            row.scrub_applied_trace_level
                .as_deref()
                .unwrap_or_else(|| panic!("row {i}: scrub_applied_trace_level not persisted")),
            row.scrub_model_digest.as_deref(),
            row.scrub_key_id
                .as_deref()
                .unwrap_or_else(|| panic!("row {i}: scrub_key_id not persisted")),
            row.scrub_timestamp
                .unwrap_or_else(|| panic!("row {i}: scrub_timestamp not persisted")),
        );
        let sig_bytes = BASE64
            .decode(row.scrub_signature.as_ref().unwrap())
            .unwrap();
        let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        pubkey.verify_strict(&preimage, &sig).unwrap_or_else(|_| {
            panic!(
                "row {i}: scrub_signature must verify against a preimage rebuilt \
                 from persisted columns — a peer has nothing else to work from"
            )
        });
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
    let sk = agent_with_registered_key(&backend, "agent-shutdown", 0xC0).await;
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
        )
        .await;
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
    let sk = agent_with_registered_key(&backend, "agent-av17", 0x17).await;

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
        agent_id_hash: None,
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
        deployment_profile: None,
        cohort_scope: "federation".into(),
        cohort_target_id: None,
        signature: String::new(),
        signature_key_id: "agent-av17".into(),
        signature_ml_dsa_65: None,
        pubkey_ml_dsa_65: None,
        pqc_key_id: None,
    };
    let payload = canonical_payload_value(&trace);
    let canon = PythonJsonDumpsCanonicalizer
        .canonicalize_value(&payload)
        .unwrap();
    // v7.2.0 (#225) — hybrid-sign so the trace passes the Full-mode
    // verify gate and reaches decompose, where the AV-17 attempt-index
    // out-of-range check fires (verify is step 2, decompose is later).
    let ed_sig = sk.sign(&canon).to_bytes();
    {
        use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner};
        let mldsa = MlDsa65SoftwareSigner::from_seed_bytes(&[0x77; 32], "qa-mldsa").unwrap();
        let mut bound = Vec::with_capacity(canon.len() + ed_sig.len());
        bound.extend_from_slice(&canon);
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = mldsa.sign(&bound).await.unwrap();
        let pqc_pk = mldsa.public_key().await.unwrap();
        trace.signature = BASE64.encode(ed_sig);
        trace.signature_ml_dsa_65 = Some(BASE64.encode(&pqc_sig));
        trace.pubkey_ml_dsa_65 = Some(BASE64.encode(&pqc_pk));
        trace.pqc_key_id = Some("qa-mldsa".to_owned());
    }
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

// ─── Scenario H: AV-26 multi-worker boot race (v0.1.5) ─────────────

/// Multi-worker boot race regression. v0.1.5 added a session-scoped
/// `pg_advisory_lock(MIGRATION_LOCK_ID)` on a dedicated single-use
/// connection at the top of `run_migrations`; this scenario spawns
/// N concurrent `PostgresBackend::connect + run_migrations` calls
/// against a freshly-truncated DB and asserts every one returns
/// `Ok(())`.
///
/// Pre-v0.1.5 this raced on Postgres catalog inserts (`pg_type` for
/// hypertable types, `IF NOT EXISTS` over the V001+V003 set) and
/// surfaced as `Error::Backend("migrations: error asserting
/// migrations table — db error")` with no SQLSTATE handle. v0.1.5
/// the second worker blocks on the advisory lock until the first
/// worker's session closes, then sees "no migrations to apply" and
/// returns clean.
///
/// Gated on `CIRIS_PERSIST_TEST_PG_URL` like the other postgres
/// integration tests. Uses `#[serial_test::serial(postgres)]` to
/// avoid races with other DB-touching tests sharing the runner.
#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(postgres)]
async fn av26_concurrent_boot_advisory_lock() {
    let Some(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok() else {
        eprintln!("scenario H skipped: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };

    use ciris_persist::store::{Backend, PostgresBackend};

    // Cold-start simulation: drop every application schema AND the migration
    // history table, so each worker really does see an unmigrated DB. (Don't
    // drop schemas in normal test runs — production never starts here.)
    //
    // v34.0.0 (CIRISPersist#704) — THIS DROPPED ONE SCHEMA BY NAME
    // (`cirislens`) while this comment claimed it left an unmigrated DB. The
    // lens tree creates FIVE; `cirisnode`, `cirisgraph`, `cirislens_derived`
    // and `cirislens_secrets` all survived. So refinery, seeing an empty
    // history, re-ran from V001 against a HALF-MIGRATED `cirisnode`: V064
    // re-added `key_grant_stream_id` (which V129 had renamed away), and V129
    // then renamed it onto the `key_grant_scope_id` still sitting there —
    // 42701 duplicate_column, all ten workers.
    //
    // The precondition had been false since the first non-`cirislens` schema
    // appeared. It cost nothing only because every cirisnode migration until
    // V129 happened to be re-runnable, so the test kept passing while
    // simulating a warm start under the name of a cold one.
    //
    // DERIVED, not listed. A hand-maintained schema list is the same defect
    // one layer up: it goes stale the first time a migration adds a schema and
    // nobody edits this test — which is exactly how this one got here.
    {
        let backend = PostgresBackend::connect(&dsn)
            .await
            .expect("scenario H setup: connect");
        let client = backend.pool().get().await.expect("setup: client");

        const APP_SCHEMAS: &str = "SELECT nspname FROM pg_namespace \
             WHERE nspname NOT IN ('public', 'information_schema') \
               AND nspname NOT LIKE 'pg\\_%'";

        let list = |rows: Vec<tokio_postgres::Row>| {
            rows.iter()
                .map(|r| r.try_get::<_, String>(0).expect("setup: nspname"))
                .collect::<Vec<_>>()
        };

        let before = list(
            client
                .query(APP_SCHEMAS, &[])
                .await
                .expect("setup: enumerate application schemas"),
        );
        for schema in before {
            // Not `let _ =`: a drop that fails silently leaves the warm state
            // that caused this, and the next reader sees a green test.
            client
                .execute(&format!(r#"DROP SCHEMA IF EXISTS "{schema}" CASCADE"#), &[])
                .await
                .unwrap_or_else(|e| panic!("setup: drop schema {schema}: {e}"));
        }
        client
            .execute(
                "DROP TABLE IF EXISTS public.ciris_persist_schema_history",
                &[],
            )
            .await
            .expect("setup: drop migration history");

        // The precondition is now CHECKED, not narrated. Without this the test
        // reports on whatever state it happens to inherit.
        let residual = list(
            client
                .query(APP_SCHEMAS, &[])
                .await
                .expect("setup: re-enumerate application schemas"),
        );
        assert!(
            residual.is_empty(),
            "scenario H is a COLD start: {residual:?} survived the drop, so the \
             workers below would migrate over existing objects and this test \
             would measure a warm boot under a cold boot's name"
        );
    }

    const N_WORKERS: usize = 10;
    let start = Instant::now();
    let mut tasks = Vec::with_capacity(N_WORKERS);
    for w in 0..N_WORKERS {
        let dsn = dsn.clone();
        tasks.push(tokio::spawn(async move {
            let backend = PostgresBackend::connect(&dsn)
                .await
                .map_err(|e| format!("worker {w}: connect: kind={} {e}", e.kind()))?;
            backend
                .run_migrations()
                .await
                .map_err(|e| format!("worker {w}: migrate: kind={} {e}", e.kind()))?;
            Ok::<_, String>(())
        }));
    }
    let mut errors = Vec::new();
    for (i, t) in tasks.into_iter().enumerate() {
        match t.await {
            Ok(Ok(())) => {}
            Ok(Err(msg)) => errors.push(msg),
            Err(je) => errors.push(format!("worker {i}: join: {je}")),
        }
    }
    let elapsed = start.elapsed();

    assert!(
        errors.is_empty(),
        "scenario H: {} of {N_WORKERS} workers failed:\n  {}",
        errors.len(),
        errors.join("\n  ")
    );

    // Sanity: schema_history table should have one row per embedded
    // migration script — exactly one set, not N_WORKERS sets — proving
    // the lock serialized correctly. v3.11.0: count comes from the
    // backend's `embedded_lens_migration_count()` helper instead of a
    // hardcoded number, so the test doesn't drift each time a
    // migration is added.
    let backend = PostgresBackend::connect(&dsn).await.unwrap();
    let client = backend.pool().get().await.unwrap();
    let row = client
        .query_one(
            "SELECT COUNT(*)::BIGINT FROM ciris_persist_schema_history",
            &[],
        )
        .await
        .expect("schema_history count");
    let count: i64 = row.get(0);
    let expected = ciris_persist::store::postgres::embedded_lens_migration_count() as i64;
    assert_eq!(
        count,
        expected,
        "schema_history has {count} rows; expected exactly {expected} (one per \
         embedded migration). Any other value means either an unexpected migration \
         landed (count > expected) or the advisory lock didn't hold (would yield \
         N_WORKERS×{expected} = {} rows).",
        N_WORKERS as i64 * expected
    );

    println!(
        "scenario H: {N_WORKERS} concurrent boots all OK in {elapsed:?}, \
         schema_history has {count} migration rows"
    );
}
