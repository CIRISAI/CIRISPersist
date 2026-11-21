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
//!
//! v62.0.0 (P7-fix8; CC 3.1.5, ruling (a)) — **the v62 trace wire.** A trace
//! arrives as its `trace:complete:v1` ROW (one composite statement under the
//! agent's AGENT-kind edition-2 key) plus the trace BLOB (its JCS bytes, no
//! signature members); the earlier form (an inline trace carrying its own
//! bound-hybrid signature) is refused `earlier_form_object` under
//! `VerifyMode::Full`. Every scenario that touches storage runs on sqlite AND
//! postgres (`_postgres`, a database of its own, like scenario H).
//!
//! - Traces are dated from the agent key's OWN window (the rule
//!   `prelude::agent_trace_instant_ms` applies under `test-anchor`): each
//!   agent's `key:record` is put with the default agent window
//!   ([`agent_key_record_start_ms`]: 180 days before today 00:00 UTC, as
//!   `fixture_switch::key_window_start_ms`), its window start is READ BACK
//!   from the record this node holds, and every trace is dated
//!   [`TRACE_OFFSET_DAYS`] (K2's 150) into it. This file does not use the
//!   `test-anchor` helpers themselves: the postgres + sqlite test lane does
//!   not enable that feature, and these scenarios must run there.
//! - A row-form trace's `trace_events` are projected in the row's OWN write,
//!   so `BatchSummary::trace_events_inserted` counts 0 for it; the scenarios
//!   count the stored rows instead ([`events`]).

#![cfg(any(feature = "sqlite", feature = "postgres"))]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
#[cfg(feature = "queue")]
use std::time::Duration;
use std::time::Instant;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner};
use ed25519_dalek::SigningKey;

use ciris_persist::federation::edition2::{emit, ingest as e2ingest, produce};
use ciris_persist::federation::{BlobStorage, FederationDirectory};
use ciris_persist::ingest::{IngestError, IngestPipeline, VerifyMode};
use ciris_persist::schema::{
    CompleteTrace, ComponentType, ReasoningEventType, SchemaVersion, TraceComponent, TraceLevel,
};
use ciris_persist::scrub::NullScrubber;
use ciris_persist::signing::LocalSigner;
use ciris_persist::store::types::TraceEventRow;
use ciris_persist::store::Backend;
use ciris_persist::verify::canonical::Canonicalizer;
use ciris_persist::verify::PythonJsonDumpsCanonicalizer;

// ─── shared fixtures ───────────────────────────────────────────────

/// What every scenario backend is: the ingest pipeline's store, the key
/// plane the statement door reads, and the blob plane the trace lands on.
trait QaBackend: Backend + FederationDirectory + BlobStorage + Send + Sync + 'static {}
impl<T: Backend + FederationDirectory + BlobStorage + Send + Sync + 'static> QaBackend for T {}

fn test_signer() -> Box<dyn HardwareSigner> {
    let mut s = Ed25519SoftwareSigner::new("qa-harness-signer");
    s.import_key(&[0x42u8; 32]).expect("import_key");
    Box::new(s) as Box<dyn HardwareSigner>
}

const DAY_MS: u64 = 86_400_000;

/// The default agent record's start, as `fixture_switch` derives it
/// (`NODE_DEFAULT_BACK_DAYS` = 180 days before today 00:00 UTC): the window
/// covers the traces dated [`TRACE_OFFSET_DAYS`] into it, and it is re-derived
/// each day, so no fixed calendar date outlives an agent record (at most 365
/// days).
fn agent_key_record_start_ms() -> u64 {
    let now = u64::try_from(Utc::now().timestamp_millis()).expect("after 1970");
    now / DAY_MS * DAY_MS - 180 * DAY_MS
}

/// How far into its key's window a trace is dated (K2's
/// `OWNER_BINDING_OFFSET_DAYS`, the offset `agent_trace_instant_ms` adds).
const TRACE_OFFSET_DAYS: u64 = 150;

/// A simulated agent: its composite signer, its identity-ref (`iss`), and
/// the instant its traces are dated from: its key's window start (read back
/// from the record this node holds) plus [`TRACE_OFFSET_DAYS`].
struct Agent {
    signer: LocalSigner,
    iss: String,
    trace_at: DateTime<Utc>,
}

/// Mint an agent's composite key (Ed25519 + ML-DSA-65 from `seed`) and put
/// its self-signed `key:record` on `b` as an **`agent`** key (CC 3.1.5,
/// key_roles R4: the agent key signs its traces and nothing else does),
/// asserted at [`agent_key_record_start_ms`], ending 364 days on (the
/// default agent window).
async fn register_agent<B: QaBackend>(b: &B, seed: u8) -> Agent {
    let id = format!("qa-agent-{seed:02x}");
    let pqc = ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(&[seed; 32], id.clone())
        .expect("ml-dsa seed");
    let signer = LocalSigner::from_parts(
        SigningKey::from_bytes(&[seed; 32]),
        id.clone(),
        Some(Arc::new(pqc)),
        Some(id),
    );
    let key = produce::composite_public_key(&signer)
        .await
        .expect("composite public key");
    let (_, iss) = produce::signer_identity(&signer)
        .await
        .expect("identity-ref");
    let start = agent_key_record_start_ms();
    let payload = emit::key_record_payload(
        &key,
        &["agent"],
        &iss,
        start,
        Some(start + 364 * DAY_MS),
        None,
    )
    .expect("key:record payload");
    let statement = produce::sign_row(
        &signer,
        &iss,
        ciris_persist::federation::types::attestation_type::SCORES,
        emit::KEY_RECORD_FAMILY,
        &payload,
    )
    .await
    .expect("sign the key:record");
    e2ingest::put_statement(b, &statement, None, e2ingest::INGEST_TIER)
        .await
        .expect("the agent's key:record lands");
    // The key's OWN window, as this node holds it (the projected record's
    // `valid_from` is the record's start).
    let held = FederationDirectory::lookup_public_key(b, &iss)
        .await
        .expect("lookup_public_key")
        .expect("the agent's key is held");
    Agent {
        signer,
        iss,
        trace_at: held.valid_from
            + chrono::Duration::days(i64::try_from(TRACE_OFFSET_DAYS).expect("days")),
    }
}

/// A trace (no signature members: the row is its signature) starting one hour
/// after `start` (an agent's dated instant), with `n_components` components (`attempt_index` =
/// `seq` = the component's index unless `data_of` says otherwise).
fn trace_value(
    agent_id_hash: &str,
    trace_id: &str,
    thought_id: &str,
    n_components: usize,
    start: DateTime<Utc>,
    data_of: impl Fn(usize) -> serde_json::Map<String, serde_json::Value>,
) -> serde_json::Value {
    let started = start + chrono::Duration::hours(1);
    let stamp = |t: DateTime<Utc>| {
        t.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
            .parse()
            .expect("a wire instant")
    };
    let components = (0..n_components)
        .map(|i| TraceComponent {
            component_type: ComponentType::Conscience,
            event_type: ReasoningEventType::ConscienceResult,
            timestamp: stamp(started + chrono::Duration::seconds(i as i64)),
            data: data_of(i),
            agent_id_hash: None,
        })
        .collect();
    let trace = CompleteTrace {
        trace_id: trace_id.into(),
        thought_id: thought_id.into(),
        task_id: Some("task-qa".into()),
        agent_id_hash: agent_id_hash.into(),
        started_at: stamp(started),
        completed_at: stamp(started + chrono::Duration::seconds(n_components as i64 + 1)),
        trace_level: TraceLevel::Generic,
        trace_schema_version: SchemaVersion::parse("2.7.0").unwrap(),
        components,
        deployment_profile: None,
        cohort_scope: "federation".into(),
        cohort_target_id: None,
        signature: String::new(),
        signature_key_id: String::new(),
        signature_ml_dsa_65: None,
        pubkey_ml_dsa_65: None,
        pqc_key_id: None,
        run_kind: None,
    };
    serde_json::to_value(&trace).unwrap()
}

fn seq_data(i: usize) -> serde_json::Map<String, serde_json::Value> {
    let mut data = serde_json::Map::new();
    data.insert("attempt_index".into(), serde_json::json!(i));
    data.insert("seq".into(), serde_json::json!(i));
    data
}

/// `trace` as a ROW-FORM batch event signed by `agent`: the trace blob (JCS,
/// no signature members) and its `trace:complete:v1` statement, the same
/// row `ingest::seal_trace_row` builds (without its scrub, which needs the
/// `scrub` feature and would rewrite the trace under test).
async fn row_event(agent: &Agent, trace: &serde_json::Value) -> (serde_json::Value, Vec<u8>) {
    use ciris_persist::ingest::{
        canonical_trace_blob, trace_row_payload, TRACE_FAMILY_ID, TRACE_ROW_TYPE,
    };
    let blob = canonical_trace_blob(trace).expect("a trace object");
    let parsed: CompleteTrace = serde_json::from_slice(&blob).expect("the blob is a trace");
    let payload = trace_row_payload(&parsed, &blob, &agent.iss).expect("the row payload");
    let statement = produce::sign_row(
        &agent.signer,
        &agent.iss,
        TRACE_ROW_TYPE,
        TRACE_FAMILY_ID,
        &payload,
    )
    .await
    .expect("sign the trace row");
    (
        serde_json::json!({
            "event_type": "complete_trace",
            "trace_level": "generic",
            "statement": BASE64.encode(statement),
            "trace_blob": BASE64.encode(&blob),
        }),
        blob,
    )
}

/// A batch envelope around `events`.
fn batch(events: Vec<serde_json::Value>) -> Vec<u8> {
    serde_json::json!({
        "events": events,
        "batch_timestamp": "2026-05-01T00:00:00Z",
        "consent_timestamp": "2025-01-01T00:00:00Z",
        "trace_level": "generic",
        "trace_schema_version": "2.7.0",
    })
    .to_string()
    .into_bytes()
}

/// A one-trace row-form batch by `agent`.
async fn row_batch(
    agent: &Agent,
    agent_id_hash: &str,
    trace_id: &str,
    thought_id: &str,
    n_components: usize,
) -> Vec<u8> {
    let trace = trace_value(
        agent_id_hash,
        trace_id,
        thought_id,
        n_components,
        agent.trace_at,
        seq_data,
    );
    batch(vec![row_event(agent, &trace).await.0])
}

/// Every stored `trace_events` row (each scenario's backend is its own).
async fn events<B: Backend>(b: &B) -> Vec<TraceEventRow> {
    b.fetch_trace_events_page(-1, i64::MAX, None)
        .await
        .expect("fetch_trace_events_page")
        .into_iter()
        .map(|(_, r)| r)
        .collect()
}

#[cfg(feature = "sqlite")]
fn sqlite() -> Arc<ciris_persist::store::sqlite::SqliteBackend> {
    Arc::new(ciris_persist::store::test_backend::test_backend())
}

/// Run `body` over a migrated postgres backend in a database of ITS OWN
/// (created here, dropped after, as scenario H does): the scenarios count
/// every stored row. Skipped when `CIRIS_PERSIST_TEST_PG_URL` is unset.
#[cfg(feature = "postgres")]
async fn on_fresh_pg<F, Fut>(tag: &str, body: F)
where
    F: FnOnce(Arc<ciris_persist::store::PostgresBackend>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let Some(base) = std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok() else {
        eprintln!("{tag} skipped: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let name = format!("ciris_qa_{tag}_{}", uuid::Uuid::new_v4().simple());
    let cut = base.rfind('/').expect("dsn has a database");
    let dsn = format!("{}/{name}", &base[..cut]);
    let (admin, conn) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
        .await
        .expect("connect to the base test database");
    tokio::spawn(conn);
    admin
        .batch_execute(&format!(r#"CREATE DATABASE "{name}""#))
        .await
        .expect("create this scenario's database");
    let outcome = tokio::spawn(async move {
        let b = ciris_persist::store::PostgresBackend::connect(&dsn)
            .await
            .expect("connect");
        b.run_migrations().await.expect("migrations");
        body(Arc::new(b)).await;
    })
    .await;
    admin
        .batch_execute(&format!(r#"DROP DATABASE IF EXISTS "{name}" WITH (FORCE)"#))
        .await
        .expect("drop this scenario's database");
    if let Err(e) = outcome {
        std::panic::resume_unwind(e.into_panic());
    }
}

// ─── Scenario A: high-volume concurrent agents ─────────────────────

/// THREAT_MODEL.md AV-9 stress: N parallel agents each submit M
/// distinct batches; assert no cross-agent dedup collisions, every
/// statement verified, and every stored row attributed to the agent
/// whose row carried it.
async fn high_volume_concurrent_agents_on<B: QaBackend>(backend: Arc<B>) {
    const N_AGENTS: usize = 8;
    const N_BATCHES_PER_AGENT: usize = 16;
    const COMPONENTS_PER_BATCH: usize = 6;

    let signer = Arc::<dyn HardwareSigner>::from(test_signer());
    let signer_key_id = "qa-harness-signer".to_owned();

    let mut agents = Vec::new();
    for i in 0..N_AGENTS {
        let agent = register_agent(&*backend, (i + 1) as u8).await;
        agents.push((format!("hash-{i:02}"), agent));
    }

    let start = Instant::now();
    let verified = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for (a_idx, (agent_id_hash, agent)) in agents.iter().enumerate() {
        for b in 0..N_BATCHES_PER_AGENT {
            let bytes = row_batch(
                agent,
                agent_id_hash,
                &format!("trace-{a_idx:02}-{b:04}"),
                &format!("th-{a_idx:02}-{b:04}"),
                COMPONENTS_PER_BATCH,
            )
            .await;
            let backend = backend.clone();
            let signer = signer.clone();
            let signer_key_id = signer_key_id.clone();
            let verified = verified.clone();
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
                verified.fetch_add(s.signatures_verified, Ordering::Relaxed);
            }));
        }
    }
    for t in tasks {
        t.await.unwrap();
    }
    let elapsed = start.elapsed();

    assert_eq!(
        verified.load(Ordering::Relaxed),
        N_AGENTS * N_BATCHES_PER_AGENT,
        "every trace row's statement verified"
    );
    let expected = N_AGENTS * N_BATCHES_PER_AGENT * COMPONENTS_PER_BATCH;
    let rows = events(&*backend).await;
    assert_eq!(
        rows.len(),
        expected,
        "all rows persisted across concurrent agents"
    );
    for row in &rows {
        let (_, agent) = agents
            .iter()
            .find(|(h, _)| *h == row.agent_id_hash)
            .expect("a row of a known agent");
        assert_eq!(
            row.signing_key_id, agent.iss,
            "each row is attributed to the agent whose statement carried it"
        );
    }
    println!(
        "scenario A: {N_AGENTS} agents × {N_BATCHES_PER_AGENT} batches × {COMPONENTS_PER_BATCH} components = {expected} rows in {elapsed:?}"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn high_volume_concurrent_agents() {
    high_volume_concurrent_agents_on(sqlite()).await;
}

#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn high_volume_concurrent_agents_postgres() {
    on_fresh_pg(
        "a",
        high_volume_concurrent_agents_on::<ciris_persist::store::PostgresBackend>,
    )
    .await;
}

// ─── Scenario B: AV-5 schema-version flood ─────────────────────────

/// THREAT_MODEL.md AV-5 stress: 10k malformed bodies, assert pipeline
/// rejects each typed without unbounded memory growth (the v0.1.2
/// `Cow<'static, str>` fix should hold), and nothing is stored.
async fn av5_schema_version_flood_on<B: QaBackend>(backend: Arc<B>) {
    const N: usize = 10_000;
    let signer = test_signer();

    let pipeline = IngestPipeline {
        backend: &*backend,
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
    assert!(events(&*backend).await.is_empty(), "backend untouched");
    println!("scenario B: {N} malformed schema-version submissions, all rejected, no rows");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn av5_schema_version_flood() {
    av5_schema_version_flood_on(sqlite()).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn av5_schema_version_flood_postgres() {
    on_fresh_pg(
        "b",
        av5_schema_version_flood_on::<ciris_persist::store::PostgresBackend>,
    )
    .await;
}

// ─── Scenario C: AV-6 JSON-bomb depth ──────────────────────────────

/// THREAT_MODEL.md AV-6: 64-deep nested data blob → typed
/// DataTooDeep rejection, at the batch parse (no store is reached, so this
/// runs once).
#[tokio::test]
#[cfg(feature = "sqlite")]
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
    let backend = ciris_persist::store::test_backend::test_backend();
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
/// as the dedup-key prefix. Both rows must persist, each its own agent's.
async fn av9_cross_agent_dedup_on<B: QaBackend>(backend: Arc<B>) {
    let signer = test_signer();
    let a = register_agent(&*backend, 0xAA).await;
    let b = register_agent(&*backend, 0xBB).await;

    // The SAME instants for both: one window start, one shape.
    let trace_a = trace_value(
        "hash-A",
        "trace-collide",
        "th-collide",
        1,
        a.trace_at,
        seq_data,
    );
    let trace_b = trace_value(
        "hash-B",
        "trace-collide", // SAME trace_id
        "th-collide",    // SAME thought_id
        1,
        a.trace_at,
        seq_data,
    );
    let bytes_a = batch(vec![row_event(&a, &trace_a).await.0]);
    let bytes_b = batch(vec![row_event(&b, &trace_b).await.0]);

    let pipeline = IngestPipeline {
        backend: &*backend,
        canonicalizer: &PythonJsonDumpsCanonicalizer,
        scrubber: &NullScrubber,
        signer: &*signer,
        signer_key_id: "qa",
    };
    let s_a = pipeline.receive_and_persist(&bytes_a).await.unwrap();
    let s_b = pipeline.receive_and_persist(&bytes_b).await.unwrap();
    assert_eq!(s_a.signatures_verified, 1, "agent A's row is admitted");
    assert_eq!(s_b.signatures_verified, 1, "agent B's row is admitted");
    let rows = events(&*backend).await;
    assert_eq!(
        rows.len(),
        2,
        "agent B's row persists despite same trace_id/thought_id"
    );
    for (hash, agent) in [("hash-A", &a), ("hash-B", &b)] {
        let row = rows
            .iter()
            .find(|r| r.agent_id_hash == hash)
            .unwrap_or_else(|| panic!("{hash}'s row persists"));
        assert_eq!(row.signing_key_id, agent.iss, "{hash}: its own agent's row");
    }
    println!("scenario D: cross-agent dedup — both agents persisted distinct rows");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn av9_cross_agent_dedup() {
    av9_cross_agent_dedup_on(sqlite()).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn av9_cross_agent_dedup_postgres() {
    on_fresh_pg(
        "d",
        av9_cross_agent_dedup_on::<ciris_persist::store::PostgresBackend>,
    )
    .await;
}

// ─── Scenario E: AV-24 sign-verify round-trip on every row ─────────

/// Every persisted row's scrub_signature ed25519_verifies against the
/// signer's public key + a preimage rebuilt from persisted columns. Tests at
/// scale.
///
/// v62.0.0 (P7-fix8) — the node's scrub signature is the provenance of a
/// trace this node scrubbed and stored LOCALLY: an unsigned trace a relay
/// hands over under `VerifyMode::TrustPreVerified` (local-only, never
/// served). A row-form trace's rows are its agent's statement's (scenario A
/// asserts their attribution); the node signs no scrub over them. So this
/// scenario runs the relay path, where the property lives.
async fn av24_sign_verify_round_trip_all_rows_on<B: QaBackend>(backend: Arc<B>) {
    const N_BATCHES: usize = 32;
    const COMPONENTS: usize = 8;

    let signer = Arc::<dyn HardwareSigner>::from(test_signer());
    let signer_key_id = "qa-harness-signer".to_owned();
    // The relay's attribution names a key this node holds (as I3482 does).
    let agent = register_agent(&*backend, 0x42).await;
    let start = agent.trace_at;

    let mut tasks = Vec::new();
    for b in 0..N_BATCHES {
        let mut trace = trace_value(
            "hash-qa",
            &format!("trace-{b:04}"),
            &format!("th-{b:04}"),
            COMPONENTS,
            start,
            seq_data,
        );
        trace["signature_key_id"] = serde_json::json!(agent.iss);
        let bytes = batch(vec![serde_json::json!({
            "event_type": "complete_trace", "trace_level": "generic", "trace": trace,
        })]);
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
            pipeline
                .receive_and_persist_with(&bytes, VerifyMode::TrustPreVerified)
                .await
                .unwrap();
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }

    // Verify each row's scrub_signature against the signer's pubkey.
    let pubkey_bytes = signer.public_key().await.unwrap();
    let pubkey_arr: [u8; 32] = pubkey_bytes.as_slice().try_into().unwrap();
    let pubkey = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_arr).unwrap();

    let snap = events(&*backend).await;
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
        assert_eq!(row.scrub_key_id.as_deref(), Some("qa-harness-signer"));
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

#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn av24_sign_verify_round_trip_all_rows() {
    av24_sign_verify_round_trip_all_rows_on(sqlite()).await;
}

#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn av24_sign_verify_round_trip_all_rows_postgres() {
    on_fresh_pg(
        "e",
        av24_sign_verify_round_trip_all_rows_on::<ciris_persist::store::PostgresBackend>,
    )
    .await;
}

// ─── Scenario F: graceful shutdown drain under load ────────────────

/// AV-19: spawn_persister processes a steady stream, then we drop the
/// producer mid-stream. PersisterHandle.shutdown() drains the queue
/// without losing rows.
#[cfg(feature = "queue")]
async fn av19_graceful_shutdown_under_load_on<B: QaBackend>(backend: Arc<B>) {
    use ciris_persist::{spawn_persister, Journal, DEFAULT_QUEUE_DEPTH};
    let dir = tempfile::tempdir().unwrap();
    let journal = Arc::new(Journal::open(dir.path().join("j.redb")).unwrap());
    let agent = register_agent(&*backend, 0xC0).await;
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
        let bytes = row_batch(
            &agent,
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

    let expected = N * 4;
    assert_eq!(
        events(&*backend).await.len(),
        expected,
        "all submitted rows landed despite mid-load shutdown"
    );
    println!("scenario F: {N} batches submitted under load, all {expected} rows drained on graceful shutdown");
}

#[cfg(all(feature = "sqlite", feature = "queue"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn av19_graceful_shutdown_under_load() {
    av19_graceful_shutdown_under_load_on(sqlite()).await;
}

#[cfg(all(feature = "postgres", feature = "queue"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn av19_graceful_shutdown_under_load_postgres() {
    on_fresh_pg(
        "f",
        av19_graceful_shutdown_under_load_on::<ciris_persist::store::PostgresBackend>,
    )
    .await;
}

// ─── Scenario G: AV-17 attempt_index out-of-range ──────────────────

/// MAX_ATTEMPT_INDEX bound holds; values above the cap reject typed, and
/// nothing of the trace is kept: no row, no `trace_events`, no blob.
async fn av17_attempt_index_out_of_range_on<B: QaBackend>(backend: Arc<B>) {
    let signer = test_signer();
    let agent = register_agent(&*backend, 0x17).await;

    // A trace with attempt_index = 4_294_967_296 (u32::MAX + 1).
    // Pre-v0.1.3 this would have wrapped to 0 via `as u32`.
    let trace = trace_value(
        "hash-av17",
        "trace-av17",
        "th-av17",
        1,
        agent.trace_at,
        |_| {
            let mut data = serde_json::Map::new();
            data.insert(
                "attempt_index".into(),
                serde_json::Value::Number(serde_json::Number::from(4_294_967_296i64)),
            );
            data
        },
    );
    // The row is well-formed and signed by the agent: the statement door
    // would admit it; the trace itself cannot decompose.
    let (event, blob) = row_event(&agent, &trace).await;
    let bytes = batch(vec![event]);

    let pipeline = IngestPipeline {
        backend: &*backend,
        canonicalizer: &PythonJsonDumpsCanonicalizer,
        scrubber: &NullScrubber,
        signer: &*signer,
        signer_key_id: "qa",
    };
    let err = pipeline.receive_and_persist(&bytes).await.unwrap_err();
    let kind = err.kind();
    assert_eq!(
        kind, "schema_attempt_index_out_of_range",
        "a typed schema rejection, before anything is written"
    );
    assert!(events(&*backend).await.is_empty(), "no trace_events");
    let sha: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(&blob).into();
    assert!(
        !backend.has_blob(&sha).await.expect("has_blob"),
        "no blob kept for a trace this node refused"
    );
    println!("scenario G: attempt_index=2^32 rejected with kind={kind}");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn av17_attempt_index_out_of_range() {
    av17_attempt_index_out_of_range_on(sqlite()).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn av17_attempt_index_out_of_range_postgres() {
    on_fresh_pg(
        "g",
        av17_attempt_index_out_of_range_on::<ciris_persist::store::PostgresBackend>,
    )
    .await;
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
/// integration tests, but it boots in a database of its own. It used to
/// `DROP SCHEMA` every application schema of the shared database to simulate
/// a cold start, which pulled `cirislens` out from under whichever direct-DSN
/// neighbour was running. The test-group serializer only covered neighbours
/// named `postgres_*`, so `i1152_member_commitment_unique_postgres` reported
/// `relation "cirislens.content_manifest" does not exist` on a loaded run
/// (certify, v61.0.1). A database nobody else has ever touched is also the
/// truer cold start: nothing can survive a drop that never happens.
#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn av26_concurrent_boot_advisory_lock() {
    let Some(base) = std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok() else {
        eprintln!("scenario H skipped: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let name = format!("ciris_av26_{}", uuid::Uuid::new_v4().simple());
    let cut = base.rfind('/').expect("dsn has a database");
    let dsn = format!("{}/{name}", &base[..cut]);
    let (admin, conn) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
        .await
        .expect("scenario H setup: connect to the base test database");
    tokio::spawn(conn);
    admin
        .batch_execute(&format!(r#"CREATE DATABASE "{name}""#))
        .await
        .expect("scenario H setup: create this test's database");

    // Spawned so a failed assertion comes back as a value: the database is
    // dropped either way, then the panic resumes.
    let outcome = tokio::spawn(av26_cold_boot(dsn)).await;
    admin
        .batch_execute(&format!(r#"DROP DATABASE IF EXISTS "{name}" WITH (FORCE)"#))
        .await
        .expect("scenario H teardown: drop this test's database");
    if let Err(e) = outcome {
        std::panic::resume_unwind(e.into_panic());
    }
}

#[cfg(feature = "postgres")]
async fn av26_cold_boot(dsn: String) {
    use ciris_persist::store::{Backend, PostgresBackend};

    // The precondition is CHECKED, not narrated (#704: a warm boot once ran
    // under this test's name because one schema was dropped of five).
    // DERIVED, not listed, so a migration that adds a schema is covered.
    {
        let backend = PostgresBackend::connect(&dsn)
            .await
            .expect("scenario H setup: connect");
        let client = backend.pool().get().await.expect("setup: client");
        let residual: Vec<String> = client
            .query(
                "SELECT nspname FROM pg_namespace \
                 WHERE nspname NOT IN ('public', 'information_schema') \
                   AND nspname NOT LIKE 'pg\\_%'",
                &[],
            )
            .await
            .expect("setup: enumerate application schemas")
            .iter()
            .map(|r| r.get(0))
            .collect();
        assert!(
            residual.is_empty(),
            "scenario H is a COLD start: {residual:?} already exist, so the \
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

// ─── scenario I: the ceremony's host verbs, awaited in a spawned task ──

/// v62.0.0 (KR-fix16; the rule after BF22: a host's `tokio::spawn` of a
/// persist future is verified from an EXTERNAL crate, never ruled from
/// reading) — **every Engine verb the genesis ceremony calls is awaited
/// inside `tokio::spawn`.** `tokio::spawn` requires the future to be `Send +
/// 'static`; proving that walks the whole future, so an opaque recursive
/// future (E0275, the recursion-depth overflow BF22 fixed at
/// `put_admitted_row`) or a `!Send` value held across an await fails THIS
/// FILE's build. No behaviour is asserted: each verb is called with
/// placeholder arguments and its `Result` dropped; the claim is that the
/// file compiles and each task joins without a panic.
///
/// The verbs: `accept_root`, `accept_root_draft`, `root_standing` (steps 7
/// and 8); `owner_binding_draft`, `check_owner_binding`,
/// `submit_owner_binding`, `node_owner_binding`,
/// `serve_seat_owner_announced` (step 9); and the draft-and-voice surface
/// they stand on, none of which this file named before: `statement_draft`,
/// `submit_voice`, `voice_status`, `held_rows_for`, `voice_draft`,
/// `voice_held_row`, plus `root_grants_for` and `owner_of`.
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn ceremony_verbs_are_awaitable_in_a_spawned_task() {
    use ciris_persist::Engine;
    let pqc = ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(
        &[0x16u8; 32],
        "qa-ceremony-verbs".to_owned(),
    )
    .expect("ml-dsa seed");
    let signer = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&[0x16u8; 32]),
        "qa-ceremony-verbs".to_owned(),
        Some(Arc::new(pqc)),
        Some("qa-ceremony-verbs".to_owned()),
    ));
    let engine = Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("an Engine"),
    );
    // Placeholders: well-formed where a verb parses its argument first.
    struct Args {
        node: String,
        owner: String,
        hex32: String,
        scopes: Vec<String>,
        statement: Vec<u8>,
    }
    let args = Arc::new(Args {
        node: "urn:ciris:placeholder-node".to_owned(),
        owner: "urn:ciris:placeholder-owner".to_owned(),
        hex32: "00".repeat(32),
        scopes: vec!["infra:serve".to_owned(), "infra:attest".to_owned()],
        statement: b"not a statement".to_vec(),
    });

    // Each verb in a task of its own: `$e` is the Engine, `$a` the
    // arguments, both moved into the spawned future.
    macro_rules! spawned {
        ($name:literal, |$e:ident, $a:ident| $body:expr) => {{
            let $e = Arc::clone(&engine);
            let $a = Arc::clone(&args);
            tokio::spawn(async move {
                let _ = &$a;
                let _ = $body;
            })
            .await
            .unwrap_or_else(|err| panic!("{}: the spawned task did not join: {err}", $name));
        }};
    }

    // Steps 7 and 8: this node accepts the root.
    spawned!("accept_root", |e, a| e.accept_root("humanity-accord").await);
    spawned!("accept_root_draft", |e, a| e
        .accept_root_draft("humanity-accord", &a.owner, &a.hex32, 1)
        .await);
    spawned!("root_standing", |e, a| e.root_standing().await);
    // Step 9: the seat's owner binding.
    spawned!("owner_binding_draft", |e, a| e
        .owner_binding_draft(&a.node, &a.scopes, &a.owner, &a.hex32, 1)
        .await);
    spawned!("check_owner_binding", |e, a| e
        .check_owner_binding(&a.statement, &a.node, &["infra:attest"])
        .await);
    spawned!("submit_owner_binding", |e, a| e
        .submit_owner_binding(&a.statement)
        .await);
    spawned!("node_owner_binding", |e, a| e
        .node_owner_binding(&a.node)
        .await);
    spawned!("serve_seat_owner_announced", |e, a| e
        .serve_seat_owner_announced(&a.node)
        .await);
    spawned!("owner_of", |e, a| e.owner_of(&a.node).await);
    // The draft-and-voice surface.
    spawned!("statement_draft", |e, a| {
        let envelope =
            serde_json::json!({"dimension": "trust:confers:v1", "scope": ["infra:attest"]});
        e.statement_draft(
            "delegates_to",
            &envelope,
            &a.owner,
            &a.hex32,
            &a.node,
            1,
            None,
        )
        .await
    });
    spawned!("submit_voice", |e, a| e.submit_voice(&a.statement).await);
    spawned!("voice_status", |e, a| e.voice_status(&a.hex32).await);
    spawned!("held_rows_for", |e, a| e
        .held_rows_for(Some(a.node.as_str()), Some("bound_node"), None, 10)
        .await);
    spawned!("voice_draft", |e, a| e
        .voice_draft(&a.hex32, &a.owner)
        .await);
    spawned!("voice_held_row", |e, a| e
        .voice_held_row(&a.hex32, None)
        .await);
    spawned!("root_grants_for", |e, a| e
        .root_grants_for(&a.node, None)
        .await);
}
