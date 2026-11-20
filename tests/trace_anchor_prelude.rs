//! v62.0.0 (P7-fix8; the adopters' ask) — **the `prelude` trace helpers, as
//! an adopter calls them** (an external crate, `use ciris_persist::prelude::*`
//! only): an agent key, a trace dated in its window, the signed edition-2
//! row, through the real door on sqlite and postgres; and the same row on
//! the batch door (`IngestPipeline::receive_and_persist`) from
//! `trace_row_event`. Witnesses the exact paths ADOPTION-NOTES gives Server.

#![cfg(feature = "test-anchor")]
#![cfg(any(feature = "sqlite", feature = "postgres"))]

use ciris_persist::federation::BlobStorage;
use ciris_persist::prelude::*;

fn a_trace(trace_id: &str) -> serde_json::Value {
    serde_json::json!({
        "trace_id": trace_id,
        "thought_id": format!("{trace_id}-th"),
        "agent_id_hash": "prelude-agent-hash",
        "started_at": "2000-01-01T00:00:00Z",
        "completed_at": "2000-01-01T00:00:01Z",
        "trace_level": "generic",
        "trace_schema_version": "2.7.0",
        "cohort_scope": "federation",
        "components": [{
            "component_type": "observation",
            "event_type": "THOUGHT_START",
            "timestamp": "2000-01-01T00:00:00Z",
            "data": {"attempt_index": 0},
        }],
    })
}

fn unique(tag: &str) -> String {
    format!(
        "prelude-{tag}-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    )
}

async fn events_of<B: Backend>(b: &B, trace_id: &str) -> usize {
    b.fetch_trace_events_page(-1, i64::MAX, None)
        .await
        .expect("fetch_trace_events_page")
        .into_iter()
        .filter(|(_, r)| r.trace_id == trace_id)
        .count()
}

async fn body<B>(b: &B)
where
    B: Backend + FederationDirectory + BlobStorage,
{
    // The door, directly.
    let agent = unique("agent");
    put_agent_trace_key(b, &agent).await;
    let trace_id = unique("trace");
    let mut trace = a_trace(&trace_id);
    date_trace(&mut trace, agent_trace_instant_ms(&agent));
    let row = sign_agent_trace(&agent, &trace).expect("the helper signs");
    let held = admit_trace_row(b, &row).await.expect("the row lands");
    assert!(!held, "admitted, not held");
    assert!(events_of(b, &trace_id).await > 0, "projected");

    // The batch door, from the wire event.
    let trace_id = unique("trace-batch");
    let mut trace = a_trace(&trace_id);
    date_trace(&mut trace, agent_trace_instant_ms(&agent));
    let row = sign_agent_trace(&agent, &trace).expect("signs");
    let body = serde_json::json!({
        "events": [trace_row_event(&row, "generic")],
        "batch_timestamp": "2026-05-01T00:00:00Z",
        "consent_timestamp": "2025-01-01T00:00:00Z",
        "trace_level": "generic",
        "trace_schema_version": "2.7.0",
    });
    let mut s = ciris_keyring::Ed25519SoftwareSigner::new("prelude-scrub");
    s.import_key(&[0x5Au8; 32]).expect("import_key");
    let pipeline = ciris_persist::ingest::IngestPipeline {
        backend: b,
        canonicalizer: &PythonJsonDumpsCanonicalizer,
        scrubber: &ciris_persist::scrub::NullScrubber,
        signer: &s,
        signer_key_id: "prelude-scrub",
    };
    let summary = pipeline
        .receive_and_persist(body.to_string().as_bytes())
        .await
        .expect("the batch door admits the row-form event");
    assert_eq!(summary.signatures_verified, 1);
    assert!(events_of(b, &trace_id).await > 0, "projected");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn prelude_trace_helpers_land_sqlite() {
    let b = ciris_persist::store::test_backend::test_backend();
    body(&b).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn prelude_trace_helpers_land_postgres() {
    let Some(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok() else {
        eprintln!("skipped: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let b = ciris_persist::store::PostgresBackend::connect(&dsn)
        .await
        .expect("connect");
    b.run_migrations().await.expect("migrations");
    body(&b).await;
}
