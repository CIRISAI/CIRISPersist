//! #226 — app-level hashed dedup shards, proven on BOTH durable backends
//! (Postgres + SQLite).
//!
//! The trace-ingest dedup path is a `ON CONFLICT DO NOTHING` upsert against
//! one shared UNIQUE index (`trace_events_dedup`, V001). Under concurrent
//! aggregate ingest every writer contends on that single hot index, so
//! aggregate throughput goes sublinear. V094 relieves it CENTRALLY (plain
//! PG + SQLite, no extensions, no TimescaleDB) by PREFIXING the dedup index
//! with a `shard_key` derived deterministically from a subset of the dedup
//! key — concurrent inserts spread across `TRACE_DEDUP_SHARD_COUNT` disjoint
//! B-tree subtrees.
//!
//! Project rule (NO pg/sqlite asymmetry): the shard column, the sharded
//! UNIQUE index, the FNV shard function, and the legacy backfill are
//! identical on both backends; only the SQL dialect differs. Both backends
//! run the SAME assertions:
//!
//! * `dedup_preserved_*` — the sharded index still dedups a re-ingest
//!   exactly (and does NOT falsely dedup a distinct trace).
//! * `legacy_backfill_*` — a simulated pre-V094 row (`shard_key = NULL`)
//!   gets the byte-identical shard on the next `run_migrations`, and a
//!   post-migration re-ingest of that trace still dedups against it.
//!
//! - Postgres is gated on `CIRIS_PERSIST_TEST_PG_URL` (plain `postgres:16`),
//!   self-isolating via a uuid agent_id_hash.
//! - SQLite uses an in-memory database.

#![cfg(all(feature = "postgres", feature = "sqlite"))]

use chrono::{DateTime, Utc};

use ciris_persist::schema::{ReasoningEventType, TraceLevel};
use ciris_persist::store::types::TraceEventRow;
use ciris_persist::store::{trace_dedup_shard_key_parts, Backend, VerificationSource};

/// A minimal `ACTION_RESULT` trace row for `insert_trace_events_batch`.
/// The dedup key is `(agent_id_hash, trace_id, thought_id, event_type,
/// attempt_index, ts)`; the shard derives from all but `ts`.
fn row(agent_hash: &str, trace_id: &str, thought_id: &str, ts: DateTime<Utc>) -> TraceEventRow {
    TraceEventRow {
        trace_id: trace_id.to_owned(),
        thought_id: thought_id.to_owned(),
        task_id: None,
        step_point: None,
        event_type: ReasoningEventType::ActionResult,
        attempt_index: 0,
        ts,
        agent_name: None,
        agent_id_hash: agent_hash.to_owned(),
        cognitive_state: None,
        trace_level: TraceLevel::Generic,
        payload: serde_json::Map::new(),
        cost_llm_calls: None,
        cost_tokens: None,
        cost_usd: None,
        signature: "c2ln".to_owned(),
        signing_key_id: "k1".to_owned(),
        signature_verified: true,
        verification_source: VerificationSource::Persist,
        schema_version: "2.7.0".to_owned(),
        pii_scrubbed: false,
        agent_role: None,
        agent_template: None,
        deployment_domain: None,
        deployment_type: None,
        deployment_region: None,
        deployment_trust_mode: None,
        original_content_hash: None,
        scrub_signature: None,
        scrub_key_id: None,
        scrub_timestamp: None,
        // v32.0.0 (#690) — no scrub ran here, so no claim is made.
        scrub_ner_ran: None,
        scrub_applied_trace_level: None,
        scrub_model_digest: None,
        cohort_scope: "federation".to_owned(),
        cohort_target_id: None,
        signature_ml_dsa_65: None,
        pubkey_ml_dsa_65: None,
        pqc_key_id: None,
    }
}

/// The shard the insert path / backfill must both produce for `row(...)`.
fn expected_shard(agent_hash: &str, trace_id: &str, thought_id: &str) -> i16 {
    trace_dedup_shard_key_parts(agent_hash, trace_id, thought_id, "ACTION_RESULT", 0)
}

/// Backend-agnostic dedup assertions (no raw SQL — pure `Backend` API).
async fn dedup_body<B: Backend>(backend: &B, agent_hash: &str) {
    let ts: DateTime<Utc> = "2026-04-30T00:16:00Z".parse().unwrap();
    let r = row(agent_hash, "t-1", "th-1", ts);

    // First insert lands.
    let rep = backend
        .insert_trace_events_batch(std::slice::from_ref(&r))
        .await
        .unwrap();
    assert_eq!(rep.inserted, 1, "first insert lands");

    // Re-ingest of the SAME dedup tuple → deduped by the sharded index
    // (the shard is deterministic, so the duplicate hits the same shard).
    let rep = backend
        .insert_trace_events_batch(std::slice::from_ref(&r))
        .await
        .unwrap();
    assert_eq!(rep.inserted, 0, "exact re-ingest MUST dedup");
    assert_eq!(rep.conflicted, 1, "re-ingest reported as conflict");

    // A distinct trace that differs ONLY in `ts` (same shard, different key)
    // is NOT a duplicate — the `ts` column in the index keeps them apart.
    let ts2: DateTime<Utc> = "2026-04-30T00:16:01Z".parse().unwrap();
    let r2 = row(agent_hash, "t-1", "th-1", ts2);
    let rep = backend.insert_trace_events_batch(&[r2]).await.unwrap();
    assert_eq!(
        rep.inserted, 1,
        "same shard but distinct ts MUST NOT be falsely deduped"
    );
}

#[tokio::test]
async fn sqlite_dedup_preserved_under_sharding() {
    let backend = ciris_persist::store::SqliteBackend::open_in_memory()
        .await
        .expect("open sqlite");
    backend.run_migrations().await.expect("sqlite migrations");
    dedup_body(&backend, "ah-sqlite").await;
}

#[tokio::test]
async fn sqlite_legacy_backfill_and_reingest_dedup() {
    let backend = ciris_persist::store::SqliteBackend::open_in_memory()
        .await
        .expect("open sqlite");
    backend.run_migrations().await.expect("sqlite migrations");

    let agent_hash = "ah-sqlite-legacy";
    let ts: DateTime<Utc> = "2026-04-30T00:16:00Z".parse().unwrap();
    let r = row(agent_hash, "t-legacy", "th-legacy", ts);
    backend
        .insert_trace_events_batch(std::slice::from_ref(&r))
        .await
        .unwrap();

    // Simulate a pre-V094 legacy row: null out its shard_key via raw SQL.
    let conn = backend.conn_handle();
    {
        let c = conn.lock();
        c.execute(
            "UPDATE trace_events SET shard_key = NULL WHERE trace_id = ?1",
            rusqlite::params!["t-legacy"],
        )
        .unwrap();
        let n: i64 = c
            .query_row(
                "SELECT COUNT(*) FROM trace_events WHERE shard_key IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(n, 1, "row is now NULL-shard (legacy)");
    }

    // Re-run migrations → refinery no-ops, the Rust backfill fills the NULL.
    backend
        .run_migrations()
        .await
        .expect("re-run runs backfill");

    let want = expected_shard(agent_hash, "t-legacy", "th-legacy");
    {
        let c = conn.lock();
        let got: i64 = c
            .query_row(
                "SELECT shard_key FROM trace_events WHERE trace_id = ?1",
                rusqlite::params!["t-legacy"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            got,
            i64::from(want),
            "backfill computed the insert-path shard"
        );
    }

    // A post-migration re-ingest of the legacy trace MUST dedup against the
    // now-backfilled row (this is the whole point of the backfill).
    let rep = backend.insert_trace_events_batch(&[r]).await.unwrap();
    assert_eq!(rep.inserted, 0, "re-ingest of backfilled legacy row dedups");
}

#[tokio::test]
async fn postgres_dedup_preserved_under_sharding() {
    let Some(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok() else {
        eprintln!(
            "postgres_dedup_preserved_under_sharding skipped: CIRIS_PERSIST_TEST_PG_URL unset"
        );
        return;
    };
    let backend = ciris_persist::store::PostgresBackend::connect(&dsn)
        .await
        .expect("connect postgres");
    backend.run_migrations().await.expect("pg migrations");
    let agent_hash = format!("ah-pg-{}", uuid::Uuid::new_v4().simple());
    dedup_body(&backend, &agent_hash).await;
}

#[tokio::test]
async fn postgres_legacy_backfill_and_reingest_dedup() {
    let Some(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok() else {
        eprintln!(
            "postgres_legacy_backfill_and_reingest_dedup skipped: CIRIS_PERSIST_TEST_PG_URL unset"
        );
        return;
    };
    let backend = ciris_persist::store::PostgresBackend::connect(&dsn)
        .await
        .expect("connect postgres");
    backend.run_migrations().await.expect("pg migrations");

    let agent_hash = format!("ah-pg-legacy-{}", uuid::Uuid::new_v4().simple());
    let trace_id = format!("t-legacy-{}", uuid::Uuid::new_v4().simple());
    let ts: DateTime<Utc> = "2026-04-30T00:16:00Z".parse().unwrap();
    let r = row(&agent_hash, &trace_id, "th-legacy", ts);
    backend
        .insert_trace_events_batch(std::slice::from_ref(&r))
        .await
        .unwrap();

    // Simulate a pre-V094 legacy row: null out its shard_key via raw SQL on
    // a pooled connection.
    let pool = backend.pool();
    {
        let client = pool.get().await.unwrap();
        let n = client
            .execute(
                "UPDATE cirislens.trace_events SET shard_key = NULL WHERE trace_id = $1",
                &[&trace_id],
            )
            .await
            .unwrap();
        assert_eq!(n, 1, "one legacy row nulled");
    }

    // Re-run migrations → the Rust backfill fills the NULL shard.
    backend
        .run_migrations()
        .await
        .expect("re-run runs backfill");

    let want = expected_shard(&agent_hash, &trace_id, "th-legacy");
    {
        let client = pool.get().await.unwrap();
        let got: i16 = client
            .query_one(
                "SELECT shard_key FROM cirislens.trace_events WHERE trace_id = $1",
                &[&trace_id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(got, want, "backfill computed the insert-path shard");
    }

    // Post-migration re-ingest of the legacy trace dedups against the row.
    let rep = backend.insert_trace_events_batch(&[r]).await.unwrap();
    assert_eq!(rep.inserted, 0, "re-ingest of backfilled legacy row dedups");
}
