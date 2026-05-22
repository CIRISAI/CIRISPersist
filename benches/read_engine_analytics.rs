//! ReadEngine analytical-query scaling (v1.10.x bench-coverage cut).
//!
//! Seeds an in-memory `SqliteBackend` `trace_events` table at
//! parameterized row counts, then benches the three headline
//! `ReadEngine` primitives:
//!
//! - `list_trace_summaries` — `GROUP BY trace_id` triage list.
//! - `aggregate_llm_costs`  — cost rollup over the trace corpus.
//! - `cross_agent_divergence` — per-agent z-score over a metric.
//!
//! The point is the **size sweep** (1k / 10k / 25k rows): a query that
//! is fine at 1k but quadratic at 25k shows up here as a slope, which
//! catches a missing-index or N+1 regression that a single-size bench
//! would miss. The top size is capped at 25k — 100k pushed the CI
//! seed cost past the bench job's budget.
//!
//! # Expected curve
//!
//! All three primitives are **linear scans** of `trace_events` — the
//! 10k→25k segment (the asymptotic regime) grows in lock-step with
//! row count (measured ~2.5× time for the 2.5× row step on a quiet
//! box). The **1k point sits above the asymptotic line**: it is
//! fixed-overhead-bound (connection-mutex acquire + `spawn_blocking`
//! hop + statement prep dominate when there is little data), so
//! 1k→10k looks sub-linear. That two-regime shape is expected and
//! stable — a regression is a *slope* change in the 10k→25k segment,
//! or the whole curve shifting up. `SamplingMode::Flat` keeps the
//! per-point CIs to ~±1% so a real slope change is unambiguous (an
//! earlier linear-sampling run reported a spurious "superlinear"
//! `cross_agent_divergence` that flat sampling showed was noise).

use chrono::{DateTime, TimeZone, Utc};
use ciris_persist::read::{DeviationMetric, LlmCallFilter, ReadEngine, TimeWindow, TraceFilter};
use ciris_persist::schema::{ReasoningEventType, TraceLevel};
use ciris_persist::store::sqlite::SqliteBackend;
use ciris_persist::store::types::TraceEventRow;
use ciris_persist::store::Backend;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode};

/// Row counts to sweep. 25k is the ceiling — see module docs.
const SIZES: &[usize] = &[1_000, 10_000, 25_000];

/// Build one `trace_events` row. Mirrors the `re_event` test helper in
/// `src/store/sqlite.rs` — cost columns + deployment_domain populated
/// so `aggregate_llm_costs` and `cross_agent_divergence` have data to
/// chew on.
#[allow(clippy::too_many_arguments)] // a bench fixture builder — flat arg list mirrors TraceEventRow
fn bench_event(
    trace_id: &str,
    thought_id: &str,
    event_type: ReasoningEventType,
    ts: DateTime<Utc>,
    agent_id_hash: &str,
    agent_name: &str,
    domain: &str,
    payload: serde_json::Map<String, serde_json::Value>,
) -> TraceEventRow {
    TraceEventRow {
        trace_id: trace_id.to_owned(),
        thought_id: thought_id.to_owned(),
        task_id: Some(format!("task-{trace_id}")),
        step_point: None,
        event_type,
        attempt_index: 0,
        ts,
        agent_name: Some(agent_name.to_owned()),
        agent_id_hash: agent_id_hash.to_owned(),
        cognitive_state: Some("WORK".to_owned()),
        trace_level: TraceLevel::Generic,
        payload,
        cost_llm_calls: Some(2),
        cost_tokens: Some(150),
        cost_usd: Some(0.01),
        signature: "sig".to_owned(),
        signing_key_id: "key-1".to_owned(),
        signature_verified: true,
        verification_source: ciris_persist::store::types::VerificationSource::Persist,
        schema_version: "2.7.0".to_owned(),
        pii_scrubbed: true,
        agent_role: Some("ally".to_owned()),
        agent_template: Some("ally-v3".to_owned()),
        deployment_domain: Some(domain.to_owned()),
        deployment_type: Some("production".to_owned()),
        deployment_region: Some("us-east".to_owned()),
        deployment_trust_mode: None,
        original_content_hash: Some("hash".to_owned()),
        scrub_signature: Some("scrub-sig".to_owned()),
        scrub_key_id: Some("scrub-key".to_owned()),
        scrub_timestamp: None,
    }
}

/// Seed a fresh migrated in-memory backend with `n_traces` traces, each
/// a 3-event trace (THOUGHT_START + DMA_RESULTS + CONSCIENCE_RESULT) so
/// every read primitive under bench has real shape to scan.
///
/// Rows spread across **24 agents in one `deployment_domain`**. The
/// agent cardinality is load-bearing for `cross_agent_divergence`: an
/// earlier 2-agent seed was degenerate — with only 2 groups the SQLite
/// planner picked a tiny skip-scan over the V042 covering index (the
/// `GROUP BY` temp B-tree was effectively free), so the bench could
/// not observe the covering-index optimisation at all. 24 agents is a
/// realistic per-domain federation population and makes the bench
/// measure the query shape V042 actually targets.
async fn seed_backend(n_traces: usize) -> SqliteBackend {
    const N_AGENTS: usize = 24;
    let backend = SqliteBackend::open_in_memory().await.unwrap();
    backend.run_migrations().await.unwrap();
    let base = Utc.with_ymd_and_hms(2026, 5, 1, 12, 0, 0).unwrap();

    // Insert in batches so a 25k-trace seed doesn't build one giant
    // 75k-row Vec — keeps peak memory bounded.
    let mut batch: Vec<TraceEventRow> = Vec::with_capacity(3 * 256);
    for i in 0..n_traces {
        let trace_id = format!("trace-{i:06}");
        let thought_id = format!("{trace_id}-th");
        let ts = base + chrono::Duration::seconds(i as i64);
        let agent_idx = i % N_AGENTS;
        let agent_hash = format!("agenthash-{agent_idx:02}");
        let agent_name = format!("agent-{agent_idx:02}");
        let domain = "research";

        batch.push(bench_event(
            &trace_id,
            &thought_id,
            ReasoningEventType::ThoughtStart,
            ts,
            &agent_hash,
            &agent_name,
            domain,
            serde_json::Map::new(),
        ));
        let mut dma = serde_json::Map::new();
        // csdma score varies a little per agent so divergence has signal.
        dma.insert(
            "csdma_plausibility_score".to_owned(),
            serde_json::json!(0.5 + (agent_idx as f64) * 0.2 + ((i % 7) as f64) * 0.01),
        );
        batch.push(bench_event(
            &trace_id,
            &thought_id,
            ReasoningEventType::DmaResults,
            ts,
            &agent_hash,
            &agent_name,
            domain,
            dma,
        ));
        let mut con = serde_json::Map::new();
        let overridden = i % 5 == 0;
        con.insert(
            "conscience_passed".to_owned(),
            serde_json::json!(!overridden),
        );
        con.insert(
            "action_was_overridden".to_owned(),
            serde_json::json!(overridden),
        );
        batch.push(bench_event(
            &trace_id,
            &thought_id,
            ReasoningEventType::ConscienceResult,
            ts + chrono::Duration::seconds(1),
            &agent_hash,
            &agent_name,
            domain,
            con,
        ));

        if batch.len() >= 3 * 256 {
            backend
                .insert_trace_events_batch(&std::mem::take(&mut batch))
                .await
                .unwrap();
            batch.reserve(3 * 256);
        }
    }
    if !batch.is_empty() {
        backend.insert_trace_events_batch(&batch).await.unwrap();
    }
    backend
}

fn read_engine_analytics(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    // The analytical time window spans the whole seeded corpus.
    let window = TimeWindow::new(
        Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap(),
        Utc.with_ymd_and_hms(2026, 5, 2, 0, 0, 0).unwrap(),
    )
    .unwrap();

    let mut group = c.benchmark_group("read_engine_analytics");
    // Seeding 25k traces (75k rows) is the dominant cost; lower the
    // sample count so the bench job stays inside its budget. The seed
    // itself is in `iter_batched` setup, NOT measured — but the
    // backend is rebuilt per sample, so fewer samples = less seed time.
    group.sample_size(20);
    // Flat sampling — every query here runs in milliseconds-to-
    // hundreds-of-ms; criterion's default linear sampling produces
    // wide, noisy confidence intervals for ops that slow (it can fit
    // only ~1 iteration per sample). Flat sampling is criterion's
    // recommended mode for slow benchmarks and yields the tight,
    // comparable curve a regression/leak baseline needs.
    group.sampling_mode(SamplingMode::Flat);

    for &size in SIZES {
        // list_trace_summaries — GROUP BY trace_id, newest-first page.
        group.bench_with_input(
            BenchmarkId::new("list_trace_summaries", size),
            &size,
            |b, &size| {
                b.iter_batched(
                    || runtime.block_on(seed_backend(size)),
                    |backend| {
                        runtime.block_on(async {
                            let page = backend
                                .list_trace_summaries(TraceFilter::default(), None, 100)
                                .await
                                .unwrap();
                            black_box(page);
                        });
                    },
                    criterion::BatchSize::PerIteration,
                );
            },
        );

        // aggregate_llm_costs — cost rollup over the corpus.
        group.bench_with_input(
            BenchmarkId::new("aggregate_llm_costs", size),
            &size,
            |b, &size| {
                b.iter_batched(
                    || runtime.block_on(seed_backend(size)),
                    |backend| {
                        runtime.block_on(async {
                            let agg = backend
                                .aggregate_llm_costs(LlmCallFilter::default())
                                .await
                                .unwrap();
                            black_box(agg);
                        });
                    },
                    criterion::BatchSize::PerIteration,
                );
            },
        );

        // cross_agent_divergence — per-agent z-score over csdma score.
        group.bench_with_input(
            BenchmarkId::new("cross_agent_divergence", size),
            &size,
            |b, &size| {
                b.iter_batched(
                    || runtime.block_on(seed_backend(size)),
                    |backend| {
                        runtime.block_on(async {
                            let rows = backend
                                .cross_agent_divergence(
                                    "research",
                                    window,
                                    DeviationMetric::CsdmaPlausibility,
                                )
                                .await
                                .unwrap();
                            black_box(rows);
                        });
                    },
                    criterion::BatchSize::PerIteration,
                );
            },
        );
    }
    group.finish();
}

criterion_group!(benches, read_engine_analytics);
criterion_main!(benches);
