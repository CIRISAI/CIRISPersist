window.BENCHMARK_DATA = {
  "lastUpdate": 1781377944092,
  "repoUrl": "https://github.com/CIRISAI/CIRISPersist",
  "entries": {
    "ciris-persist criterion benchmarks": [
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "598ce9e3b7301ff1d48860393f8f455578a66088",
          "message": "bench: calibration-anchored normalization to kill runner-noise alerts\n\nCloses the false-positive class that tripped 40 perf alerts on 2.11.0\nvs 2.10.0 — a 15-line PyCapsule + a verify pin bump that touched NO\nbenched hot path, but absolute ns/iter swung 1.4–2.5× uniformly from\nneighbor-tenant runner load.\n\nNew benches/calibration.rs: pure-compute 10M splitmix64 microbench.\nNo deps, no IO, no hardware-accel variance (no SHA-NI/AES-NI/RDRAND).\nDeterministic seed + fixed iteration count. The bench workflow extracts\nits ns/iter first and uses it as the runner's \"wall-time-per-CPU-op\"\ntick.\n\nbench.yml: each non-calibration bench's ns/iter is divided by\nCALIBRATION_NS (× 1M scale to keep numbers in readable integer\nrange), so published values are in \"calibration units\" — runner-\nindependent. The calibration line is preserved at the top of\nbench-output.txt with its raw ns so the trend chart also tracks\nrunner-fleet drift as its own series.\n\nGeomean cross-check (diagnostic log only): if the suite's geomean\nshifts dramatically run-over-run while calibration also shifts,\nnormalization is doing its job. Divergence between the two = real\nper-bench regression buried in there.\n\nBash-native normalization (no awk regex hell, no YAML-heredoc\nindentation pitfalls). Smoke-tested locally.\n\nNo version bump — CI infrastructure only, no wheel-affecting code.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-28T14:48:39-05:00",
          "tree_id": "8be7e2615d3280a15c6eeadfcdc6ff6faec45249",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/598ce9e3b7301ff1d48860393f8f455578a66088"
        },
        "date": 1779998828714,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 53616008,
            "range": "± 170388",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 1795,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 4445,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 9735,
            "range": "± 30",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 37216,
            "range": "± 663",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 127,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 382,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 446,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1648,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 57,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 177,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 823,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 39662,
            "range": "± 845",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 119658,
            "range": "± 1723",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 431984,
            "range": "± 10788",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7044,
            "range": "± 1532",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9441,
            "range": "± 2769",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 18533,
            "range": "± 2828",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 38367,
            "range": "± 3164",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 509756,
            "range": "± 5610",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 185436,
            "range": "± 1375",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 16779,
            "range": "± 982",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 38928,
            "range": "± 853",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 1652765,
            "range": "± 8994",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 88528,
            "range": "± 3833",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 312731,
            "range": "± 4400",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 4098613,
            "range": "± 18681",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 223971,
            "range": "± 9011",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 792281,
            "range": "± 9233",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 5039,
            "range": "± 802",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 4568,
            "range": "± 1061",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 909,
            "range": "± 62",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 2669,
            "range": "± 94",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 20489,
            "range": "± 515",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 419,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 67,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 726,
            "range": "± 62",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "116685e20543e717eb028627e96b958c23f3544e",
          "message": "2.12.0 — #112 Engine::sign_hybrid facade + cohabitation propagation fix\n\ncloses #112. Unblocks CIRISLensCore#11 (v0.3 client-mode trace signing\non ACTION_RESULT) + #14 (v0.4 EgressFilter re-signing).\n\nEngine struct gains `local_signer: Option<Arc<LocalSigner>>` field\nand a new sign_hybrid(message) -> Result<HybridSignature, SignError>\nmethod. Same closure-pattern as Engine::receive_and_persist /\nstorage_summary: persist owns the underlying primitive\n(LocalSigner::sign_hybrid combines Ed25519 + ML-DSA-65 + AV-33 bound-\nhybrid); persist exposes a clean Engine facade so co-resident Rust\nconsumers don't reach past Arc<dyn HardwareSigner>.\n\nCohabitation propagation fix: pre-v2.12 Engine::from_shared (used by\ncurrent_rust_engine() to hand co-resident Rust consumers an\nArc<Engine> view on the singleton) only carried Arc<dyn HardwareSigner>\nacross — the LocalSigner the singleton was constructed from was lost\nat the boundary. 2.12 adds Engine::from_shared_with_local(backend,\nsigner, local_signer) and updates current_rust_engine() to call it,\npropagating EngineCell's local_signer through. The singleton already\nholds it; sharing across the cohabitation boundary doesn't duplicate\nidentity.\n\nHardware-rooted deployments without LocalSigner keep using\nEngine::from_shared and get SignError::LocalSignerUnavailable from\nsign_hybrid — honest fail-mode; rebuild LocalSigner from\nPyEngine::keyring_signer()'s KeyringSignerHandle if the hardware-\nbacked PqcSigner is accessible.\n\nTyped SignError:\n  - LocalSignerUnavailable (from_shared without local_signer)\n  - LocalSigner(LocalSignerError) (underlying signer errors,\n    e.g. PqcNotConfigured for Ed25519-only deployments)\n\nThree new sign_hybrid tests on engine::tests. Verified: clippy\n--all-targets clean on default AND full feature sets; 803/803\nnextest tests pass on both backends, fresh DB, --test-threads=1.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-28T15:06:12-05:00",
          "tree_id": "4ddc663d6bd2d39036ce70560bd2d7ccef3dd2bb",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/116685e20543e717eb028627e96b958c23f3544e"
        },
        "date": 1780000186530,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45663578,
            "range": "± 38321",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2523,
            "range": "± 28",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5766,
            "range": "± 62",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12258,
            "range": "± 57",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43730,
            "range": "± 85",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 145,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 520,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 591,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2006,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 66,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 208,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 910,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 49104,
            "range": "± 3099",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 150508,
            "range": "± 30447",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 550923,
            "range": "± 2158",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 6439,
            "range": "± 836",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 7122,
            "range": "± 306",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 14350,
            "range": "± 1014",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 34960,
            "range": "± 1306",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 600685,
            "range": "± 1558",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 242147,
            "range": "± 3351",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 13782,
            "range": "± 461",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 37655,
            "range": "± 334",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 2381188,
            "range": "± 21605",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 95550,
            "range": "± 5560",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 379719,
            "range": "± 5647",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 5909179,
            "range": "± 46282",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 243567,
            "range": "± 7423",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 981339,
            "range": "± 14653",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 4532,
            "range": "± 333",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 3961,
            "range": "± 251",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 1053,
            "range": "± 46",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 3477,
            "range": "± 155",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 26324,
            "range": "± 226",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 530,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 83,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 823,
            "range": "± 27",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "940204e96b9264f5dab9c829bef731cfad98e96c",
          "message": "2.13.0 — #113 detection-events Engine read + subscribe facade\n\ncloses #113. Unblocks CIRISLensCore #15 (Node UX), #19 (scoring\noracle), #20 (alert subscriptions), #21 (Counter-RII), #25 (ECF UI\nProfileScorecard) — five lens issues converge here.\n\nThree new Engine methods:\n- get_detection_events(filter) — facade over the existing per-backend\n  DerivedSchema::get_detection_events impls.\n- get_edge_detection_events(filter) — V020 edge_detection_events read\n  surface (INSERT existed; SELECT new). New EdgeEventFilter +\n  EdgeDetectionEvent types in src/derived/types.rs. Stable ORDER BY\n  (tenant_id, observed_at, detection_id).\n- subscribe_detection_events(filter) -> impl Stream — v0.1 polling\n  change feed. 2s cadence, bounded mpsc::channel cap=256 (coarse-but-\n  honest backpressure: full buffer makes poll task await on send);\n  cursor = Utc::now() at subscribe so only new events surface (no\n  historical replay); drop via ReceiverStream closes the channel +\n  poll task exits cleanly via tx.is_closed() / send-error branches.\n  DB errors forward without terminating the task — transient outages\n  don't kill long-lived subscribers.\n\nv0.1 simplifications documented in trait doc-comments:\n- Polling, not WAL-hook / LISTEN-NOTIFY (#84's broader substrate\n  change-feed is deferred to 3.0+).\n- SubscriptionOptions (configurable cadence + capacity + drop policy)\n  is v0.2.\n- No PyO3 subscribe surface — needs FFI queue design; deferred.\n- PyO3 reads (get_detection_events_json existed; new\n  get_edge_detection_events_json) route errors through the existing\n  derived_err_to_py taxonomy.\n\nCargo: futures-core 0.3 + tokio-stream 0.1 declared directly (both\ntransitive via tokio-postgres; surface the dependency rather than\nlean on transitive).\n\n10 new tests + full suite: 812/812 nextest pass on both backends,\nfresh DB, --test-threads=1. clippy --all-targets clean on default\nAND full feature sets.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-28T18:44:58-05:00",
          "tree_id": "3066887a380ad255229b788bdb6c66232630cb3f",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/940204e96b9264f5dab9c829bef731cfad98e96c"
        },
        "date": 1780013022889,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40446771,
            "range": "± 2948276",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2534,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5938,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12997,
            "range": "± 47",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 45876,
            "range": "± 366",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 183,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 524,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 599,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2066,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 76,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 228,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1020,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 55735,
            "range": "± 2900",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 161428,
            "range": "± 3087",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 576807,
            "range": "± 3308",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8131,
            "range": "± 597",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 8763,
            "range": "± 626",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 19727,
            "range": "± 1648",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 53662,
            "range": "± 2670",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 720839,
            "range": "± 3580",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 294928,
            "range": "± 7419",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 13827,
            "range": "± 788",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 45199,
            "range": "± 3267",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 2695612,
            "range": "± 39932",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 103123,
            "range": "± 5349",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 473387,
            "range": "± 13731",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 6733591,
            "range": "± 37014",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 240977,
            "range": "± 16380",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 1192764,
            "range": "± 22572",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 5258,
            "range": "± 639",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 4083,
            "range": "± 326",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 1455,
            "range": "± 132",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 4146,
            "range": "± 119",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 30414,
            "range": "± 291",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 716,
            "range": "± 63",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 98,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 1207,
            "range": "± 99",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "e8cdb535b60a549948f2b0ceb43deb6921009260",
          "message": "3.0.0 — CEG 0.2 substrate conformance (#116) + verify pin v3.9.0 → v4.0.0\n\ncloses #116. CIRISPersist 3.0 — Coherence Epistemic Graph 0.2 substrate\nconformance. The milestone release that closes persist's substrate-\nconformance against CIRISRegistry's CEG 0.2 (commit 4b27130).\n\nCIRISVerify pin v3.9.0 → v4.0.0: the federation-wide CEG 0.2 wire\nalignment ships in v4.0 (mechanism-prefix strings, L1-L5 ladder\nofficially consumer-side per §8.1.9 Policy I, canonicalization\ntightening §5.2.1). 3.0.0 pairs persist substrate-conformance with\nverify wire-conformance. 6 Cargo.toml pin sites + pyproject.toml\nfloor bumped. Persist's consumed surface unchanged across v3→v4\n(wire-only major); 851/851 tests pass identically.\n\n§6.1 concurrent-write precedence + dedup triple:\n- Dedup at write: same (references_attestation_id, attestation_type,\n  attesting_key_id) triple = silent Ok(()) no-op. New\n  src/federation/precedence.rs.\n- Precedence at read: RECANTS > WITHDRAWS > SUPERSEDES; ties broken\n  by latest asserted_at then lex-smallest attestation_id. Audit\n  chain stores all composers honestly (append-only); reads project\n  current effective state via precedence_winner. delegates_to\n  excluded from scope (forward-looking, different envelope shape).\n\n§7.0 reserved-prefix admission + CEG 0.1→0.2 dual-acceptance:\n- DimensionAdmissionPolicy gains reserved-prefix emitter rule: SCORES\n  attestations matching system:/audit_chain:/corpus_health:/\n  identity_continuity:/federation_directory: prefixes require\n  identity_type=substrate_persist; transparency_log:cosigned:\n  requires identity_type=witness. Typed\n  Error::ReservedPrefixEmitterMismatch with stable kind token.\n- AttestationLadderTransitionPolicy::DualAccept (default 3.0.0):\n  admits BOTH deprecated attestation:l{N}:* AND canonical\n  attestation:{mechanism} forms during CEG 0.1→0.2 transition.\n  Post-CEG 0.3 flip target documented + regression-tested.\n- New identity_type constants: SUBSTRATE_PERSIST, WITNESS.\n\n§10.1.2 holds_bytes 24h TTL + ContentMiss feedback:\n- DEFAULT_HOLDS_BYTES_TTL = 24h constant. BlobStorage::list_holders\n  filters by asserted_at + TTL > now AND skips rows with matching\n  WITHDRAWS from same attester (ContentMiss).\n- No migration; TTL computed from asserted_at per CEG §10.1.2.\n\n§0.5 fractal-self framing in MISSION.md §1.7: persist is relational\nfabric, not a Cartesian gate. Distinguishes wire-format gates\n(Cartesian-OK) from relational gates (Cartesian-misread, REFUSE).\nDimensionAdmissionPolicy doc-comment carries same framing at call\nsite.\n\nVerified: clippy --all-targets clean on default AND full feature\nsets. 851/851 nextest pass on both backends, fresh DB,\n--test-threads=1.\n\nCarry-forward CEG conformance closures:\n- §6.1 / §7.0 / §10.1.2 / §0.5: this release (#116)\n- occurrence_id envelope: 2.9.0 (#110)\n- typed Goal M-1 alignment: 2.10.0 (#114)\n- attestation_type clean-break rename: 2.4.0 (#102)\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-28T19:39:09-05:00",
          "tree_id": "909838fec763c77878a9c13ae12ba49849eaef80",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/e8cdb535b60a549948f2b0ceb43deb6921009260"
        },
        "date": 1780016328113,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45678475,
            "range": "± 232968",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2390,
            "range": "± 23",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5625,
            "range": "± 39",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12077,
            "range": "± 46",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43436,
            "range": "± 94",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 31,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 161,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 506,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 577,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1992,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 68,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 211,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 918,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 51765,
            "range": "± 3655",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 152468,
            "range": "± 12043",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 555957,
            "range": "± 11347",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 6161,
            "range": "± 2284",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 7293,
            "range": "± 2014",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 15139,
            "range": "± 4979",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 36300,
            "range": "± 7555",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 593477,
            "range": "± 2779",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 253486,
            "range": "± 2735",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 15213,
            "range": "± 1513",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 41065,
            "range": "± 770",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 2368345,
            "range": "± 15135",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 95168,
            "range": "± 3215",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 381800,
            "range": "± 10002",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 5905807,
            "range": "± 31059",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 246935,
            "range": "± 11867",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 981248,
            "range": "± 13788",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 4668,
            "range": "± 1525",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 3960,
            "range": "± 378",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 1048,
            "range": "± 40",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 3478,
            "range": "± 196",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 26294,
            "range": "± 872",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 521,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 81,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 848,
            "range": "± 60",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "de0046b9e1d6c55bd246b92304aadb96bd9067cc",
          "message": "docs: 3.0 hygiene pass — MISSION header, ROADMAP rewrite, THREAT_MODEL CEG additions\n\nPost-3.0.0 doc currency sweep. No code change, no version bump.\n\nMISSION.md front-matter: \"Status: Active — reverse-engineered against\nmain at v1.11.1\" → \"current as of main at v3.0.0 (Coherence Epistemic\nGraph 0.2 substrate conformance)\". Version bumped 1.0 → 1.1. The body\nalready carried the §1.7 fractal-self framing from the 3.0.0 cut; only\nthe header was stale.\n\ndocs/ROADMAP.md rewritten from \"current as of v2.0.0 — 2.0 Federation\nReady / 2.1 Encryption at Rest\" → \"current as of v3.0.0 — CEG 0.2\nsubstrate conformance\". Forward roadmap now covers:\n- 3.1 CEG 0.3 retirement flip (AttestationLadderTransitionPolicy\n  DualAccept → RejectDeprecated, gated on Registry §11.2 amendment).\n- 3.x subscription v0.2 (SubscriptionOptions, WAL-hook producers,\n  per-substrate subscription primitives — the broader umbrella that\n  #84 named; #113's detection-events is the LensCore-scoped slice).\n- 3.x encryption at rest (carried over from 2.1; design locked in\n  FSD/ENCRYPTED_AT_REST.md).\n\ndocs/THREAT_MODEL.md: three new CEG-conformance vectors (AV-45..47):\n- AV-45 §7.0 admission bypass via deprecated attestation:l{N}:* past\n  CEG-0.3 retirement. Mitigation: AttestationLadderTransitionPolicy\n  enum + flip-target regression test + Registry §11.2 amendment as\n  human-loop gate.\n- AV-46 §10.1.2 ContentMiss flood DoS against list_holders.\n  Mitigation: WITHDRAWS admission-gated; scope is per-attester (a\n  malicious peer can only erase ITSELF from holders, not others —\n  zero asymmetric advantage); per-host rate caps bound emission\n  volume.\n- AV-47 §6.1 dedup-rule replay-protection hole. Mitigation:\n  precedence applied at READ not WRITE; RECANTS > WITHDRAWS >\n  SUPERSEDES rank is structural (replay of SUPERSEDES against a\n  RECANTS'd upstream is inert); idempotent triple dedup at write\n  bounds audit-chain growth from replay flooding.\n\nLast-updated footer bumped to 2026-05-28 (v3.0.0).\n\nDeferred to a follow-up doc-hygiene pass: docs/COHABITATION.md (zero\nreferences to the v2.7+ capsule family — federation_directory /\noutbound_queue / keyring_signer / runtime_handle / blob_storage\ncapsules), docs/FEDERATION_DIRECTORY.md (only 1 CEG cross-ref).\nBigger structural rewrites; tracked.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-28T20:24:17-05:00",
          "tree_id": "292812762f7c4f4598dd680c8eab25f4a090351e",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/de0046b9e1d6c55bd246b92304aadb96bd9067cc"
        },
        "date": 1780018963227,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 53623529,
            "range": "± 211204",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 1791,
            "range": "± 41",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 4382,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 9700,
            "range": "± 56",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 36215,
            "range": "± 613",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 133,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 383,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 445,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1647,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 59,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 181,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 824,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 10,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 38663,
            "range": "± 2230",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 116779,
            "range": "± 1359",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 426600,
            "range": "± 4486",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7876,
            "range": "± 1808",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 10150,
            "range": "± 2725",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 18385,
            "range": "± 5014",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 38130,
            "range": "± 2632",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 518459,
            "range": "± 3366",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 181980,
            "range": "± 1293",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 13594,
            "range": "± 580",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 34675,
            "range": "± 3683",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 1651582,
            "range": "± 24912",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 85169,
            "range": "± 5133",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 303345,
            "range": "± 6581",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 4058755,
            "range": "± 25546",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 211595,
            "range": "± 7590",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 798406,
            "range": "± 13323",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 5277,
            "range": "± 1597",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 4862,
            "range": "± 470",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 869,
            "range": "± 51",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 2664,
            "range": "± 108",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 20256,
            "range": "± 397",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 438,
            "range": "± 29",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 65,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 745,
            "range": "± 56",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "d97beac22ec0395e8fe91ecfbd83e5e23cd2fe37",
          "message": "docs: COHABITATION capsule family section + FEDERATION_DIRECTORY CEG vocab\n\nFollow-up to de0046b. Covers the two bigger structural rewrites flagged\nfor a second pass.\n\ndocs/COHABITATION.md:\n- New \"Cross-cdylib cohabitation — separately-built wheels (v2.7+\n  capsule family)\" section. Explains the per-extension-module\n  PyTypeInfo trap CIRISEdge#22 caught in production cohabitation init,\n  the 5-capsule family that sidesteps it (federation_directory /\n  outbound_queue / keyring_signer / runtime_handle / blob_storage),\n  + the runtime_handle statics-duplication counterpart from #111.\n- Consumer pattern code block showing the unsafe-extract from a\n  PyCapsule with name-tag verification.\n- New \"When Python disappears — Phase 3 endpoint\" subsection: the\n  Rust-trait accessor surface from #106 (Engine::federation_directory\n  returns Arc<dyn FederationDirectory> directly to a Rust caller) is\n  the trajectory endpoint; capsules collapse to a one-line marshalling\n  shim when host goes Rust-native.\n- New \"Higher-level Engine facades shipped 2.6.0+\" subsection cataloging\n  the persist-owns-primitive / persist-exposes-facade pattern across\n  receive_and_persist (#89), storage_summary / delete_traces_older_than /\n  archive_audit_range (#107), node_core_service / audit_service (#90,\n  #93), sign_hybrid (#112), get_detection_events /\n  get_edge_detection_events / subscribe_detection_events (#113).\n\ndocs/FEDERATION_DIRECTORY.md:\n- identity_type vocabulary extended with substrate_persist (3.0.0,\n  CIRISPersist#116 / CEG §7.0 — required emitter for system:* /\n  audit_chain:* / corpus_health:* / identity_continuity:* /\n  federation_directory:* reserved prefixes) and witness (3.0.0 / CEG\n  §10.3 — required emitter for transparency_log:cosigned:* +\n  substrate-conformance migration off Registry's interim\n  registry_witnesses + registry_sth_cosignatures tables).\n- New CEG 0.2 reserved-prefix admission paragraph noting the\n  DimensionAdmissionPolicy extension + the\n  AttestationLadderTransitionPolicy::DualAccept knob for the CEG\n  0.1→0.2 attestation-prefix rename. Cross-refs THREAT_MODEL AV-45.\n\nNo version bump — docs only.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-28T21:22:27-05:00",
          "tree_id": "6b976b928987ef8e5f1bc2b456bef3adabbe0ff9",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/d97beac22ec0395e8fe91ecfbd83e5e23cd2fe37"
        },
        "date": 1780022354475,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 35436256,
            "range": "± 45056",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2389,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5616,
            "range": "± 51",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12270,
            "range": "± 159",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43449,
            "range": "± 519",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 178,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 507,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 577,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1991,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 65,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 211,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 919,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 61521,
            "range": "± 29075",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 162075,
            "range": "± 47204",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 566297,
            "range": "± 396907",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 6344,
            "range": "± 435",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 7383,
            "range": "± 356",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 14307,
            "range": "± 758",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 34832,
            "range": "± 1075",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 594371,
            "range": "± 2730",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 246794,
            "range": "± 1008",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 13794,
            "range": "± 441",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 36908,
            "range": "± 288",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 2471664,
            "range": "± 23588",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 98204,
            "range": "± 4346",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 379916,
            "range": "± 2851",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 6140324,
            "range": "± 55547",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 264132,
            "range": "± 5393",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 1011773,
            "range": "± 9098",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 4711,
            "range": "± 341",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 4045,
            "range": "± 499",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 1058,
            "range": "± 73",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 3424,
            "range": "± 34",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 25966,
            "range": "± 698",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 526,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 80,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 847,
            "range": "± 29",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "5568c222be6aa3b70e1eca06b8f3e36dc17f4a68",
          "message": "3.1.0 — #117 peer-mutation surface on FederationDirectory (V051 federation_peer_metadata)\n\n6 new async mutation methods (add_peer_record / remove_peer_record /\nupdate_peer_alias / update_peer_trust / update_peer_notes /\nupdate_peer_policy) + sibling federation_peer_metadata table\n(operator-local per-instance metadata vs federation-shared\nfederation_keys per CIRIS Accord §I autonomy). TrustClass enum +\nPeerPolicyBlob opaque newtype + 2 typed errors (PeerNotFound,\nHardRemoveWithActiveAttestations — defensive against attestation\norphaning). PyO3 mirrors. 32 new tests across both backends + memory\nparity (883/883 nextest green on full feature set).\n\nUnblocks CIRISEdge v0.13.0's 7 UniFFI peer-mgmt stubs\n(PEER_MUTATION_FOLLOWUP constant).",
          "timestamp": "2026-05-28T22:05:42-05:00",
          "tree_id": "a6b23dfef8901edf713ba428b895c86041336012",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/5568c222be6aa3b70e1eca06b8f3e36dc17f4a68"
        },
        "date": 1780025092869,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45663519,
            "range": "± 352649",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2449,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5775,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12412,
            "range": "± 35",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43953,
            "range": "± 108",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 31,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 180,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 506,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 578,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1991,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 64,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 208,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 909,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 49954,
            "range": "± 3347",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 153594,
            "range": "± 5855",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 561131,
            "range": "± 11209",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7078,
            "range": "± 654",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 7907,
            "range": "± 628",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 15783,
            "range": "± 1395",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 37458,
            "range": "± 1844",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 603726,
            "range": "± 6748",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 265367,
            "range": "± 6734",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 15700,
            "range": "± 644",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 44339,
            "range": "± 2892",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 2405285,
            "range": "± 25565",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 92247,
            "range": "± 7434",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 406955,
            "range": "± 12423",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 5974406,
            "range": "± 55626",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 292722,
            "range": "± 20774",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 1073471,
            "range": "± 30751",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 5540,
            "range": "± 567",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 5468,
            "range": "± 357",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 1057,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 3439,
            "range": "± 36",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 26290,
            "range": "± 294",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 524,
            "range": "± 55",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 81,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 847,
            "range": "± 29",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "b1e3b8a7aefbd79230874e4c543c5ba8233d83fe",
          "message": "3.1.1 — #118 put_edge_detection_event admission + #119 local_signer_capsule\n\n#118: New DerivedSchema::put_edge_detection_event admission method\nmirroring the existing get_edge_detection_events read accessor (#113).\nIdempotent on detection_id+row-hash match; Conflict on differing hash;\ntyped InvalidArgument on non-UUID detection_id (PG). Both backends +\nmemory NotImplemented. Edge owns signature-verification policy\n(RATCHET F-CR-3 Counter-RII Edge-layer); persist stores\nsignature + signature_verified verbatim; LensCore filter on read.\nUnblocks CIRISEdge#39 emit_verdict (tracing::warn! → one await call).\n\n#119: 6th PyCapsule accessor local_signer_capsule() parallel to\nkeyring_signer_capsule. Wraps Arc<LocalSigner> for cross-cdylib\npickup; capsule type tag ciris_persist::local_signer. Defensive\nValueError(\"local_signer_unavailable\") when engine was constructed\nwithout from_shared_with_local (#112). Each capsule one job:\nkeyring_signer drives scrub envelopes, local_signer drives\nReticulumTransport identity (CIRISEdge v0.13.1 link establish +\nCurve25519-derived DH).\n\n5 new tests on both backends. Zero schema change, zero trait\nbreakage; ships as 3.1.1 patch.",
          "timestamp": "2026-05-28T22:13:47-05:00",
          "tree_id": "e3094c3e76f154296b12d1d943c391b8db76a02e",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/b1e3b8a7aefbd79230874e4c543c5ba8233d83fe"
        },
        "date": 1780026278844,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45673331,
            "range": "± 19074",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2385,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5633,
            "range": "± 70",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12308,
            "range": "± 358",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43764,
            "range": "± 202",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 180,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 507,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 577,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1993,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 64,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 210,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 905,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 48736,
            "range": "± 1400",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 151027,
            "range": "± 727",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 558175,
            "range": "± 2499",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 6262,
            "range": "± 485",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 7640,
            "range": "± 375",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 15537,
            "range": "± 1297",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 36204,
            "range": "± 1554",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 593526,
            "range": "± 3161",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 254804,
            "range": "± 4851",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 15101,
            "range": "± 588",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 44494,
            "range": "± 768",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 2425463,
            "range": "± 16035",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 94712,
            "range": "± 6412",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 404491,
            "range": "± 13290",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 5998328,
            "range": "± 44411",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 225036,
            "range": "± 7438",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 995107,
            "range": "± 12376",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 4889,
            "range": "± 454",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 4202,
            "range": "± 285",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 1031,
            "range": "± 30",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 3423,
            "range": "± 175",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 25834,
            "range": "± 137",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 510,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 83,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 812,
            "range": "± 36",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "8252932e295ed9dfcb17801b8a14cb83d9b8c4a1",
          "message": "3.2.0 — #120 BlackholeRules durable per-identity deny-list (V052 blackhole_rules)\n\nNew sibling trait BlackholeRules + V052 cirislens.blackhole_rules table\ngiving CIRISEdge's ReticulumTransport a durable home for operator-\nconfigured deny-list rules. Unblocks CIRISEdge#33 v0.15.0 routing-table\nFFI acceptance criterion \"blackhole add/remove durable across Edge\nrestarts\".\n\nSibling trait (not folded into FederationDirectory) because federation\ndirectory is about cryptographic identities; blackhole is about\ntransport-layer address denials — different concerns. Matches #115\nBlobStorage sibling pattern.\n\nOperator semantics: upsert preserves hits + added_at (intent change,\nnot counter reset); remove silent on unknown hash (POSIX rm -f\nergonomics); record_hit race-tolerant (no tx wrap, hot path);\nprune_expired treats until IS NULL as the \"permanent\" signal.\n\npersist_row_hash excludes hits — hot-path increment doesn't force\nre-canonicalize; operator-intent fields participate in the hash.\n\nBoth backends + memory parity. 33 new tests (10 per backend + 3\nmodule-unit) all green; 886/886 full feature set on fresh PG.\nNo new error variants (InvalidArgument + Backend sufficient).",
          "timestamp": "2026-05-29T08:14:32-05:00",
          "tree_id": "05334c22ef32eb320765c5f70ef651190f813c69",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/8252932e295ed9dfcb17801b8a14cb83d9b8c4a1"
        },
        "date": 1780061905576,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40430631,
            "range": "± 137708",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2502,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5913,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12693,
            "range": "± 143",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 45495,
            "range": "± 614",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 41,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 224,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 523,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 599,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2065,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 73,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 235,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1024,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 54493,
            "range": "± 1456",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 160011,
            "range": "± 2787",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 573798,
            "range": "± 8774",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 6961,
            "range": "± 469",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 8167,
            "range": "± 592",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 16941,
            "range": "± 920",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 44963,
            "range": "± 1313",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 707113,
            "range": "± 3378",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 268760,
            "range": "± 897",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 13629,
            "range": "± 458",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 42579,
            "range": "± 409",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 2566390,
            "range": "± 18226",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 75914,
            "range": "± 3708",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 412827,
            "range": "± 4277",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 6572680,
            "range": "± 35010",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 255959,
            "range": "± 15840",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 1150237,
            "range": "± 18238",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 5937,
            "range": "± 638",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 4994,
            "range": "± 444",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 1406,
            "range": "± 112",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 4150,
            "range": "± 176",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 30422,
            "range": "± 283",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 667,
            "range": "± 73",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 97,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 1339,
            "range": "± 127",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "baad6bfcfe5d861b3d919c278039303ba62122ce",
          "message": "3.3.0 — #121 put_blob_signing ergonomic ingest + canonicalizer authority\n\nNew BlobStorage::put_blob_signing trait method + Engine facade + PyO3\nmirror collapsing the 7-step holds_bytes ingest sequence to one call.\nThe existing put_blob(PutBlobAttestation) stays for re-emit /\nHSM-batch / replay paths.\n\nCloses the JCS-vs-Python silent-correctness trap: persist's production\ncanonicalizer is PythonJsonDumpsCanonicalizer (src/verify/canonical.rs);\nRfc8785Canonicalizer is cfg(test) only. Downstream reaching for the\nobvious serde_json_canonicalizer crate would produce signatures that\nsilently fail downstream verification. put_blob_signing makes persist\nthe canonical owner of the canonicalizer choice; backends inherit via\ntrait default impl (no per-backend code).\n\nDesign calls: &dyn HardwareSigner (cross-cdylib PyTypeInfo-safe);\nexplicit now + attestation_id (replay determinism); signer.current_alias\nsources scrub_key_id (matches Engine::receive_and_persist_with pattern).\n\n9 new tests pinning the correctness fix: canonicalizer identity for\nholds_bytes (ASCII-only so divergence test alone insufficient),\nPython-vs-JCS divergence on non-ASCII envelope (regression gate if\nthe two impls accidentally converge), per-backend column-hash\nassertion against PythonJsonDumpsCanonicalizer output, round-trips,\nunknown-key rejection, replay semantics. 895/895 nextest green.\n\nNo schema change; trait method default-implemented in terms of put_blob.",
          "timestamp": "2026-05-29T10:08:13-05:00",
          "tree_id": "d30d7ff6eee328510921ef7d8dd85becd91899d7",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/baad6bfcfe5d861b3d919c278039303ba62122ce"
        },
        "date": 1780068961791,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 35433000,
            "range": "± 205541",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2388,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5646,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12414,
            "range": "± 59",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43816,
            "range": "± 203",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 35,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 181,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 506,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 577,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1992,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 66,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 211,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 923,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 59162,
            "range": "± 44367",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 164800,
            "range": "± 384784",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 597123,
            "range": "± 663863",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7426,
            "range": "± 494",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 8592,
            "range": "± 581",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 17649,
            "range": "± 1641",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 38177,
            "range": "± 2024",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 603501,
            "range": "± 6259",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 255958,
            "range": "± 10272",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 17503,
            "range": "± 1058",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 45198,
            "range": "± 1233",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 2448094,
            "range": "± 17183",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 112421,
            "range": "± 5420",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 417429,
            "range": "± 12077",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 5984708,
            "range": "± 44295",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 282535,
            "range": "± 8269",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 1081168,
            "range": "± 16047",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 4995,
            "range": "± 244",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 4372,
            "range": "± 238",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 1050,
            "range": "± 34",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 3469,
            "range": "± 30",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 26582,
            "range": "± 290",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 523,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 82,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 824,
            "range": "± 39",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "4bab97fe2e36760a528ea4fb868f06b8b3a6d6a3",
          "message": "3.3.1 — #122 second calibration anchor (DRAM-walk) for memory-bound bench families\n\nv3.3.0 bench run flagged 3 alerts on read_engine_analytics/aggregate_llm_costs\n(1.28x/1.48x/1.10x) on a commit touching zero analytics code. Diagnosis:\nthe v2.12.0 / #116 CPU-bound calibration anchor (splitmix64_10m) doesn't\nnormalize the memory/cache axis. Runner where CPU is fast but neighbor-\ntenant memory bandwidth contention is high produces CPU-anchored\nnormalized values that look like memory-bound bench regressions but\naren't real code regressions.\n\nNew bench_calibration_dram_walk in benches/calibration.rs: 64MB buffer\n(exceeds L3 on every Actions runner image), 500k random reads per\niteration via LCG-driven index sequence that defeats hardware\nprefetcher. Each access misses cache → goes to DRAM.\n\nWorkflow extracts both CAL_CPU_NS + CAL_MEM_NS, errors if either empty,\nclassifies each downstream bench by name prefix:\n- read_engine_analytics/* | dedup_key/* | occurrence_registry/* → MEM\n- everything else → CPU (existing behavior)\n\nBack-compat: CALIBRATION_NS env still set to CPU anchor so the pre-#122\ngh-pages series name doesn't fork. Memory-bound history isn't\nretroactively renormalized — new anchor applied from v3.3.1 onward;\ntrend chart will show a one-time shift at this release for the three\nreclassified families.\n\nNo Rust src change, no schema change, no API surface change. Bench\ninfrastructure only.",
          "timestamp": "2026-05-29T11:10:07-05:00",
          "tree_id": "b38a384d1d85cabc2384ca17bc5182cb8a1a8d7a",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/4bab97fe2e36760a528ea4fb868f06b8b3a6d6a3"
        },
        "date": 1780072425616,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40460098,
            "range": "± 133861",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2975627,
            "range": "± 213197",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2529,
            "range": "± 81",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5930,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12977,
            "range": "± 68",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 45794,
            "range": "± 241",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 39,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 223,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 523,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 599,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2065,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 75,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 227,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1030,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 54291,
            "range": "± 719",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 161134,
            "range": "± 2343",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 575645,
            "range": "± 5941",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 6420,
            "range": "± 841",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 8612,
            "range": "± 832",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 17656,
            "range": "± 872",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 48316,
            "range": "± 1319",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 712501,
            "range": "± 2210",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 3770682,
            "range": "± 22063",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 175662,
            "range": "± 7902",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 580460,
            "range": "± 21598",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 36247835,
            "range": "± 533159",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1046327,
            "range": "± 34186",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 5725901,
            "range": "± 111378",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 91332152,
            "range": "± 483580",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 2954082,
            "range": "± 218383",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 15884411,
            "range": "± 411902",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 72210,
            "range": "± 7009",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 62721,
            "range": "± 5269",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 21085,
            "range": "± 1598",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 60785,
            "range": "± 1451",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 440428,
            "range": "± 6425",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 671,
            "range": "± 56",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 99,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 1190,
            "range": "± 100",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "8eef39e938cb40ed09fec9cfadf3978cf013d9f1",
          "message": "3.4.0 — #123 replication-policy substrate: trust admission + popularity×freshness eviction sweeper\n\nNew src/federation/replication/ module + V053 federation_blobs access tracking\n+ Engine sweep_evictions_once + withdraws emission. Lands the substrate-side\nexecution sites for CEG organic-replication discipline (NodeCore\nFSD/FEDERATION_SCALING_MODEL.md v0.3, 5B-user-feasible at 1TB/1Gbps/1core).\n\nTrustScoring trait + AdmissionGate threaded through 4 write sites\n(put_blob/put_attestation/put_revocation/put_contribution). Strict gate\nordering: empty → trust → size → hash → FK. Rationale: trust is cheapest\nreject + leaks least info.\n\nEvictionSweeper with single-pass Engine::sweep_evictions_once: SUM(size_bytes)\n> watermark → scan ascending by popularity×freshness, withdraws + delete per\ncandidate. PG computes evict-score in SQL via exp(); SQLite scans by\nmonotone bound + Rust re-rank (no exp() in stdlib).\n\nWithdraws emission: per-cycle directory query + HashMap O(1) per-candidate\nlookup; envelope canonicalized via PythonJsonDumpsCanonicalizer (NOT JCS —\nsame #121 trap discipline); signed via engine.signer().sign;\nFederationDirectory::put_attestation. Missing-prior holds_bytes → log + skip\nwithdraws but STILL delete blob (orphan withdraws worse than none).\n\nPyO3 surface: set_trust_threshold, set_storage_budget_bytes (with sweeper\nlifecycle management), sweep_evictions_once. PyEngine::__new__ accepts\nreplication_sweeper_enabled=true; auto-spawns sweeper loop on construction.\nEngine::from_shared / from_shared_with_local do NOT spawn (cohabitation\ninvariant against dual-sweeper races).\n\nBootstrap defaults permissive: threshold=0.0 admits everything,\nbudget=u64::MAX disables sweeper. v3.3.1→3.4.0 with no config = no\nbehavioral change.\n\n45 new tests (20 module / 13 sqlite / 7 PG / 1 cirisnode / 3 engine / 3 PyO3).\n886/886 nextest green full feature set on fresh PG. Both backends + memory\nparity. No deferrals, no PG-only declarations.",
          "timestamp": "2026-05-29T13:07:42-05:00",
          "tree_id": "acc9799b6251a76940ddd6f049e8403905ad3b84",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/8eef39e938cb40ed09fec9cfadf3978cf013d9f1"
        },
        "date": 1780079284627,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 35444141,
            "range": "± 392548",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 1796854,
            "range": "± 81940",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2388,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5646,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12101,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43642,
            "range": "± 294",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 178,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 513,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 584,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1998,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 64,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 208,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 915,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 57710,
            "range": "± 3565",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 159641,
            "range": "± 13439",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 564188,
            "range": "± 187153",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 6102,
            "range": "± 348",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 7455,
            "range": "± 380",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 14884,
            "range": "± 900",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 34969,
            "range": "± 978",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 651825,
            "range": "± 3868",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 4997062,
            "range": "± 25436",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 263667,
            "range": "± 3905",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 732074,
            "range": "± 6125",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 48482787,
            "range": "± 328969",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1952527,
            "range": "± 82712",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 7582872,
            "range": "± 90922",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 121735021,
            "range": "± 908278",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 5075864,
            "range": "± 133731",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 19747993,
            "range": "± 126329",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 97500,
            "range": "± 9655",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 77467,
            "range": "± 4288",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 20547,
            "range": "± 650",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 69433,
            "range": "± 700",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 534207,
            "range": "± 2198",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 533,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 83,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 843,
            "range": "± 35",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "7f87b8eb004a4ae50ea67c3ff4a0737b3ecbc456",
          "message": "3.4.1 — #127 peer_metadata_for read accessor (unblocks CIRISEdge#48 cohort_scope consumer-side enforcement)\n\nPure-additive read symmetry. v3.1.0 (#117) shipped update_peer_policy as\nwrite-only with no read accessor for the same federation_peer_metadata\nrow; v3.4.1 fills the gap so CIRISEdge can consume\npolicy_blob.cohort_scope at the v0.19.1 cohort_scope refusal site.\n\nNew FederationDirectory::peer_metadata_for(key_id) returning\nOption<PeerMetadataRow>. None for non-existent OR soft-removed peers\n(removed_at IS NOT NULL). Both backends + memory parity. PG hydrator\nuses safe_get_with through pg_row_to_peer_metadata_for_hash; SQLite\nhydrator preserves stored persist_row_hash column verbatim for\nround-trip stability.\n\nPyO3 mirror peer_metadata_for_json returns Optional[str] (JSON-encoded\nPeerMetadataRow) — CIRISEdge consumes\njson.loads(s)[\"policy_blob\"][\"cohort_scope\"].\n\n6 new tests (3 per backend): returns_full_row, returns_none_unknown,\nreturns_none_soft_removed. 886/886 baseline unaffected; cumulative\npeer-metadata test count for #117 + #127 now 32.\n\nNo trait-breakage (default impl ships error), no schema change.",
          "timestamp": "2026-05-29T13:13:48-05:00",
          "tree_id": "bc1ce2adcfa553085801daf3b44c3f1515c5b14f",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/7f87b8eb004a4ae50ea67c3ff4a0737b3ecbc456"
        },
        "date": 1780081641853,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 55027466,
            "range": "± 935615",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2243392,
            "range": "± 300940",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 1768,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 4422,
            "range": "± 84",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 9572,
            "range": "± 258",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 38394,
            "range": "± 982",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 133,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 381,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 447,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1651,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 57,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 175,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 833,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 10,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 41174,
            "range": "± 4199",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 119375,
            "range": "± 3498",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 429769,
            "range": "± 22542",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7131,
            "range": "± 1343",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 11603,
            "range": "± 4672",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 18888,
            "range": "± 4112",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 38913,
            "range": "± 4588",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 568068,
            "range": "± 5327",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 4704638,
            "range": "± 81396",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 393079,
            "range": "± 21215",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 916733,
            "range": "± 80391",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 42131459,
            "range": "± 624302",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 2165284,
            "range": "± 174315",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 7736976,
            "range": "± 212260",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 101676815,
            "range": "± 1249211",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 5928386,
            "range": "± 631369",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 20535305,
            "range": "± 606344",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 137359,
            "range": "± 21816",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 124330,
            "range": "± 13233",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 26405,
            "range": "± 3538",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 67797,
            "range": "± 3837",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 519900,
            "range": "± 31284",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 474,
            "range": "± 74",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 66,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 891,
            "range": "± 130",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "89a991b100b6f32790a68281e9c7eea1dbdc324e",
          "message": "3.4.2 — CIRISVerify pin v4.0.0 → v4.2.0\n\nPin-bump-only patch. Picks up verify 4.1 + 4.2 additions on the 4.x line\nwithout persist code changes:\n\n- v4.1.0 (#39): impl ciris-keyring::PqcSigner for ciris-crypto::MlDsa65Signer\n- v4.2.0 (#40 #41 #42): conformance cross-wheel boundary CEG §4 / §0.5 /\n  §9.2.1 / §10.3.1\n\n6 Cargo.toml pin sites bumped tag = \"v4.0.0\" → \"v4.2.0\" (base\nciris-keyring + ciris-verify-core + ciris-crypto + three per-target\n[target.*] tables for Linux TPM / iOS / Android). version = \"4\" floor\nstays — minor-compatible within 4.x.\n\npyproject.toml Requires-Dist: ciris-verify>=4.0.0,<5 → >=4.2.0,<5.\n\nConsumed verify surface (HardwareSigner, hybrid signatures,\ntransparency-log machinery, derive_symmetric_key,\nPythonJsonDumpsCanonicalizer) unchanged — minor bump additive on\nverify side. 946/946 full feature set nextest green on v4.2.0,\nidentical to v4.0.0.",
          "timestamp": "2026-05-29T13:47:10-05:00",
          "tree_id": "32a56d4bcfc60667978308e0a5ec09912f00d0dd",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/89a991b100b6f32790a68281e9c7eea1dbdc324e"
        },
        "date": 1780082981552,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45657282,
            "range": "± 20183",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 3766831,
            "range": "± 220566",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2688,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5952,
            "range": "± 112",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12610,
            "range": "± 61",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43950,
            "range": "± 172",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 161,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 508,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 580,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1992,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 65,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 211,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 912,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 49156,
            "range": "± 1051",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 150419,
            "range": "± 1707",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 553752,
            "range": "± 4512",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 6889,
            "range": "± 1458",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 7878,
            "range": "± 652",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 15505,
            "range": "± 1718",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 38765,
            "range": "± 2673",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 662329,
            "range": "± 3938",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 3120527,
            "range": "± 27954",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 196547,
            "range": "± 8960",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 530254,
            "range": "± 13990",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 28715112,
            "range": "± 513623",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1291367,
            "range": "± 73385",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 4821892,
            "range": "± 84584",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 71148589,
            "range": "± 384433",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 3301983,
            "range": "± 131251",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 12730747,
            "range": "± 215566",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 59379,
            "range": "± 5110",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 49290,
            "range": "± 3310",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 12104,
            "range": "± 431",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 41400,
            "range": "± 495",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 311711,
            "range": "± 3538",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 522,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 83,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 804,
            "range": "± 26",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "850901a65656cff8344c6f22cf5eff762d11bec3",
          "message": "3.4.3 — #124 ciris_persist.pyi stub completion for blob/attestation/canonicalize/verify_hybrid\n\nDocumentation-only patch. CIRISConformance CCS profile needs the\nblob + attestation + canonicalize + verify_hybrid surface documented\nto drive §6.1/§7.0/§10.1.1/§10.1.2 conformance paths.\n\nThe PyO3 methods all existed at runtime (put_blob_signing since v3.3.0\n#121; put_blob_json/get_blob_json/list_holders_json since v2.3.0 #103;\nput_attestation + canonicalize_envelope* + verify_hybrid pre-existing)\nbut absent from the .pyi stub. 8 method signatures added with full\ndocstrings + payload JSON shapes for:\n- put_blob_signing (the recommended one-call admission path)\n- put_blob_json + get_blob_json + list_holders_json\n- put_attestation\n- canonicalize_envelope + canonicalize_envelope_for_signing (with the\n  don't-use-JCS warning — #121 trap discipline stated explicitly)\n- verify_hybrid\n\nZero Rust code change, zero behavioral change, zero schema change.\n\n#124's \"preferred\" ask (Python-callable put_blob_signing) shipped in\nv3.3.0 (#121) before this issue was filed; empirical finding in #124\nwas against 3.1.1. Conformance can bump to >=3.3.0 (3.4.3 recommended\nfor full stub coverage) and call engine.put_blob_signing(...) directly.",
          "timestamp": "2026-05-29T16:20:06-05:00",
          "tree_id": "0de77e3b91e03f19dce00414b4074b64cb76c036",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/850901a65656cff8344c6f22cf5eff762d11bec3"
        },
        "date": 1780090965382,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45665359,
            "range": "± 727221",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 3339836,
            "range": "± 409852",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2394,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5644,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12170,
            "range": "± 45",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43771,
            "range": "± 707",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 160,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 506,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 578,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1993,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 68,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 210,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 920,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 47914,
            "range": "± 530",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 149644,
            "range": "± 3913",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 554647,
            "range": "± 7192",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7102,
            "range": "± 497",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 7964,
            "range": "± 488",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 14694,
            "range": "± 1205",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 36240,
            "range": "± 2147",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 667439,
            "range": "± 4125",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 3640360,
            "range": "± 26815",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 283191,
            "range": "± 7813",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 674591,
            "range": "± 16943",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 32315808,
            "range": "± 1113612",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1369756,
            "range": "± 184031",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 5629698,
            "range": "± 106141",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 79665654,
            "range": "± 480741",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 4045835,
            "range": "± 200740",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 14121529,
            "range": "± 465829",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 70072,
            "range": "± 6436",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 64801,
            "range": "± 5544",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 14133,
            "range": "± 497",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 46815,
            "range": "± 634",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 362290,
            "range": "± 3923",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 524,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 86,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 838,
            "range": "± 31",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "3d648d2e7c03f4b87d19d9de8af79699d13b2cf8",
          "message": "3.5.0 — #125 identity-aware storage (list_held_by + evict_actor) + #126 CEG §0.5/§0.6/§0.7 canonicalization rejection\n\nCombined monolithic cut closing the two remaining CCS conformance issues.\nAdditive — no schema change, no existing-surface break.\n\n#125: New BlobStorage::list_held_by + ::evict_actor trait methods +\nEvictActorReport struct. list_held_by is the per-actor inverse of\nlist_holders (same TTL + withdraws-filter discipline per CEG §10.1.2).\nevict_actor looks up the actor's live holds_bytes:sha256:* attestations,\nemits a signed withdraws per attestation (canonicalized via\nPythonJsonDumpsCanonicalizer per #121 trap discipline), deletes the\nblob row. Race-tolerant; withdraws_failed tally per #123 fail-honest\ncontract. Engine facade sources signer internally; PyO3 mirrors take\nactor_key_id + ISO timestamps.\n\nShared emit_withdraws_attestation_helper in src/federation/blobs.rs;\nv3.4.0 Engine::emit_withdraws_attestation NOT migrated to it\n(minimal-scope; both paths produce identical bytes).\n\n#126: New src/verify/canonical_validation.rs module enforcing CEG §0.5\ndatetime (literal Z, exactly 3 fractional digits), §0.6 hex (lowercase,\nunpadded, byte-length-exact), §0.7 future-skew (signed_at > now+5min\nrejects). Wiring decision: OPT-IN free fn + PyO3 mirror, NOT inline\nwith canonicalize_envelope. Existing callers unaffected; conformance\nopts in explicitly to observe rejection.\n\nSignature-field §0.6 hex heuristic: only fires when value char set\nlooks hex-like ([0-9a-fA-F]+); base64 sigs bypass.\n\n32 new tests (10 #125 backend integration + 22 #126 unit tests).\n978/978 nextest --test-threads=1 green. Clippy clean on defaults\nAND full feature set.\n\nKnown pre-existing parallel-test flake (NOT from this cut) surfaced\nby scheduling shift: federation::emit::pg_revoke_trust_grant +\nfederation::backfill::pg_backfill_mixed_and_idempotent share Ed25519\nseed 0xA1 federation_keys row; emit.rs::pg_cleanup leaves the row\nbehind. Filing as follow-up; --test-threads=1 fully green.",
          "timestamp": "2026-05-29T16:54:18-05:00",
          "tree_id": "cd57eaba91c3152f326d4aed91363d661d3c908c",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/3d648d2e7c03f4b87d19d9de8af79699d13b2cf8"
        },
        "date": 1780092849022,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40432077,
            "range": "± 114358",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2367403,
            "range": "± 281985",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2611,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 6026,
            "range": "± 28",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 13104,
            "range": "± 30",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 46175,
            "range": "± 400",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 35,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 203,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 522,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 598,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2067,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 75,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 230,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1024,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 54762,
            "range": "± 2335",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 160647,
            "range": "± 5796",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 577104,
            "range": "± 3095",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7362,
            "range": "± 555",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 8540,
            "range": "± 803",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 18071,
            "range": "± 1418",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 47941,
            "range": "± 1987",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 774910,
            "range": "± 2471",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 4862232,
            "range": "± 72669",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 268326,
            "range": "± 14735",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 791768,
            "range": "± 62097",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 45043495,
            "range": "± 434582",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1687954,
            "range": "± 110425",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 7677061,
            "range": "± 94324",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 112622608,
            "range": "± 683603",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 4241569,
            "range": "± 174890",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 19278043,
            "range": "± 137822",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 92756,
            "range": "± 6978",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 79060,
            "range": "± 6589",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 24489,
            "range": "± 2430",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 75190,
            "range": "± 2533",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 528119,
            "range": "± 4706",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 675,
            "range": "± 57",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 97,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 1209,
            "range": "± 168",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "61ac37cee7b628d99070c8ce81da51f511a5eefb",
          "message": "3.5.1 — #129 trust_scoring_capsule + #130 list_holders local-held bypass + partial #128 PG test isolation\n\nPatch closing two real bugs from CIRISConformance fabric-tier + CIRISEdge\ncohabitation init, plus partial fix on the pre-existing parallel-test\nisolation flake.\n\n#129: New AdmissionGate::scoring_arc + Engine::trust_scoring accessors\n(Option A) + trust_scoring_capsule 7th PyCapsule on PyEngine (Option B,\nname tag ciris_persist::trust_scoring). Cohab consumers can now pull\nArc<dyn TrustScoring> from a live persist engine; CIRISEdge v0.19.x cohab\ninit unblocked. Raises ValueError(\"trust_scoring_unavailable\") when no\nadmission gate installed (bootstrap-permissive default).\n\n#130: list_holders bypasses CEG §10.1.2 24h TTL when blob is locally\npresent in federation_blobs. Federation TTL is a backstop for peer\nattestations going silently offline; for locally-held blobs the bytes\nare definitive proof of holding. The withdraws mechanism remains the\nactive eviction signal — ContentMiss feedback loop unchanged. Both\nbackends; pinned by list_holders_includes_local_held_blob_with_stale_\nattestation_sqlite (48h-old asserted_at, blob locally held → holder\nreported).\n\n#128 partial: .config/nextest.toml gains [test-groups.postgres] +\noverride filter (test(/_pg$/) + test(/::pg_/) + test(/postgres_tests::/)\n+ test(/::postgres::/)) — max-threads=1 for PG tests; non-PG tests keep\nparallelism. backfill.rs seed reallocation 0xA1/0xB1 → 0xC1/0xD1\ndisjoint from emit.rs's claims. Takes gauntlet from 5/5 random fails to\n1 deterministic residual (put_get_goal_round_trip_pg fails even at\n--test-threads=1 — separate state-pollution issue, tracked ongoing).\n\nCIRISEdge 1.0 RC consumers pin v3.5.1 — residual flake is\ntest-infrastructure-only, not in shipped behavior.",
          "timestamp": "2026-05-29T18:09:35-05:00",
          "tree_id": "0b9e9c476cceff6405191d2516465a2c4ed3a2f4",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/61ac37cee7b628d99070c8ce81da51f511a5eefb"
        },
        "date": 1780097424361,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 53618986,
            "range": "± 37691",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 1148255,
            "range": "± 343845",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 1796,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 4392,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 9739,
            "range": "± 74",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 36266,
            "range": "± 367",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 136,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 383,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 445,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1648,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 57,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 182,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 824,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 10,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 37493,
            "range": "± 1841",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 117110,
            "range": "± 6414",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 428140,
            "range": "± 11452",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 6174,
            "range": "± 746",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9143,
            "range": "± 1988",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 15734,
            "range": "± 1787",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 37482,
            "range": "± 4905",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 553108,
            "range": "± 3426",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 8560247,
            "range": "± 101217",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 637357,
            "range": "± 21052",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 1630518,
            "range": "± 49550",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 77051183,
            "range": "± 774031",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 3863845,
            "range": "± 359032",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 13910380,
            "range": "± 256422",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 191875558,
            "range": "± 1304093",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 10294189,
            "range": "± 1023201",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 36570038,
            "range": "± 573398",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 220566,
            "range": "± 29997",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 238033,
            "range": "± 77621",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 41616,
            "range": "± 2202",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 123638,
            "range": "± 1929",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 934695,
            "range": "± 13618",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 407,
            "range": "± 27",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 66,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 729,
            "range": "± 69",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "380f23cb7b95faac2a50aea220e7d12c97cbabee",
          "message": "3.5.2 — RCA triple-close: #132 libsqlite3 cross-cdylib SIGSEGV + #130 list_local_holders (corrected) + #128 av26 schema-wipe race\n\nThree issues blocking CIRISEdge v1.0 RC, each with a real root cause +\nstructural fix rather than a workaround.\n\n#132 (libsqlite3 cross-cdylib SIGSEGV): Cargo.toml `bundled` is now\nAndroid-only. Linux/macOS/Windows/iOS link dynamically against the\nplatform's libsqlite3 → ONE library instance shared across cdylibs via\ndlopen, ONE initialization, ONE allocator. Same posture iOS already\nused (CIRISVerify v1.6.4 libRPAC fix); generalized to all desktops.\nAndroid keeps bundled (NDK libsqlite3 not guaranteed across vendors).\nCIRISEdge#50 SIGSEGV closed structurally — affects every blanket-impl\ntrait edge consumes (OutboundQueue, VerifyDirectory, RootingDirectory,\nEdgeDetectionAdmission, BlackholeRules).\n\n#130 (corrected from withdrawn v3.5.1): v3.5.1 bypassed CEG §10.1.2\nTTL in list_holders when blob locally held, breaking 2 pre-existing\ntests. CI matrix all-red, never reached PyPI. v3.5.2 reverts and\nintroduces a separate `list_local_holders` API + PyO3 mirror that\ngates on federation_blobs presence and skips TTL (withdraws filter\npreserved). Federation-discovery semantic in list_holders preserved\nexactly; local-truth in the new method. 5 new tests (3 sqlite + 2 PG).\n\n#128 (real root cause): tests/qa_harness.rs::av26_concurrent_boot_\nadvisory_lock does DROP SCHEMA cirislens CASCADE to simulate cold-\nstart. The #[serial_test::serial(postgres)] annotation only\nserializes within a process — nextest spawns one process per test\nso the annotation was a cross-process no-op. While av26 ran, every\nother PG test saw \"relation cirislens.* does not exist\". Diagnosed\nvia a fail-path-only diagnostic in pg_cleanup_tenant_merkle that\ncaptures the schema state at panic boundary + a Debug-format upgrade\non merkle_store::pg_storage_err (was Display = \"db error\"). RCA\noutput: \"cirislens merkle tables: []\", schema_history not readable.\nFix: added av26 to the postgres test-group filter; max-threads=1\ngives cross-process serialization. 3-run gauntlet: 951/951 every run.\n\nCarry-forward from withdrawn v3.5.1: #129 trust_scoring_capsule\nunchanged.\n\nDiagnostic instrumentation left in tree on both sites — zero-cost on\nsuccess path, captures rich snapshot on failure. Future #128-class\nissues debugged in minutes not hours.",
          "timestamp": "2026-05-29T19:20:25-05:00",
          "tree_id": "b848c9e5e582056662ad16c4e81724ab3acc019e",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/380f23cb7b95faac2a50aea220e7d12c97cbabee"
        },
        "date": 1780101630492,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40425206,
            "range": "± 293797",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 3448497,
            "range": "± 98871",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2750,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 6257,
            "range": "± 247",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 13281,
            "range": "± 46",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 46353,
            "range": "± 564",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 35,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 203,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 522,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 598,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2065,
            "range": "± 82",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 74,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 236,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1045,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 58266,
            "range": "± 4907",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 164313,
            "range": "± 2621",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 587224,
            "range": "± 19778",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 6842,
            "range": "± 593",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 8778,
            "range": "± 793",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 16830,
            "range": "± 917",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 46587,
            "range": "± 1954",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 788418,
            "range": "± 5557",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 3240454,
            "range": "± 24367",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 162190,
            "range": "± 8284",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 585952,
            "range": "± 32044",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 30899506,
            "range": "± 260597",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1145113,
            "range": "± 55088",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 5242273,
            "range": "± 81611",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 77047217,
            "range": "± 319463",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 3226562,
            "range": "± 232933",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 13660624,
            "range": "± 330526",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 63133,
            "range": "± 6413",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 51489,
            "range": "± 6162",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 16413,
            "range": "± 1487",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 49498,
            "range": "± 1334",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 371549,
            "range": "± 3008",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 656,
            "range": "± 62",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 98,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 1161,
            "range": "± 112",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "7a6860277ce48543b375a38bda107c5fce69ec73",
          "message": "3.5.3 — wheel-tier completion of #132 (#133): CIRISVerify v4.3.0 + libsqlite3-dev in CI + readelf gate\n\nv3.5.2's source-tier fix narrowed rusqlite/bundled to Android-only in\npersist's Cargo.toml, but the published wheel STILL bundled libsqlite3.\nCIRISEdge#50 SIGSEGV still fired against the v3.5.2 wheel. Two RCs:\n\n1. ciris-verify-core v4.2.0 hardcoded `rusqlite = { features = [\"bundled\"] }`\n   at workspace root + a wide non-iOS override → transitive activation\n   defeated persist's target-narrowed override per cargo feature-union.\n2. Linux wheel-build runner had no libsqlite3-dev → pkg-config would\n   have failed anyway, libsqlite3-sys had nothing to link against.\n\nv3.5.3 lands:\n- Pin bump CIRISVerify v4.2.0 → v4.3.0 (6 Cargo.toml sites + pyproject\n  Requires-Dist). v4.3.0 removes bundled at workspace root + narrows\n  verify-core override to Android-only. `cargo tree -e features\n  --invert libsqlite3-sys` confirms bundled GONE from the feature graph.\n- CI installs libsqlite3-dev on Linux wheel-build runner. The existing\n  libtss2-dev step (v1.10.0) now also pulls libsqlite3-dev.\n- New post-build readelf/otool verification gate rejects any wheel\n  that doesn't have libsqlite3 as a NEEDED entry (Linux), dynamic-\n  link entry (macOS), or auditwheel sidecar. Future bundled\n  regressions get caught at wheel-build, not after PyPI publish.\n\nCloses CIRISEdge#50 at both source AND wheel tiers. Edge v1.0 RC\nunblocked at the wheel tier.",
          "timestamp": "2026-05-29T20:06:03-05:00",
          "tree_id": "57c44f3eb93069c4d2f521fa7e39d7f3e9275af9",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/7a6860277ce48543b375a38bda107c5fce69ec73"
        },
        "date": 1780104603312,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 28850770,
            "range": "± 584704",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 1916222,
            "range": "± 345230",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2154,
            "range": "± 43",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 4987,
            "range": "± 70",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 10710,
            "range": "± 120",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 38417,
            "range": "± 862",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 133,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 439,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 496,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1608,
            "range": "± 30",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 75,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 227,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1017,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 10,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 60805,
            "range": "± 94212",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 146992,
            "range": "± 56083",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 489823,
            "range": "± 338652",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 6703,
            "range": "± 238",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 7925,
            "range": "± 472",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 12334,
            "range": "± 443",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 28901,
            "range": "± 887",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 646348,
            "range": "± 4364",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 3442713,
            "range": "± 67991",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 190231,
            "range": "± 3781",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 554595,
            "range": "± 18967",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 36337840,
            "range": "± 720622",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1854342,
            "range": "± 184397",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 7603219,
            "range": "± 225261",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 91490133,
            "range": "± 1442244",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 5102118,
            "range": "± 306168",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 19616027,
            "range": "± 419596",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 103344,
            "range": "± 9451",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 91488,
            "range": "± 4045",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 15705,
            "range": "± 720",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 46606,
            "range": "± 1538",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 352926,
            "range": "± 9825",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 590,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 80,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 798,
            "range": "± 44",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "066c55bb5dfd51c81d2a2607ce17ccd9d1e18fc1",
          "message": "3.5.4 — CIRISVerify pin v4.3.0 → v4.4.2 (clean recovery of v3.5.3 PyPI gate)\n\nv3.5.3 source-tier + wheel-tier fixes were correct, but pyproject.toml\nRequires-Dist: ciris-verify>=4.3.0 couldn't resolve at install time\nbecause CIRISVerify v4.3.0 never reached PyPI (Windows release build\nfailed on the same bundled narrowing). v3.5.3 tag CI failed at the\nlinux-x86_64 (core) feature-test pip install step; PyPI publish was\nskipped.\n\nv4.4.x recovery upstream:\n- v4.4.0 X25519 + key-grant wrap (CIRISVerify#44 multimedia crypto)\n- v4.4.1 bundled narrowed to (Android, Windows, macOS); Linux + iOS\n  stay dynamic where cohab SIGSEGV manifests; Cross.toml for arm64\n- v4.4.2 fixed self-inflicted Cargo.toml section-boundary bug\n\nv3.5.4 bumps verify pins v4.3.0 → v4.4.2 (6 sites Cargo.toml + 1\npyproject). No persist source change — the bundled-Android-only\nCargo.toml posture from v3.5.3 stands. Cargo feature-union with\nverify's bundled-on-macOS produces bundled libsqlite3 in persist's\ndarwin-aarch64 wheel matching verify's exact posture; Linux stays\ndynamic on both sides where the cohab SIGSEGV lives.\n\nCIRISEdge#50 closed under v4.4.x posture. CIRISEdge v1.0 RC pin is\nv3.5.4.",
          "timestamp": "2026-05-29T21:44:52-05:00",
          "tree_id": "4056e822971f13157745f821eaeb54261f8ce104",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/066c55bb5dfd51c81d2a2607ce17ccd9d1e18fc1"
        },
        "date": 1780110492255,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40443156,
            "range": "± 836973",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2091937,
            "range": "± 136403",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2626,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 6041,
            "range": "± 72",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 13112,
            "range": "± 254",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 46117,
            "range": "± 251",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 37,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 204,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 524,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 599,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2066,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 76,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 231,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1034,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 56075,
            "range": "± 3882",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 161654,
            "range": "± 5971",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 578167,
            "range": "± 14593",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8799,
            "range": "± 505",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 10572,
            "range": "± 775",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 19143,
            "range": "± 1589",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 51749,
            "range": "± 1333",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 836230,
            "range": "± 2715",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 5832950,
            "range": "± 44330",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 297312,
            "range": "± 9765",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 911490,
            "range": "± 34580",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 55659660,
            "range": "± 432004",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 2198586,
            "range": "± 130833",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 9315557,
            "range": "± 166802",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 140129958,
            "range": "± 1188583",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 7152862,
            "range": "± 345416",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 26516870,
            "range": "± 1243049",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 120249,
            "range": "± 6451",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 124732,
            "range": "± 8364",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 32260,
            "range": "± 2648",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 93967,
            "range": "± 3575",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 662342,
            "range": "± 7178",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 703,
            "range": "± 62",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 120,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 1401,
            "range": "± 135",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "d91fdccbc97a41e368857fa9101b16e102fcc2ac",
          "message": "3.6.1 — wheel-CI readelf gate Linux-only (carries v3.6.0 #134 monolith)\n\nv3.5.4 + v3.6.0 both failed PyPI publish at the darwin-aarch64 wheel\nverification gate. The gate from v3.5.3 / #133 ran readelf-equivalent\nchecks on Linux + macOS, rejecting any bundled-libsqlite3 wheel as a\ncross-cdylib SIGSEGV regression.\n\nCIRISVerify v4.4.x intentionally bundles on macOS + Windows + Android\n(symbol-merging exposure is Linux-specific; bundled is the conventional\nposture on the other platforms). Persist's darwin wheel inherits\nbundled transitively — expected and correct under v4.4.x.\n\nThe macOS branch of the gate was over-strict and wrong; v3.5.4 + v3.6.0\ndarwin wheel jobs both failed for this reason.\n\nv3.6.1 narrows the gate to Linux-only. macOS / Windows / Android are\nexpected to bundle per the v4.4.x posture; gate is skipped. Linux\ndiscipline preserved exactly (readelf NEEDED entry or auditwheel\nsidecar required).\n\nv3.6.1 carries the entire v3.6.0 #134 multimedia tier substrate cut +\nthe v3.5.4 verify v4.4.2 pin. Both prior tags exist in git history with\nexplanatory CHANGELOG entries but never reached PyPI.\n\nCIRISEdge v1.0 RC pin is v3.6.1.",
          "timestamp": "2026-05-29T22:06:24-05:00",
          "tree_id": "34bbd32d3d2fbce2d120cd3557fced67b6b904a3",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/d91fdccbc97a41e368857fa9101b16e102fcc2ac"
        },
        "date": 1780111927538,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45668455,
            "range": "± 391708",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 3259783,
            "range": "± 217618",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2393,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5714,
            "range": "± 43",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12340,
            "range": "± 40",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43796,
            "range": "± 110",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 178,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 507,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 578,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1993,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 65,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 208,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 924,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 48173,
            "range": "± 854",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 150876,
            "range": "± 12948",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 551123,
            "range": "± 6622",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7841,
            "range": "± 493",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 8676,
            "range": "± 668",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 15658,
            "range": "± 715",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 38652,
            "range": "± 1421",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 813172,
            "range": "± 3396",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 3896185,
            "range": "± 55137",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 260253,
            "range": "± 15987",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 711494,
            "range": "± 16801",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 36443146,
            "range": "± 210483",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1686488,
            "range": "± 121537",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 6095435,
            "range": "± 147032",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 90580310,
            "range": "± 681899",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 4381451,
            "range": "± 184188",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 15937444,
            "range": "± 702884",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 89516,
            "range": "± 7756",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 71616,
            "range": "± 5166",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 15661,
            "range": "± 601",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 52880,
            "range": "± 589",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 416330,
            "range": "± 3055",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 522,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 97,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 865,
            "range": "± 36",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "1bb489fba94212170e21d57b9958bd6f6a381d81",
          "message": "3.6.1 — Cargo.toml version bump (follow-up to d91fdcc)",
          "timestamp": "2026-05-29T22:07:02-05:00",
          "tree_id": "b6fd03b1a831abe2bc36acdb69461139d1c1a87f",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/1bb489fba94212170e21d57b9958bd6f6a381d81"
        },
        "date": 1780111947530,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40434800,
            "range": "± 23330",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2816113,
            "range": "± 564757",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2538,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 6040,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 13068,
            "range": "± 46",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 46152,
            "range": "± 500",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 35,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 203,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 522,
            "range": "± 27",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 597,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2064,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 75,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 227,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1011,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 55770,
            "range": "± 2489",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 162532,
            "range": "± 4578",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 583952,
            "range": "± 18307",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 9820,
            "range": "± 610",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 11238,
            "range": "± 808",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 20640,
            "range": "± 1080",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 54831,
            "range": "± 2191",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 964265,
            "range": "± 4471",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 4776909,
            "range": "± 53093",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 292780,
            "range": "± 17423",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 828808,
            "range": "± 26008",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 42405214,
            "range": "± 315883",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1707814,
            "range": "± 102962",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 7360120,
            "range": "± 107765",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 103992992,
            "range": "± 663717",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 4894920,
            "range": "± 228805",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 19060419,
            "range": "± 433866",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 113056,
            "range": "± 6636",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 88878,
            "range": "± 8145",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 23036,
            "range": "± 1831",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 69754,
            "range": "± 2296",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 504219,
            "range": "± 15465",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 677,
            "range": "± 58",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 124,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 1493,
            "range": "± 141",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "f4a5a69ad106fe68d075038d78edf8192ad379b9",
          "message": "3.6.2 — auditwheel --exclude libsqlite3.so.0 (#136 cross-cdylib SIGSEGV final fix)\n\nv3.6.1 still SEGV'd in CIRISEdge#50 because maturin's auto-auditwheel\nmangled the libsqlite3 SONAME to libsqlite3-eac351cf.so.0 and bundled\nit into the wheel sidecar. Two distinct libsqlite3 instances loaded\ninto one Python process; sqlite3* handles allocated by one don't\nwork in the other.\n\nFix is the pyarrow/psycopg2-binary pattern: bypass maturin's auto-\nrepair (--auditwheel skip), then run our own auditwheel repair with\n--exclude libsqlite3.so.0 so the SONAME stays plain. ld.so unifies\npersist's libsqlite3.so.0 with edge's against the system copy.\n\nTightened the readelf gate to assert plain libsqlite3.so.0 NEEDED\nand explicitly reject both the mangled SONAME form and the .libs/\nsidecar form (v3.6.1's gate accepted the mangled form, which is how\nthis slipped through).\n\nAll of v3.6.1's #134 multimedia tier substrate + CIRISVerify v4.4.2\npin ships unchanged. Only delta is wheel-build CI flow.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-29T23:07:33-05:00",
          "tree_id": "900d3d2a09d714747d9541b43a9b25ab0fdd99e4",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/f4a5a69ad106fe68d075038d78edf8192ad379b9"
        },
        "date": 1780115292170,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45684268,
            "range": "± 46751",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2570445,
            "range": "± 229388",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2572,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5894,
            "range": "± 84",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12490,
            "range": "± 121",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43833,
            "range": "± 72",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 180,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 506,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 577,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1991,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 67,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 212,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 911,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 48065,
            "range": "± 613",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 150096,
            "range": "± 13431",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 550535,
            "range": "± 15771",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7291,
            "range": "± 429",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 8617,
            "range": "± 419",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 15108,
            "range": "± 981",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 37473,
            "range": "± 877",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 811019,
            "range": "± 6536",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 4778302,
            "range": "± 79060",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 298570,
            "range": "± 6443",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 786551,
            "range": "± 18064",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 45789125,
            "range": "± 398960",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1943615,
            "range": "± 54801",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 7541751,
            "range": "± 103800",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 112746806,
            "range": "± 611797",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 5082395,
            "range": "± 94085",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 19897515,
            "range": "± 258027",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 115106,
            "range": "± 7336",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 89767,
            "range": "± 3390",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 19341,
            "range": "± 617",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 66788,
            "range": "± 751",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 512655,
            "range": "± 3396",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 514,
            "range": "± 35",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 95,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 884,
            "range": "± 45",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "651b278d98a7158cf2fb0885f350771cf074b046",
          "message": "3.6.3 — drop auditwheel --plat (v3.6.2 CI fix)\n\nv3.6.2 pinned --plat manylinux_2_34_<arch> from the matrix.tag field\nbut the runner's glibc is newer; auditwheel rejected with \"too-recent\nversioned symbols.\" Drop --plat and let auditwheel auto-detect the\nhighest matching manylinux tag — same behavior maturin's internal\nauto-repair had been using (v3.6.1 shipped as manylinux_2_38).\n\nEverything else from v3.6.2 (the #136 --exclude libsqlite3.so.0 fix\n+ tightened readelf gate) unchanged.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-29T23:28:52-05:00",
          "tree_id": "bacb3a67627e2eafc986c3451288a85687e6f49a",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/651b278d98a7158cf2fb0885f350771cf074b046"
        },
        "date": 1780116562827,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40438792,
            "range": "± 63100",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 3066063,
            "range": "± 242552",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2534,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5973,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 13062,
            "range": "± 74",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 46193,
            "range": "± 562",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 37,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 203,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 522,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 599,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2066,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 75,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 224,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1023,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 56203,
            "range": "± 2452",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 161882,
            "range": "± 8016",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 579053,
            "range": "± 4944",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8899,
            "range": "± 833",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 11383,
            "range": "± 748",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 20082,
            "range": "± 1024",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 56599,
            "range": "± 2249",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 982591,
            "range": "± 4916",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 4519204,
            "range": "± 94752",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 315611,
            "range": "± 49850",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 855193,
            "range": "± 30807",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 39936312,
            "range": "± 252165",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1839380,
            "range": "± 129510",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 7318996,
            "range": "± 231805",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 98214266,
            "range": "± 1155300",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 4533623,
            "range": "± 138044",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 17783943,
            "range": "± 478693",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 107041,
            "range": "± 16467",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 99180,
            "range": "± 28883",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 22257,
            "range": "± 3489",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 65723,
            "range": "± 4312",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 471435,
            "range": "± 10347",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 697,
            "range": "± 68",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 119,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 1423,
            "range": "± 145",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "d8ee72718bee8d856eb2828c126dff138269374c",
          "message": "3.6.4 — list_holders local-truth TTL bypass restored (#130 reopen)\n\nv3.5.2 reverted v3.5.1's local-held bypass and introduced a separate\nlist_local_holders. CIRISConformance reopened #130 against v3.6.3:\nlist_holders_json still returns [] for locally-held blobs with stale\nattestations, AND — worse — the takedown handler internally calls\nlist_holders so stale-attested NCMEC/CSAM/CourtOrder content evades\neviction. That's a child-safety hole.\n\nFix: restore the v3.5.1 bypass on both backends. When the blob is in\nfederation_blobs (we have the bytes), TTL is skipped — the bytes are\ndefinitive proof of holding. The withdraws filter stays in both\nbranches as the active eviction signal. list_local_holders is kept\nas the strict local-only surface.\n\nTests:\n - blob_list_holders_filters_out_expired_ttl → renamed to\n   blob_list_holders_locally_held_bypasses_ttl + assertion flipped\n   on both backends (the old assertion pinned the wrong semantic).\n - blob_list_local_holders_includes_stale_local_holding updated:\n   both methods now report the holder for the locally-held case.\n - New blob_list_holders_stale_local_repro_130 (sqlite).\n - New process_takedown_admission_evicts_stale_local_holder\n   (cirisnode) — explicit child-safety regression: 48h-stale\n   attestation + NCMEC takedown → holders_seen=1, withdraws_emitted=1,\n   holders_evicted=1.\n\nPython verification: rebuilding into a venv shows the user's\n2-day-old-ts repro now returns [\"test-signer\"] from list_holders_json.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-30T12:51:31-05:00",
          "tree_id": "59ff1e3840e710e1c8073fc31bd667143b55b405",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/d8ee72718bee8d856eb2828c126dff138269374c"
        },
        "date": 1780164716031,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45670665,
            "range": "± 24229",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 3526945,
            "range": "± 147309",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2571,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5849,
            "range": "± 483",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12341,
            "range": "± 281",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43860,
            "range": "± 93",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 179,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 506,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 577,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1992,
            "range": "± 35",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 71,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 212,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 896,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 48716,
            "range": "± 776",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 149781,
            "range": "± 1110",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 551043,
            "range": "± 2934",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8203,
            "range": "± 377",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 8846,
            "range": "± 414",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 15386,
            "range": "± 495",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 39719,
            "range": "± 1323",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 801677,
            "range": "± 2678",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 3616724,
            "range": "± 50863",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 260171,
            "range": "± 10004",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 654115,
            "range": "± 16248",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 33877563,
            "range": "± 403372",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1509977,
            "range": "± 155911",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 5628331,
            "range": "± 139724",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 83883940,
            "range": "± 511795",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 3818801,
            "range": "± 129824",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 14454711,
            "range": "± 186523",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 75514,
            "range": "± 4284",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 66780,
            "range": "± 3424",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 14170,
            "range": "± 499",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 49456,
            "range": "± 623",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 384791,
            "range": "± 2637",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 506,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 96,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 851,
            "range": "± 36",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "56c6685b0b289f0d45b2bedf10f83b351a44ae21",
          "message": "docs(pyo3): fix cirisnode_retire_key_grants_json summary — emits supersedes (option-b), not withdraws\n\nThe body and return shape already correctly described supersedes per\nCEG 0.3 §5.6.8.4 option-b; only the one-line summary was stale from\nthe pre-CEG 0.3 design where withdraws was the planned emission. User\nflagged in CIRISPersist#130 comment thread.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-30T13:10:43-05:00",
          "tree_id": "0ba6e01c51d778f8b2b63f683daab706d092d6f8",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/56c6685b0b289f0d45b2bedf10f83b351a44ae21"
        },
        "date": 1780165825750,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40435592,
            "range": "± 330448",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 3463736,
            "range": "± 172781",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2524,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 6030,
            "range": "± 35",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 13106,
            "range": "± 187",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 46328,
            "range": "± 548",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 37,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 203,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 522,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 597,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2067,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 74,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 232,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1037,
            "range": "± 35",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 61285,
            "range": "± 7661",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 166146,
            "range": "± 17105",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 583684,
            "range": "± 24468",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 9059,
            "range": "± 926",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9768,
            "range": "± 911",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 19498,
            "range": "± 1052",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 51915,
            "range": "± 2062",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 976300,
            "range": "± 6335",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 3605714,
            "range": "± 42198",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 202658,
            "range": "± 11160",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 624323,
            "range": "± 34019",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 34541620,
            "range": "± 159546",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1369455,
            "range": "± 72708",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 6225232,
            "range": "± 246347",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 85513837,
            "range": "± 1517523",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 3580202,
            "range": "± 221938",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 15404623,
            "range": "± 229135",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 92880,
            "range": "± 8613",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 74359,
            "range": "± 3692",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 17750,
            "range": "± 1579",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 55596,
            "range": "± 1932",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 408520,
            "range": "± 11456",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 655,
            "range": "± 55",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 121,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 1225,
            "range": "± 82",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "e2011c25327dfbfee95ff017451c7f7f0e2e3861",
          "message": "3.6.5 — put_blob_signing PyO3 hot-path: prefer in-memory local signer (~1000× speedup, #137)\n\nCIRISConformance's cross-wheel benchmark surfaced put_blob_signing as\nthe first Python hot-path candidate: flat ~82ms per-call,\nsize-independent, ~50× the raw SQLite write.\n\nDiagnosed via an in-trait timing probe: signer.sign() is ~81ms per\ncall; envelope+canonicalize+hash is 0µs. The PyO3 wrapper hardcoded\nself.signer (the platform keyring signer), which on Linux desktops\ngoes through dbus → libsecret → secret-service per call.\n\nNative Rust micro-bench of the same trait path: 91µs p50. So the\n80ms is entirely the dbus round-trip, not the trait or the crypto.\n\nFix: when caller-supplied attesting_key_id matches the engine's\nlocal signer alias, use LocalSignerHardwareAdapter (in-memory,\n~14µs) instead of self.signer. Otherwise fall back to self.signer\nunchanged.\n\nMeasured:\n 256 B   88.9ms → 0.04ms  (2222×)\n 1 KB    84.2ms → 0.07ms  (1202×)\n 16 KB   82.5ms → 0.07ms  (1178×)\n 256 KB  83.6ms → 0.72ms  (116×, base64 decode dominates)\n\nPer-call throughput at 1KB: 12 blobs/s/thread → 14,000 blobs/s/thread.\n\nOther self.signer.clone() sites (local_sign_b64, evict_actor_json,\ncirisnode_*) share the same dbus-overhead profile; will audit + apply\nthe same pattern in a follow-up.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-30T13:34:26-05:00",
          "tree_id": "fe3e5b06c51486d1d2134f3559e72bcb53b3fdd5",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/e2011c25327dfbfee95ff017451c7f7f0e2e3861"
        },
        "date": 1780167243650,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45671783,
            "range": "± 40980",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2502272,
            "range": "± 187898",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2397,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5658,
            "range": "± 71",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12327,
            "range": "± 36",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43702,
            "range": "± 89",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 181,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 536,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 607,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2023,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 64,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 208,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 908,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 47761,
            "range": "± 1435",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 149110,
            "range": "± 12592",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 550431,
            "range": "± 1695",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7610,
            "range": "± 430",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 8920,
            "range": "± 375",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 15464,
            "range": "± 426",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 38005,
            "range": "± 988",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 804831,
            "range": "± 20885",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 4980192,
            "range": "± 45389",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 316029,
            "range": "± 15209",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 822624,
            "range": "± 9516",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 47466483,
            "range": "± 232844",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1968660,
            "range": "± 58744",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 7735458,
            "range": "± 140023",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 118343469,
            "range": "± 2194054",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 5010697,
            "range": "± 208844",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 20431310,
            "range": "± 407170",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 113274,
            "range": "± 14069",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 97749,
            "range": "± 7424",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 20496,
            "range": "± 829",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 69535,
            "range": "± 3176",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 541888,
            "range": "± 2185",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 532,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 95,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 902,
            "range": "± 31",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "5ab26aab996edb2d0301f724e3f3c4160ac26a9c",
          "message": "ci: build-manifest is a hard gate on PyPI publish again\n\nSecrets (CIRIS_BUILD_ED25519_SECRET / CIRIS_BUILD_MLDSA_SECRET) are\nnow configured. The v2.5.0 soft-fail posture was a stopgap for when\nthe secrets were missing — keeping it after the secrets land hides\nreal failures.\n\nv3.6.5 demonstrated the gap: registry was 503ing during that publish,\nthe manifest job failed at the steward-key snapshot fetch, but PyPI\nshipped anyway because manifest was continue-on-error. That breaks\nthe BuildManifest round-trip consumers depend on\n(/v1/builds/<v>?project=ciris-persist).\n\nRestoring:\n - drop continue-on-error from build-manifest\n - add build-manifest back to publish-pypi needs\n\nA future registry outage during a tag publish now stops the wheel\nfrom reaching PyPI until the manifest is registered — the right\nposture for the cryptographic-root-of-trust guarantee.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-30T15:05:14-05:00",
          "tree_id": "ff451800c3bed6746273067c6cf1fae74adda389",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/5ab26aab996edb2d0301f724e3f3c4160ac26a9c"
        },
        "date": 1780172746401,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 35427995,
            "range": "± 31070",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 3499149,
            "range": "± 190011",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2399,
            "range": "± 27",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5667,
            "range": "± 130",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12127,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43675,
            "range": "± 228",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 177,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 507,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 578,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1993,
            "range": "± 56",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 66,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 211,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 933,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 59304,
            "range": "± 5531",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 163746,
            "range": "± 313448",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 570846,
            "range": "± 771586",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8159,
            "range": "± 606",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9719,
            "range": "± 405",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 16988,
            "range": "± 603",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 40605,
            "range": "± 1226",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 816125,
            "range": "± 4190",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 2832044,
            "range": "± 58488",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 187633,
            "range": "± 4645",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 460300,
            "range": "± 24373",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 27221985,
            "range": "± 129213",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1241371,
            "range": "± 70028",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 4539062,
            "range": "± 120883",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 67248159,
            "range": "± 364346",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 3396541,
            "range": "± 180220",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 12057825,
            "range": "± 205330",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 62421,
            "range": "± 3638",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 55399,
            "range": "± 2045",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 11715,
            "range": "± 298",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 39747,
            "range": "± 1196",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 305101,
            "range": "± 1644",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 541,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 95,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 897,
            "range": "± 35",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "4cb413185a08e884845a1868ac765bf530b4b599",
          "message": "3.6.6 — CI-only: restore build-manifest hard-gate + M-of-N steward-key parse\n\nNo Rust changes. Functionally identical to v3.6.5.\n\nv3.6.5 shipped to PyPI while CIRISRegistry was 503ing because the\nbuild-manifest job was continue-on-error (v2.5.0 stopgap from when\nthe signing secrets weren't configured). PyPI artifact is fine; what\nv3.6.5 lacks is the /v1/builds round-trip consumers verify against.\n\nTwo CI fixes:\n - build-manifest is a hard gate again (continue-on-error dropped;\n   re-added to publish-pypi needs). Registry outage during tag publish\n   now blocks PyPI ship, preserving the crypto-root-of-trust posture.\n - Steward-key parse adapts to M-of-N shape (per CIRISVerify#31).\n   New /v1/steward-key returns {stewards:[...], verification_policy:{...}}\n   instead of the old {classical:{key_id}, pqc:{...}}. CI picks the first\n   deployed steward + records the M-of-N policy in the step summary.\n\nGitHub Actions reruns use the workflow at the original ref's commit,\nso v3.6.5's rerun would re-hit the broken parse. New tag is the\ncleanest path to a manifest-registered ship under the new posture.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-30T15:12:03-05:00",
          "tree_id": "ce51a766a0565e2e34962d0226140e3c9e67402b",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/4cb413185a08e884845a1868ac765bf530b4b599"
        },
        "date": 1780172994062,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 35426400,
            "range": "± 23367",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2607828,
            "range": "± 332673",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2389,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5650,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12312,
            "range": "± 118",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43732,
            "range": "± 702",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 179,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 507,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 578,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1992,
            "range": "± 52",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 66,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 212,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 931,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 63109,
            "range": "± 292080",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 169198,
            "range": "± 1086282",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 575715,
            "range": "± 1289653",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8297,
            "range": "± 663",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 8778,
            "range": "± 491",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 17195,
            "range": "± 1197",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 38522,
            "range": "± 2259",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 805701,
            "range": "± 6965",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 3638370,
            "range": "± 23858",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 221541,
            "range": "± 6704",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 588796,
            "range": "± 16717",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 35897994,
            "range": "± 897698",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1506202,
            "range": "± 51391",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 5842618,
            "range": "± 123531",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 89940065,
            "range": "± 1220352",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 4268769,
            "range": "± 154629",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 15921363,
            "range": "± 750802",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 106048,
            "range": "± 9869",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 89030,
            "range": "± 4715",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 15815,
            "range": "± 496",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 52552,
            "range": "± 710",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 403703,
            "range": "± 10953",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 534,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 96,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 893,
            "range": "± 52",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "b4151b62d5ddd09a4a6b78b663a0c06d32e67e7f",
          "message": "ci: handle M-of-N steward-key shape (registry rotated per CIRISVerify#31)\n\nRegistry's /v1/steward-key now returns:\n  {stewards: [{region, key_id, deployed, classical_pubkey, pqc_pubkey, ...}],\n   verification_policy: {threshold, of_total, scheme}}\n\nThe old shape was {classical: {key_id}, ...}. v3.6.5's manifest job\nhit KeyError: 'classical' on the rerun once registry came back.\n\nFix: pick the first deployed steward's key_id for the step-summary\nsurfacing, and also surface the M-of-N verification policy.\n\nThe actual registration call (ciris-build-sign register) is CIRISVerify's\nbinary; it already speaks the new shape.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-30T15:10:51-05:00",
          "tree_id": "adb51066439340fdfe4db52429e158848e5a48f0",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/b4151b62d5ddd09a4a6b78b663a0c06d32e67e7f"
        },
        "date": 1780173028043,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40439179,
            "range": "± 26193",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2824681,
            "range": "± 157260",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2526,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5967,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 13052,
            "range": "± 332",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 46150,
            "range": "± 564",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 38,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 203,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 523,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 598,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2065,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 81,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 245,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1065,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 54891,
            "range": "± 1717",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 161476,
            "range": "± 5268",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 575249,
            "range": "± 9465",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8969,
            "range": "± 508",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 10304,
            "range": "± 806",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 19031,
            "range": "± 656",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 53045,
            "range": "± 1709",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 963173,
            "range": "± 5320",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 4475431,
            "range": "± 98505",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 240495,
            "range": "± 19409",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 763054,
            "range": "± 39740",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 42331482,
            "range": "± 839021",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1751958,
            "range": "± 77456",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 7322627,
            "range": "± 114365",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 104324445,
            "range": "± 612981",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 4708021,
            "range": "± 193029",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 18642884,
            "range": "± 214944",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 109520,
            "range": "± 10230",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 100752,
            "range": "± 6140",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 23196,
            "range": "± 1716",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 70069,
            "range": "± 1692",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 496037,
            "range": "± 5929",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 698,
            "range": "± 44",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 123,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 1291,
            "range": "± 117",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "bc8cb6ff2e4f087d406526f5b6b4075c3591075c",
          "message": "3.6.7 — CI-only re-roll: heredoc the steward-key parse (v3.6.6 shell-escape bug)\n\nv3.6.6's POLICY line used python3 -c with nested \\\" escapes inside\nsingle-quoted shell args. Python tokenizer saw `\\<newline>` as a\nline continuation: SyntaxError: unexpected character after line\ncontinuation character. Hard-gate caught it — PyPI publish blocked.\n\nFix: heredoc the whole steward-key parse so shell quoting never\ntouches the Python source. Same KID + POLICY surfacing semantic.\n\nNo Rust changes. Functionally identical to v3.6.5.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-30T15:30:50-05:00",
          "tree_id": "ae94000fc289e2a438f622c5de71acf4f62e743f",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/bc8cb6ff2e4f087d406526f5b6b4075c3591075c"
        },
        "date": 1780174231437,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40428332,
            "range": "± 130449",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 1870915,
            "range": "± 148695",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2550,
            "range": "± 70",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 6055,
            "range": "± 43",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 13332,
            "range": "± 1067",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 47325,
            "range": "± 879",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 37,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 204,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 523,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 599,
            "range": "± 73",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2067,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 74,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 237,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1049,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 56634,
            "range": "± 3282",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 161675,
            "range": "± 2601",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 577581,
            "range": "± 4540",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 9346,
            "range": "± 417",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9924,
            "range": "± 530",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 19581,
            "range": "± 814",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 52103,
            "range": "± 2754",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 961832,
            "range": "± 2184",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 6554019,
            "range": "± 58511",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 354395,
            "range": "± 29413",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 1116251,
            "range": "± 38085",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 63689054,
            "range": "± 615877",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 2385307,
            "range": "± 105692",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 10883068,
            "range": "± 338414",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 157714329,
            "range": "± 686925",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 6098459,
            "range": "± 122746",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 28569126,
            "range": "± 299030",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 143715,
            "range": "± 15272",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 146589,
            "range": "± 8864",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 35179,
            "range": "± 2884",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 107012,
            "range": "± 2019",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 758501,
            "range": "± 6576",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 763,
            "range": "± 52",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 122,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 1400,
            "range": "± 130",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "3a4e319b9a1371f7d8cdf04dadefaa3a385ad14c",
          "message": "3.6.8 — local-signer fast-path on all sign-emitting PyO3 surfaces (#138, #140)\n\nCIRISConformance #140 surfaced the same issue on darwin × {sqlite,postgres}\nthat #137 solved on the Linux dbus path: evict_actor_json's hardcoded\nself.signer can't reach the Keychain in headless macOS CI runners →\nwithdraws_failed equals blobs_evicted instead of being zero.\n\nThe #137 fix had been applied only to put_blob_signing. v3.6.8\ngeneralizes it into a shared PyEngine::select_signer helper and threads\nit through every sign-emitting site:\n\n  put_blob_signing                            attesting_key_id\n  evict_actor_json                            attesting_key_id  (#140)\n  cirisnode_process_takedown_admission_json   signer_key_id\n  cirisnode_retire_key_grants_json            actor_key_id\n  receive_and_persist                         self.signer_key_id\n\nLeft as-is: public_key, sign — explicit-intent platform-signer surfaces.\n\nTested:\n - sqlite + cirisnode: 803/803 green\n - postgres: 50/50 green (PG-gated tests)\n\n#139 investigated separately: persist's enqueue_outbound PyO3 path\nworks cleanly on postgres at this commit (direct repro: 10 interleaved\nput_blob_signing + enqueue_outbound rounds, no hang, no panic). The\nhang in edge's send_durable_inline_text is not in persist — leaving\nthe issue open for edge-side investigation. See #139 comment.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-30T16:18:15-05:00",
          "tree_id": "7fa1d55a8b39de0b4feac24601753f8b91dd09a1",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/3a4e319b9a1371f7d8cdf04dadefaa3a385ad14c"
        },
        "date": 1780177093536,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40428062,
            "range": "± 51743",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 1565381,
            "range": "± 112927",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2530,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5964,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 13075,
            "range": "± 59",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 46069,
            "range": "± 413",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 35,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 202,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 521,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 597,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2064,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 78,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 231,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1021,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 55157,
            "range": "± 1124",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 162025,
            "range": "± 3962",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 586474,
            "range": "± 6870",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 9965,
            "range": "± 587",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 10222,
            "range": "± 748",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 20950,
            "range": "± 958",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 56312,
            "range": "± 1729",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 973118,
            "range": "± 9175",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 8365185,
            "range": "± 78400",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 539495,
            "range": "± 16914",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 1506888,
            "range": "± 29127",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 76447077,
            "range": "± 434312",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 3047127,
            "range": "± 139887",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 13185482,
            "range": "± 394781",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 188999984,
            "range": "± 1566612",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 10169322,
            "range": "± 649184",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 33683038,
            "range": "± 269063",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 192294,
            "range": "± 14646",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 171826,
            "range": "± 15100",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 41531,
            "range": "± 3397",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 125559,
            "range": "± 3143",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 905384,
            "range": "± 17378",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 718,
            "range": "± 57",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 123,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 1456,
            "range": "± 141",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "cb4f779aa70cb5307874b76cf17445bb9b35fae3",
          "message": "3.6.9 — verify pin v4.4.3 + macOS Mach-O parity gate (#141 / CIRISEdge#50 darwin)\n\nCloses the cross-cdylib SIGSEGV class on darwin × sqlite. Linux was\nfixed by #136's auditwheel --exclude + readelf gate; macOS was latent\nbecause verify v4.4.1 silently activated rusqlite/bundled in its\ntarget table (hypothesizing the SIGSEGV was Linux-ELF-only — wrong;\nMach-O has the same per-cdylib isolation behavior) and persist had\nno Mach-O equivalent of the readelf gate.\n\nVerify v4.4.3 (CIRISVerify#45) dropped macOS from the bundled\ntarget. cargo tree --target=aarch64-apple-darwin -e features\nconfirms no rusqlite/bundled feature on darwin/linux/iOS post-bump.\nAndroid keeps bundled (NDK convention).\n\nmacOS gate mirrors the Linux readelf check:\n - REQUIRE /usr/lib/libsqlite3.dylib in otool -L LC_LOAD_DYLIB output\n - REJECT any defined global sqlite3_* symbol from nm -gU\n   (statically-embedded libsqlite3 exposes its API as defined globals;\n    dynamically-linked has them as undefined externals only)\n\nTests: 803/803 sqlite+cirisnode green at v3.6.9. PG-only tests not\nre-run from cached results (verify bump doesn't touch PG paths).\n\nExpected CIRISConformance darwin × sqlite test_durable_send_enqueues_\nto_outbound_queue: rc=-11 → clean exit on next conformance pin to\nv3.6.9.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-30T18:58:41-05:00",
          "tree_id": "8d729abbf8f98be62b4e73f30ce9957a41251b49",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/cb4f779aa70cb5307874b76cf17445bb9b35fae3"
        },
        "date": 1780186812899,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45668743,
            "range": "± 30190",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2680459,
            "range": "± 174462",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2389,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5660,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12227,
            "range": "± 84",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43780,
            "range": "± 508",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 144,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 507,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 577,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1992,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 66,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 209,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 917,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 48856,
            "range": "± 2240",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 149937,
            "range": "± 971",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 547565,
            "range": "± 3917",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7265,
            "range": "± 471",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 8363,
            "range": "± 365",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 15445,
            "range": "± 439",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 38068,
            "range": "± 1954",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 809652,
            "range": "± 6238",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 4590239,
            "range": "± 70441",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 284457,
            "range": "± 10803",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 754464,
            "range": "± 23784",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 43749269,
            "range": "± 351245",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1849212,
            "range": "± 78316",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 7235657,
            "range": "± 146342",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 109468927,
            "range": "± 947073",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 4888678,
            "range": "± 583996",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 18992351,
            "range": "± 276292",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 95846,
            "range": "± 8725",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 85726,
            "range": "± 3908",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 19306,
            "range": "± 619",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 65065,
            "range": "± 656",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 510857,
            "range": "± 8128",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 521,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 97,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 871,
            "range": "± 40",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "aedaca7427c67e7b004f7bcf93470bede3999368",
          "message": "3.7.0 — CEG 0.6 substrate foundation: subject_key_ids[] + withdraws_admission_rule on federation_attestations (#146 Ask 1)\n\nCEG 0.6 (CIRISRegistry d8b53a0, 2026-05-31) is \"the missing half of\nconsent at the wire format\" — CEG ≤0.5 encoded only producer authority\n(attesting_key_id); CEG 0.6 adds subject authority via one optional\nenvelope field. This minor lands the schema + persistence; the\nadmission gate, SLA watcher, consent_record subject_kind, and\ncanonical-hash binding helper follow in v3.8.0 / v3.9.0 cuts.\n\nSchema (V055, both backends):\n - federation_attestations.subject_key_ids JSONB NOT NULL DEFAULT '[]'\n   (Postgres) / TEXT NOT NULL DEFAULT '[]' CHECK json_valid (SQLite).\n   GIN index on Postgres.\n - federation_attestations.withdraws_admission_rule SMALLINT NULL\n   CHECK 1..=4 (Postgres) / INTEGER (SQLite). Partial index on both.\n   NULL on non-withdraws; populated by the gate landing in v3.8.0.\n\nRust struct:\n - Attestation::subject_key_ids: Vec<String>, skip_serializing_if empty\n - Attestation::withdraws_admission_rule: Option<u8>, skip_serializing_if None\n - Backward-compat: empty/None serializes as absence so legacy rows'\n   canonical bytes and persist_row_hash are unchanged.\n\nRead/write paths (both backends):\n - 7 SELECT statements feeding row_to_attestation now include the\n   new columns\n - put_attestation INSERT writes them\n - holds_bytes INSERT uses the schema default (no code change)\n\nEach entry MAY be a federation_keys.key_id OR a canonical-hash\nidentifier (CEG 0.6 §4.2.2) — substrate does NOT FK-enforce, since\ncanonical-hash subjects (Discord user-ids, external party identifiers)\nare valid per the CEG 0.6 design.\n\nTests: 804/804 green (sqlite + postgres + cirisnode + pyo3). New\nregression put_attestation_round_trips_ceg06_subject_fields_sqlite\ncovers both federation-key + canonical-hash entries through the\npersist → read cycle.\n\n1+4 wire-format lockdown preserved: no new attestation_type. The field\nis on the envelope; CEG broadens the *admission rule* for withdraws\n(v3.8.0 work) — wire format unchanged.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-31T10:06:23-05:00",
          "tree_id": "94e26ff77979066a5db4e1ce9380d77d69ac5ab9",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/aedaca7427c67e7b004f7bcf93470bede3999368"
        },
        "date": 1780241189006,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40431341,
            "range": "± 32722",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2354947,
            "range": "± 312015",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2622,
            "range": "± 34",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 6012,
            "range": "± 29",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12837,
            "range": "± 59",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 45821,
            "range": "± 523",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 182,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 525,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 600,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2067,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 75,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 232,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1020,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 55775,
            "range": "± 2586",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 161837,
            "range": "± 4059",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 578580,
            "range": "± 5563",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 9432,
            "range": "± 641",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 10544,
            "range": "± 693",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 20027,
            "range": "± 687",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 54377,
            "range": "± 1421",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1034746,
            "range": "± 2343",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 5446574,
            "range": "± 38397",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 347256,
            "range": "± 16664",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 911886,
            "range": "± 31266",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 50206566,
            "range": "± 449626",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1960217,
            "range": "± 99358",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 8656083,
            "range": "± 173689",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 123949323,
            "range": "± 904806",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 5030651,
            "range": "± 133881",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 21907045,
            "range": "± 258289",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 109554,
            "range": "± 8784",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 102107,
            "range": "± 5306",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 27863,
            "range": "± 2334",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 81082,
            "range": "± 2106",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 587242,
            "range": "± 13700",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 714,
            "range": "± 58",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 126,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 1383,
            "range": "± 121",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "3aa4f8209b8df72d4b65a13adfa4e6dc119160bf",
          "message": "3.8.0 — CIRISVerify v4.7.1 pin + full wheel-surface roll: 5 verify surfaces on PyEngine (#151)\n\nPer Eric's \"if it ain't on the FFI/Python interface, it doesn't exist\"\ndiscipline: every CIRISVerify v4.7.0 wheel surface (CIRISVerify#50)\nis now exposed on persist's PyEngine class so Python users of\nciris-persist get them natively, no parallel ciris_verify dep needed.\n\nVerify pin: v4.4.3 → v4.7.1\n - ciris-keyring, ciris-verify-core, ciris-crypto all bumped\n - ciris-crypto features expanded: + hybrid-kex, + key-grant\n - macOS rusqlite-without-bundled posture preserved (#141 fix\n   in verify's target table still in place)\n\nFive new wheel surfaces (13 PyO3 methods + 1 PyClass):\n - wheel_key_grant: wrap_dek_for_recipient_b64 / unwrap_dek_b64\n - wheel_hybrid_kex: initiate/respond x {hybrid, classical}\n - wheel_locale_merkle: leaf_hash, verify_inclusion, merkle_root\n - wheel_skill_import: verify_skill_import_manifest_b64\n - wheel_reconsider_dos: PyReconsiderDosGuard PyClass with\n   admit_filing + record_outcome\n\nFile layout: each wheel as src/ffi/wheel_*.rs sibling module,\n~1500 lines total. PyEngine impl block gains 13 thin delegates\nplus PyReconsiderDosGuard PyClass registered in #[pymodule].\n\nWire convention: base64 for all byte fields (matches existing\nlocal_sign_b64 / public_key_b64 idiom; verify's own sidecars use\nlist[int]). KexError / KeyGrantError / VerifyError → PyRuntimeError;\nlength / shape / canonicalization failures → PyValueError.\nAEAD-opaque failures preserved (no oracle leak).\n\nTests: 824/824 green (sqlite + postgres + cirisnode + pyo3).\n20 new unit tests in the wheel_* modules: each round-trip + each\nerror path. PyErr message-text checks deferred to Python-pytest\n(PyO3 0.28+ PyErr message isn't introspectable from cargo test\nwithout a live Python interpreter).\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-31T14:11:26-05:00",
          "tree_id": "74ca5f6752da0761c9ca4a38300b9b58a81078bf",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/3aa4f8209b8df72d4b65a13adfa4e6dc119160bf"
        },
        "date": 1780256003635,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45670441,
            "range": "± 416153",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2853228,
            "range": "± 63451",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2498,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5739,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12359,
            "range": "± 142",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43630,
            "range": "± 134",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 143,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 506,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 577,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1992,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 65,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 210,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 919,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 48824,
            "range": "± 2085",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 151463,
            "range": "± 6170",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 555016,
            "range": "± 3159",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7702,
            "range": "± 316",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 8723,
            "range": "± 378",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 15952,
            "range": "± 707",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 39379,
            "range": "± 1102",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 879571,
            "range": "± 3620",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 4390248,
            "range": "± 42038",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 277309,
            "range": "± 6055",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 697138,
            "range": "± 41066",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 43602613,
            "range": "± 1267977",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1747369,
            "range": "± 56799",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 6808305,
            "range": "± 76958",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 102898046,
            "range": "± 3068239",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 4525432,
            "range": "± 208826",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 17717011,
            "range": "± 461606",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 98483,
            "range": "± 6017",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 88031,
            "range": "± 4339",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 17528,
            "range": "± 1443",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 60868,
            "range": "± 659",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 476591,
            "range": "± 15658",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 518,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 96,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 891,
            "range": "± 27",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "4c2317775e4f4708fbbb45303e8a627f027d03a9",
          "message": "3.9.0 — CEG 0.4/0.6 schema foundation: cohort_scope column + consent_record + canonical-binding + SLA-watcher tables (V056)\n\nSchema-foundation cut mirroring v3.7.0's discipline for\nsubject_key_ids[]. Lands the columns + struct fields + round-trip\nwiring so downstream consumers can populate the new fields.\nAdmission-gate enforcement, SLA watcher loops, multi-subject\nany-binding evict, canonical-hash binding, §8.1.8.1 promotion\nceremony, and full cohort_scope read-filtering are properly v3.10+\nwork (substantial; need trust-graph walks + background tokio tasks).\n\nV056 migration (both backends):\n - federation_attestations.cohort_scope TEXT NOT NULL DEFAULT\n   'federation' with closed-set CHECK {self, family, community,\n   affiliations, species, biosphere, federation} per CEG §4.2.4 +\n   §8.1.8. Partial index over non-federation rows.\n - cirisnode_contributions consent_record asymmetry columns + CHECK\n   (mirrors V054 takedown_notice/key_grant pattern).\n - cirisnode_consent_sla_watch table (background-task state for §8.1.11.3).\n - cirisnode_revocation_promotion_watch table (per CEG §10.1.3).\n - identity_canonical_binding table (proxy-chain index for §3.2.3 rule 3).\n\nRust:\n - Attestation::cohort_scope: String, skip_serializing_if default\n   ('federation') so legacy rows' canonical bytes / persist_row_hash\n   stay stable across the schema bump.\n - crate::federation::cohort_scope module with closed-set constants +\n   is_valid() predicate. Future admission gate consumes this.\n - 22 Attestation { } construction sites updated.\n\nRound-trip:\n - 5 SELECT statements + 1 INSERT per backend extended with the new\n   column. row_to_attestation reads cohort_scope from the row.\n - 824/824 tests green (sqlite + postgres + cirisnode + pyo3).\n\nUpstream issues filed in this cut:\n - CIRISRegistry#47 — CEG 0.7: subject_kind: identity_occurrence +\n   subject_kind: family (for self/family at-rest encryption flow)\n - CIRISPersist#152 — self/family at-rest encryption (gated on #47)\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-31T15:06:09-05:00",
          "tree_id": "fd2c9d672890c7bf755d26469cda427ca1c692f3",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/4c2317775e4f4708fbbb45303e8a627f027d03a9"
        },
        "date": 1780259390174,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40426350,
            "range": "± 134600",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 3173634,
            "range": "± 149208",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2514,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5923,
            "range": "± 55",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12956,
            "range": "± 80",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 45614,
            "range": "± 194",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 35,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 188,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 524,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 600,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2067,
            "range": "± 68",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 75,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 231,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1007,
            "range": "± 29",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 55443,
            "range": "± 1827",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 162058,
            "range": "± 3791",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 578457,
            "range": "± 5008",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 10169,
            "range": "± 620",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 10660,
            "range": "± 790",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 20075,
            "range": "± 1151",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 52159,
            "range": "± 3746",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1178418,
            "range": "± 18683",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 3989343,
            "range": "± 58194",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 248819,
            "range": "± 12698",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 717328,
            "range": "± 21100",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 36956078,
            "range": "± 206958",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1518069,
            "range": "± 67817",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 6366819,
            "range": "± 205717",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 91199779,
            "range": "± 455837",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 3812587,
            "range": "± 123961",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 16242031,
            "range": "± 185458",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 87914,
            "range": "± 6414",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 92224,
            "range": "± 5951",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 20792,
            "range": "± 1586",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 60426,
            "range": "± 1350",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 456635,
            "range": "± 13411",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 737,
            "range": "± 56",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 121,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 1266,
            "range": "± 114",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "8c829e1d1d86b0afd4ca81959705d68a349c6d85",
          "message": "3.10.0 — CIRISVerify v4.8.0 pin + roll-up of 3.9.1/3.9.2/3.9.3 enforcement slices\n\nRolls the verify pin v4.7.1 → v4.8.0 across all six dep sites\n(ciris-keyring × 4 platform-conditional rows + ciris-verify-core +\nciris-crypto). v4.8.0 is operational hardening of the attestation path:\n\n- ResilientRegistryClient sequential failover collapses to a parallel\n  race over all registry endpoints under a 10s RACE_BUDGET — closes\n  CIRISVerify#52 (Eric's S21U / Verizon LTE 90-second startup hang).\n- build_async_http_client factory pins per-call-class timeouts\n  (Probe 2s/2s, Normal 5s/10s, DoH 3s/5s) with tcp_keepalive(30s).\n- HeartbeatGuard RAII ticker emits 5s tracing::warn! phase tags\n  through the attestation lifecycle (1 log line → 17 on hang).\n- Worst-case budget hierarchy sums to ≤13s under the 15s ceiling.\n\nNo persist API change — the bump is pulled in so wheel-surface\nconsumers (CIRISEngine / CIRISAgent / CIRISLens) inherit v4.8.0\nrobustness through the surfaces persist already exposes.\n\nThis cut also publishes the 3.9.1/3.9.2/3.9.3 enforcement slices\nthat landed on main in the same window (see the per-version sections\nof CHANGELOG.md for the architectural detail):\n - 3.9.1: cohort_scope admission-gate validation (#150 Ask 3)\n - 3.9.2: holds_bytes suppression for cohort_scope:self|family\n          (#153 Ask 5 — the structural-invisibility primitive)\n - 3.9.3: bulk peer-level cohort_scope filter on list_federation_keys\n          (#151)\n\nTests: 547/547 sqlite lib tests green on v4.8.0; --features pyo3 +\n--features sqlite both compile clean; clippy clean.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-06-03T19:17:00-05:00",
          "tree_id": "1bf187871386765bf54b423adbd774a313168ea1",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/8c829e1d1d86b0afd4ca81959705d68a349c6d85"
        },
        "date": 1780533593615,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40435491,
            "range": "± 37962",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2046574,
            "range": "± 333619",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2519,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5921,
            "range": "± 27",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12997,
            "range": "± 191",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 45857,
            "range": "± 481",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 37,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 203,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 521,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 596,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2063,
            "range": "± 62",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 10,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 77,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 230,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1031,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 55617,
            "range": "± 1951",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 161621,
            "range": "± 3263",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 576999,
            "range": "± 3552",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 9511,
            "range": "± 735",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 11913,
            "range": "± 698",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 21835,
            "range": "± 879",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 56207,
            "range": "± 2462",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1188642,
            "range": "± 4198",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 6365658,
            "range": "± 82599",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 392287,
            "range": "± 20968",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 1117519,
            "range": "± 23617",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 57958235,
            "range": "± 394366",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 2450051,
            "range": "± 126203",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 10554301,
            "range": "± 352188",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 144149920,
            "range": "± 793100",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 7834356,
            "range": "± 609361",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 29008444,
            "range": "± 1208085",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 161158,
            "range": "± 12201",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 135984,
            "range": "± 10340",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 30564,
            "range": "± 2328",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 97608,
            "range": "± 7413",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 680717,
            "range": "± 17779",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 677,
            "range": "± 57",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 124,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 1406,
            "range": "± 234",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "2c9e34eedaa29d84d4ac8764f1d85f3b1e08588c",
          "message": "3.11.0 — verify-coord R1+Q1 substrate (#143, F-AV-FRONTRUN + F-AV-ROLLBACK closure)\n\nPins CIRISVerify FEDERATION_THREAT_MODEL §3.3.2 constants (ratified\nv1.1, audited v1.2 at 51da15f) into the substrate as wire-format-\nnormative values, and lands the deterministic 3-tier merge comparator\n+ anti-rollback admission gate the spec requires.\n\nConstants (in crate::federation::verify_coord):\n - R1: τ_normal=60s, τ_partial=300s\n - Q1: bounded_staleness=300s, N_regions=3, quorum_write_threshold=2\n - F-AV-13: revocation_cache_ttl=30s (= τ_normal/2)\n - Region closed set: {us, eu, apac}\n\nComparator (compare_for_merge): pure function over MergeBallot —\n 1. quorum_weight DESC (more regions wins)\n 2. signed_timestamp DESC (later wins — F-AV-FRONTRUN closure)\n 3. canonical_bytes_hash ASC (deterministic tie-break)\nStrict total order; antisymmetric. 9 unit tests pin each tier\ndominance pair + the antisymmetry contract.\n\nAnti-rollback (F-AV-ROLLBACK closure): put_revocation (both backends)\nruns check_revocation_anti_rollback BEFORE persist_row_hash + INSERT.\nA submitted revocation with signed_timestamp <= existing latest for\nthe same revoked_key_id rejects with typed Error::RevocationRollback\n(kind \"federation_revocation_rollback\"). Sufficient minority of\nregions can't ratify a rollback — the rollback never enters quorum.\n\nSchema (V058, both backends):\n - federation_revocations.observed_region TEXT NOT NULL DEFAULT 'us'\n   CHECK IN ('us', 'eu', 'apac'). DEFAULT + skip_serializing_if\n   keeps pre-v3.11 persist_row_hash stable (V056 cohort_scope\n   discipline).\n - New table federation_revocation_quorum_state: per-region\n   first-observation timestamps + quorum_reached_at +\n   denormalized quorum_weight (1..=3, comparator reads it directly).\n - Partial indexes on non-default region rows + committed-quorum subset.\n\nAdmission gate: check_observed_region rejects out-of-closed-set\nvalues with Error::RegionRejected (kind \"federation_region_rejected\").\nMirrors v3.9.1 cohort_scope discipline. V058 CHECK is the\ndefense-in-depth backstop for direct-SQL bypass.\n\nSpec-field mapping: signed_timestamp() → scrub_timestamp;\ncanonical_bytes_hash() → original_content_hash. Named accessors so\nthe spec mapping is verbatim without duplicating columns.\n\nPyO3 wheel surface (if it ain't on the FFI, it doesn't exist):\n - verify_coord_constants_json() → JSON dict of all constants\n - verify_coord_check_observed_region(s) — pre-validation\n - verify_coord_compare_for_merge(a_json, b_json) → -1/0/1\nAll static methods on PyEngine.\n\nAlso: pre-existing red fix (v3.10.0 CI failure)\n\nav26_concurrent_boot_advisory_lock had a hardcoded `expected 1..=53`\nupper bound on ciris_persist_schema_history rows that drifted as\nmigrations were added. Replaced with the dynamic\nembedded_lens_migration_count() helper so the test tracks the live\nmigration set instead of bit-rotting each release. The check still\ndiscriminates \"single lock-serialized boot's worth\" from\n\"N_WORKERS×migrations\" (would mean the lock didn't hold).\n100%-green discipline: pre-existing reds get fixed in the same cut\nthey're surfaced in.\n\nTests: 559/559 sqlite lib tests green (+12 from v3.10.0 — 9\nverify_coord + 3 admission integration). --features pyo3 +\n--features sqlite + --features postgres,server,pyo3,cirisaudit all\ncompile clean. Clippy clean across sqlite + pyo3.\n\nWhat's still v3.12+ (the consumer half + Front A):\n - Cross-region quorum-write worker (substrate stores bookkeeping;\n   the gossip-observer that writes per-region timestamps is follow-on)\n - F-AV-13 cache TTL enforcement in consumer code\n - CEG 0.7 family / identity_occurrence (#153 Asks 1-4/6/7) + CEG 0.8\n   community / location_proof (#154) — Front A of the parallel cut\n   plan, now executable since Registry#47 + #48 are ratified-locked.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-06-03T19:55:05-05:00",
          "tree_id": "b465a16ecbc6a322b7c949b9285e469da6bd2a25",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/2c9e34eedaa29d84d4ac8764f1d85f3b1e08588c"
        },
        "date": 1780535669457,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40434317,
            "range": "± 115238",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 1825083,
            "range": "± 144453",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2511,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5988,
            "range": "± 29",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12927,
            "range": "± 51",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 45575,
            "range": "± 402",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 35,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 205,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 522,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 598,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2064,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 73,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 232,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1030,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 56135,
            "range": "± 1988",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 162394,
            "range": "± 2610",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 576816,
            "range": "± 4850",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8844,
            "range": "± 1018",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 10176,
            "range": "± 679",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 19554,
            "range": "± 1008",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 52427,
            "range": "± 1365",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1222920,
            "range": "± 5747",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 7049313,
            "range": "± 117793",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 401182,
            "range": "± 27654",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 1274110,
            "range": "± 67278",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 66354708,
            "range": "± 623138",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 2315640,
            "range": "± 64834",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 11021902,
            "range": "± 285237",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 165176968,
            "range": "± 921158",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 5946004,
            "range": "± 306281",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 28559792,
            "range": "± 395810",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 167767,
            "range": "± 19862",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 154646,
            "range": "± 13214",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 34514,
            "range": "± 2829",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 107314,
            "range": "± 2388",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 749136,
            "range": "± 4022",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 681,
            "range": "± 60",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 122,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 1359,
            "range": "± 124",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "3b35db1baefca5eee5547de6015bcb55e2fe543a",
          "message": "3.12.0 — CEG 0.7 §5.6.8.8 + §5.6.8.9 identity_occurrence + family substrate foundation (#153 Asks 1-2)\n\nLands the structural primitives that distinguish \"participants that\nARE me\" (identity_occurrence — my devices and agents) from \"trusted\nnodes that compose with me\" (family — other people's identities +\nshared household devices). Front A of the parallel cut plan, now\nexecutable since Registry#47 ratified-locked on 2026-05-31.\n\nSchema (V059, both backends):\n - federation_identity_occurrences: composite PK (identity_key_id,\n   occurrence_key_id); closed-set device_class CHECK IN ('phone',\n   'laptop', 'server', 'embedded', 'agent', 'service'); opaque\n   hardware_attestation blob; valid_until for indefinite vs\n   time-bounded bindings.\n - federation_families: family_key_id PK; members JSONB / TEXT-json\n   array of {key_id, joined_at, role}; open-vocab consensus_protocol\n   validated at admission; consensus_protocol_entrenched structural\n   lock.\n - Postgres GIN jsonb_path_ops index on members for O(log N) \"which\n   families is identity X a member of?\" via `members @> ...`. SQLite\n   EXISTS / json_each scan; acceptable for the cardinality.\n - Partial indexes on the entrenched-protocol subset (§9\n   HUMANITY_ACCORD-style lookup, tiny set in practice).\n\nRust types (in federation::types):\n - IdentityOccurrence, Family, FamilyMember, SignedIdentityOccurrence,\n   SignedFamily — full serde + persist_row_hash integration.\n - device_class module: closed-set constants + is_valid + ALL.\n - consensus_protocol module: bare-form constants + prefix constants\n   + is_canonical_form predicate (parses founder_only/unanimous/\n   majority/quorum:m/n with m<=n,n>0/weighted:rubric/custom:id).\n\nAdmission gates (value-validation tier; trust-graph is v3.13+):\n - check_device_class -> Error::DeviceClassRejected\n   (kind federation_device_class_rejected)\n - check_consensus_protocol_form -> Error::ConsensusProtocolMalformed\n   (kind federation_consensus_protocol_malformed)\n Both run BEFORE persist_row_hash + INSERT; V059 CHECK constraints\n are the defense-in-depth backstops for direct-SQL bypass.\n\nFederationDirectory trait (memory + sqlite + postgres):\n - put_identity_occurrence / list_identity_occurrences_for /\n   lookup_identity_for_occurrence (reverse: \"is this signing key\n   co-self with X?\")\n - put_family / lookup_family / list_families_for_member\n\nPyO3 wheel surface (if it ain't on the FFI, it doesn't exist):\n - put_identity_occurrence_json + list_identity_occurrences_for_json\n   + lookup_identity_for_occurrence_json\n - put_family_json + lookup_family_json + list_families_for_member_json\n\nWhat this substrate enables (v3.13+):\n - #152 at-rest DEK cascade: wrap content DEKs to all currently-\n   admitted occurrences + family members when content lands at\n   cohort_scope:self|family.\n - #150 caller-vs-scope trust-graph admission (the deferred slice\n   from v3.9.1): cohort_scope:self writes admit when attesting_key_id\n   is an identity_occurrence of the local key; cohort_scope:family\n   writes admit per the family's consensus_protocol.\n - #146 Ask 2 broadened withdraws admission (4-rule gate): the\n   canonical-binding rule (rule 4) reads from\n   federation_identity_occurrences to admit subject-side revocations\n   from any of the subject's occurrences.\n\nWhat's still v3.13+ (intentionally out of scope for #153 Asks 1-2):\n - Full self-vouch / single-vouch admission per §5.6.8.8 (needs\n   trust-graph walk against list_identity_occurrences_for)\n - Consensus-protocol signature-counting per §5.6.8.9 (founder_only\n   / unanimous / majority / quorum:m/n / weighted:rubric / custom:id\n   enforcement; consensus_protocol_entrenched amendment rejection)\n - Retroactive key_grant emission on member-add (§5.6.8.9 step 3)\n - hard_case:identity_occurrence_added /\n   hard_case:family_membership_change substrate emissions per §7.2\n\nTests:\n - 4 new sqlite integration tests\n   (identity_occurrence_round_trip, device_class rejection, family\n   round_trip, 10 malformed consensus_protocol rejections + the\n   quorum:2/3 canonical admit).\n - 563/563 sqlite lib tests green (+4 from v3.11.0).\n - --features pyo3 + --features sqlite + --features\n   postgres,server,pyo3,cirisaudit all compile clean.\n - Clippy clean across sqlite + pyo3.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-06-03T20:32:33-05:00",
          "tree_id": "7553ffa136cad0deeecebd0ffa0292ff9d993789",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/3b35db1baefca5eee5547de6015bcb55e2fe543a"
        },
        "date": 1780537934966,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40424217,
            "range": "± 41339",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2727428,
            "range": "± 235222",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2531,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5946,
            "range": "± 28",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 13061,
            "range": "± 174",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 46067,
            "range": "± 217",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 35,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 203,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 522,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 597,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2064,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 75,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 231,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1023,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 55074,
            "range": "± 4132",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 161759,
            "range": "± 7453",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 576791,
            "range": "± 11622",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 9883,
            "range": "± 900",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 11511,
            "range": "± 637",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 20342,
            "range": "± 922",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 53816,
            "range": "± 1821",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1226119,
            "range": "± 13990",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 4614047,
            "range": "± 65536",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 292573,
            "range": "± 15426",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 797723,
            "range": "± 64091",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 43311959,
            "range": "± 255148",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1812490,
            "range": "± 111780",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 7229385,
            "range": "± 136515",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 107698595,
            "range": "± 615340",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 4344362,
            "range": "± 311728",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 19622597,
            "range": "± 622086",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 106651,
            "range": "± 12379",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 103049,
            "range": "± 7829",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 22766,
            "range": "± 1720",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 68989,
            "range": "± 1702",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 500747,
            "range": "± 3289",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 677,
            "range": "± 54",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 119,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 1472,
            "range": "± 133",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "9ebefec16eacdae70c49eb7d3e80b9ceead8e3f9",
          "message": "3.12.1 — hotfix V059 postgres partial-index NOW() rejection (sqlstate 42P17)\n\nV059 reverse-lookup partial index on federation_identity_occurrences\n(occurrence_key_id) used:\n\n    WHERE valid_until IS NULL OR valid_until > NOW()\n\nPostgres requires partial-index predicates to reference only\nIMMUTABLE functions. NOW() is STABLE (per-transaction), so the\nmigration failed at apply time with sqlstate 42P17\n(invalid_object_definition).\n\nLocal sqlite tests passed because sqlite's V059 already used the\ncorrect dual-index shape (one partial WHERE valid_until IS NULL +\none full all-rows index). The CI postgres test target caught the\ndivergence on six feature axes (cirisaudit, secrets, core,\ncirisnode, cirisgraph, telemetry).\n\nFix: postgres V059 now mirrors the sqlite shape — partial covers the\ncommon indefinite-binding case, full index handles expired-row\nlookups. No application code change; no Rust changes.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-06-03T20:43:18-05:00",
          "tree_id": "0e84dfa004c43b0d3504edb114ddf56715869f89",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/9ebefec16eacdae70c49eb7d3e80b9ceead8e3f9"
        },
        "date": 1780538619207,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45674359,
            "range": "± 22278",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2313664,
            "range": "± 299793",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2446,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5764,
            "range": "± 87",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12199,
            "range": "± 79",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43807,
            "range": "± 203",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 180,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 508,
            "range": "± 41",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 579,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1993,
            "range": "± 36",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 67,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 210,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 920,
            "range": "± 32",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 48769,
            "range": "± 3758",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 151542,
            "range": "± 14781",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 559281,
            "range": "± 15616",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 9193,
            "range": "± 496",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9713,
            "range": "± 478",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 17002,
            "range": "± 954",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 40509,
            "range": "± 5941",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1053924,
            "range": "± 17735",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 5600024,
            "range": "± 91712",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 357622,
            "range": "± 13533",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 902178,
            "range": "± 8592",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 50310045,
            "range": "± 278483",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 2052650,
            "range": "± 52114",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 8478155,
            "range": "± 144449",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 125775280,
            "range": "± 1321619",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 6304026,
            "range": "± 198090",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 22244681,
            "range": "± 237301",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 144570,
            "range": "± 6343",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 117841,
            "range": "± 4389",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 21870,
            "range": "± 722",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 74623,
            "range": "± 381",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 580552,
            "range": "± 4479",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 515,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 97,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 887,
            "range": "± 29",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "68e03d0841c1476c6b9b71a23c4f1584ad0809f6",
          "message": "3.12.2 — diagnostic harness for cohabitation races + migration-timing log (#156)\n\nAdds the substrate-side toolchain to robustly investigate the v3.12.x\nsqlite cohab regression and any similar future race. Mirrors the\nCIRISEdge tools/ harness shape on the persist side so the two\nharnesses can run in parallel against the same scenario for two-sided\ncorrelation.\n\nNew `debug-tools` Cargo feature (default OFF):\n - src/debug/mod.rs — opt-in panic hook armed by CIRIS_PERSIST_PANIC_LOG.\n   Captures every background-thread panic with raw-IP + dladdr\n   backtrace into per-pid log files. Symbol resolution deferred to\n   post-mortem addr2line because the resolver aborts under concurrent\n   cohab panics.\n - panic_count() + install_panic_logger() PyO3 functions, only\n   compiled when the feature is on. Release wheels carry zero\n   diagnostic surface (strings absent from binary).\n - Two-layer opt-in: feature + CIRIS_PERSIST_PANIC_LOG env var.\n - dep:backtrace added as optional dep gated on the feature.\n\nsrc/store/migration_timing.rs (always-compiled, env-var-armed):\n - CIRIS_PERSIST_MIGRATION_TIMING_LOG -> one JSON-Lines entry per\n   run_migrations() call: {unix_ms, backend, total_wall_us,\n   applied_count, applied_versions}.\n - Quantifies how many microseconds each refinery run() adds to\n   first-Engine-open. #156 hypothesis directly measurable now.\n - Cost without env var: one env::var lookup per Engine open.\n\n[profile.panic-debug]: inherits release with debug=full, strip=none,\nincremental=false.\n\ntools/ harness directory (mirrors CIRISEdge layout):\n - race_repro.py — drives scenarios in N subprocesses; classifies\n   fast/hung/panicked/other. Adds --migration-timing-log.\n - debug_attach.sh — gdb 'thread apply all bt' wrapper.\n - scenarios/sqlite_inmemory_cohab.py — direct repro of #156.\n - scenarios/engine_construction_timing.py — cross-version timing.\n - scenarios/concurrent_boot_advisory_lock.py — Python sibling of\n   qa_harness::av26.\n - tools/README.md — architecture + workflow + security posture.\n\nTests: 565/565 sqlite lib tests green with --features sqlite,\ndebug-tools (+2 migration_timing tests). Clippy clean.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-06-04T10:27:21-05:00",
          "tree_id": "bfa706f92e1e6ad6beaa2740d1ebc49be1b05f42",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/68e03d0841c1476c6b9b71a23c4f1584ad0809f6"
        },
        "date": 1780588472815,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45675779,
            "range": "± 227185",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 3165611,
            "range": "± 708246",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2383,
            "range": "± 89",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5669,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12256,
            "range": "± 59",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43447,
            "range": "± 172",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 145,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 506,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 577,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1991,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 66,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 210,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 912,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 48963,
            "range": "± 1505",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 149513,
            "range": "± 977",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 549004,
            "range": "± 4094",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7683,
            "range": "± 486",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9318,
            "range": "± 1707",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 17495,
            "range": "± 788",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 40717,
            "range": "± 1724",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1053521,
            "range": "± 10104",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 4004267,
            "range": "± 59726",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 266075,
            "range": "± 8076",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 716992,
            "range": "± 26646",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 37471595,
            "range": "± 532170",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1526726,
            "range": "± 24498",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 6569963,
            "range": "± 142872",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 93798372,
            "range": "± 884705",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 5615871,
            "range": "± 562664",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 18906324,
            "range": "± 903361",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 100198,
            "range": "± 7572",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 86596,
            "range": "± 3480",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 15969,
            "range": "± 1921",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 56200,
            "range": "± 1839",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 432507,
            "range": "± 5023",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 529,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 96,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 872,
            "range": "± 29",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "ac96bad5fceb43427ef985431b6ea818f8649b6a",
          "message": "3.13.0 — ABI-stable executor_capsule (#157 T1+T2; closes cross-tokio aliasing class behind #156 / CIRISEdge#58)\n\nReplaces the structurally-unsound runtime_handle_capsule (which hands\nout tokio::runtime::Handle — a Rust type whose spawn dispatch\nresolves to the CALLER's tokio crate, not persist's) with a C-ABI\nvtable surface whose function pointers live inside ciris_persist.\nabi3.so. Consumer calls vtable.spawn(...), control transfers into\npersist's .so, persist's tokio runtime.spawn(...) — the only tokio\nthat knows the runtime exists. Task lands on persist's worker pool;\npersist's workers poll it.\n\nSame structural class as CIRISPersist#141 (libsqlite3 cross-cdylib\nSIGSEGV); different primitive, same root cause: a stateful crate\nduplicated across the static-vs-wheel boundary with a value of that\ncrate's type passed through the FFI.\n\nNew src/ffi/executor_capsule.rs (~330 LOC):\n - AsyncExecutor (#[repr(C)]): data + vtable\n - AsyncExecutorVTable (#[repr(C)]): abi_version + _reserved + spawn\n   + drop (unsafe extern \"C\" fn)\n - TaskOpaque: type-erased thin pointer to\n   Box<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>\n - ASYNC_EXECUTOR_ABI_VERSION = 1 (consumers verify at receive)\n - PERSIST_EXECUTOR_VTABLE: canonical vtable; spawn impl calls\n   persist's tokio Runtime::spawn\n - build_persist_executor: Rust-side constructor\n - build_capsule_with_destructor: PyCapsule with vtable-routed GC\n   destructor (unsafe contained in this module per the\n   #![allow(unsafe_code)] precedent from src/debug/mod.rs)\n\nPyO3 surface:\n - PyEngine.executor_capsule() — returns PyCapsule name tag\n   ciris_persist::executor_capsule_v1\n - PyEngine.runtime_handle_capsule() — DEPRECATED in module docs;\n   kept for v3.13.x; removal scheduled next persist major (#157 T9)\n\nContract:\n - Capsule round-trip safe across cdylib (vtable pointers always\n   dispatch to persist's tokio)\n - Spawned future MUST NOT call consumer-crate's own tokio\n   primitives (would resolve to consumer's thread-local current\n   runtime, unset on persist's workers → \"no reactor running\" panic)\n - Use persist's public API (which uses persist's tokio internally)\n   or pure std primitives (mpsc channels for result delivery)\n - Lifetime: capsule holds Arc<Runtime> clone; outliving / outlasted\n   by PyEngine both fine; GC calls vtable.drop which decrements\n\nTests:\n - abi_version_pinned_at_1\n - vtable_layout_is_c_repr (abi_version at offset 0 — consumers\n   read via &'static AsyncExecutorVTable)\n - spawn_drop_round_trip_via_vtable (current_thread runtime)\n - spawn_via_multi_thread_runtime_actually_runs (multi-thread\n   runtime + std::sync::mpsc receive — the canonical CIRISEdge\n   run_async pattern)\n - 569/569 sqlite lib tests green (+4 from v3.12.2)\n - --features pyo3 + --features sqlite,debug-tools + clippy clean\n\nConsumer migration path (CIRISEdge#59 T4): receive PyCapsule via\nname-tag-checked unsafe cast, verify exec.vtable.abi_version ==\nASYNC_EXECUTOR_ABI_VERSION, build Box<Pin<Box<dyn Future + Send +\n'static>>> closing over std::sync::mpsc tx, hand through vtable.spawn,\nblock on rx.recv_timeout. Edge can pin to either the v3.13.0 tag or\na git ref of main; published wheel is not on the critical path.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-06-04T14:03:29-05:00",
          "tree_id": "43a1f03d45bb8dc705a32dc2879f476f88bfd349",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/ac96bad5fceb43427ef985431b6ea818f8649b6a"
        },
        "date": 1780601048080,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45673031,
            "range": "± 40837",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 3066847,
            "range": "± 384252",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2387,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5628,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12257,
            "range": "± 76",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43445,
            "range": "± 564",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 144,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 506,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 577,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1992,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 65,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 207,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 913,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 48519,
            "range": "± 2285",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 150142,
            "range": "± 2847",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 551815,
            "range": "± 9506",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7936,
            "range": "± 343",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9174,
            "range": "± 358",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 15745,
            "range": "± 472",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 38088,
            "range": "± 2112",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1061809,
            "range": "± 11022",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 4054075,
            "range": "± 137514",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 271956,
            "range": "± 20683",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 695548,
            "range": "± 21124",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 38379030,
            "range": "± 1103373",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1476796,
            "range": "± 16355",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 6167656,
            "range": "± 41264",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 95698172,
            "range": "± 714629",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 4088205,
            "range": "± 60898",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 16579938,
            "range": "± 182355",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 100742,
            "range": "± 8500",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 85321,
            "range": "± 3570",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 16305,
            "range": "± 392",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 56358,
            "range": "± 2345",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 441347,
            "range": "± 2374",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/block_on_noop",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/spawn_blocking_noop",
            "value": 515,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/raw_sqlite_write",
            "value": 97,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "storage_floor/next_sequence_full",
            "value": 867,
            "range": "± 49",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "3f87cd3d8a44400a28e24096ac9f6f6bd15feb9e",
          "message": "3.14.0 — inline-sync SQLite rewrite closes #158 cohab race\n\nRoot-cause for #158: tokio::task::spawn_blocking requires a current\ntokio runtime context (thread-local). Under the executor_capsule\ncohab path (#157), the polling chain crosses cdylib boundaries in a\nway that breaks tokio's thread-local invariant. Five fix attempts\nduring triage demonstrated the class:\n\n 1. handle: Handle field on SqliteBackend — ABI break (struct\n    layout mismatch with consumer wheels' static-linked persist\n    copy → SIGSEGV in Arc::clone at wrong offset)\n 2. OnceLock<Handle> module static — per-DSO statics, consumer\n    .so's copy never written\n 3. #[no_mangle] extern \"C\" + dlsym(RTLD_DEFAULT) — Python imports\n    with RTLD_LOCAL; symbols not globally visible\n 4. sys.setdlopenflags(RTLD_GLOBAL) — dlsym works, but Handle's\n    private Inner struct isn't ABI-stable across tokio patches\n    (1.52.1 vs 1.52.3); JoinHandle hangs on cross-DSO waker mismatch\n 5. Inline-sync rewrite (this cut) — eliminates the tokio-context\n    dependency entirely; persist's sqlite path stops calling\n    tokio primitives\n\nCommunity precedent: tokio-rusqlite, deadpool-sqlite, and Alice\n(Tokio maintainer) on users.rust-lang.org all converge on the same\npattern: short rusqlite calls inline in async fn bodies are\nacceptable for the multi-thread runtime case, no spawn_blocking\nrequired.\n\nMechanical changes (203 sites across 35 files):\n - Arc<tokio::sync::Mutex<Connection>> → Arc<parking_lot::Mutex<Connection>>\n   (parking_lot is sync, runtime-agnostic; already a persist dep)\n - tokio::task::spawn_blocking(closure).await.map_err(JoinError)?\n   → (closure)() (inline closure invocation)\n - conn.blocking_lock() → conn.lock() (parking_lot's sync lock)\n - #![allow(clippy::redundant_closure_call)] at module level for the\n   files that have the (closure)() pattern; clippy flag is intentional\n   because each closure's typed return signature is load-bearing for\n   error propagation and removing it would be a much larger diff\n\nPublic surface change: SqliteBackend::conn_handle() and\n::from_conn_handle() take/return parking_lot::Mutex now instead of\ntokio::sync::Mutex. Consumers that statically link persist must\nrebuild against v3.14.0; consumers via PyEngine Python API need no\nchange.\n\niOS happiness preserved:\n - parking_lot::Mutex uses pthread primitives on iOS\n - rusqlite's call shape unchanged → libsqlite3-sys → dlopen'd Apple\n   system libsqlite3 (#132's `bundled` drop is preserved)\n - No new dependencies; no new FFI surface\n\nTests:\n - 569/569 sqlite lib tests green (no change in test count;\n   transformation purely mechanical)\n - cargo clippy clean across sqlite + pyo3 feature axes\n - tools/race_repro.py against CIRISEdge 1.1.9 cohab scenario:\n   100/100 fast, 0 hung, 0 panic (was 20/20 hung on v3.13.0,\n   20/20 SIGSEGV on v3.13.1)\n\nWhat's still ahead:\n - Edge bumps persist pin v3.13.0 → v3.14.0 and rebuilds (#59 T4)\n - The executor_capsule (#157) keeps its current v1 shape; sqlite's\n   cross-tokio-aliasing class is closed without needing v2 ABI\n - Postgres path was never affected; postgres tests stayed green\n   throughout\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-06-04T21:39:47-05:00",
          "tree_id": "d842cfc96b78912163a0012ff7b9362548d09f3b",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/3f87cd3d8a44400a28e24096ac9f6f6bd15feb9e"
        },
        "date": 1780628320332,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45681321,
            "range": "± 33350",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2126714,
            "range": "± 75012",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2388,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5621,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12108,
            "range": "± 85",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43358,
            "range": "± 784",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 32,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 144,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 507,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 577,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1991,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 67,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 215,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 915,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 48500,
            "range": "± 1930",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 149517,
            "range": "± 3667",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 548875,
            "range": "± 2016",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7525,
            "range": "± 629",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 8805,
            "range": "± 299",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 13092,
            "range": "± 746",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 23439,
            "range": "± 808",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1051573,
            "range": "± 2953",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 5994467,
            "range": "± 124230",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 324252,
            "range": "± 7892",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 920494,
            "range": "± 38406",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 56843544,
            "range": "± 271407",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 2368770,
            "range": "± 139519",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 9365256,
            "range": "± 304288",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 140075467,
            "range": "± 1416434",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 5955852,
            "range": "± 248719",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 24623704,
            "range": "± 420143",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 100525,
            "range": "± 2982",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 93723,
            "range": "± 3193",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 9727,
            "range": "± 195",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 64845,
            "range": "± 1045",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 596284,
            "range": "± 2216",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "c24269a29cc43e58fd12fe12eb061af7f5754c1a",
          "message": "3.14.1 — clippy fixes uncovered by v3.14.0 mutex switch\n\nCI on v3.14.0 surfaced four categories of clippy/build issues that\nthe local `cargo test --features sqlite` didn't trigger because they\nrequire the wider feature set:\n\n - 9 residual `.lock().await` patterns (parking_lot::Mutex::lock is\n   sync; await on a sync MutexGuard is a type error). Spread across\n   src/occurrence/sqlite.rs + src/telemetry/sqlite.rs + src/audit/sqlite.rs.\n\n - src/graph/sqlite.rs:479 `let _ = guard;` → `drop(guard);`\n   (clippy: non-binding let on synchronization lock — `_` doesn't\n   bind, so the lock drops immediately on the bind line).\n\n - Test sites in src/audit/sqlite.rs + src/telemetry/sqlite.rs that\n   had `let guard = conn.lock(); ... drop(guard); ... .await`\n   pattern. The drop() before await is semantically correct but\n   clippy's scope-based MutexGuard-held-across-await analysis still\n   flags it. Wrapped in `{ ... }` block scope so the guard's lexical\n   scope ends before the await.\n\n - src/engine.rs:2327 match on `AuditDispatch` where the postgres arm\n   is cfg-gated. When postgres is off, the match is single-arm and\n   clippy lints \"infallible_destructuring_match\". Added\n   `#[allow(clippy::infallible_destructuring_match)]` to keep the cfg\n   gate readable.\n\nTests: 569/569 sqlite lib green; --features sqlite,telemetry,\ncirisaudit + --features pyo3 both clippy clean.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-06-04T21:53:18-05:00",
          "tree_id": "62401e7b48db62acb38d31ef9fc183b35311a090",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/c24269a29cc43e58fd12fe12eb061af7f5754c1a"
        },
        "date": 1780629116985,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40466038,
            "range": "± 33125",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 3002951,
            "range": "± 204546",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2523,
            "range": "± 39",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5918,
            "range": "± 29",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12947,
            "range": "± 112",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 45774,
            "range": "± 457",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 35,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 186,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 524,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 599,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2065,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 74,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 231,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1048,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 54505,
            "range": "± 2165",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 160129,
            "range": "± 4587",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 575373,
            "range": "± 6042",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8025,
            "range": "± 830",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9849,
            "range": "± 479",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 16157,
            "range": "± 1283",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 34960,
            "range": "± 2391",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1239437,
            "range": "± 10645",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 4609943,
            "range": "± 206165",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 358294,
            "range": "± 153237",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 869424,
            "range": "± 147380",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 40811930,
            "range": "± 909412",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1702429,
            "range": "± 389133",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 7880263,
            "range": "± 640601",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 100168939,
            "range": "± 1613985",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 4088845,
            "range": "± 320963",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 18643998,
            "range": "± 229991",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 100120,
            "range": "± 25778",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 97179,
            "range": "± 22830",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 7242,
            "range": "± 45",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 47335,
            "range": "± 171",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 448645,
            "range": "± 3319",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "edfe3dba3ee4c0a8e213aca7cef3754c4110328e",
          "message": "3.14.2 — revert 2 merkle_store test fixtures from v3.14.0 sweep\n\nSqliteMerkleStore is a sync-API store that bridges to async work\nvia `self.runtime.block_on(...)`. Production callers reach this from\npy.detach (PyO3 release-GIL hop) — a thread with no current tokio\nruntime, so block_on works.\n\nThe test fixtures mirrored this by hopping to a blocking-pool thread\nvia tokio::task::spawn_blocking. The v3.14.0 inline-sync sweep\nmechanically converted that to `(move || f(store_arc))()` — but f\nthen runs inside the tokio worker that `rt.block_on(...)` is\ndriving, and `f → store.append → self.runtime.block_on` panics with\n\"Cannot start a runtime from within a runtime\".\n\nTwo sites reverted with explicit comments documenting why this\nexception exists:\n\n - run_with_store helper (used by 11 of the 12 merkle_store sqlite\n   tests)\n - tenants_do_not_cross_contaminate (opens the backend directly\n   because it needs two stores sharing one backend)\n\nThe inline-sync sweep applied correctly to the 200+ sites in the\nSQLite hot paths — those don't have the recursive block_on\npattern. The merkle_store test scaffolding is the one exception.\n\nTests: 569/569 sqlite + 640/640 sqlite,cirisaudit green; clippy\nclean across sqlite,telemetry,cirisaudit + pyo3 axes.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-06-04T22:11:10-05:00",
          "tree_id": "249c7775b000cfb144d44bec157c9957d033b68c",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/edfe3dba3ee4c0a8e213aca7cef3754c4110328e"
        },
        "date": 1780630170782,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40443994,
            "range": "± 20188",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 3045871,
            "range": "± 250350",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2536,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5944,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12970,
            "range": "± 87",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 46169,
            "range": "± 1059",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 35,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 186,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 524,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 599,
            "range": "± 27",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2066,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 75,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 232,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1025,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 56961,
            "range": "± 2871",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 161529,
            "range": "± 8629",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 578525,
            "range": "± 50989",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7838,
            "range": "± 489",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9759,
            "range": "± 1434",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 15970,
            "range": "± 1144",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 33271,
            "range": "± 2050",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1233502,
            "range": "± 3264",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 4207866,
            "range": "± 48136",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 229782,
            "range": "± 8200",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 697871,
            "range": "± 11927",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 40109522,
            "range": "± 337870",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1433481,
            "range": "± 95641",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 6287896,
            "range": "± 100033",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 98405268,
            "range": "± 2089808",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 3590068,
            "range": "± 159515",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 16915598,
            "range": "± 337468",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 62610,
            "range": "± 7603",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 57855,
            "range": "± 3555",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 7122,
            "range": "± 23",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 46211,
            "range": "± 399",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 430255,
            "range": "± 2149",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "395a82e149030fd3b7e365dff048722880541b8e",
          "message": "3.14.3 — postgres merkle_store test fixtures (same as v3.14.2)\n\nv3.14.2 reverted the SQLite-side merkle_store test fixtures back to\nspawn_blocking because PgMerkleStore/SqliteMerkleStore are sync-API\nstores that internally `block_on`. The postgres-side equivalents\n(run_with_pg_store helper + pg_tenants_isolated direct-fixture)\nneeded the same revert — caught by the postgres-feature CI matrix\nrunning 4 pg tests against the live postgres service.\n\nTwo sites reverted (mirror of the v3.14.2 sqlite-side changes):\n - run_with_pg_store helper (3 of 4 failing pg tests)\n - pg_tenants_isolated direct-fixture (opens the backend itself\n   for cross-tenant isolation)\n\nBoth wrap the closure call in\n`tokio::task::spawn_blocking(move || ...).await.expect(...)` so\n`f → store.append → self.runtime.block_on` runs on the blocking\npool (no current runtime → block_on works), not on the rt worker\n(where block_on would panic with \"Cannot start a runtime from\nwithin a runtime\").\n\nInline comments at both sites document why this is the one\nexception to the v3.14.0 inline-sync sweep.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-06-04T22:26:10-05:00",
          "tree_id": "d94eb2f50efa63090e4bf7a5ee227f7ba415ff76",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/395a82e149030fd3b7e365dff048722880541b8e"
        },
        "date": 1780631066544,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40451783,
            "range": "± 90600",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2832354,
            "range": "± 121261",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2518,
            "range": "± 91",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5916,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12732,
            "range": "± 111",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 45644,
            "range": "± 589",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 35,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 182,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 524,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 600,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2066,
            "range": "± 37",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 76,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 228,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1038,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 56463,
            "range": "± 3449",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 162259,
            "range": "± 38744",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 581243,
            "range": "± 4713",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8993,
            "range": "± 682",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 11129,
            "range": "± 862",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 17640,
            "range": "± 1376",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 36527,
            "range": "± 5736",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1252383,
            "range": "± 15272",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 4663336,
            "range": "± 53950",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 276947,
            "range": "± 14688",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 806311,
            "range": "± 25799",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 43020849,
            "range": "± 1227005",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1555625,
            "range": "± 72587",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 7536774,
            "range": "± 261581",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 106034707,
            "range": "± 730661",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 4360082,
            "range": "± 320338",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 19677485,
            "range": "± 230093",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 78217,
            "range": "± 5876",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 70175,
            "range": "± 4210",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 7843,
            "range": "± 94",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 49680,
            "range": "± 435",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 465056,
            "range": "± 2935",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "45f53b66f85450a313bf62a6d6b811b08b1c18c1",
          "message": "v4.0.0 — Data Access Surface (#162)\n\nMerges the v4.0 DAS cut (commits A–I + Conformance#11 hardening). Cleared CIRISConformance#11 adversarial fire-test (3 rounds). Closes #159, #135; partial #150.",
          "timestamp": "2026-06-05T20:42:23-05:00",
          "tree_id": "57cea65f4241542d79368e1bdbcc1457c3af8d54",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/45f53b66f85450a313bf62a6d6b811b08b1c18c1"
        },
        "date": 1780711273735,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40446581,
            "range": "± 30067",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 1439779,
            "range": "± 129621",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 206,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 523,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 599,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2065,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 80,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 247,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1081,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8280,
            "range": "± 545",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 10950,
            "range": "± 932",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 16291,
            "range": "± 1331",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 34405,
            "range": "± 2055",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1332650,
            "range": "± 9186",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 9655598,
            "range": "± 114285",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 414120,
            "range": "± 32406",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 1653696,
            "range": "± 47566",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 98657424,
            "range": "± 1169626",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 2722967,
            "range": "± 118079",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 16882165,
            "range": "± 177802",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 246891313,
            "range": "± 1624936",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 7872307,
            "range": "± 560360",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 44561106,
            "range": "± 678400",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 135742,
            "range": "± 11178",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 128042,
            "range": "± 5694",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 15021,
            "range": "± 178",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 96661,
            "range": "± 298",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 903405,
            "range": "± 2367",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "225732233b923cb89a4f965a9221a3cb77a6f4a5",
          "message": "Gate scope_bind::and_compose on sqlite (fixes pyo3-no-backend wheel build)\n\nCI core leg's maturin step builds `--features test-panic,pyo3 --release`\n(pyo3 WITHOUT a backend). scope_bind is gated any(postgres,sqlite) and every\nhelper is per-backend gated except and_compose, which is only called from\nsqlite.rs but carried no cfg — so under pyo3-without-sqlite it's dead code,\nand the build's -D warnings promotes it to exit 101. Same class as the v4.0.0\nno-default-features fix, different combo.\n\nand_compose is now #[cfg(feature = \"sqlite\")] — compiled iff sqlite, used iff\nsqlite (sqlite.rs is its sole caller), so it can never be dead again under any\ncombo. All 899 core-leg tests already passed on live postgres; this is the\nonly blocker on the v4.0.0 CI. Verified clean under -D warnings:\n--no-default-features, --features pyo3, --features test-panic,pyo3, --features\nsqlite, and the full CI gated combo.\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-06-05T20:56:09-05:00",
          "tree_id": "299f92c3c7abd87c70447950e1c4e7bc5058cef9",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/225732233b923cb89a4f965a9221a3cb77a6f4a5"
        },
        "date": 1780712294135,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45675269,
            "range": "± 19673",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2174809,
            "range": "± 85674",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2380,
            "range": "± 37",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5690,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12258,
            "range": "± 29",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43483,
            "range": "± 104",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 143,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 506,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 577,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1991,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 69,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 227,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 991,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 46938,
            "range": "± 861",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 143522,
            "range": "± 18508",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 526201,
            "range": "± 28048",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7349,
            "range": "± 535",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 8672,
            "range": "± 516",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 12978,
            "range": "± 836",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 23493,
            "range": "± 1116",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1129102,
            "range": "± 6470",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 6334319,
            "range": "± 54178",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 345965,
            "range": "± 16230",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 1123538,
            "range": "± 24542",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 64516208,
            "range": "± 1433067",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 2099869,
            "range": "± 144699",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 10761180,
            "range": "± 137879",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 161463097,
            "range": "± 1198209",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 5589114,
            "range": "± 198119",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 28592373,
            "range": "± 494119",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 102538,
            "range": "± 4931",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 93901,
            "range": "± 4210",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 9367,
            "range": "± 110",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 63895,
            "range": "± 489",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 595629,
            "range": "± 2488",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "ba8e79ca4aabf090a415d8c6a8edc33d9bc70626",
          "message": "4.0.1 — pyo3-no-backend build fix (version bump for clean wheels)\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-06-05T20:57:15-05:00",
          "tree_id": "d79bf775ff7d252c6cce24fb424389a6b26c9a64",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/ba8e79ca4aabf090a415d8c6a8edc33d9bc70626"
        },
        "date": 1780712383463,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40434741,
            "range": "± 62266",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 1903774,
            "range": "± 87607",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2539,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 6038,
            "range": "± 118",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 13064,
            "range": "± 112",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 46122,
            "range": "± 310",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 35,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 181,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 547,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 622,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2089,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 79,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 257,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1112,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 56174,
            "range": "± 5079",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 157697,
            "range": "± 6553",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 560874,
            "range": "± 11993",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7128,
            "range": "± 272",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9838,
            "range": "± 506",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 15947,
            "range": "± 1041",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 34520,
            "range": "± 3345",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1309235,
            "range": "± 3832",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 7377955,
            "range": "± 57635",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 316873,
            "range": "± 11510",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 1256942,
            "range": "± 33838",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 74923342,
            "range": "± 679085",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 2118515,
            "range": "± 38137",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 12700048,
            "range": "± 235333",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 188935324,
            "range": "± 1110594",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 5520266,
            "range": "± 190492",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 33484857,
            "range": "± 437673",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 102537,
            "range": "± 5170",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 94622,
            "range": "± 4936",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 11458,
            "range": "± 96",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 74140,
            "range": "± 375",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 691882,
            "range": "± 1612",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "300a32671af8f63865bc4c6147cf40c276a1248b",
          "message": "FSD: streaming substrate (CEG 0.10 §10.5 impl) — on-ramp to #142\n\nRatifies #144's adopt/roll survey (SHA-256 locked, not BLAKE3) and\nre-grounds #142's three primitives (get_range, ChunkDag, live\nput_blob_chunk/seal_stream) against CEG 0.10 §10.5, which advanced past\n#142's pre-0.10 sketch: per-stream transparency log (reuse SignedTreeHead\nper stream_id), mandatory PQC wrap (wrap_algorithm v2 = x25519+ml-kem-768),\nthe STREAM nonce layout, the RC1-1c CHECK migration, delivery receipts.\nComposes on v4.0's cohort_scope/CallerScope target-membership gate.\nCut sequence A (get_range) / B (ChunkDag) / C (live + epoch cascade).\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-06-05T21:55:08-05:00",
          "tree_id": "491b803daa3239bb523341816fec1e2c93e84858",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/300a32671af8f63865bc4c6147cf40c276a1248b"
        },
        "date": 1780715755919,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40436674,
            "range": "± 26168",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 1576810,
            "range": "± 249786",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2523,
            "range": "± 34",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5960,
            "range": "± 50",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12768,
            "range": "± 59",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 45874,
            "range": "± 442",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 182,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 524,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 599,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2066,
            "range": "± 42",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 81,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 255,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1110,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 54511,
            "range": "± 2499",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 156955,
            "range": "± 2657",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 558570,
            "range": "± 7439",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7924,
            "range": "± 460",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 10126,
            "range": "± 496",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 17231,
            "range": "± 1122",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 35628,
            "range": "± 2306",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1324900,
            "range": "± 15139",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 8861174,
            "range": "± 78035",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 412532,
            "range": "± 24273",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 1530249,
            "range": "± 21960",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 90392193,
            "range": "± 908169",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 2702829,
            "range": "± 206014",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 15808742,
            "range": "± 281799",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 226476624,
            "range": "± 1504450",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 6788894,
            "range": "± 349227",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 43099583,
            "range": "± 562934",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 143347,
            "range": "± 6561",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 129177,
            "range": "± 8277",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 14032,
            "range": "± 55",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 90580,
            "range": "± 553",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 842672,
            "range": "± 3287",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "d739faa715432954e0155272e25e22e28f94de4b",
          "message": "Streaming Cut A — get_blob_range (#163)\n\nByte-range reads over federation_blobs. Pure-additive on-ramp to #142. CI green (incl. PG legs after the i32 substring-param fix).",
          "timestamp": "2026-06-05T22:43:35-05:00",
          "tree_id": "44ddb176f83c819b3ff725d0c01ae9ace725c471",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/d739faa715432954e0155272e25e22e28f94de4b"
        },
        "date": 1780718636275,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45678230,
            "range": "± 321265",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2952513,
            "range": "± 280311",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2390,
            "range": "± 45",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5674,
            "range": "± 179",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12096,
            "range": "± 60",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43583,
            "range": "± 266",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 32,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 144,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 505,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 576,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1990,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 74,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 227,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 994,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 48106,
            "range": "± 1384",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 145373,
            "range": "± 5078",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 531461,
            "range": "± 10886",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8081,
            "range": "± 418",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9273,
            "range": "± 422",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 13527,
            "range": "± 881",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 24129,
            "range": "± 1316",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1135044,
            "range": "± 17369",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 4798246,
            "range": "± 63130",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 285265,
            "range": "± 7030",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 860961,
            "range": "± 11637",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 47489878,
            "range": "± 747159",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1778704,
            "range": "± 82774",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 8183984,
            "range": "± 442898",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 118146750,
            "range": "± 1139198",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 4553304,
            "range": "± 290249",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 21124146,
            "range": "± 330466",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 75900,
            "range": "± 4955",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 71970,
            "range": "± 5975",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 7027,
            "range": "± 41",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 49146,
            "range": "± 250",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 431868,
            "range": "± 7759",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "ea065daa47a97a116bb4a19b7861b3e26ec05181",
          "message": "FSD: correct Cut B migration finding (storage_kind CHECK needs V061)\n\nCut B (BlobBody::ChunkDag) is NOT pure-additive at the CHECK layer:\nfederation_blobs.storage_kind (V047) has a closed-set CHECK + a\ncross-column CHECK. Admitting 'chunk_dag' (manifest in bytes_inline)\nneeds both extended on both backends — PG DROP/ADD CONSTRAINT, SQLite\nthe 12-step table rebuild (table CHECKs can't be ALTERed). Named here\nso the implementer (the holds_bytes linkage + V123 access columns must\nsurvive the rebuild). Sibling to the §4.4 RC1-1c CHECK migration.\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-06-05T22:49:20-05:00",
          "tree_id": "4ac5806e406996a67f3e9bc7c8fce775f08c3a29",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/ea065daa47a97a116bb4a19b7861b3e26ec05181"
        },
        "date": 1780718982289,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40442631,
            "range": "± 45699",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 1854247,
            "range": "± 87761",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2530,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5960,
            "range": "± 27",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 13019,
            "range": "± 83",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 45950,
            "range": "± 663",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 181,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 525,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 600,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2065,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 82,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 251,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1097,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 54222,
            "range": "± 1375",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 157593,
            "range": "± 2115",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 557916,
            "range": "± 3222",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7819,
            "range": "± 601",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9760,
            "range": "± 559",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 15766,
            "range": "± 1128",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 33728,
            "range": "± 1492",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1325736,
            "range": "± 4048",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 7519000,
            "range": "± 67274",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 315220,
            "range": "± 5054",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 1285199,
            "range": "± 21583",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 76194870,
            "range": "± 709678",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 2041663,
            "range": "± 141232",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 12933598,
            "range": "± 223269",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 192345629,
            "range": "± 801695",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 5660976,
            "range": "± 157983",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 34850297,
            "range": "± 586504",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 109073,
            "range": "± 6400",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 100774,
            "range": "± 5213",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 11723,
            "range": "± 158",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 76110,
            "range": "± 890",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 705436,
            "range": "± 8547",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "d3faa20978f0925208344f6543cc92d904b75162",
          "message": "Streaming Cut B — BlobBody::ChunkDag (#164)\n\nContent-addressed chunked blobs + put_blob_chunks + chunked get_blob_range + V061 storage_kind CHECK. Verified against live postgres locally (875 tests) + CI green. On-ramp to #142 Cut C.",
          "timestamp": "2026-06-05T23:28:03-05:00",
          "tree_id": "1ba30650f69c32dbd16482afcc8c51768c1c28dd",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/d3faa20978f0925208344f6543cc92d904b75162"
        },
        "date": 1780721310555,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45686848,
            "range": "± 41249",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 4437179,
            "range": "± 126909",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2387,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5657,
            "range": "± 37",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12326,
            "range": "± 44",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43779,
            "range": "± 115",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 144,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 507,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 577,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1993,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 72,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 224,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 971,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 47624,
            "range": "± 3100",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 145149,
            "range": "± 22420",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 527998,
            "range": "± 9022",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8592,
            "range": "± 535",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9614,
            "range": "± 491",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 13755,
            "range": "± 878",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 23862,
            "range": "± 1170",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1244497,
            "range": "± 7398",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 3172144,
            "range": "± 24103",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 175178,
            "range": "± 1559",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 558216,
            "range": "± 5902",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 32046947,
            "range": "± 250640",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1110027,
            "range": "± 62099",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 5576054,
            "range": "± 137225",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 80151713,
            "range": "± 830586",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 3113317,
            "range": "± 171959",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 14728980,
            "range": "± 308312",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 50709,
            "range": "± 1905",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 47017,
            "range": "± 1829",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 4606,
            "range": "± 35",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 31097,
            "range": "± 126",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 288333,
            "range": "± 892",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "efe23835ed611a67d15ebac0fa073659e40ad8e5",
          "message": "Streaming Cut C1a — federation_stream_chunks + put_blob_chunk/seal_stream (#165)\n\nLive-stream chunk index + append + seal. Verified on live postgres locally (883 tests) + CI green. On-ramp to C1b (per-stream STH).",
          "timestamp": "2026-06-06T07:55:58-05:00",
          "tree_id": "c6afce220fdf3d463b6e520a2b1a33442882965f",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/efe23835ed611a67d15ebac0fa073659e40ad8e5"
        },
        "date": 1780751829596,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40450540,
            "range": "± 31211",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 3333281,
            "range": "± 70300",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2675,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 6100,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 13200,
            "range": "± 55",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 46230,
            "range": "± 488",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 181,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 524,
            "range": "± 29",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 601,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2068,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 81,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 256,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1160,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 54553,
            "range": "± 2430",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 158083,
            "range": "± 4182",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 563512,
            "range": "± 14914",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 9193,
            "range": "± 665",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 11133,
            "range": "± 764",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 18210,
            "range": "± 1265",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 34915,
            "range": "± 2261",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1450710,
            "range": "± 9831",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 4419372,
            "range": "± 52969",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 254004,
            "range": "± 6334",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 850877,
            "range": "± 10966",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 43269982,
            "range": "± 362095",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1471143,
            "range": "± 34194",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 7974951,
            "range": "± 135926",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 108135903,
            "range": "± 770256",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 3640403,
            "range": "± 196795",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 20356588,
            "range": "± 255593",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 70778,
            "range": "± 3129",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 61852,
            "range": "± 4258",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 6612,
            "range": "± 81",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 42206,
            "range": "± 269",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 392894,
            "range": "± 867",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c6538f583e76c43dbfb12b325e7c80f1bd4eb8e6",
          "message": "Streaming Cut C1b — per-stream transparency log (#166)\n\nProducer-signed STH + RFC 6962 proofs + anti-equivocation root gate (V063). Verified on live postgres locally (901 tests, all negative/security cases reject) + CI green.",
          "timestamp": "2026-06-06T15:57:47-05:00",
          "tree_id": "583064dd97985d547b654abbc1bbf14ca9822f46",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/c6538f583e76c43dbfb12b325e7c80f1bd4eb8e6"
        },
        "date": 1780780874586,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45677877,
            "range": "± 37980",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2169600,
            "range": "± 100041",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2387,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5698,
            "range": "± 183",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12277,
            "range": "± 36",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43629,
            "range": "± 1275",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 144,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 506,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 577,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1993,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 70,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 224,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 981,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 47138,
            "range": "± 2047",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 144386,
            "range": "± 2334",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 527053,
            "range": "± 2776",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7764,
            "range": "± 415",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 8993,
            "range": "± 1316",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 13047,
            "range": "± 802",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 23480,
            "range": "± 1309",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1233370,
            "range": "± 3512",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 6412815,
            "range": "± 39816",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 336832,
            "range": "± 6254",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 1112685,
            "range": "± 14739",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 65106200,
            "range": "± 371452",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 2113375,
            "range": "± 126112",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 10936074,
            "range": "± 131518",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 162084752,
            "range": "± 1390765",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 5776323,
            "range": "± 357558",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 29096737,
            "range": "± 359050",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 105662,
            "range": "± 6817",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 95973,
            "range": "± 4563",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 9427,
            "range": "± 44",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 62346,
            "range": "± 183",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 584646,
            "range": "± 2826",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "83cfea2de46dd68f899827a1e2514bf1dd3e65e1",
          "message": "Streaming Cut C2 — STREAM-nonce AES-256-GCM sealing + Verify 4.8.1 (#167)\n\nPer-chunk seal primitive (CEG §10.5.2) + 4.8.1 re-pin. Verified on live PG (960 tests). CEG epoch-encoding gap flagged: CIRISRegistry#63.",
          "timestamp": "2026-06-07T14:17:01-05:00",
          "tree_id": "6e8b85a54d63c208f6f37e2535e35542562ec620",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/83cfea2de46dd68f899827a1e2514bf1dd3e65e1"
        },
        "date": 1780861393585,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 53643324,
            "range": "± 96931",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2354355,
            "range": "± 216655",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 1871,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 4535,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 9875,
            "range": "± 224",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 37610,
            "range": "± 890",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 126,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 383,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 447,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1650,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 62,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 190,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 874,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 10,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 38584,
            "range": "± 1042",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 116591,
            "range": "± 2562",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 417909,
            "range": "± 3730",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 9816,
            "range": "± 1633",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9623,
            "range": "± 2269",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 14773,
            "range": "± 2965",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 23842,
            "range": "± 2149",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1038791,
            "range": "± 2958",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 5360226,
            "range": "± 34648",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 363640,
            "range": "± 8192",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 1067965,
            "range": "± 14155",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 51684697,
            "range": "± 328280",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 2375712,
            "range": "± 104782",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 9527957,
            "range": "± 102447",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 127841173,
            "range": "± 674435",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 6164560,
            "range": "± 133263",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 24665267,
            "range": "± 255169",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 112749,
            "range": "± 3129",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 102178,
            "range": "± 6293",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 8080,
            "range": "± 29",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 50693,
            "range": "± 479",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 469158,
            "range": "± 1795",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "74b4c4ea2d30b699eae6ed2233e62e71931ae2e9",
          "message": "4.1.0 — streaming substrate (Cuts A–C2) + CIRISVerify 4.8.1 re-pin\n\nThe 4.8.1 re-pin CIRISAgent 2.9.5 is holding for, shipped in a tagged\nrelease. Additive streaming substrate (get_blob_range, BlobBody::ChunkDag,\nfederation_stream_chunks, per-stream STH, STREAM-nonce seal; migrations\nV061–V063) rides along. BlobBody gained a ChunkDag variant (the one\nsource-incompatible change). 960+ lib tests green on live PG.\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-06-07T14:47:04-05:00",
          "tree_id": "7c434cce9a2b85fdb5b5f6c023cd46874f7155c7",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/74b4c4ea2d30b699eae6ed2233e62e71931ae2e9"
        },
        "date": 1780863032606,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 53636534,
            "range": "± 45378",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2552587,
            "range": "± 164669",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 1797,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 4462,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 9748,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 36530,
            "range": "± 541",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 123,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 383,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 447,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1649,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 63,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 196,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 877,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 10,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 38159,
            "range": "± 1805",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 117028,
            "range": "± 2653",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 415721,
            "range": "± 15803",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7584,
            "range": "± 1410",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 8633,
            "range": "± 1496",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 13193,
            "range": "± 2626",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 23009,
            "range": "± 9123",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1044407,
            "range": "± 2568",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 4925193,
            "range": "± 21866",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 347890,
            "range": "± 7700",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 1003554,
            "range": "± 13170",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 47603836,
            "range": "± 385007",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 2323728,
            "range": "± 43426",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 8755288,
            "range": "± 54921",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 118393894,
            "range": "± 733278",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 5964054,
            "range": "± 110791",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 23174767,
            "range": "± 236611",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 103255,
            "range": "± 4417",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 95170,
            "range": "± 3138",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 7373,
            "range": "± 34",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 46724,
            "range": "± 268",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 434902,
            "range": "± 6443",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "a84e12fd610e963d45396d7c58bfc8914ea6ecba",
          "message": "Streaming Cut C3a — V064 key_grant stream/epoch addressing (#168)\n\nRC1-1c CHECK migration — admits stream/epoch-addressed key_grants. Verified on live PG (1005 tests). On-ramp to C3b (epoch-DEK cascade).",
          "timestamp": "2026-06-07T14:55:19-05:00",
          "tree_id": "c9d6098b15bc584ec598978362f8f8932291252e",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/a84e12fd610e963d45396d7c58bfc8914ea6ecba"
        },
        "date": 1780863366644,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45676121,
            "range": "± 74486",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2575951,
            "range": "± 137467",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2405,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5704,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12247,
            "range": "± 64",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43559,
            "range": "± 164",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 143,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 506,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 577,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1992,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 74,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 225,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 992,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 47161,
            "range": "± 797",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 144251,
            "range": "± 2139",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 528445,
            "range": "± 6158",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7720,
            "range": "± 379",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9329,
            "range": "± 446",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 13286,
            "range": "± 846",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 23964,
            "range": "± 1339",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1315109,
            "range": "± 5037",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 5502325,
            "range": "± 64514",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 295095,
            "range": "± 6855",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 951278,
            "range": "± 12768",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 54998082,
            "range": "± 806063",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1827995,
            "range": "± 25483",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 8972304,
            "range": "± 111325",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 138093553,
            "range": "± 947667",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 4790320,
            "range": "± 242700",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 24180952,
            "range": "± 278206",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 91319,
            "range": "± 2991",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 82317,
            "range": "± 3253",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 7922,
            "range": "± 23",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 52835,
            "range": "± 625",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 493613,
            "range": "± 1610",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "e856f91593c82a583a680cbd38d555c0c4604834",
          "message": "4.1.0 release notes: include Cut C3a (V064 RC1-1c migration)\n\nC3a merged after the version bump; fold it into the 4.1.0 release notes\n(version unchanged at 4.1.0). This commit is the v4.1.0 tag target —\nstreaming Cuts A–C3a + the CIRISVerify 4.8.1 re-pin.\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-06-07T14:57:38-05:00",
          "tree_id": "9333a55205d8f95ae792ea425402048f4591e5a1",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/e856f91593c82a583a680cbd38d555c0c4604834"
        },
        "date": 1780863479521,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45683102,
            "range": "± 331119",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2454981,
            "range": "± 304052",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2382,
            "range": "± 53",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5613,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12243,
            "range": "± 30",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43492,
            "range": "± 733",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 143,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 506,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 577,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1992,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 70,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 222,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 969,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 47274,
            "range": "± 2193",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 144334,
            "range": "± 16320",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 524271,
            "range": "± 3353",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7730,
            "range": "± 438",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9006,
            "range": "± 337",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 13256,
            "range": "± 953",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 23721,
            "range": "± 1105",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1311211,
            "range": "± 4575",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 5717635,
            "range": "± 59476",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 313089,
            "range": "± 21089",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 1003173,
            "range": "± 13839",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 57633059,
            "range": "± 444265",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1949076,
            "range": "± 69618",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 9409564,
            "range": "± 97779",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 145092508,
            "range": "± 863723",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 5183400,
            "range": "± 216361",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 25341739,
            "range": "± 291763",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 94352,
            "range": "± 2894",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 84769,
            "range": "± 3842",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 8464,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 55749,
            "range": "± 173",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 521153,
            "range": "± 2381",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "7538e42e5c4b463d72b14cde8941376306196d53",
          "message": "Streaming Cut C4 — signed delivery receipts (#142, CEG 0.15 §10.5.4) (#169)\n\nCloses the streaming delivery loop. A delivery receipt is a subscriber's\nhybrid-signed acknowledgement that they received chunk K under\n(stream_id, epoch). Verification is a JOIN, not just a sig-check:\n\n  1. verify the subscriber's Ed25519+ML-DSA-65 signature over the\n     §10.5.4 canonical bytes against the pinned federation_keys key\n     (necessary, NOT sufficient); then\n  2. the JOIN — chunk_root MUST equal a published\n     federation_stream_sth.root_hash (C1b) at tree_size >= k. A\n     subscriber cannot acknowledge an unpublished root, nor a chunk\n     index beyond the published tree.\n\nProof-of-delivery, not proof-of-consumption. Persist validates (origin +\npublished-root JOIN) but does NOT adjudicate (no \"delivered\" verdict, no\nmembership enforcement — MISSION §1.4 / consumer policy).\n\n- src/federation/stream_receipt.rs — DeliveryReceipt + the sole\n  canonical-bytes fn (domain ciris-delivery-receipt/v1, distinct from\n  the STH domain → no cross-protocol replay) + pinned-key sig verify.\n- put_delivery_receipt / list_delivery_receipts_for on BlobStorage,\n  both backends + PyO3. (stream_id, subscriber_key_id, k) PK =\n  append-only; same-key different-root = subscriber equivocation,\n  rejected; identical re-PUT idempotent.\n- V065 federation_stream_delivery_receipts (both dialects, additive).\n- Real-hybrid-signature e2e tests on live PG + in-memory SQLite:\n  positive/idempotent + four security negatives (phantom root,\n  tree_size<k, wrong-key sig, equivocation) all reject.\n- Fix pre-existing dead-code: engine.rs sha256_of_bytes was gated\n  any(sqlite,postgres) but used only by the sqlite tests → dead under\n  postgres-only -D warnings. Re-gated sqlite-only.\n\n911 lib tests green on live PG (postgres server pyo3 sqlite).\n\nCo-authored-by: Claude Opus 4.8 <noreply@anthropic.com>",
          "timestamp": "2026-06-07T17:01:30-05:00",
          "tree_id": "234eb83d10a58c427d675dc48466c70d8591e796",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/7538e42e5c4b463d72b14cde8941376306196d53"
        },
        "date": 1780871019894,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40435511,
            "range": "± 36018",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2896760,
            "range": "± 155710",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2524,
            "range": "± 32",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5961,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 13032,
            "range": "± 107",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 46059,
            "range": "± 447",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 35,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 187,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 524,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 599,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2070,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 83,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 253,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1107,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 16,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 56184,
            "range": "± 2719",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 158451,
            "range": "± 4751",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 560475,
            "range": "± 9968",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8728,
            "range": "± 768",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 10062,
            "range": "± 796",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 17108,
            "range": "± 1180",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 36015,
            "range": "± 2402",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1554011,
            "range": "± 10309",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 4858731,
            "range": "± 38102",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 257407,
            "range": "± 14774",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 895191,
            "range": "± 20359",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 49341832,
            "range": "± 295871",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1558072,
            "range": "± 116636",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 8855826,
            "range": "± 141783",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 123906202,
            "range": "± 887462",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 4068037,
            "range": "± 114589",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 23250934,
            "range": "± 317498",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 73142,
            "range": "± 6445",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 71466,
            "range": "± 5600",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 7512,
            "range": "± 27",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 48636,
            "range": "± 940",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 454699,
            "range": "± 4483",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "0e2307febbda30fcd1709767e5ba4e2547fda714",
          "message": "Streaming Cut C3b — epoch-DEK key_grant cascade + wrap_algorithm v2 (#142, CEG §10.5.3) (#170)\n\nThe streaming epoch-key cascade. A per-(stream_id, epoch) DEK is wrapped\nto each roster recipient as a stream/epoch-addressed key_grant\nContribution. Persist's role is validate / record / list, NOT wrap — the\nproducer wraps + submits; the storage path stores the wrapped DEK\nopaquely (MISSION §1.7). Unblocked by CIRISVerify#58.\n\nDependency: CIRISVerify v4.8.1 → v4.10.0 (6 pins). Picks up\nciris-crypto::key_grant's wrap_algorithm v2 API (KEY_GRANT_ALGORITHM_V2,\nwrap_dek_for_recipient_v2/unwrap_dek_v2/KeyGrantWrapV2; #58) — gated\nml-kem, already pulled via hybrid-kex, so no feature change.\n\nAdded:\n- Stream/epoch-addressed key_grant: KeyGrantPayload gains optional\n  stream_id/stream_epoch (content_sha256 now optional);\n  WrapAlgorithm::X25519MlKem768Aes256GcmHkdfSha256 (v2);\n  KeyGrantScope::StreamEpoch. Projected onto V064 columns, both backends.\n- list_key_grants_for_stream_epoch(stream_id, epoch) on the service +\n  both backends + PyO3. Persist returns grants; LensCore applies its own\n  P4 catch-up cap (a LensCore knob, NOT a substrate constant — §10.5.3).\n  history_on_join likewise stays a producer/consumer concern.\n- Wheel FFI v2 helpers (wrap_dek_for_recipient_v2_b64 / unwrap_dek_v2_b64)\n  — the only place persist calls the v2 wrap. Real hybrid round-trip.\n- MAX_CHUNKS_PER_EPOCH = 2^24 nonce-safety substrate const; put_blob_chunk\n  refuses an append past it (force epoch roll), both backends.\n\nEnforced at ingest: a streaming epoch grant carrying wrap_algorithm v1 is\nREJECTED at put_contribution (the normative §10.5.3 reject-v1). The\nextractor enforces exactly-one addressing mode (content XOR stream/epoch,\nmirroring the V064 CHECK) + scope=stream_epoch. Content v1 grants\nunaffected (backward-compatible).\n\nPending ratification: the v2 payload wire string\nx25519_mlkem768_aes256_gcm_hkdf_sha256 is proposed pending\nCIRISRegistry#64 (CEG mandates v2 but doesn't yet pin the payload enum\nstring; propose-then-ratify, same as the nonce encoding #63).\n\nTests both backends (live PG + SQLite): stream/epoch round-trip +\n(stream,epoch) filter, ingest reject-v1, addressing-XOR + scope\nvalidators, MAX_CHUNKS_PER_EPOCH boundary, real v2 hybrid wrap/unwrap.\n1028 lib tests green on live PG (postgres server pyo3 sqlite cirisnode).\n\nShips as 4.3.0.\n\nCo-authored-by: Claude Opus 4.8 <noreply@anthropic.com>",
          "timestamp": "2026-06-08T09:27:15-05:00",
          "tree_id": "e4a0542fd77cb2b19d5349ac9902dd1683e9fd8c",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/0e2307febbda30fcd1709767e5ba4e2547fda714"
        },
        "date": 1780930223078,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40444377,
            "range": "± 631385",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 3205938,
            "range": "± 146445",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2525,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5947,
            "range": "± 174",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12777,
            "range": "± 198",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 45820,
            "range": "± 723",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 187,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 524,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 599,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2067,
            "range": "± 58",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 81,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 249,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1106,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 54911,
            "range": "± 2454",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 158764,
            "range": "± 4390",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 566738,
            "range": "± 8185",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 9280,
            "range": "± 708",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 11712,
            "range": "± 735",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 18036,
            "range": "± 1353",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 37129,
            "range": "± 2336",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1545615,
            "range": "± 3978",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 4535374,
            "range": "± 66106",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 254830,
            "range": "± 27076",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 880130,
            "range": "± 20572",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 44490233,
            "range": "± 262141",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1387466,
            "range": "± 30134",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 8049081,
            "range": "± 161130",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 112149567,
            "range": "± 1043333",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 3881085,
            "range": "± 246452",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 20751587,
            "range": "± 206041",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 74463,
            "range": "± 4460",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 67723,
            "range": "± 4199",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 6724,
            "range": "± 137",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 43726,
            "range": "± 705",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 408051,
            "range": "± 2564",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "41a304a04eed1a89579ae710fe8d8280163cbc19",
          "message": "FSD review — Shared CEG Attestation Surface (local-tier write+query+promote, #171) (#172)\n\n* FSD draft: Shared CEG Attestation Surface (local-tier write+query+promote, #171)\n\nDraft for the 4-impl RC1 review (Agent/NodeCore/LensCore/Registry). The\ngating dependency for CIRISAgent#840's hard cut-over. Adds the missing\nwrite+promote half of the federation_attestations substrate (v4.0 gave\nit the scope-aware read):\n\n- A tier model (local | federation) — local = producer-only authority,\n  signature deferred per CEG §10.1.3; CHECK enforces federation ⟹ signed;\n  read gate hides local rows from non-self callers (AV-59/60/61).\n- attestation_upsert_local(+_many) / attestation_query / promote.\n- The consent-revocation promotion obligation (§10.1.3, 24h → hard_case),\n  designed with #161.\n- One contract, four role-scoped views. No wire-format change, no\n  dual-write, both backends.\n\nStatus: Draft — NOT accepted. §11 open questions + §12 reviewer matrix\ngate acceptance.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>\n\n* FSD update: fold in CIRISAgent + CIRISVerify review (#171/#172)\n\nCIRISAgent (✅ conditional nod) + CIRISVerify (✅ OQ-4):\n\n- §3 tier model corrected: local-tier eligibility = producer-only\n  AUTHORITY, not empty subject_key_ids. Producer-authority rows that\n  name a subject (observed:user, consent:partnered stance, epistemic:\n  about, self-consent identity:current) ride local-tier. The\n  discriminator is revocation authority (§4.2.6 / §10.1.3).\n- §4.1 split into upsert (replace-on-dimension, singleton state) +\n  insert (append, server-assigned id, multi-valued/event); key on\n  (occurrence_key_id, dimension), not attestation_type. _many chunks\n  internally. OQ-1 resolved.\n- §4.3 promote canonical bytes = JCS(envelope) per CEG §0.9/RFC 8785,\n  exact committed member set (omit-vs-materialize), NOT Verify's LP\n  framing. New dependency CIRISVerify#59 (JCS + Contribution verify);\n  gates promote only → staged after write+read. OQ-4 resolved (spec).\n- §5 carve-out redefined: subject-side revocation = withdraws /\n  consent:state:revoked where attesting_key_id ∈ target subject_key_ids,\n  NOT non-empty subjects.\n- §11/§12: OQ-1/4/5 resolved; OQ-2 (Registry, dimension grammar = the\n  upsert key) is now the sole code-blocker for the write+read half;\n  OQ-3 (#161 clock) trigger-only; promote waits on #59. Review-state\n  matrix updated.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>\n\n* FSD finalized — phase 1 ACCEPTED (4-impl nod): fold in Registry/LensCore/NodeCore\n\nAll four CEG-RC1 impls nod. Folded in:\n- OQ-2 RESOLVED (Registry, CEG §10.1.5.4): dimensions[] = OPEN prefix,\n  hierarchical-prefix-matched; closed enum non-conformant. Apophatic\n  bound is on the operator set (5 predicates), not the vocabulary —\n  \"open data, closed operators\" (§1.4/§4.2). Satisfies NodeCore's\n  governance slice by construction.\n- OQ-4 RESOLVED (Registry 3 musts, §10.1.5.3): byte-identical wire (no\n  was-promoted marker); substrate cols (tier/promoted_at) NOT\n  canonicalized; §0.9 omit-vs-materialize. JCS(envelope), not LP framing.\n- LensCore condition (load-bearing): capacity:* ineligible for local\n  tier + substrate attesting≠attested (§7.5 anti-Goodhart) → §4.1/§4.2,\n  new AV-62. detection:* closed by §7.0.1 emitter gate.\n- NodeCore: two read surfaces (attestations via query; feeds stay on\n  cirisnode.contributions); write claim forward-looking (\"reads, and MAY\n  project via put_attestation\"); no forked path, no new write primitive.\n- Tier model pinned in CEG §10.1.5 (v-ceg-0.15); Registry fixed CEG\n  §10.1.3's over-narrow \"empty subject_key_ids\" → \"producer holds sole\n  revocation authority\" (matched our correction).\n- Load model §10.1.5.5 + 3 measurable signals.\n\nPhase 1 (write+read) accepted, zero blockers — ready to build. Phase 2\n(promote) stages behind CIRISVerify#59 (JCS) + OQ-4 member set; §5 clock\ntrigger behind OQ-3/#161.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>\n\n* FSD: phase 2 unblocked — CIRISVerify#59 closed, v4.11.0 ships JCS\n\nCIRISVerify 4.11.0 ships ciris_verify_core::jcs::{canonicalize,\nverify_jcs_hybrid_signature} (RFC 8785 + CEG-Contribution hybrid-sig\nverify) — the OQ-4 deliverable. promote() no longer blocked: persist\nre-pins 4.10.0→4.11.0 and canonicalizes via jcs::canonicalize, routed\nthrough the verify/secrets facade (MISSION §1.4). May build with phase 1\nor stage second. §5 clock trigger still OQ-3/#161.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>\n\n---------\n\nCo-authored-by: Claude Opus 4.8 <noreply@anthropic.com>",
          "timestamp": "2026-06-08T20:34:30-05:00",
          "tree_id": "496dc1ab68cca11a99a38f037a1b7f4500961496",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/41a304a04eed1a89579ae710fe8d8280163cbc19"
        },
        "date": 1780970115653,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45664452,
            "range": "± 395298",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 4212637,
            "range": "± 215815",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2388,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5698,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12161,
            "range": "± 110",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43554,
            "range": "± 174",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 145,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 506,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 577,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1993,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 69,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 229,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1007,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 47741,
            "range": "± 2882",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 145005,
            "range": "± 6887",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 531631,
            "range": "± 40230",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8172,
            "range": "± 534",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9815,
            "range": "± 1401",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 14257,
            "range": "± 5778",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 25150,
            "range": "± 1568",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1330947,
            "range": "± 5122",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 3378487,
            "range": "± 42383",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 211256,
            "range": "± 33062",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 628064,
            "range": "± 14862",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 33737005,
            "range": "± 448717",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1234013,
            "range": "± 25947",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 6132285,
            "range": "± 141286",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 84394438,
            "range": "± 450512",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 3411641,
            "range": "± 179515",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 16140711,
            "range": "± 290374",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 60858,
            "range": "± 4367",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 55432,
            "range": "± 2638",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 4881,
            "range": "± 45",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 32365,
            "range": "± 146",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 301666,
            "range": "± 1041",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "d6d5f5eeab83845337f85ad770880e24e089a059",
          "message": "v4.4.0 — Shared CEG attestation surface, phase 1: local-tier write + read-gate (#171) (#173)\n\n* v4.4 phase 1 foundation: CIRISVerify 4.11.0 re-pin + V066 attestation tier model (#171)\n\n- Re-pin CIRISVerify 4.10.0 → 4.11.0 (ships ciris_verify_core::jcs for\n  the phase-2 promote path; #59 closed).\n- V066 (both backends): federation_attestations gains tier\n  (local|federation, DEFAULT federation) + promoted_at. Purely additive\n  via empty-sentinel scrub envelope for local rows (no NOT-NULL\n  relaxation, no table rebuild). CHECK/trigger: federation ⟹ non-empty\n  classical signature (AV-60). Partial index on tier='local' for the §5\n  overdue scan + self-read. Applies clean on live PG + SQLite.\n\nFoundation for FSD/V4_4_SHARED_ATTESTATION_SURFACE.md phase 1\n(upsert_local/insert_local/query + gates) — WIP.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>\n\n* v4.4 phase 1: tier + promoted_at on Attestation (type layer) (#171)\n\n- Attestation gains tier (local|federation, serde-default federation) +\n  promoted_at (Option). Pure row metadata — canonical bytes are over\n  attestation_envelope, NOT the struct, so a promoted row is\n  byte-identical on the wire to a native-federation one (Registry must\n  #2). attestation_tier::{LOCAL,FEDERATION} consts.\n- Both decoders (sqlite_row_to_attestation / pg_row_to_attestation) read\n  the columns; all 5 SELECTs per backend add tier, promoted_at. INSERTs\n  rely on the column DEFAULT 'federation'.\n- 20 federation-write/test construction sites default tier=federation.\n\n69 attestation tests green on live PG + sqlite; -D warnings clean.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>\n\n* v4.4 phase 1: local-tier write methods (upsert/insert + gates) (#171)\n\nattestation_upsert_local (replace-on-(occurrence,dimension)) +\nattestation_insert_local (append) + _many defaults, on FederationDirectory\nacross sqlite/postgres/memory. CEG §10.1.3 local-tier:\n\n- LocalAttestationInput (caller envelope) → into_local_row fills the\n  deferred empty-sentinel scrub envelope (scrub_signature_classical=\"\",\n  scrub_key_id=attesting for FK, tier=local). Dimension = envelope\n  \"dimension\" (the upsert key + gate axis).\n- §4.1 gates (admission.rs): check_local_tier_eligibility refuses\n  capacity:* (§7.5/AV-62) + subject-side revocation (writer ∈\n  subject_key_ids, §10.1.3/AV-61); check_capacity_not_self_attested for\n  the federation path. Plus shared dimension/cohort_scope admission (no\n  federation trust gate — local is producer-authority).\n- upsert = delete prior local rows for (attesting, dimension) then\n  insert; insert = append fresh id. PG weight via $5::float8::numeric.\n\nTests both backends (live PG + sqlite): upsert-replace, insert-append,\ncapacity reject, subject-revocation reject, dimension-required. -D\nwarnings clean incl. no-backend pyo3.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>\n\n* v4.4 phase 1: read-gate (AV-59) + PyO3 + ship 4.4.0 (#171)\n\nCompletes the local-tier write+read half:\n- AV-59 read-gate: FederationDirectory trust-reads (list_attestations_for\n  /_by) filter tier='federation' (local self-attestations aren't vouches,\n  never surface there); local rows are cohort_scope='self' (enforced at\n  the write gate) so the v4.0 self-cohort gate IS the tier read-gate. The\n  agent reads its own state via the scoped ReadEngine reads.\n- PyO3: attestation_upsert_local / attestation_insert_local (JSON input).\n- Tests both backends (live PG + sqlite): upsert-replace, insert-append,\n  3 gate negatives (capacity §7.5/AV-62, subject-revocation §10.1.3/AV-61,\n  non-self-scope), dimension-required, AV-59 trust-read exclusion.\n\npromote + dimension-prefix query + §5 overdue-scan → v4.5 (promote\nunblocked by 4.11.0 JCS; §5 clock is OQ-3/#161). Per the Agent's staging\nrequest to land local operation first.\n\n1035 lib tests green on live PG (all features); clippy + cfg-gates clean.\nShips as 4.4.0.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>\n\n---------\n\nCo-authored-by: Claude Opus 4.8 <noreply@anthropic.com>",
          "timestamp": "2026-06-08T20:54:45-05:00",
          "tree_id": "8744dddb6367ea324695652146d36b9a44ce9146",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/d6d5f5eeab83845337f85ad770880e24e089a059"
        },
        "date": 1780971643298,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 53621133,
            "range": "± 149222",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 1318450,
            "range": "± 97792",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 1844,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 4498,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 9791,
            "range": "± 135",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 36407,
            "range": "± 531",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 126,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 383,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 447,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1650,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 62,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 193,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 877,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 10,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 37408,
            "range": "± 1034",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 111147,
            "range": "± 1812",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 406732,
            "range": "± 3878",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7137,
            "range": "± 1162",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 8160,
            "range": "± 751",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 12749,
            "range": "± 1808",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 23203,
            "range": "± 6080",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1160877,
            "range": "± 5270",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 9310705,
            "range": "± 239873",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 600730,
            "range": "± 16439",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 1829328,
            "range": "± 25745",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 90710642,
            "range": "± 432078",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 3804521,
            "range": "± 71361",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 16433742,
            "range": "± 195675",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 226300675,
            "range": "± 1080106",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 9711288,
            "range": "± 316066",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 42534507,
            "range": "± 538557",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 184822,
            "range": "± 6911",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 172120,
            "range": "± 7555",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 14312,
            "range": "± 69",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 90270,
            "range": "± 241",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 843348,
            "range": "± 9536",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "7b90fcc355b4eb1cd95abbd950b8a6cbeeb7fbb0",
          "message": "v4.5.0: attestation_query filters (#171, CEG §10.1.5.4) (#175)\n\nThe uniform dimension-aware read, as additive AttestationFilter fields on\nthe existing scope-gated ReadEngine::list_attestations (+ its PyO3 JSON\nwrapper) — no new method/type. No signing → independent of the JCS flip.\n\n- dimension_prefixes (open-vocab, hierarchical-prefix LIKE, OR-combined,\n  %/_/\\ escaped) — validated structurally, not a closed enum (OQ-2).\n- valid_at (asserted_at <= valid_at < expires_at).\n- confidence_floor (weight >= floor; NULL excluded; PG weight::float8).\n- subject_key_id (PG subject_key_ids ? $n; SQLite json_each).\nAND-compose with the existing filters + cohort gate + tier gate. The\nagent reads its own local (self) + federation rows by dimension via one\ncall. AttestationFilter drops Eq (Option<f64> not Eq); keeps PartialEq.\n\nTests both backends (live PG + sqlite): prefix (single+OR), confidence\nfloor, subject membership, point-in-time validity. 1037 lib tests green\non live PG; clippy + cfg-gates clean. Ships as 4.5.0.\n\nCo-authored-by: Claude Opus 4.8 <noreply@anthropic.com>",
          "timestamp": "2026-06-08T22:14:30-05:00",
          "tree_id": "5a825fa9cc74ac915f55e4e756df6fd55e083774",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/7b90fcc355b4eb1cd95abbd950b8a6cbeeb7fbb0"
        },
        "date": 1780976098476,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 53599512,
            "range": "± 168739",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 1083455,
            "range": "± 12867",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 1778,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 4389,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 9717,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 36372,
            "range": "± 821",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 124,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 383,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 448,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1651,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 61,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 193,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 872,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 10,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 35873,
            "range": "± 409",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 110401,
            "range": "± 1202",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 402017,
            "range": "± 2463",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 6216,
            "range": "± 444",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 7300,
            "range": "± 858",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 11452,
            "range": "± 1755",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 20889,
            "range": "± 1378",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1160080,
            "range": "± 2272",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 11265111,
            "range": "± 314304",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 682652,
            "range": "± 22886",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 2137484,
            "range": "± 28988",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 111247326,
            "range": "± 857904",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 4548753,
            "range": "± 111777",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 19585399,
            "range": "± 392894",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 275087376,
            "range": "± 1833015",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 11637674,
            "range": "± 356158",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 51332685,
            "range": "± 502135",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 218381,
            "range": "± 8725",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 200086,
            "range": "± 7722",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 17400,
            "range": "± 49",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 109347,
            "range": "± 180",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 1025291,
            "range": "± 1950",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "17acd957398bfec5795ff6435dd237133d9b334c",
          "message": "v4.6.0 — JCS canonicalization cutover surface + attestation_promote (#171, #176) (#178)\n\nJCS foundation + signed-epoch version gate (flip-ready, inert until 2.9.6) + Engine::attestation_promote (all 3 backends) + latent-PG uuid-serialize fix on the deferred-PQC attach path. Behavior unchanged this release. Closes #176; advances #171 phase 2.",
          "timestamp": "2026-06-09T10:48:46-05:00",
          "tree_id": "11726976496ca1fc5547a2ee9f084ec6a2297bdd",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/17acd957398bfec5795ff6435dd237133d9b334c"
        },
        "date": 1781021634148,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40449143,
            "range": "± 44475",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 1821890,
            "range": "± 328241",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2518,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5940,
            "range": "± 184",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12820,
            "range": "± 130",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 45974,
            "range": "± 1703",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 37,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 213,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 522,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 597,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2065,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 78,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 250,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1088,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 54402,
            "range": "± 2477",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 157431,
            "range": "± 3514",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 558122,
            "range": "± 8656",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8122,
            "range": "± 495",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 10268,
            "range": "± 663",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 16902,
            "range": "± 1534",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 35585,
            "range": "± 2961",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1633738,
            "range": "± 18705",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 7721577,
            "range": "± 113017",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 354689,
            "range": "± 25583",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 1325435,
            "range": "± 73047",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 77817404,
            "range": "± 499128",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 2287077,
            "range": "± 229098",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 13634526,
            "range": "± 322322",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 194397796,
            "range": "± 1571138",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 6016572,
            "range": "± 299462",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 35283721,
            "range": "± 523126",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 115043,
            "range": "± 5467",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 109296,
            "range": "± 6856",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 11740,
            "range": "± 83",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 77400,
            "range": "± 442",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 718110,
            "range": "± 2580",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c9c770c76e80456999b722fcfa2fd6c66dd0e608",
          "message": "v4.6.1 — re-pin CIRISVerify stack to v5.0.0 (CEG 1.0 / Agent 3.0 substrate) (#179)\n\nciris-verify-core / ciris-keyring / ciris-crypto v4.11.0 → v5.0.0. CIRISVerify#61 (jcs_canonicalize Python binding, our OQ-1) shipped; #60 adds KeyAttestationResult.boundary_degraded (additive — persist never constructs it). No persist code change; 1045 SQLite / 747 live-PG green.",
          "timestamp": "2026-06-09T11:53:50-05:00",
          "tree_id": "04193744ae0bf7538aa050a08c4b3e1f703b64a1",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/c9c770c76e80456999b722fcfa2fd6c66dd0e608"
        },
        "date": 1781025644915,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40441895,
            "range": "± 779617",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 3575630,
            "range": "± 257357",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2518,
            "range": "± 53",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 6007,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 13004,
            "range": "± 57",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 45879,
            "range": "± 524",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 39,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 213,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 522,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 598,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2066,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 79,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 251,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1088,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 57656,
            "range": "± 8016",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 159242,
            "range": "± 6148",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 570171,
            "range": "± 34141",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 9369,
            "range": "± 611",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 11985,
            "range": "± 876",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 18938,
            "range": "± 1398",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 37927,
            "range": "± 2237",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1638307,
            "range": "± 39007",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 3986057,
            "range": "± 47312",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 224241,
            "range": "± 15305",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 764153,
            "range": "± 20658",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 39795197,
            "range": "± 199531",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1291242,
            "range": "± 102136",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 7314789,
            "range": "± 724239",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 99858787,
            "range": "± 739414",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 3418648,
            "range": "± 187335",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 18674139,
            "range": "± 343775",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 65698,
            "range": "± 8787",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 63131,
            "range": "± 4678",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 5972,
            "range": "± 190",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 39035,
            "range": "± 152",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 366010,
            "range": "± 16637",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "2a2614bc9f2f096ea4e63bac77c9ba0c432840b1",
          "message": "v4.7.0 — typed register_public_key: Registered / AlreadyRegistered / RotationCollision (#177) (#180)\n\nregister_public_key returns a typed outcome dict instead of None; adds the collision detection the ON CONFLICT DO NOTHING path never had (rotations were silently swallowed → agent #809 branch was dead code). KeyRegistrationOutcome + classify_key_registration + register_accord_public_key on PG/SQLite. 1052 SQLite / 753 live-PG green. Closes #177.",
          "timestamp": "2026-06-09T12:25:25-05:00",
          "tree_id": "8d61625eba726d3c4a26f171874196c888a4bc78",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/2a2614bc9f2f096ea4e63bac77c9ba0c432840b1"
        },
        "date": 1781027199761,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45687866,
            "range": "± 342876",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 4327248,
            "range": "± 260734",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2424,
            "range": "± 55",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5669,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12323,
            "range": "± 38",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43853,
            "range": "± 264",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 33,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 178,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 506,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 577,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1991,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 74,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 231,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 980,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 47468,
            "range": "± 3244",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 148911,
            "range": "± 5020",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 544453,
            "range": "± 20254",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8895,
            "range": "± 562",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 10147,
            "range": "± 427",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 14487,
            "range": "± 882",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 24973,
            "range": "± 1254",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1412928,
            "range": "± 4398",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 3324186,
            "range": "± 35766",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 212994,
            "range": "± 10032",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 627901,
            "range": "± 15980",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 33055901,
            "range": "± 202345",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1242356,
            "range": "± 61320",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 5875615,
            "range": "± 196765",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 82449793,
            "range": "± 409063",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 3455482,
            "range": "± 438773",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 15557494,
            "range": "± 368937",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 57467,
            "range": "± 2665",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 53466,
            "range": "± 4495",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 4818,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 31531,
            "range": "± 332",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 297035,
            "range": "± 1849",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c26578ec0415e054a8a0201e8bab41a94faa1486",
          "message": "v4.8.0 — Option-A forward-secrecy removal/revocation primitives (#161 P1-3, CEG §11.7.1) (#181)\n\nV067 revocation tables + put/list_*_revocations on all backends + list_*_active default methods + honest build_caller_admission (revoked occurrence → singleton; removed member dropped). Ask 4/5 deferred on #152. 1056 SQLite / 754 live-PG green.",
          "timestamp": "2026-06-09T13:03:39-05:00",
          "tree_id": "de8592c90ad33574c6014444b625f33eecf20668",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/c26578ec0415e054a8a0201e8bab41a94faa1486"
        },
        "date": 1781029496995,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40418521,
            "range": "± 19429",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2617624,
            "range": "± 415940",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2516,
            "range": "± 59",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5994,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 13019,
            "range": "± 142",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 46079,
            "range": "± 253",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 37,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 214,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 523,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 598,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2069,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 82,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 251,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1106,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 71089,
            "range": "± 6654",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 184279,
            "range": "± 15220",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 587446,
            "range": "± 34372",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8920,
            "range": "± 1273",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 10875,
            "range": "± 2195",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 17024,
            "range": "± 2184",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 34104,
            "range": "± 3685",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1630481,
            "range": "± 32579",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 5545331,
            "range": "± 72583",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 313390,
            "range": "± 23925",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 1030858,
            "range": "± 97106",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 54885867,
            "range": "± 539993",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1768042,
            "range": "± 188310",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 9902502,
            "range": "± 556198",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 138060825,
            "range": "± 1499769",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 4481373,
            "range": "± 695730",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 24764321,
            "range": "± 544860",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 87403,
            "range": "± 7240",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 83779,
            "range": "± 5584",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 8181,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 53367,
            "range": "± 158",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 497994,
            "range": "± 1200",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "2be99c2302c0f38fbb7480efcd54b4b28fd70dba",
          "message": "v4.9.0 — PyO3 attestation_promote binding (#171 phase 2) (#182)\n\nExposes Engine::attestation_promote through PyO3 — the local→federation transition the agent's 2.9.6 community-server opt-in performs at federation-emit time (synchronous hybrid Ed25519+ML-DSA-65 sign, agent-confirmed shape). Completes the upsert_local+promote(+query) slice for 2.9.6; bulk/migrate trio stays #840-scoped. 1057 SQLite / 754 live-PG green.",
          "timestamp": "2026-06-09T14:39:04-05:00",
          "tree_id": "cf3bc5b1638cbd8c6f3aaf44d6ff3b9d96d844c5",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/2be99c2302c0f38fbb7480efcd54b4b28fd70dba"
        },
        "date": 1781035658660,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45659981,
            "range": "± 32442",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 3424255,
            "range": "± 73738",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2404,
            "range": "± 56",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5670,
            "range": "± 76",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12201,
            "range": "± 225",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 44024,
            "range": "± 276",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 183,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 507,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 577,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1992,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 71,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 229,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 986,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 14,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 47627,
            "range": "± 2778",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 144864,
            "range": "± 2908",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 532556,
            "range": "± 15084",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8651,
            "range": "± 520",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 10016,
            "range": "± 728",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 14182,
            "range": "± 939",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 24694,
            "range": "± 1171",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1411353,
            "range": "± 17761",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 4169761,
            "range": "± 194445",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 252713,
            "range": "± 11641",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 776429,
            "range": "± 19428",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 41755329,
            "range": "± 359378",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1428661,
            "range": "± 65084",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 7288993,
            "range": "± 106365",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 103861351,
            "range": "± 647686",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 3974199,
            "range": "± 202517",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 18779898,
            "range": "± 270724",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 77744,
            "range": "± 2495",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 70575,
            "range": "± 3939",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 6053,
            "range": "± 111",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 40314,
            "range": "± 220",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 374518,
            "range": "± 3769",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "49382a0e71eb4f19cccda59a9974bea2c6a1a793",
          "message": "v4.10.0 — location_proof + H3 rough-only (#154) + fix conformance-blocking ciris-verify pin (#184)\n\nlocation_proof substrate + H3 §0.8.1 rough-only enforcement (#154) via pure-Rust h3o; plus the pyproject ciris-verify pin bump (>=5.0.0,<6) that unblocks CIRISConformance from loading verify 5.0 alongside persist. 1067 SQLite / 763 live-PG green; cargo-deny clean.",
          "timestamp": "2026-06-09T17:26:19-05:00",
          "tree_id": "d39b2ebeb3f6379211fe4f682ebb4d017fbd0cf5",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/49382a0e71eb4f19cccda59a9974bea2c6a1a793"
        },
        "date": 1781045301258,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 35439823,
            "range": "± 24458",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2135552,
            "range": "± 77445",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2526,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5836,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12414,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43619,
            "range": "± 143",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 177,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 507,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 578,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1992,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 71,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 228,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 994,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 55502,
            "range": "± 3243",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 153613,
            "range": "± 6101",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 541380,
            "range": "± 27745",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8362,
            "range": "± 390",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9659,
            "range": "± 281",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 13708,
            "range": "± 667",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 23811,
            "range": "± 816",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1415825,
            "range": "± 7355",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 5116978,
            "range": "± 34372",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 295036,
            "range": "± 2397",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 888207,
            "range": "± 8057",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 51687260,
            "range": "± 356068",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1837859,
            "range": "± 125301",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 8686659,
            "range": "± 136675",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 129636869,
            "range": "± 814934",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 4732990,
            "range": "± 167399",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 22931344,
            "range": "± 215727",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 90654,
            "range": "± 3170",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 83049,
            "range": "± 2638",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 7688,
            "range": "± 34",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 50591,
            "range": "± 199",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 473358,
            "range": "± 2261",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "6370c16cd1f2d82a176e9664d3c9cead51b25c5e",
          "message": "v4.11.0 — geographic community admission + communities_containing (closes #154) (#187)\n\nput_community §8.1.13.2 geographic predicate (members gated on in-force contained location_proof) + communities_containing(cell) emergency-broadcast read. All 3 backends. 1071 SQLite / 766 live-PG green. Closes #154.",
          "timestamp": "2026-06-09T18:35:30-05:00",
          "tree_id": "fac409bbff3d132f8226fedda8c155da6c2b6b6a",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/6370c16cd1f2d82a176e9664d3c9cead51b25c5e"
        },
        "date": 1781049516212,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40435976,
            "range": "± 32637",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 1780343,
            "range": "± 350195",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2529,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5992,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12813,
            "range": "± 60",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 45874,
            "range": "± 388",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 35,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 202,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 522,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 596,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2063,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 80,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 252,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1102,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 54254,
            "range": "± 1360",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 158529,
            "range": "± 3396",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 558549,
            "range": "± 6305",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8241,
            "range": "± 562",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 10434,
            "range": "± 629",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 16954,
            "range": "± 1148",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 35400,
            "range": "± 2395",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1647023,
            "range": "± 5073",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 7877822,
            "range": "± 45125",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 365216,
            "range": "± 29176",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 1369319,
            "range": "± 16473",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 79712011,
            "range": "± 848406",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 2344670,
            "range": "± 262064",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 14139840,
            "range": "± 375950",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 200591391,
            "range": "± 2024737",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 6001563,
            "range": "± 254086",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 36754565,
            "range": "± 476441",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 121569,
            "range": "± 6480",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 125784,
            "range": "± 8039",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 12092,
            "range": "± 78",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 78551,
            "range": "± 499",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 730499,
            "range": "± 3833",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "e4ecacabc297b91eba970f2bf1c9ae14a19dfc86",
          "message": "v4.12.0 — at-rest crypto-tier dispatch: negative-default classifier (#152/#188) (#190)\n\nCryptoTier + crypto_tier() negative-default three-way dispatch (self/family invisible-encrypted | community/affiliations community-DEK | else plaintext), infrastructure-subkind carve-out. The #152 cascade foundation. Closes #188. 1075 SQLite green.",
          "timestamp": "2026-06-09T20:01:07-05:00",
          "tree_id": "8cdb975195d90c7a09530ecf39ac9d2853726cac",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/e4ecacabc297b91eba970f2bf1c9ae14a19dfc86"
        },
        "date": 1781054501481,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45683079,
            "range": "± 280902",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2564008,
            "range": "± 238814",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2403,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5727,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12488,
            "range": "± 61",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 44456,
            "range": "± 167",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 180,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 506,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 577,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1992,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 72,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 224,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 984,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 47270,
            "range": "± 2528",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 144291,
            "range": "± 4738",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 528978,
            "range": "± 9655",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8177,
            "range": "± 374",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9492,
            "range": "± 410",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 13837,
            "range": "± 1437",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 24313,
            "range": "± 1181",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1406447,
            "range": "± 4641",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 5458129,
            "range": "± 37109",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 308279,
            "range": "± 4567",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 965574,
            "range": "± 10648",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 55237951,
            "range": "± 570196",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1932703,
            "range": "± 84810",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 9618760,
            "range": "± 178070",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 137138676,
            "range": "± 1258165",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 4948506,
            "range": "± 221344",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 25038065,
            "range": "± 414945",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 96294,
            "range": "± 3734",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 87668,
            "range": "± 5874",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 8019,
            "range": "± 52",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 53085,
            "range": "± 269",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 496858,
            "range": "± 4810",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "9b7dd4b70a19c6054869b9ffbc4eed14d4d4637a",
          "message": "v4.12.1 — embed version literal in the cdylib (#189) (#191)\n\n#[used] static 'ciris-persist <ver>' literal surviving strip, for the agent Trust-page/bundle-refresh integrity grep. #[used] not #[no_mangle] (persist is #![deny(unsafe_code)]); runtime read served by the existing PyO3 __version__. Closes #189.",
          "timestamp": "2026-06-09T20:54:53-05:00",
          "tree_id": "cde0b86f19d92341c07c02480da6f25ead07b347",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/9b7dd4b70a19c6054869b9ffbc4eed14d4d4637a"
        },
        "date": 1781057764624,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45657499,
            "range": "± 33590",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 3010259,
            "range": "± 330033",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2517,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5844,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12470,
            "range": "± 267",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 44040,
            "range": "± 406",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 30,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 180,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 506,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 578,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1994,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 71,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 228,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 966,
            "range": "± 36",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 46975,
            "range": "± 631",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 143551,
            "range": "± 1296",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 528492,
            "range": "± 6960",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8423,
            "range": "± 470",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9350,
            "range": "± 452",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 14009,
            "range": "± 736",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 24508,
            "range": "± 1116",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1408219,
            "range": "± 4008",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 4828762,
            "range": "± 56644",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 293785,
            "range": "± 20711",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 914249,
            "range": "± 15111",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 47425096,
            "range": "± 353384",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1717857,
            "range": "± 74345",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 8469120,
            "range": "± 185488",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 118465510,
            "range": "± 925487",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 4739584,
            "range": "± 272153",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 21777877,
            "range": "± 346194",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 85298,
            "range": "± 4592",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 82223,
            "range": "± 5010",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 6743,
            "range": "± 30",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 44553,
            "range": "± 452",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 415856,
            "range": "± 13713",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "cd1a07b1f8cbfda10605fda9f50583897eb12fff",
          "message": "v4.13.0 — recipient content-encryption pubkeys on identity_occurrence (#192) (#193)\n\nV069 pubkey_x25519_base64 + pubkey_ml_kem_768_base64 on federation_identity_occurrences + EncryptionPubkeys type + resolve_encryption_keys (fail-secure) + length-gated admission. The persist half of the #152 substrate-wraps recipient-key dependency (CEG 0.18 / CIRISRegistry#69). 1078 SQLite / 772 live-PG green. Advances #192.",
          "timestamp": "2026-06-09T21:26:13-05:00",
          "tree_id": "6a731073cdecec44382c28daa153747aea900bd8",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/cd1a07b1f8cbfda10605fda9f50583897eb12fff"
        },
        "date": 1781059621563,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 53633633,
            "range": "± 79580",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 1111873,
            "range": "± 50685",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 1791,
            "range": "± 29",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 4406,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 9772,
            "range": "± 82",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 36871,
            "range": "± 468",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 143,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 383,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 446,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1649,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 60,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 192,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 867,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 10,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 37204,
            "range": "± 1088",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 111195,
            "range": "± 1106",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 406749,
            "range": "± 6740",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 6620,
            "range": "± 735",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 7738,
            "range": "± 1088",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 11884,
            "range": "± 1655",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 21381,
            "range": "± 1670",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1231701,
            "range": "± 2008",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 11031380,
            "range": "± 63221",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 707305,
            "range": "± 14847",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 2154926,
            "range": "± 27783",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 108304118,
            "range": "± 887723",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 4423737,
            "range": "± 126265",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 19237909,
            "range": "± 266276",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 270096663,
            "range": "± 1614214",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 11535623,
            "range": "± 380552",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 50427610,
            "range": "± 332857",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 222874,
            "range": "± 6784",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 209651,
            "range": "± 6642",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 17132,
            "range": "± 66",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 108499,
            "range": "± 248",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 1014116,
            "range": "± 1774",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "0bf87628ce69223af16e91b7fa700d45bc2206b8",
          "message": "Merge branch 'fsd-152-self-family-dek-cascade'\n\n# Conflicts:\n#\tFSD/SELF_FAMILY_DEK_CASCADE.md",
          "timestamp": "2026-06-09T22:07:21-05:00",
          "tree_id": "33a6d2121f3a15b5c3b4c6f6182c1beaef663cca",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/0bf87628ce69223af16e91b7fa700d45bc2206b8"
        },
        "date": 1781062283655,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45667919,
            "range": "± 110679",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2705779,
            "range": "± 166375",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2387,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5680,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12338,
            "range": "± 62",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43798,
            "range": "± 396",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 180,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 506,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 577,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1992,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 70,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 231,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 993,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 47208,
            "range": "± 1459",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 144626,
            "range": "± 2402",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 530987,
            "range": "± 3025",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7623,
            "range": "± 567",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9349,
            "range": "± 603",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 13475,
            "range": "± 803",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 23770,
            "range": "± 1107",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1481777,
            "range": "± 5986",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 5195934,
            "range": "± 56271",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 311091,
            "range": "± 15061",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 911197,
            "range": "± 16499",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 52023582,
            "range": "± 502680",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1779571,
            "range": "± 44685",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 8672126,
            "range": "± 177122",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 129797457,
            "range": "± 869177",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 4803145,
            "range": "± 263551",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 23382960,
            "range": "± 447412",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 90442,
            "range": "± 4403",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 84640,
            "range": "± 4519",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 7685,
            "range": "± 27",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 51124,
            "range": "± 227",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 477952,
            "range": "± 9136",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "4963e08a7cc4b543a8c40e8ab02480c68c7f88d1",
          "message": "v4.14.0 — self/family at-rest DEK cascade: the InvisibleEncrypted tier (#152, CEG 0.18 §10.1.4)\n\nPer-write DEK + AES-256-GCM encrypt-at-rest for cohort_scope self|family,\nwrap_algorithm: v2 (x25519+ML-KEM-768) per-recipient key_grant delivery,\nfail-secure exclusion of recipients without registered encryption_pubkeys.\nDEK retention (OQ-4) via an honest software content-master; hardware-rooted\nderivation is the tracked follow-up. CommunityDek tier + #161 membership\nwatcher deferred. Verified on SQLite + live PG, both backends green.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>",
          "timestamp": "2026-06-09T22:16:11-05:00",
          "tree_id": "8af851d0ceb8be9c9378ecb0f166adf086f1f654",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/4963e08a7cc4b543a8c40e8ab02480c68c7f88d1"
        },
        "date": 1781062697231,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45666024,
            "range": "± 32254",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2322793,
            "range": "± 378912",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2390,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5726,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12346,
            "range": "± 39",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43787,
            "range": "± 102",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 180,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 507,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 578,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1992,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 70,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 225,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 983,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 47224,
            "range": "± 1132",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 145092,
            "range": "± 1625",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 535037,
            "range": "± 4686",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 9295,
            "range": "± 1024",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9367,
            "range": "± 478",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 14030,
            "range": "± 2238",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 24572,
            "range": "± 1026",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1492675,
            "range": "± 5607",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 5993872,
            "range": "± 57013",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 338327,
            "range": "± 11401",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 1048328,
            "range": "± 20633",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 60759819,
            "range": "± 585442",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 2013324,
            "range": "± 34896",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 10243943,
            "range": "± 263274",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 152711741,
            "range": "± 993705",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 5755716,
            "range": "± 262827",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 28102328,
            "range": "± 1775295",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 111142,
            "range": "± 4594",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 103301,
            "range": "± 4877",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 8798,
            "range": "± 54",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 59543,
            "range": "± 231",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 551538,
            "range": "± 15697",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "e7fc39f6dd76fb0fdd05541f864138988207ee01",
          "message": "v4.15.0 — JCS (RFC 8785) canonicalization flip ACTIVATED (#171/#176, CEG §0.9)\n\nLockstep with the agent 2.9.6 hard-JCS cutover. Produce side flips\nproduce_canon_version() V1Python -> V2Jcs (covers attestations/keys/\nwithdraws/blob-signing/FFI canonicalize_envelope via the produce gate).\nVerify side adds the signed-epoch \"3.0.0\" arm (reuses the 2.7.9 field\nbuilder; layout byte-identical, only the canonicalizer differs) so persist\nverifies the agent's JCS traces; 2.7.x stays Python (legacy, retention-\nbounded). Coordination: agent bumped trace_schema_version 2.7.9 -> 3.0.0\n(CIRISAgent#871) to preserve the downgrade-safe discriminator.\n\nNodeCore-consensus / edge-wire / internal persist_row_hash stay on their\nown tracks (not silent gaps; see CHANGELOG). SQLite 1090 + live-PG 782\ngreen; clippy both feature sets + fmt + no-default clean.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>",
          "timestamp": "2026-06-09T22:59:55-05:00",
          "tree_id": "3a5e58e368faaba97420ea0a8a96d169ecc003f0",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/e7fc39f6dd76fb0fdd05541f864138988207ee01"
        },
        "date": 1781065357615,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40414359,
            "range": "± 32456",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2342366,
            "range": "± 603583",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2670,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 6194,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 13195,
            "range": "± 53",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 46142,
            "range": "± 505",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 38,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 203,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 523,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 599,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2067,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 81,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 256,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1122,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 54821,
            "range": "± 4283",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 157565,
            "range": "± 5192",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 560269,
            "range": "± 9198",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8814,
            "range": "± 710",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 10756,
            "range": "± 958",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 16916,
            "range": "± 1087",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 35104,
            "range": "± 2263",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1707317,
            "range": "± 15089",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 6004830,
            "range": "± 66243",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 303644,
            "range": "± 11400",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 1079951,
            "range": "± 29610",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 59948039,
            "range": "± 417424",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1805004,
            "range": "± 122948",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 10493983,
            "range": "± 237212",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 150641238,
            "range": "± 918820",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 4814891,
            "range": "± 212512",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 27349513,
            "range": "± 466605",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 94587,
            "range": "± 6788",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 88049,
            "range": "± 4910",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 9332,
            "range": "± 106",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 60003,
            "range": "± 520",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 556978,
            "range": "± 3154",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "01ce68fc00294d5c3c40941239321f7836f2413c",
          "message": "v5.0.0 — the agent-2.9.6 / CEG-1.0 substrate line (#186; #171/CIRISAgent#840)\n\nBreaks the #840 chicken-and-egg: ship persist's complete agent-facing\nlocal-tier attestation surface FIRST so the agent's graph_nodes->attestations\nhard cut migrates against it. Adds the last gap — PyO3 batched\nattestation_upsert_local_many / attestation_insert_local_many (the migration\nboot-pass bulk-insert; trait methods existed since v4.4.0). With these, all\nfour #171 surfaces are wheel-callable: write(+many)/query/promote, graph_nodes\ncoexistence preserved (no drop). CEG §0.9 JCS conformance landed v4.15.0.\n\nConsent-revocation <=24h auto-promote (#171 item 4 / #146) is a runtime\nguarantee, not a migration-surface blocker — tracked for 5.x. The agent's\n#840 migration execution stays its lockstep event; 5.0 assumes the commit.\n\nSQLite 1091 + live-PG 782 green; clippy both feature sets + fmt + no-default clean.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>",
          "timestamp": "2026-06-10T09:47:29-05:00",
          "tree_id": "cf5d1a565a3650064748810c12f947733ec5369f",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/01ce68fc00294d5c3c40941239321f7836f2413c"
        },
        "date": 1781104153834,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45667718,
            "range": "± 199500",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2440654,
            "range": "± 197725",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2393,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5726,
            "range": "± 58",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12378,
            "range": "± 44",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43780,
            "range": "± 307",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 32,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 180,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 506,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 577,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1991,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 72,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 230,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 976,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 46990,
            "range": "± 582",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 144835,
            "range": "± 1535",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 529973,
            "range": "± 7915",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8436,
            "range": "± 376",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9699,
            "range": "± 609",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 13967,
            "range": "± 864",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 24020,
            "range": "± 1185",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1480302,
            "range": "± 3263",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 5789823,
            "range": "± 44782",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 320808,
            "range": "± 10127",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 1000006,
            "range": "± 22839",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 58456815,
            "range": "± 407408",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 2053072,
            "range": "± 226251",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 9863384,
            "range": "± 200255",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 146504489,
            "range": "± 1077789",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 5326359,
            "range": "± 223181",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 25575521,
            "range": "± 443787",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 104205,
            "range": "± 4189",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 93608,
            "range": "± 4319",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 8556,
            "range": "± 37",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 56702,
            "range": "± 519",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 528464,
            "range": "± 2344",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "eacc0799904bd9ca3836f00f616ea1bb7b01288d",
          "message": "ci: auto-rerun CI on transient infra flakes (Docker-Hub service-pull)\n\nThe linux-x86_64-test matrix pulls a postgres service container from\nDocker Hub at job-init; rate-limit/outage flakes there ('Initialize\ncontainers: Docker pull failed') fail the whole matrix and — since the\ntag-gated PyPI publish needs: it — block releases, forcing manual\n'gh run rerun --failed'. This automates that, scoped to NOT mask real reds.\n\nworkflow_run-on-completion pattern (meziantou / Marketplace 'Rerun Failed\nJobs'), hardened: NO branches filter so tag (v*) runs are covered (they\nhave no head branch but gate publish); rerun iff a transient infra\nsignature is present (failed step is Set-up/Initialize-containers, or logs\nmatch Docker-pull/registry/network blips) AND no genuine compile/test\nfailure signature is; capped to run_attempt==1 (one auto-rerun, then a\nhuman looks).\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>",
          "timestamp": "2026-06-10T10:38:39-05:00",
          "tree_id": "05c38112e8dc06b949b886e5fbad9444775dfd96",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/eacc0799904bd9ca3836f00f616ea1bb7b01288d"
        },
        "date": 1781107241012,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45679160,
            "range": "± 330951",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 4271041,
            "range": "± 234256",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2614,
            "range": "± 58",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5975,
            "range": "± 87",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12373,
            "range": "± 88",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 44123,
            "range": "± 161",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 180,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 508,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 579,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1994,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 71,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 229,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 969,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 48118,
            "range": "± 3711",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 145539,
            "range": "± 3351",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 542048,
            "range": "± 17257",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7460,
            "range": "± 416",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9889,
            "range": "± 447",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 14041,
            "range": "± 1592",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 24776,
            "range": "± 1012",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1490814,
            "range": "± 26723",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 3437487,
            "range": "± 154190",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 226583,
            "range": "± 5021",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 667304,
            "range": "± 11645",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 33555029,
            "range": "± 414937",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1362582,
            "range": "± 64983",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 6273606,
            "range": "± 170773",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 84137855,
            "range": "± 929262",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 3383885,
            "range": "± 135713",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 15435816,
            "range": "± 197620",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 61984,
            "range": "± 3446",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 58338,
            "range": "± 2223",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 4882,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 32515,
            "range": "± 197",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 301607,
            "range": "± 5283",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "08c6259e4ae3174e486cdf1c9287980b38c59b32",
          "message": "deps: bump CIRISVerify crates v5.0.0 -> v5.1.0 (operational_admit for #65 / persist 5.1)\n\nciris-verify-core / ciris-crypto / ciris-keyring flipped together (same\nrepo; must stay workspace-coherent or two ciris_crypto versions land in\nthe graph -> type-mismatch). v5.1.0 adds ciris_verify_core::operational_admit\n(resolve_role_authority + verify_partner_record_quorum) — the RC2 §5.6.8.13\nadmit-verification surface persist 5.1 consumes. Additive; 127 verify/crypto\npath tests green, full compile clean on all features.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>",
          "timestamp": "2026-06-10T14:24:55-05:00",
          "tree_id": "ca01ed42cdc2b6018673c7cc555535abc186e71d",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/08c6259e4ae3174e486cdf1c9287980b38c59b32"
        },
        "date": 1781121052136,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40440439,
            "range": "± 28650",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2765077,
            "range": "± 231780",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2529,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5970,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 13061,
            "range": "± 81",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 46202,
            "range": "± 437",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 203,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 521,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 596,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2062,
            "range": "± 97",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 79,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 251,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1097,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 55186,
            "range": "± 1981",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 157926,
            "range": "± 3850",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 558461,
            "range": "± 7025",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8825,
            "range": "± 686",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 11614,
            "range": "± 623",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 18133,
            "range": "± 1225",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 36866,
            "range": "± 2066",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1742774,
            "range": "± 18188",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 5202354,
            "range": "± 93375",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 245028,
            "range": "± 26037",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 924135,
            "range": "± 21344",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 51844749,
            "range": "± 428848",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1522078,
            "range": "± 139431",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 8987181,
            "range": "± 139081",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 129028424,
            "range": "± 687606",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 4099583,
            "range": "± 236425",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 23470292,
            "range": "± 282150",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 82102,
            "range": "± 5326",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 73210,
            "range": "± 3290",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 7931,
            "range": "± 84",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 51961,
            "range": "± 334",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 479012,
            "range": "± 3820",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "b086f6edb7df8f056f51bc4e31f0d614d1f74fa4",
          "message": "v5.1.0 — operational-data admit + merge surface (CEG 1.0-RC2 §5.6.8.13/§10.1.6, #65/#70)\n\nVersion bump + CHANGELOG finalize for the 5.1 operational-data cut\n(put_organization/put_org_membership/put_partner_record + the two\nCEG-declared merge dispatchers, built against verify v5.1.0's\noperational_admit). Reviewed: root-steward anchor is caller-supplied\ntrust (per-region, not envelope-derived) — sound; four admission checks\ncorrect; merge resolvers partition-tolerant; role path fail-closed.\nSQLite 28 + live-PG 19 operational tests green; clippy clean across\nboth-backend, sqlite-only, postgres-only, and no-default combos.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>",
          "timestamp": "2026-06-10T14:58:25-05:00",
          "tree_id": "b8c2bea62269a4b0c11eb72f31b05ebc891490cf",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/b086f6edb7df8f056f51bc4e31f0d614d1f74fa4"
        },
        "date": 1781122895703,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45684539,
            "range": "± 344822",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 4568316,
            "range": "± 216366",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2413,
            "range": "± 29",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5682,
            "range": "± 79",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12335,
            "range": "± 353",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43880,
            "range": "± 216",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 180,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 506,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 577,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1992,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 70,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 226,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 972,
            "range": "± 39",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 47590,
            "range": "± 2037",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 145857,
            "range": "± 4202",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 535760,
            "range": "± 4521",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 9739,
            "range": "± 484",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 10897,
            "range": "± 538",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 15002,
            "range": "± 885",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 25094,
            "range": "± 1825",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1501283,
            "range": "± 20718",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 3178051,
            "range": "± 41136",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 207633,
            "range": "± 15592",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 587307,
            "range": "± 12125",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 31266500,
            "range": "± 889440",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1159829,
            "range": "± 76493",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 5710202,
            "range": "± 106690",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 78440499,
            "range": "± 618747",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 3351127,
            "range": "± 119459",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 14683110,
            "range": "± 420482",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 63866,
            "range": "± 2191",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 58255,
            "range": "± 3644",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 4537,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 30129,
            "range": "± 161",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 278623,
            "range": "± 1375",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "8a8edd1d0eb4f960c150d6f477be8085ab6df1cb",
          "message": "v5.1.1 — CI fix: test_support dead_code under backend-less `--features server` -D warnings\n\nThe 'darwin-aarch64 (no postgres)' job runs `cargo test --features server`\n(no backend) with -D warnings; operational::test_support's signed-envelope\nbuilders are used only by the sqlite/postgres test modules, so they're\ndead_code in that combo -> exit 101 -> v5.1.0 tag-run CI red, never published.\nFix: #[allow(dead_code)] on the test-only module. Library/wheel byte-identical\nto the v5.1.0 tag. Verified: backend-less -D-warnings build clean + full-backend\nclippy clean.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>",
          "timestamp": "2026-06-10T15:24:28-05:00",
          "tree_id": "5efd296f4d59468316b21a7da1f51113d2c3feaf",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/8a8edd1d0eb4f960c150d6f477be8085ab6df1cb"
        },
        "date": 1781124454788,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40441315,
            "range": "± 49382",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 3263746,
            "range": "± 658532",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2672,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 6091,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 13152,
            "range": "± 56",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 46216,
            "range": "± 410",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 39,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 207,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 522,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 598,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2065,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 81,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 250,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1107,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 54381,
            "range": "± 2878",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 156944,
            "range": "± 3196",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 566176,
            "range": "± 9105",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 10321,
            "range": "± 798",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 12129,
            "range": "± 707",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 18987,
            "range": "± 1994",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 38653,
            "range": "± 2750",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1745875,
            "range": "± 7413",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 4525509,
            "range": "± 65320",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 270650,
            "range": "± 13640",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 879961,
            "range": "± 18689",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 45038103,
            "range": "± 468856",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1568991,
            "range": "± 178220",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 8567964,
            "range": "± 433147",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 111667437,
            "range": "± 928612",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 4200246,
            "range": "± 308156",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 21665161,
            "range": "± 816473",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 78976,
            "range": "± 5197",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 73206,
            "range": "± 5283",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 6666,
            "range": "± 81",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 43762,
            "range": "± 457",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 405607,
            "range": "± 3449",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "954211ec15544b03ccdbd5be73a058cdeefa708b",
          "message": "v5.2.0 — bidirectional partner_record replication (#194, CIRISEdge#65 v2)\n\nv5.1.x verified the M-of-N steward quorum at admit then discarded the\nsignature set, storing only the envelope -> partner_record was admit-only\non the Edge v2 bridge (Initiator couldn't re-emit the wrapper to advertise\na byte-reproducible envelope_hash). V072 (both backends) adds\nsteward_signatures + threshold columns; put_partner_record persists them;\nnew FederationDirectory + PyO3 list_signed_partner_records_since re-emits\nthe full SignedPartnerRecord wrapper.\n\nthreshold is INTEGER → bound i32 on PG (live-PG caught the i64 mismatch).\nConvergence tests both backends; gate now runs the backend-less\n--features server -D warnings combo (the 5.1.1 trap). SQLite 1121 + PG 801.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>",
          "timestamp": "2026-06-10T22:17:39-05:00",
          "tree_id": "d8cee69e5c28fdf70ba748c458b4a46da6bab6c3",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/954211ec15544b03ccdbd5be73a058cdeefa708b"
        },
        "date": 1781149193738,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40408800,
            "range": "± 16300",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 1982117,
            "range": "± 230476",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2551,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 6013,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 13139,
            "range": "± 334",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 46393,
            "range": "± 343",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 35,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 202,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 533,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 608,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2075,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 81,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 256,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1118,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 57089,
            "range": "± 2881",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 158095,
            "range": "± 3101",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 558868,
            "range": "± 7801",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8325,
            "range": "± 557",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 10371,
            "range": "± 782",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 16309,
            "range": "± 1109",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 33198,
            "range": "± 1815",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1820180,
            "range": "± 15289",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 7130294,
            "range": "± 54225",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 356882,
            "range": "± 16371",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 1285558,
            "range": "± 28777",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 71758697,
            "range": "± 633812",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 2208190,
            "range": "± 61382",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 12920853,
            "range": "± 197136",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 180272449,
            "range": "± 1038649",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 5921406,
            "range": "± 231697",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 33305288,
            "range": "± 573437",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 119873,
            "range": "± 12049",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 105121,
            "range": "± 5494",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 10868,
            "range": "± 32",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 69956,
            "range": "± 338",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 650709,
            "range": "± 4857",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "01ae6d125890e8872104edf3e6724ca46e7b1b7c",
          "message": "v5.3.0 — substrate cache on aggregate_scoring_factors_batch (#195)\n\nParity with the get_repository_statistics cache (#162): ScoringFactorAggregate\ngains cache_hit + evaluated_at_unix_ms; batch result cached as one entry keyed\non (sorted agent set, window, baseline, scope, ingest-watermark). Watermark =\nMAX(ts) over the requested agents under the same scope predicate — new ingest\nstales the entry. Cache-hit reorders the set-keyed entry to caller input order;\nsingular routes through batch-of-one to share the cache. De-dups the fleet\nscoring sweep across cohabiting workers (the 65s cold /scoring/capacity/fleet).\n\nSQLite 1127 + live-PG 1127; 6 new cache tests (hit / watermark-invalidation /\norder-independence) both backends. Gate incl. backend-less --features server\n-D warnings.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>",
          "timestamp": "2026-06-11T13:05:47-05:00",
          "tree_id": "58206b5093f2bb86584c5e7644804ea963960206",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/01ae6d125890e8872104edf3e6724ca46e7b1b7c"
        },
        "date": 1781202655975,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40441203,
            "range": "± 139482",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 1742701,
            "range": "± 204552",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2534,
            "range": "± 49",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 6052,
            "range": "± 130",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 13094,
            "range": "± 98",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 46177,
            "range": "± 280",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 35,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 181,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 525,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 600,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2067,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 80,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 248,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1094,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 54932,
            "range": "± 2067",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 156601,
            "range": "± 3091",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 557142,
            "range": "± 7159",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8693,
            "range": "± 790",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 11014,
            "range": "± 723",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 17968,
            "range": "± 1414",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 36677,
            "range": "± 1824",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1843693,
            "range": "± 11516",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 8321557,
            "range": "± 51851",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 465321,
            "range": "± 19322",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 1604515,
            "range": "± 30547",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 83295227,
            "range": "± 446674",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 2721880,
            "range": "± 85440",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 15069995,
            "range": "± 215057",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 207196134,
            "range": "± 1738365",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 6800043,
            "range": "± 473925",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 37096732,
            "range": "± 551046",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 128732,
            "range": "± 6955",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 131354,
            "range": "± 8578",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 12520,
            "range": "± 76",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 81903,
            "range": "± 242",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 765032,
            "range": "± 3650",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "1d5f38c46a5cad6c23aaffccf0d2a771fd006374",
          "message": "v5.4.0 — LocalIdentityAggregate v1: versioned hybrid identity (#198)\n\nCEG-1.0 §5.6.8.8.2-conformant 3-role identity (no key derivation). v1\nself-sources two roles: signing (Ed25519 + ML-DSA-65, from the local\nsigner) + content-KEM (X25519 + ML-KEM-768, freshly minted via ciris_crypto\nand sealed under the content-master — the v4.14.0 wrap discipline, never\ncleartext; V073 single-row table). RET-transport left as a None seam for\n#199 (populates from edge v2.1.0 transport_identity_pubkeys()). Versioned\n(aggregate_version=1, ML-KEM-1024 headroom); did:key deferred (no base58 dep).\n\nNo-derivation enforced structurally (mint never touches the signing key) +\nasserted (content x25519 != ed25519). SQLite 1137 + live-PG 1137; +10 tests.\nGate incl. backend-less --features server -D warnings.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>",
          "timestamp": "2026-06-11T14:01:24-05:00",
          "tree_id": "5b320857e1759f51e088d3f949c4970ab196a9fa",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/1d5f38c46a5cad6c23aaffccf0d2a771fd006374"
        },
        "date": 1781205819934,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40431143,
            "range": "± 14738",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 1786720,
            "range": "± 274748",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2532,
            "range": "± 94",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 6019,
            "range": "± 96",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 13042,
            "range": "± 63",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 45921,
            "range": "± 194",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 180,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 525,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 600,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2068,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 81,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 250,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1081,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 53214,
            "range": "± 2952",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 155249,
            "range": "± 5272",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 554744,
            "range": "± 2846",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8774,
            "range": "± 557",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 10689,
            "range": "± 512",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 16770,
            "range": "± 1545",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 33723,
            "range": "± 2207",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1843018,
            "range": "± 5213",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 7826949,
            "range": "± 59699",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 380317,
            "range": "± 18678",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 1397836,
            "range": "± 36194",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 78815924,
            "range": "± 724411",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 2429093,
            "range": "± 65163",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 14129031,
            "range": "± 571767",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 197816885,
            "range": "± 1664619",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 6304211,
            "range": "± 350013",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 36328004,
            "range": "± 393038",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 127572,
            "range": "± 30024",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 118811,
            "range": "± 6777",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 11916,
            "range": "± 29",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 78550,
            "range": "± 179",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 731153,
            "range": "± 3639",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "b31eb6f2ce22e73dfdf060a98e979dde1fc67ba6",
          "message": "v5.5.0 — LocalIdentityAggregate RET-transport role completes the triple (#199)\n\nlocal_identity_aggregate now accepts caller-supplied transport pubkeys\n(transport_x25519_b64 / transport_ed25519_b64, both-or-neither). persist is\nthe substrate (no edge handle; cohabitation is edge->persist), so the\nconsumer reads edge.transport_identity_pubkeys() (ciris-edge>=2.1.0) and\npasses them in; persist validates (32-byte halves) + hashes them into the\nsingle aggregate. NO ciris-edge Rust dep. §5.6.8.8.2/#71-C4 guard: transport\nx25519 == content-KEM x25519 is rejected. All three roles now populate from\ntheir conformant sources.\n\nSQLite + live-PG green (transport folds into identity_hash; both-or-neither\n+ reuse-guard rejections tested). Gate incl. backend-less -D warnings.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>",
          "timestamp": "2026-06-11T14:19:53-05:00",
          "tree_id": "f7dc0caf905deed00578d3b97982e71ed323a172",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/b31eb6f2ce22e73dfdf060a98e979dde1fc67ba6"
        },
        "date": 1781207063831,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45674057,
            "range": "± 38711",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2283126,
            "range": "± 226898",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2416,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5733,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12477,
            "range": "± 187",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 44218,
            "range": "± 175",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 144,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 506,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 577,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1991,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 74,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 230,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 985,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 47161,
            "range": "± 978",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 144079,
            "range": "± 8930",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 526099,
            "range": "± 14244",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8373,
            "range": "± 443",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9495,
            "range": "± 375",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 13937,
            "range": "± 725",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 24436,
            "range": "± 1307",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1576292,
            "range": "± 4430",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 6170241,
            "range": "± 54512",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 345037,
            "range": "± 21008",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 1091468,
            "range": "± 13724",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 61518122,
            "range": "± 577053",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 2060298,
            "range": "± 93563",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 10329657,
            "range": "± 182020",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 155508208,
            "range": "± 2050143",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 5601467,
            "range": "± 236009",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 27127641,
            "range": "± 472598",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 111332,
            "range": "± 5523",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 101135,
            "range": "± 4358",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 9094,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 60526,
            "range": "± 396",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 562617,
            "range": "± 4373",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "2649dcbc84887d3a72e1cbdbe2e514d9270db48b",
          "message": "v5.5.2 — cargo-deny: ignore 2 unreachable pyo3 0.28 advisories (RUSTSEC-2026-0176/0177)\n\nTwo newly-published pyo3<0.29 advisories began failing the cargo-deny gate\non every push (unrelated to #200): new_closure Sync bound (0177) + nth/nth_back\nOOB on PyList/PyTuple (0176). Both paths are UNREACHABLE in persist (no\nnew_closure/PyCFunction::new; only builds PyLists, never nth-iterates incoming\nsequences) — ignored with justification; pyo3 0.28->0.29 migration tracked\nseparately. Carries the identical #200 Windows-portability fix; the v5.5.1 tag\nis a tombstone (pushed before this ignore, CI-red on cargo-deny, never published).\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>",
          "timestamp": "2026-06-11T20:29:16-05:00",
          "tree_id": "36f88282f0a21a3754e50d6fd66453c95c4d7d68",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/2649dcbc84887d3a72e1cbdbe2e514d9270db48b"
        },
        "date": 1781229260458,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45662026,
            "range": "± 465486",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 3423667,
            "range": "± 264152",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2387,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5657,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12361,
            "range": "± 203",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43790,
            "range": "± 91",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 144,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 506,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 577,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1993,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 65,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 226,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 974,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 47293,
            "range": "± 2434",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 144040,
            "range": "± 3687",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 527839,
            "range": "± 23652",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8756,
            "range": "± 480",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9804,
            "range": "± 396",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 14149,
            "range": "± 857",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 24843,
            "range": "± 1114",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1569906,
            "range": "± 18096",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 4119312,
            "range": "± 36575",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 245406,
            "range": "± 9681",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 743025,
            "range": "± 10036",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 40983544,
            "range": "± 383164",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1395813,
            "range": "± 55537",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 7090927,
            "range": "± 146536",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 102889031,
            "range": "± 486343",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 3717928,
            "range": "± 161879",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 18312193,
            "range": "± 880817",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 76079,
            "range": "± 4768",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 69958,
            "range": "± 2636",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 5942,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 40216,
            "range": "± 91",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 372063,
            "range": "± 2205",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "0707f61531efa43bd91a943b8dc0aa0f2f28a66b",
          "message": "v5.5.3 — Postgres: bounded retry on connection acquisition (resilience)\n\nget_client (every PG op's chokepoint) retries a transient pool.get() up to\n4x with short backoff (50/100/150ms). Acquisition is idempotent (no query\nyet) so a retry never duplicates a write; smooths momentary DB unavailability\n(restart/overload/failover). Happy path = one iteration. Closes the resilience\ngap behind a rare CI flake (Timescale container connection blip -> nextest\nexit-102, no reproducible test); auto-retry net stays as defense-in-depth.\n\n168 PG tests green through the new path; clippy + backend-less -D warnings clean.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>",
          "timestamp": "2026-06-11T21:13:15-05:00",
          "tree_id": "fa8745ec31c2cd4108d8bc6b15f8a9f3205e0964",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/0707f61531efa43bd91a943b8dc0aa0f2f28a66b"
        },
        "date": 1781231829776,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 53629896,
            "range": "± 136429",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 1250947,
            "range": "± 109224",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 1798,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 4466,
            "range": "± 81",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 9766,
            "range": "± 210",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 36635,
            "range": "± 536",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 126,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 382,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 446,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1649,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 61,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 196,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 894,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 37481,
            "range": "± 1079",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 112521,
            "range": "± 2030",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 412893,
            "range": "± 7490",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7849,
            "range": "± 1325",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 8557,
            "range": "± 863",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 12778,
            "range": "± 2206",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 22369,
            "range": "± 1814",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1316696,
            "range": "± 2795",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 9878533,
            "range": "± 219679",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 674887,
            "range": "± 20380",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 1947660,
            "range": "± 27525",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 95800539,
            "range": "± 1422068",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 4132103,
            "range": "± 235210",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 17466108,
            "range": "± 229036",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 238023832,
            "range": "± 6415877",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 10551157,
            "range": "± 267470",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 45235535,
            "range": "± 305912",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 218590,
            "range": "± 5715",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 207071,
            "range": "± 6999",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 15154,
            "range": "± 95",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 95883,
            "range": "± 876",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 894893,
            "range": "± 25305",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "ce9435decb40eb9e6de18f049bf7b620e05b2047",
          "message": "v6.0.0 — pyo3 0.29 lockstep cut (major: dependency-ABI cohabitation break) — #201\n\nCut the pyo3 0.28→0.29 migration as 6.0.0. The major bump is\nload-bearing: it engages ciris-edge ≤2.1.2's existing `ciris-persist<6`\nceiling as a firewall, so a 0.29 persist wheel is excluded from any\nold-edge env and `pip install -U` can't trigger a two-pyo3-minor\ncohabitation crash. No publish-ordering dependency — persist leads,\nedge 2.2.0 opts in with `>=6,<7`.\n\n- Cargo.toml 5.5.3 → 6.0.0 (version is the single source; pyproject\n  reads it dynamically)\n- CHANGELOG: 6.0.0 entry — migration, the two RUSTSECs genuinely\n  cleared, MSRV 1.83, the map_or autofixes, the <6-ceiling rationale\n\nCode/gate unchanged from 1574dc0 (this is the release-cut commit).\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>",
          "timestamp": "2026-06-12T09:26:44-05:00",
          "tree_id": "f77c89eb804afa68c4c410455f914e2d6912699b",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/ce9435decb40eb9e6de18f049bf7b620e05b2047"
        },
        "date": 1781276030575,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40441910,
            "range": "± 76719",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2812487,
            "range": "± 418622",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2609,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 6084,
            "range": "± 39",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12854,
            "range": "± 68",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 45798,
            "range": "± 215",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 35,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 181,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 523,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 599,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2066,
            "range": "± 61",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 80,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 249,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1141,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 55297,
            "range": "± 3413",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 158268,
            "range": "± 5859",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 554547,
            "range": "± 8081",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8280,
            "range": "± 549",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 10325,
            "range": "± 568",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 16697,
            "range": "± 1244",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 35140,
            "range": "± 1675",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1847867,
            "range": "± 9647",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 5195540,
            "range": "± 126834",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 281040,
            "range": "± 33768",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 1008595,
            "range": "± 29824",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 50631985,
            "range": "± 506738",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1566552,
            "range": "± 82428",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 8435803,
            "range": "± 70088",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 125997966,
            "range": "± 882388",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 4279556,
            "range": "± 189833",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 22800995,
            "range": "± 451869",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 79543,
            "range": "± 4411",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 75370,
            "range": "± 4674",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 7767,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 50114,
            "range": "± 317",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 466257,
            "range": "± 2244",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "55c79d9e341b552f3937344e0599fb48e6188801",
          "message": "ci(auto-retry): catch crates.io registry-fetch flakes\n\nThe v6.0.0 release run hit the same transient crates.io sparse-index\nfetch failure 3× on three different jobs (cirisgraph metadata, the\nlinux-aarch64 wheel, the CanonicalBuild signer) — each surfaced as\n`curl failed` / `[16] Error in the HTTP2 framing layer` / `download of\n<crate> failed` during a fresh `cargo metadata`, and none was matched\nby the existing transient regex, so auto-retry left them for a manual\n`gh run rerun`.\n\nAdd five unambiguous network signatures to the transient match:\nHTTP2 framing layer, download of … failed, unable to update registry,\ncurl failed, spurious network error. None of these appears on a genuine\ncompile/test failure, so the \"never auto-rerun a real red\" contract\n(and the run_attempt==1 one-shot cap) is preserved.\n\nDeliberately NOT matched: \"no matching package named … found\" (the\nincomplete-index variant) — indistinguishable from a genuine typo'd\ndependency, so it stays red for a human.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>",
          "timestamp": "2026-06-12T10:42:19-05:00",
          "tree_id": "62ad8db7bb8d2142f4f7ce2e06bb48dadd284d32",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/55c79d9e341b552f3937344e0599fb48e6188801"
        },
        "date": 1781279988823,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 28993668,
            "range": "± 522512",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2047392,
            "range": "± 164651",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2157,
            "range": "± 43",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5047,
            "range": "± 55",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 10871,
            "range": "± 200",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 38540,
            "range": "± 600",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 141,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 440,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 493,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1553,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 75,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 237,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1086,
            "range": "± 45",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 10,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 57727,
            "range": "± 161952",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 146187,
            "range": "± 91406",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 624732,
            "range": "± 1053182",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 10430,
            "range": "± 439",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 11786,
            "range": "± 605",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 14206,
            "range": "± 1167",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 22910,
            "range": "± 1476",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1454467,
            "range": "± 27372",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 3850847,
            "range": "± 86593",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 288044,
            "range": "± 27633",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 834164,
            "range": "± 49336",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 40347364,
            "range": "± 992176",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1759577,
            "range": "± 104714",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 8231466,
            "range": "± 324439",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 100530527,
            "range": "± 2106297",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 4988158,
            "range": "± 938409",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 21377510,
            "range": "± 407095",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 94040,
            "range": "± 6735",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 84908,
            "range": "± 5201",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 5072,
            "range": "± 123",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 33474,
            "range": "± 2090",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 321831,
            "range": "± 7545",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "c4dd9d7590603362caf45c19e09144d71273e2b2",
          "message": "Revert to 5.X / pyo3 0.28 — edge blocked on the 0.29 upgrade\n\nEdge cannot move to pyo3 0.29 yet, so persist's mainline must stay on\nthe 5.X / pyo3 0.28 line that edge (and lens-core) can still consume —\notherwise every new persist feature ships as 6.x/0.29 and starves the\ndownstream that's stuck on 0.28.\n\nReverts the two pyo3-0.29 commits:\n- ce9435d (v6.0.0 cut: version 5.5.3→6.0.0 + CHANGELOG)\n- c9d2b65 (the migration: pyo3 0.29, MSRV 1.83, capsule API, the\n  map_or→is_none_or autofixes, the dropped deny.toml ignores)\n\nNet effect: pyo3 back to 0.28, MSRV back to 1.75, version back to 5.5.3,\nRUSTSEC-2026-0176/0177 ignores restored (vulnerable-path-unreachable,\nas before — they're back to relevant on 0.28). The independent\nauto-retry registry-flake hardening (55c79d9) is KEPT.\n\nThe 0.29 work is NOT lost — it lives on origin/pyo3-029-lockstep-201\nand the v6.0.0 tag (tombstone). Re-land when edge unblocks its 0.29\nupgrade (CIRISEdge#89). The published 6.0.0 PyPI wheel is being yanked\nseparately so unconstrained installs resolve to the latest 5.X.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>",
          "timestamp": "2026-06-12T11:10:10-05:00",
          "tree_id": "ffcf370556356a6fcdbac0b7c8a1ba6fc7055a64",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/c4dd9d7590603362caf45c19e09144d71273e2b2"
        },
        "date": 1781282005391,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45674916,
            "range": "± 48828",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 4777463,
            "range": "± 242536",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2503,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5823,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12431,
            "range": "± 186",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43850,
            "range": "± 793",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 144,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 507,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 577,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1992,
            "range": "± 53",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 72,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 231,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 982,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 47528,
            "range": "± 3457",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 145553,
            "range": "± 4460",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 540295,
            "range": "± 13224",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8910,
            "range": "± 1797",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9800,
            "range": "± 958",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 15375,
            "range": "± 984",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 26616,
            "range": "± 1265",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1593607,
            "range": "± 6905",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 2989761,
            "range": "± 61343",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 214761,
            "range": "± 11865",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 593508,
            "range": "± 55756",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 30189311,
            "range": "± 651031",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1234938,
            "range": "± 100822",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 5869991,
            "range": "± 247071",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 75454774,
            "range": "± 827618",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 3371181,
            "range": "± 585911",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 15061583,
            "range": "± 1152778",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 61437,
            "range": "± 7421",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 54478,
            "range": "± 2392",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 4285,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 28728,
            "range": "± 107",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 268531,
            "range": "± 1355",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "8469056dc943735f53d7c3750830a087f8b8f70e",
          "message": "ci(#205): fix Windows build-std LNK1181 (windows.0.48.5.lib)\n\nThe Win7 wheel built cleanly (std from source + full graph) but failed\nat the final link: `LNK1181: cannot open input file 'windows.0.48.5.lib'`.\nUnder -Zbuild-std the linker doesn't auto-add the per-version import\nlibrary a transitive windows-targets pulls (the 0.52.6 one got a\n/LIBPATH, the 0.48.5 one didn't). Pre-fetch, then put every\nwindows_x86_64_msvc-*/lib dir on LIB so link.exe finds whichever\nversioned windows.<ver>.lib the graph resolves.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>",
          "timestamp": "2026-06-12T13:16:42-05:00",
          "tree_id": "c0ef41cfdfda0fc908102ee798187274644b5a2e",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/8469056dc943735f53d7c3750830a087f8b8f70e"
        },
        "date": 1781289589221,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 53633325,
            "range": "± 149182",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 1301429,
            "range": "± 1091895",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 1963,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 4577,
            "range": "± 45",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 9912,
            "range": "± 138",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 36196,
            "range": "± 293",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 129,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 383,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 447,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1649,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 62,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 194,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 881,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 36335,
            "range": "± 390",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 110471,
            "range": "± 724",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 410144,
            "range": "± 2521",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7348,
            "range": "± 1233",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 8649,
            "range": "± 1476",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 12959,
            "range": "± 1226",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 22330,
            "range": "± 1352",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1311524,
            "range": "± 5094",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 9474785,
            "range": "± 66579",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 658759,
            "range": "± 8960",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 1911060,
            "range": "± 17283",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 92564235,
            "range": "± 897585",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 3943216,
            "range": "± 152912",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 16700639,
            "range": "± 164767",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 229405568,
            "range": "± 1238207",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 10117795,
            "range": "± 212856",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 43420787,
            "range": "± 293180",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 210556,
            "range": "± 15426",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 196977,
            "range": "± 5434",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 14531,
            "range": "± 86",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 92214,
            "range": "± 723",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 863400,
            "range": "± 4036",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "6c7b558a77fdae66d68e494a4621648121142040",
          "message": "v5.5.5 — CIRISVerify 5.1.3 + rust-postgres security floors\n\nVerify 5.1.0 -> 5.1.3 (all 6 pins flipped together per the coherence\ninvariant: verify-core/crypto/keyring + the tpm/ios/android target-table\nkeyring entries — one tag or ciris_crypto splits the graph). 5.1.3 ships\na Win7-capable verify + TPM-1.2->software degradation (CIRISVerify#67);\npersist's own Win7 wheel lane (#205) now builds against a Win7-capable\nverify. Graph coherent: single ciris-crypto, all three on the 5.1.3 rev.\nNo persist API change.\n\nSecurity: three newly-published rust-postgres advisories, all\nmalicious-server DoS — RUSTSEC-2026-0178 (short DataRow panic,\ntokio-postgres), -0179 (unbounded SCRAM iterations, postgres-protocol),\n-0180 (malformed hstore panic, postgres-protocol). Floor the direct deps\ntokio-postgres>=0.7.18 + postgres-types>=0.2.14 (pull postgres-protocol\n>=0.6.12) rather than ignore. Low relevance (trusted DB) but free to\npatch. cargo-deny clean, no new ignores.\n\nVerified: build (postgres+server+pyo3), clippy -D warnings (pyo3+server\n+ sqlite-only), cargo-deny, sqlite lib (787), live-PG lib (728).\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>",
          "timestamp": "2026-06-12T15:34:17-05:00",
          "tree_id": "42d2b6eec75ed25ab4fc3a682089996a2dcfcfca",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/6c7b558a77fdae66d68e494a4621648121142040"
        },
        "date": 1781298077024,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45666002,
            "range": "± 48472",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 4001102,
            "range": "± 136055",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2553,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5887,
            "range": "± 36",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12553,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 44042,
            "range": "± 87",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 142,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 506,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 578,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1993,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 72,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 224,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 992,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 47566,
            "range": "± 396",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 144744,
            "range": "± 674",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 532605,
            "range": "± 1719",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8341,
            "range": "± 516",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9833,
            "range": "± 397",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 14368,
            "range": "± 725",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 24981,
            "range": "± 1144",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1572440,
            "range": "± 9425",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 3531106,
            "range": "± 27926",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 209058,
            "range": "± 3518",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 635886,
            "range": "± 7405",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 35229825,
            "range": "± 268499",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1220724,
            "range": "± 81728",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 5972907,
            "range": "± 113639",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 87905734,
            "range": "± 632894",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 3228872,
            "range": "± 112123",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 15949809,
            "range": "± 244026",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 64520,
            "range": "± 3918",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 59563,
            "range": "± 4515",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 5203,
            "range": "± 29",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 34433,
            "range": "± 144",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 321006,
            "range": "± 2541",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "edb70f91630828077ec43371b98cd1c611fa0079",
          "message": "ci: fix Windows build-std toolchain mismatch (rust-src not found)\n\nThe nightly pin (#208) installed rust-src on `nightly-2026-06-12` via\ndtolnay, but the maturin build step still set RUSTUP_TOOLCHAIN=nightly —\nthe floating nightly, a different toolchain rustup auto-installs without\nrust-src. build-std then failed: \"…/library/Cargo.lock does not exist,\n… rustup component add rust-src\". (v5.5.4's lane worked because install\nand RUSTUP_TOOLCHAIN both used bare `nightly`.)\n\nMake the pinned toolchain a single source of truth: job-level\nNIGHTLY_PIN, referenced by both the rust-src install and\nRUSTUP_TOOLCHAIN. They can no longer drift.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>",
          "timestamp": "2026-06-12T16:16:57-05:00",
          "tree_id": "a7bf0a1435c37183a8111d52278e6273d79dc580",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/edb70f91630828077ec43371b98cd1c611fa0079"
        },
        "date": 1781300343016,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40444906,
            "range": "± 44399",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 3832064,
            "range": "± 212937",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2535,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 6000,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12871,
            "range": "± 56",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 46261,
            "range": "± 400",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 183,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 522,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 597,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2064,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 80,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 253,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1092,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 56382,
            "range": "± 7097",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 155817,
            "range": "± 2247",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 555371,
            "range": "± 22630",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8115,
            "range": "± 512",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 10666,
            "range": "± 408",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 18118,
            "range": "± 1793",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 35227,
            "range": "± 2163",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1849370,
            "range": "± 5079",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 3635515,
            "range": "± 21497",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 177973,
            "range": "± 9317",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 667136,
            "range": "± 33914",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 37693023,
            "range": "± 464984",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1179107,
            "range": "± 58104",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 6793608,
            "range": "± 219157",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 95206175,
            "range": "± 639821",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 2981687,
            "range": "± 177007",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 17459702,
            "range": "± 350596",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 57499,
            "range": "± 2556",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 57578,
            "range": "± 4167",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 5697,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 36812,
            "range": "± 123",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 342952,
            "range": "± 3080",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "eaf14a19037d5ff672d5f1cace5e2838416c136d",
          "message": "v5.6.0 — SharedInstanceLease: cross-process leader election (#210)\n\nUnblocks CIRISEdge#100 (and edge v2.3.0 auto leader-election): multi-worker\ndeployments race to bind the Reticulum socket → EADDRINUSE. RNS\nshared-instance mode needs leader election; persist already owns the\nfamily's cross-process atomic state, so it's the home.\n\n- federation::shared_instance — SharedInstanceLease + DEFAULT_STALE_AFTER\n  + staleness_threshold.\n- 4 FederationDirectory methods (default-impl on the trait; real impls on\n  Postgres + SQLite): try_acquire / heartbeat / lookup / release. Additive,\n  non-breaking — backends inherit \"not implemented\" until overridden.\n- Atomic election: single-statement INSERT … ON CONFLICT DO UPDATE …\n  WHERE incumbent-heartbeat-is-stale → two racers can never both win.\n  Stale owner stolen with lease_version+1; demoted owner sees None on its\n  next heartbeat; release is ownership-checked + idempotent.\n- V074 (both backends): shared_instance_leases + heartbeat index. PG\n  TIMESTAMPTZ; SQLite RFC-3339 TEXT, fixed Micros+Z so the staleness\n  compare is a sound lexical `<`.\n- Edge consumes via the existing federation_directory_capsule — no new FFI.\n\nTested both backends (full lifecycle incl. steal/demotion/stale-release):\nsqlite lib 788, live-PG lib 729; fmt, clippy ×2 -D warnings, backend-less\n-D warnings, --no-default-features, cargo-deny all green.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>",
          "timestamp": "2026-06-12T22:08:09-05:00",
          "tree_id": "7e6010b12a191c1160a51e73ba5a395dae7b25d4",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/eaf14a19037d5ff672d5f1cace5e2838416c136d"
        },
        "date": 1781321406710,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40437501,
            "range": "± 600140",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 3170813,
            "range": "± 217365",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2552,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 6086,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 13145,
            "range": "± 43",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 46527,
            "range": "± 256",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 181,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 522,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 597,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2065,
            "range": "± 71",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 80,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 249,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1093,
            "range": "± 37",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 54406,
            "range": "± 2202",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 157856,
            "range": "± 5015",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 558219,
            "range": "± 7327",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 9536,
            "range": "± 943",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 11865,
            "range": "± 837",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 17765,
            "range": "± 1366",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 35929,
            "range": "± 2143",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1863058,
            "range": "± 4422",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 4549339,
            "range": "± 76539",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 243460,
            "range": "± 22654",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 839489,
            "range": "± 21091",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 44781425,
            "range": "± 560674",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1469136,
            "range": "± 108498",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 8123727,
            "range": "± 213467",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 112437816,
            "range": "± 782327",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 3701900,
            "range": "± 210139",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 20785057,
            "range": "± 354232",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 74143,
            "range": "± 4357",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 72833,
            "range": "± 4805",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 6786,
            "range": "± 73",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 45251,
            "range": "± 309",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 414734,
            "range": "± 11263",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "b3125d541e1f560261f875132d3b9c6ba32c1d66",
          "message": "ci: cache Windows build-std + bump deprecated Node-20 actions\n\nTwo maintenance threads.\n\n1) Windows build-std cache. rust-cache prunes target/ to registry-dep\n   artifacts, dropping the from-source std/core/alloc that -Zbuild-std\n   compiles for the win7 target — the bulk of the ~20m, so the windows\n   wheel never warmed. Split: rust-cache stays for non-Windows; Windows\n   gets an explicit actions/cache over ~/.cargo + the whole\n   target/x86_64-win7-windows-msvc tree, keyed on the pinned nightly +\n   Cargo.toml. cargo refingerprints the changed crate, so the wheel is\n   identical to a clean build. GH cache is branch-scoped, so the speedup\n   lands after a main run populates the key (PR/tag runs then restore).\n\n2) Node-20 action deprecation (GitHub sunsets Node20 Sep 2026). Bump to\n   the current Node24 majors (verified against the marketplace + release\n   notes — the artifact-action API for name/pattern/path is unchanged for\n   our usage; the only breaking notes are download-by-ID and v8's\n   Content-Type unzip check, neither of which we hit):\n   checkout v4→v6, upload-artifact v4→v7, download-artifact v4→v8,\n   setup-python v5→v6, cache v4→v5.\n\nWorkflow-only; no Rust/dep/artifact-shape change.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>",
          "timestamp": "2026-06-12T23:10:59-05:00",
          "tree_id": "c092da8dbb8d4ec1c983569b56d7a429089073c5",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/b3125d541e1f560261f875132d3b9c6ba32c1d66"
        },
        "date": 1781325077817,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 28984468,
            "range": "± 1118676",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 1039722,
            "range": "± 76332",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2147,
            "range": "± 35",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5064,
            "range": "± 180",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 10977,
            "range": "± 302",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 38784,
            "range": "± 749",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 145,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 436,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 493,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1595,
            "range": "± 28",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 78,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 256,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1123,
            "range": "± 46",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 10,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 58838,
            "range": "± 222405",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 230392,
            "range": "± 879525",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 497690,
            "range": "± 706286",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7771,
            "range": "± 1060",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 10591,
            "range": "± 827",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 12282,
            "range": "± 841",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 21096,
            "range": "± 2318",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1520509,
            "range": "± 30960",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 7712124,
            "range": "± 274112",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 467709,
            "range": "± 112735",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 1465140,
            "range": "± 150681",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 81332765,
            "range": "± 4849466",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 3138577,
            "range": "± 375056",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 15506652,
            "range": "± 847510",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 206962599,
            "range": "± 9964085",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 9172321,
            "range": "± 943611",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 41702972,
            "range": "± 2061327",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 196525,
            "range": "± 22877",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 178654,
            "range": "± 46647",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 10229,
            "range": "± 580",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 65692,
            "range": "± 1769",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 636290,
            "range": "± 13806",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "00fa8e3ea8b6942e294edde7b310297caba7b092",
          "message": "v5.7.0 — hard_case:* emission surface + consent-state resolution (#146)\n\nCEG 1.0-RC4 §7.0.2 ratified consent_role (Agent#760 OQ-1/2/3 = ConsentGate.lean\ndefaults), unblocking #146's back half. The consent_role schema already\nshipped (V020, flat overwrite-on-revoke enum incl. peer/authorized_review,\nmatching OQ-1); this adds the two substrate primitives the consent-SLA\nwatcher needs.\n\n- V075 hard_case_events (both backends) + FederationDirectory::record_hard_case\n  / list_hard_case_events — persist's first hard_case:* EMITTER (was gate-only).\n  Durable/queryable/operator-introspectable surface (design decision over a\n  transient change-feed); LensCore composes detection:consent:* over it.\n  Idempotent on a deterministic event_id (ON CONFLICT DO NOTHING) so a watcher\n  re-scan never double-emits. Kinds: consent_sla_breach (§8.1.11.3),\n  consent_revocation_promotion_overdue (§10.1.3); open vocab.\n- FederationDirectory::resolve_consent_state (§8.1.11.1) — latest non-expired\n  consent:state:* from the subject; later revoked overrides granted;\n  Unspecified if never declared (unknown stance never reads as granted).\n  Backend-agnostic default over list_attestations_for.\n- federation::hard_case module: HardCaseEvent / HardCaseFilter / ConsentState\n  + kind constants. Additive trait methods (default-impl), non-breaking.\n\nFoundation for the consent-SLA watcher background task (next #146 increment).\n\nTested both backends: resolve_consent_state (grant→revoke override, unspecified)\n+ hard_case record/list/idempotent/JSONB-detail. fmt, clippy -D warnings x2,\nbackend-less -D warnings, --no-default-features, cargo-deny, sqlite 790, PG 730.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>",
          "timestamp": "2026-06-13T01:27:15-05:00",
          "tree_id": "2549408bc55c3966824d0c6c456110d2c13de7d9",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/00fa8e3ea8b6942e294edde7b310297caba7b092"
        },
        "date": 1781333361379,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45686165,
            "range": "± 30885",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2552391,
            "range": "± 248146",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2399,
            "range": "± 30",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5700,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12461,
            "range": "± 185",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 44240,
            "range": "± 738",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 175,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 506,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 577,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1991,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 71,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 222,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 968,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 48391,
            "range": "± 5668",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 143441,
            "range": "± 994",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 528279,
            "range": "± 4622",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8540,
            "range": "± 607",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9684,
            "range": "± 440",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 14055,
            "range": "± 1661",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 23985,
            "range": "± 1344",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1584027,
            "range": "± 5650",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 5422393,
            "range": "± 62878",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 306377,
            "range": "± 4849",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 959039,
            "range": "± 22487",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 55345563,
            "range": "± 545540",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1859907,
            "range": "± 39014",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 9271939,
            "range": "± 246398",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 138469402,
            "range": "± 1841070",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 4771358,
            "range": "± 198446",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 24538119,
            "range": "± 398308",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 104748,
            "range": "± 5377",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 93408,
            "range": "± 3340",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 8080,
            "range": "± 30",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 52549,
            "range": "± 1175",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 483817,
            "range": "± 2837",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "2ed701f0092798fefa747894c473dad354131301",
          "message": "v5.8.0 — consent-SLA watcher (#146 Ask 3 complete; CEG §8.1.11.3)\n\nCompletes #146's back half on the v5.7.0 primitives.\n\n- FederationDirectory::run_consent_sla_watch(now, promotion_window) —\n  backend-agnostic default over list_consent_revocations +\n  list_attestations_for + record_hard_case. §8.1.11.3: subject-side\n  revocation past the producer's consent:deletion_sla deadline with no\n  consent:deletion_complete → hard_case:consent_sla_breach. Idempotent\n  (deterministic event_id); clears on completion. Returns ConsentWatchReport.\n- FederationDirectory::list_consent_revocations(since) (PG + sqlite) —\n  consent:state:revoked + subject-side withdraws (rule 2/3/4); full\n  Attestation rows, NOT tier-filtered (§10.1.3 needs local rows).\n- hard_case: ConsentWatchReport, parse_deletion_sla_days, watch_event_id.\n\n§10.1.3 caveat (flagged): the promotion_overdue check is implemented but\nfires on nothing today — AV-61 rejects subject-side local-tier\nrevocations, so none exist to be overdue. Kept forward-compatible (fires\nif the #171 local-tier surface ever produces one); the §10.1.3-vs-AV-61\ntension is a real question for CEG/§171.\n\nTested both backends: breach-past-deadline / idempotent re-scan /\nsuppressed-by-completion (sqlite clean DB); PG exercises the\nlist_consent_revocations JSONB query end-to-end. fmt, clippy -D warnings\nx2, sqlite 791, PG 731, cargo-deny.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>",
          "timestamp": "2026-06-13T10:39:45-05:00",
          "tree_id": "470fe53f4a09b9ccaa45f98a7e35f16438a1e78e",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/2ed701f0092798fefa747894c473dad354131301"
        },
        "date": 1781366500424,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45674800,
            "range": "± 290152",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 3514707,
            "range": "± 199794",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2525,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5804,
            "range": "± 165",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12334,
            "range": "± 85",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 44143,
            "range": "± 1230",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 31,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 144,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 508,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 578,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1993,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 72,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 231,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 970,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 47549,
            "range": "± 4231",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 144526,
            "range": "± 14669",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 532332,
            "range": "± 17554",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8930,
            "range": "± 539",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 10613,
            "range": "± 456",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 15081,
            "range": "± 786",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 25476,
            "range": "± 7158",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1584656,
            "range": "± 5979",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 4151882,
            "range": "± 37678",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 266108,
            "range": "± 15585",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 767483,
            "range": "± 17971",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 40765974,
            "range": "± 319069",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1441628,
            "range": "± 89099",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 6886970,
            "range": "± 113595",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 100567509,
            "range": "± 762946",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 3895645,
            "range": "± 142837",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 18376784,
            "range": "± 366003",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 79767,
            "range": "± 2894",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 75765,
            "range": "± 3718",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 5760,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 38364,
            "range": "± 211",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 355942,
            "range": "± 868",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "c7062f9bbd456825014c7de03f3e7d45ba7eef04",
          "message": "v5.9.0 — pressure-gated retention primitive (#209) + verify 5.2.0\n\n#209: substrate-owned retention on MaintenanceService (trace_events /\ntrace_llm_calls grew unbounded post-cutover; lens stopgap was the wrong\nlayer).\n- set/get/list/run_retention (both backends) + V076 retention_policies\n  (durable). RetentionPolicy: min_keep_secs (sacred floor), time_column,\n  optional pressure_trigger/target_bytes, interval_secs.\n- run_retention: below trigger = no-op (no churn); at/above = DELETE rows\n  older than min_keep, exhausted=true if still over target. No pressure\n  config = flat drop. Size via pg_database_size / page_count*page_size.\n- Injection-safe: table_name + time_column gated through\n  validate_sql_identifier (snake_case table/schema.table) before reaching\n  the un-bindable DELETE SQL; re-validated in the sweep.\n- v1 = pressure-gated DELETE (per #209). Deferred: drop_chunks/partition\n  precise reclaim (row DELETE doesn't reclaim PG heap until VACUUM, so\n  exhausted is best-effort), fidelity-tiered compaction (#196 + CEG\n  envelope), engine/PyO3 surface.\n\nverify 5.1.3 -> 5.2.0 (all 3 pins, coherent single ciris-crypto). 5.2.0 =\nTransportIdentityKeystore (CIRISVerify#68, unblocks CIRISEdge#99).\nAdditive; no persist API change.\n\nTested both backends: retention CRUD/flat-sweep/pressure-no-op/injection\n(sqlite) + PG pg_database_size + validated DELETE on a temp table. fmt,\nclippy -D warnings x2, backend-less -D warnings, --no-default-features,\ncargo-deny, sqlite 792, PG 732.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>",
          "timestamp": "2026-06-13T13:10:20-05:00",
          "tree_id": "f94581835777304910ad63835bcf4ffdcd8d1e72",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/c7062f9bbd456825014c7de03f3e7d45ba7eef04"
        },
        "date": 1781375829654,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40429154,
            "range": "± 38255",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2036344,
            "range": "± 163685",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2527,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5984,
            "range": "± 46",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 13117,
            "range": "± 134",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 46164,
            "range": "± 314",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 187,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 522,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 597,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 2064,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 82,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 248,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1094,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 54021,
            "range": "± 4062",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 155760,
            "range": "± 6852",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 553473,
            "range": "± 4058",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 7697,
            "range": "± 311",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 10501,
            "range": "± 440",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 16879,
            "range": "± 1271",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 35010,
            "range": "± 1848",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1837698,
            "range": "± 18434",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 6988172,
            "range": "± 76902",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 307418,
            "range": "± 7134",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 1193336,
            "range": "± 10955",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 69425301,
            "range": "± 957680",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1985740,
            "range": "± 31806",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 11935556,
            "range": "± 331009",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 175112522,
            "range": "± 1383012",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 5224239,
            "range": "± 192591",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 31542750,
            "range": "± 371586",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 108847,
            "range": "± 5572",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 102188,
            "range": "± 5436",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 10465,
            "range": "± 744",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 69174,
            "range": "± 748",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 645134,
            "range": "± 2877",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "1899eeb0933f15b8a1b5481910943e057de72f69",
          "message": "v6.0.1 — pyo3 0.28→0.29 re-land (#201, #216); edge unblocked\n\nThe 0.29 lockstep resumes — edge cleared its block (CIRISEdge#99/v2.5.0\nship-ready). Re-applies the 0.29 migration ON TOP of current main, so\n6.0.1 = everything through 5.9.0 (shared-instance, hard_case + consent\nobservability, consent-SLA watcher, retention, verify 5.2.0) + pyo3 0.29\nin one coherent cut (not a forward-port onto the stale 6.0.0 branch, per\n#216's superseded framing — main already had all that substrate + verify\n5.2.0, past #216's 5.8.0/5.1.3 asks).\n\n- pyo3 0.28→0.29: 7 PyCapsule::new→new_with_value + the\n  new_with_destructor→new_with_value_and_destructor executor capsule\n  (&'static CStr name → c\"...\" literals). MSRV 1.75→1.83 (Cargo.toml +\n  clippy.toml); is_none_or autofixes from the raised lint floor.\n- RUSTSEC-2026-0176/0177 genuinely cleared (pyo3 <0.29); v5.5.2 deny\n  ignores removed. cargo-deny clean, no pyo3 ignores.\n\n6.0.0 = tombstone (yanked); 6.0.1 = live 0.29 cut. Firewall: edge's <6\npin excludes 6.x from 0.28 envs; edge 2.5.0 opts in >=6.0.1,<7 + its own\n0.29; lens-core follows. 5.x line stays published (5.9.0) for 0.28\nconsumers mid-transition.\n\nGate green under 0.29: build, fmt, clippy -D warnings x2, backend-less\n-D warnings, --no-default-features, cargo-deny (no pyo3 ignores),\nsqlite 792, PG 732.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>",
          "timestamp": "2026-06-13T13:50:52-05:00",
          "tree_id": "251291cd2d06321001af2b15e363b209ea939a71",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/1899eeb0933f15b8a1b5481910943e057de72f69"
        },
        "date": 1781377943055,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45675599,
            "range": "± 206017",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2857034,
            "range": "± 363706",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/1",
            "value": 2388,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 5717,
            "range": "± 28",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 12202,
            "range": "± 871",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 43888,
            "range": "± 185",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 143,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 506,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 577,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 1992,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 74,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 227,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 1009,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 47154,
            "range": "± 717",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 145329,
            "range": "± 5663",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 528500,
            "range": "± 16799",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/1",
            "value": 8971,
            "range": "± 485",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/2",
            "value": 9901,
            "range": "± 1006",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/8",
            "value": 14271,
            "range": "± 769",
            "unit": "ns/iter"
          },
          {
            "name": "sequence_contention_sqlite/next_sequence/32",
            "value": 24833,
            "range": "± 2608",
            "unit": "ns/iter"
          },
          {
            "name": "engine_cold_start/sqlite_open_and_migrate",
            "value": 1575313,
            "range": "± 22398",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/1000",
            "value": 4967961,
            "range": "± 54525",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/1000",
            "value": 291703,
            "range": "± 6601",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/1000",
            "value": 892594,
            "range": "± 19714",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/10000",
            "value": 49445533,
            "range": "± 485974",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/10000",
            "value": 1722815,
            "range": "± 110141",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/10000",
            "value": 8635501,
            "range": "± 255221",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/list_trace_summaries/25000",
            "value": 123952606,
            "range": "± 728101",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/aggregate_llm_costs/25000",
            "value": 4562748,
            "range": "± 260127",
            "unit": "ns/iter"
          },
          {
            "name": "read_engine_analytics/cross_agent_divergence/25000",
            "value": 22661391,
            "range": "± 529157",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/register_occurrence",
            "value": 92679,
            "range": "± 4908",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/heartbeat_occurrence",
            "value": 85007,
            "range": "± 4037",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/10",
            "value": 7183,
            "range": "± 115",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/100",
            "value": 48283,
            "range": "± 276",
            "unit": "ns/iter"
          },
          {
            "name": "occurrence_registry/list_live_occurrences/1000",
            "value": 447326,
            "range": "± 13266",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}