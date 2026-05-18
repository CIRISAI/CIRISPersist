window.BENCHMARK_DATA = {
  "lastUpdate": 1779119030597,
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
          "id": "f66fbcd159c8ceae229958b9b1bff97cf8b7e844",
          "message": "fix(bench): enter tokio runtime context for setup closures\n\ncargo test --all-targets runs criterion bench bins in smoke mode,\nwhere iter_with_setup closures execute synchronously outside any\ntokio runtime context. spawn_persister calls tokio::spawn which\npanics there with \"no reactor running\" — broke CI run 25221610071\non linux-x86_64 (full features).\n\nFix: take a runtime.enter() guard at bench-function scope. Setup\nand measurement closures share the same thread's runtime context.\n\nBelt-and-suspenders applied to ingest_pipeline.rs too — current\nIngestPipeline doesn't tokio::spawn directly but future backends\nmight, and the cost is one EnterGuard per bench function.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-01T11:06:13-05:00",
          "tree_id": "35e3e5454c92b95cad1a3f602a0697814b5ef188",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/f66fbcd159c8ceae229958b9b1bff97cf8b7e844"
        },
        "date": 1777652082043,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 103091,
            "range": "± 2336",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 253432,
            "range": "± 1209",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 551034,
            "range": "± 3934",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1967806,
            "range": "± 87499",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 460,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1693,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8266,
            "range": "± 35",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 23127,
            "range": "± 61",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 26375,
            "range": "± 473",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 91004,
            "range": "± 212",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 300,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2552,
            "range": "± 28",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 8225,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 35201,
            "range": "± 691",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 637,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2109621,
            "range": "± 69906",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6345434,
            "range": "± 82953",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23253906,
            "range": "± 360843",
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
          "id": "b16f9db72299e8295b50d5fe0fe120fdd59ecb9e",
          "message": "0.1.8 — close AV-4 timestamp drift (P0 production fix)\n\nThe lens production cutover hit verify_invalid_signature on every\nbatch from Python agents containing zero-microsecond timestamps.\nRoot cause: persist's verify::ed25519::format_iso8601 helper\nre-formatted DateTime<Utc> via chrono's %.6f%:z format string,\nwhich always emits six microsecond digits. Python's\ndatetime.isoformat() drops the fraction entirely when\nmicroseconds == 0. So an agent-signed wire timestamp of\n\"2026-04-30T00:15:53+00:00\" became \"2026-04-30T00:15:53.000000+00:00\"\non verify, canonical bytes diverged, signature rejected.\n\nTHREAT_MODEL.md AV-4 had flagged this as residual since v0.1.2.\nProduction confirmed it as P0.\n\nFix: new schema::WireDateTime wrapper holding (raw: String, parsed:\nDateTime<Utc>). Deserialize captures wire bytes; Serialize emits\nthem verbatim. wire() returns raw bytes for canonicalization;\nparsed() returns DateTime<Utc> for time arithmetic. Replaces\nDateTime<Utc> in CompleteTrace.{started_at, completed_at} and\nTraceComponent.timestamp. canonical_payload_value reads .wire()\ninstead of calling format_iso8601 (helper removed).\n\nEquality semantics: wire-byte equality, NOT instant equality.\n2026-04-30T00:15:53Z and 2026-04-30T00:15:53+00:00 are the same\ninstant but compare unequal because canonicalization treats them\ndifferently.\n\nStorage shape unchanged: store::decompose uses .parsed() to\npopulate the ts: DateTime<Utc> column on row types.\n\nRegression coverage: tests/av4_timestamp_round_trip.rs — 5\nintegration tests including the production-bug zero-microsecond\nshape. Plus 5 unit tests in schema::wire_datetime.\n\nTHREAT_MODEL.md AV-4 promoted from \"tracked residual\" to\n\"Mitigated v0.1.8\".\n\n125 tests green (103 lib + 5 AV-4 integration + 8 QA + 9 fixture);\nclippy clean across all feature combos.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-01T12:54:11-05:00",
          "tree_id": "2dc5bddf22ec2ad67d5ab1f9083130dddb28f616",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/b16f9db72299e8295b50d5fe0fe120fdd59ecb9e"
        },
        "date": 1777658397027,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 100869,
            "range": "± 173",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 249071,
            "range": "± 4371",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 543081,
            "range": "± 3309",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1936718,
            "range": "± 95449",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 469,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1783,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8463,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 23170,
            "range": "± 48",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 26424,
            "range": "± 1051",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 91111,
            "range": "± 806",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 298,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2534,
            "range": "± 43",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 8086,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 36071,
            "range": "± 92",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 635,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2033485,
            "range": "± 31545",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6205686,
            "range": "± 38684",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 22659334,
            "range": "± 85619",
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
          "id": "6e9b243cc9684315abb854388bd65707e8e1837e",
          "message": "0.1.9 — consume CIRISVerify v1.8.0 substrate primitives\n\nFive interlocking landings for BuildPrimitive::Persist consumer\nwork named in the upstream's v1.8.0 release notes.\n\n- Bump ciris-keyring v1.6.4 → v1.8.0; add ciris-verify-core v1.8.0.\n  rusqlite downgraded to 0.31 (Phase 2 stub) to share libsqlite3-sys.\n\n- Drop the v0.1.7 prediction shim. HardwareSigner::storage_descriptor()\n  is now authoritative — typed enum (Hardware / SoftwareFile /\n  SoftwareOsKeyring{User,System,Unknown} / InMemory). Engine.keyring_path()\n  authoritative; new Engine.keyring_storage_kind() returns one of seven\n  stable tokens for /health surfacing. Boot-time warn dispatches typed\n  cases including new SoftwareOsKeyring{User} and InMemory handling.\n  `dirs` dep dropped.\n\n- BuildPrimitive::Persist first-class. New src/manifest/ defines\n  PersistExtras + PersistExtrasValidator + register(). Three\n  deterministic-at-build-time fields: supported_schema_versions,\n  migration_set_sha256, dep_tree_sha256.\n\n- CI build-manifest job rewritten for ciris-build-sign. Hybrid\n  Ed25519 + ML-DSA-65 signing required — no fallback. New repo\n  secrets CIRIS_BUILD_ED25519_SECRET + CIRIS_BUILD_MLDSA_SECRET\n  (bridge team uploads per docs/BUILD_SIGNING.md).\n  src/bin/emit_persist_extras.rs produces the typed extras JSON\n  before signing.\n\n- tools/ciris_manifest.py → tools/legacy/. Deleted in v0.2.0.\n\n- 5 transitive RUSTSEC advisories accepted (all from\n  ciris-verify-core's verification stack; not on persist hot path).\n  CDLA-Permissive-2.0 added to license allow-list (webpki-roots).\n\n- docs/BUILD_SIGNING.md NEW — bridge team operator runbook.\n  INTEGRATION_LENS.md §11.5 drops predicted-vs-authoritative caveat.\n  THREAT_MODEL.md AV-27 promoted to authoritative-via-trait-method.\n\n131 tests green (109 lib including 6 new manifest + 1 new\nstorage_kind_token_dispatch — net +6 over v0.1.8); clippy clean\nacross all feature combos; cargo-deny clean.\n\nBridge team: until CIRIS_BUILD_ED25519_SECRET +\nCIRIS_BUILD_MLDSA_SECRET are uploaded, the build-manifest CI job\nwill fail loudly with a typed message pointing at\ndocs/BUILD_SIGNING.md. That's the signal the rotation work is\nneeded; other CI jobs are unaffected.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-01T13:28:02-05:00",
          "tree_id": "463a041fd0a86b8cef74c5bdb24e5bad7919b0ac",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/6e9b243cc9684315abb854388bd65707e8e1837e"
        },
        "date": 1777660690819,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 88018,
            "range": "± 409",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 225669,
            "range": "± 561",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 498503,
            "range": "± 8434",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1854239,
            "range": "± 13752",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 384,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1408,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7358,
            "range": "± 109",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 20511,
            "range": "± 86",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 23897,
            "range": "± 34",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 88318,
            "range": "± 229",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 275,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2470,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 8173,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 37624,
            "range": "± 168",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 544,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 1868892,
            "range": "± 102085",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 5649923,
            "range": "± 59285",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 20290851,
            "range": "± 104121",
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
          "id": "c217df6686b16e4bd0ca56e2662249e611b622ef",
          "message": "0.1.10 — fix abi3 wheel-tagging regression from v0.1.9\n\nP0 wheel-packaging fix. v0.1.9's maturin build produced\nciris_persist-0.1.9-cp312-cp312-manylinux_2_39_x86_64.whl instead\nof the expected cp311-abi3 form, breaking lens (which runs on\npython:3.11-slim).\n\nRoot cause: v0.1.9 added src/bin/emit_persist_extras.rs as a CI\nhelper. With the existing python-source mixed-mode layout +\nthe new [[bin]] target, maturin 1.13 auto-detection switched to\n\"binary project wheel\" mode and packaged the bin as the wheel\ncontent instead of the PyO3 cdylib library. The [lib] block\nhad no explicit crate-type so maturin couldn't disambiguate.\n\nFix: add `crate-type = [\"cdylib\", \"rlib\"]` to [lib] in Cargo.toml.\ncdylib is the Python module maturin packages; rlib keeps the\nlibrary importable from src/bin/* and integration tests.\n\nVerified locally:\n  maturin build → cp311-abi3-manylinux_2_34_x86_64.whl ✓\n  cargo run --bin emit_persist_extras → JSON output ✓\n  131 tests green; clippy clean.\n\nThe CIRISRegistry register step (issue #2) deferred to v0.1.11\nto keep this release purely the wheel-tagging fix that unblocks\nlens immediately.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-01T13:58:53-05:00",
          "tree_id": "1691a5b9c582ed1898a6cb866c2261b62fd23629",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/c217df6686b16e4bd0ca56e2662249e611b622ef"
        },
        "date": 1777662631524,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 94034,
            "range": "± 520",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 230367,
            "range": "± 705",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 503710,
            "range": "± 2219",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1787313,
            "range": "± 22489",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 442,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1635,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8166,
            "range": "± 29",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 308,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2452,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 7874,
            "range": "± 124",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 34923,
            "range": "± 141",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 621,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2123338,
            "range": "± 77718",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6085840,
            "range": "± 298515",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 21513597,
            "range": "± 293869",
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
          "id": "b67835ee67e65a775aa65db932a29062831455e1",
          "message": "0.1.11 — CI registration step + round-trip verify\n\nCloses the implementation half of CIRISPersist#2 (the issue's\nexplicit close gate, \"at least one persist build registered\nend-to-end and round-tripped,\" now lives in CI).\n\nThree new steps in .github/workflows/ci.yml::build-manifest after\nciris-build-sign:\n\n- Pre-flight steward-key check: GET ${REGISTRY_URL}/v1/steward-key\n  for ephemeral-mode visibility (logs key_id to step summary).\n  Visibility-only; doesn't gate registration.\n- Register binary manifest: POST /v1/verify/binary-manifest with\n  project=ciris-persist + wheel sha256 + version + target. Auth\n  via Bearer ${REGISTRY_ADMIN_TOKEN}.\n- Round-trip verify: GET /v1/verify/binary-manifest/<version>?project=ciris-persist,\n  diff posted vs returned binary_hash. Hash mismatch fails build.\n\nTwo new operational secrets/vars:\n- REGISTRY_URL repo variable (defaults to https://registry.ciris.ai)\n- REGISTRY_ADMIN_TOKEN repo secret (registry team issues)\n\ndocs/TODO_REGISTRY.md rewritten as historical audit trail —\nall three originally-tracked items (registry persist support,\nmanifest tool refactor, ciris-keyring-sign-cli) landed upstream.\ndocs/BUILD_SIGNING.md gains a new \"Registry registration\"\nsection documenting the four CI steps, secrets, and rotation\nguidance.\n\nBuild-manifest artifact gains three new files: steward-key.json,\nregistry-response.json, round-trip.json. 90-day retention.\n\n131 tests green; clippy clean. No Rust code changes outside\nCargo.toml version bump.\n\nCode-side persist is fully ungated. Remaining gates are\noperational (bridge uploads CIRIS_BUILD_ED25519_SECRET +\nCIRIS_BUILD_MLDSA_SECRET; registry team uploads\nREGISTRY_ADMIN_TOKEN). When all three are set, CI flips green\nend-to-end and #2 closes on the round-trip evidence.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-01T14:12:39-05:00",
          "tree_id": "963f7d51370abd330911b2bc12d317f34b2be1cd",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/b67835ee67e65a775aa65db932a29062831455e1"
        },
        "date": 1777663129343,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 88501,
            "range": "± 282",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 225748,
            "range": "± 666",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 498565,
            "range": "± 3451",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1874237,
            "range": "± 21975",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 378,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1408,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7524,
            "range": "± 60",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 269,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2564,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 8105,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 37507,
            "range": "± 467",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 569,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 1869322,
            "range": "± 125819",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 5590869,
            "range": "± 48292",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 20525365,
            "range": "± 275303",
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
          "id": "c52d4e2addb5d6643492e5528d788458673857e5",
          "message": "ci: trigger fresh run with secrets present",
          "timestamp": "2026-05-01T14:33:33-05:00",
          "tree_id": "963f7d51370abd330911b2bc12d317f34b2be1cd",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/c52d4e2addb5d6643492e5528d788458673857e5"
        },
        "date": 1777664381707,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 100520,
            "range": "± 2785",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 246842,
            "range": "± 2016",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 538460,
            "range": "± 25228",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1917522,
            "range": "± 16343",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 429,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1557,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8199,
            "range": "± 51",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 310,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2467,
            "range": "± 130",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 8232,
            "range": "± 23",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 36134,
            "range": "± 109",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 637,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2033458,
            "range": "± 24216",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6212822,
            "range": "± 51693",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 22682016,
            "range": "± 74618",
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
          "id": "2e3e29c858321a8df7ee1a46ea8af6ac7dd3c09e",
          "message": "ci: temporary diagnostic — print secret presence + lengths",
          "timestamp": "2026-05-01T14:47:08-05:00",
          "tree_id": "821e74e309b7d56351c56eb8f994075adc54e6d5",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/2e3e29c858321a8df7ee1a46ea8af6ac7dd3c09e"
        },
        "date": 1777665198838,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 93801,
            "range": "± 295",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 229919,
            "range": "± 1886",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 502269,
            "range": "± 4234",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1780339,
            "range": "± 18864",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 437,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1733,
            "range": "± 41",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8166,
            "range": "± 60",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 311,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2511,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 7763,
            "range": "± 30",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 34948,
            "range": "± 81",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2086760,
            "range": "± 99087",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 5997205,
            "range": "± 123556",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 21265755,
            "range": "± 964374",
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
          "id": "682290b16f95fb14deed51973101ebdda7c0a5cf",
          "message": "docs(registry): correct REGISTRY_URL to api.registry.ciris-services-1.ai\n\nThe earlier placeholder https://registry.ciris.ai was a guess.\nBridge team confirmed live registry is at\nhttps://api.registry.ciris-services-1.ai (steward identity verified\nvia /v1/steward-key: classical+pqc key_ids match, persistent\nacross restarts).\n\nUpdated:\n- .github/workflows/ci.yml — 3 default-URL fallbacks\n- docs/BUILD_SIGNING.md — registry-registration section default\n- docs/TODO_REGISTRY.md — historical references\n\nCI reads ${{ vars.REGISTRY_URL }} which the bridge already\ncorrected on all 5 GHA repos. Doc text was the only drift.\n\nAlso removes the v0.1.12 secret-presence diagnostic step. The\ndiagnostic identified that uploaded CIRIS_BUILD_*_SECRET values\nare 1 byte each (likely empty-pipe upload accident). Bridge to\nre-upload via:\n\n  gh secret set CIRIS_BUILD_ED25519_SECRET --repo CIRISAI/CIRISPersist \\\n    --body \"$(base64 -w0 ed25519.seed)\"\n  gh secret set CIRIS_BUILD_MLDSA_SECRET   --repo CIRISAI/CIRISPersist \\\n    --body \"$(base64 -w0 mldsa65.secret)\"\n\nOnce secrets contain real base64-encoded keys, the next push\nflips build-manifest from red → green, registers + round-trips,\nand closes CIRISPersist#2 on round-trip evidence.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-01T14:54:32-05:00",
          "tree_id": "1274fcb255fee7b88358368a5b05bd6c923b81ce",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/682290b16f95fb14deed51973101ebdda7c0a5cf"
        },
        "date": 1777665619949,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 93481,
            "range": "± 352",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 229506,
            "range": "± 683",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 501309,
            "range": "± 1994",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1783089,
            "range": "± 24415",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 441,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1750,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8158,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 312,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2497,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 7807,
            "range": "± 148",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 34861,
            "range": "± 72",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2041334,
            "range": "± 114093",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 5994182,
            "range": "± 158869",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 21175161,
            "range": "± 207959",
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
          "id": "7fbd6cf901d69f84685729fbcdbe2467bc1bd81a",
          "message": "docs(BUILD_SIGNING): correct mldsa65.secret size — 32-byte seed, not ~4032\n\nciris-build-sign generate-keys produces a 32-byte seed for both\nkeys; the full ML-DSA-65 secret key is derived at sign time\n(`MlDsa65Signer::from_seed`). My v0.1.9 doc claim of ~4032 bytes\nwas wrong. Bridge confirmed via re-upload — base64(32) = 44 chars.\n\nAlso fixes filename casing: ed25519.pub / mldsa65.pub (matching\nwhat generate-keys actually writes per ciris-build-tool sign.rs).",
          "timestamp": "2026-05-01T15:02:16-05:00",
          "tree_id": "f5740b2d4d35e908026faaef68fb9ae9c737da6a",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/7fbd6cf901d69f84685729fbcdbe2467bc1bd81a"
        },
        "date": 1777666206516,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 93363,
            "range": "± 283",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 229683,
            "range": "± 715",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 501656,
            "range": "± 2967",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1783306,
            "range": "± 10207",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 437,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1654,
            "range": "± 126",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8157,
            "range": "± 44",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 322,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2519,
            "range": "± 42",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 7801,
            "range": "± 56",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 35227,
            "range": "± 966",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 632,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2179959,
            "range": "± 211756",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6283553,
            "range": "± 475151",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 21626998,
            "range": "± 607120",
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
          "id": "f7cbbc0b62295f4aafa8a594d611aee5ba156e4c",
          "message": "ci: trigger fresh run — registry healthy, secrets correct",
          "timestamp": "2026-05-01T15:28:24-05:00",
          "tree_id": "f5740b2d4d35e908026faaef68fb9ae9c737da6a",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/f7cbbc0b62295f4aafa8a594d611aee5ba156e4c"
        },
        "date": 1777667649917,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 93885,
            "range": "± 975",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 230468,
            "range": "± 887",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 502421,
            "range": "± 12377",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1788457,
            "range": "± 51928",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 479,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1771,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8524,
            "range": "± 78",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 310,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2444,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 7708,
            "range": "± 23",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 34702,
            "range": "± 85",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2119493,
            "range": "± 179419",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6003292,
            "range": "± 94780",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 21174056,
            "range": "± 178803",
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
          "id": "2e7aff99adb9795abbc5ba789426899ceefae662",
          "message": "0.1.12 — PyPI publication via OIDC trusted publishing\n\nCloses the lens cold-build bottleneck. Currently lens rebuilds\npersist from source on every cold cache (~75min Rust compile,\ndominated by ciris-keyring + ciris-verify-core + tokio-postgres\n+ ed25519 graph). After this lands and v0.1.12 publishes, lens\ncollapses to `pip install ciris-persist==0.1.12` (~10s).\n\nNew job .github/workflows/ci.yml::publish-pypi:\n- Tag-gated (refs/tags/v*).\n- Sanity-checks wheel shape (rejects non-cp311-abi3, preventing\n  v0.1.10-class regressions silently shipping).\n- pypa/gh-action-pypi-publish@release/v1 with attestations: true\n  (PEP 740 sigstore attestations by default).\n- OIDC trusted publishing — no API token in CI secrets.\n- Environment-gated (\"pypi\" environment) for optional human-\n  approval gates per release.\n\nThree provenance layers now stack on every release:\n- git tag + commit hash (source identity)\n- BuildManifest hybrid Ed25519 + ML-DSA-65 signature (registry-side)\n- PEP 740 sigstore attestation (PyPI-side, ties artifact to GHA)\n\nThe BuildManifest is the cryptographic root. PyPI is fast delivery.\n\nNOT TAGGED YET: this commit ships the workflow change to main; the\nv0.1.12 git tag intentionally not pushed. Pushing the tag triggers\nthe publish job, which fails until PyPI's trusted publisher is\nconfigured. Operator runbook in docs/PYPI_PUBLISH.md.\n\n131 tests green; clippy clean; no Rust code changes.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-01T16:39:36-05:00",
          "tree_id": "4ebfa488547c05e63072b42b67a30ffa6cfa3c67",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/2e7aff99adb9795abbc5ba789426899ceefae662"
        },
        "date": 1777672051684,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 100801,
            "range": "± 2726",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 247310,
            "range": "± 647",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 537675,
            "range": "± 5950",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1916151,
            "range": "± 8338",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 425,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1579,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8189,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 333,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2627,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 8337,
            "range": "± 38",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 36245,
            "range": "± 117",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 650,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2035289,
            "range": "± 22706",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6209294,
            "range": "± 35516",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 22728448,
            "range": "± 71233",
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
          "id": "34b48f44b7d994bef37a17dff82599e62f72e886",
          "message": "ci: trigger on v* tag pushes (so publish-pypi actually fires)\n\nThe workflow's `push:` trigger had `branches: [main]` only — tag\npushes weren't firing CI at all, so the publish-pypi job (gated\non refs/tags/v*) never ran when v0.1.12 was tagged.\n\nAdding `tags: ['v*']` makes tag pushes trigger the same CI run\nthat branch pushes do; the publish-pypi job's existing `if`\ngate then naturally fires only on tag refs.\n\nRe-tagging v0.1.12 fresh after this lands.",
          "timestamp": "2026-05-01T16:44:20-05:00",
          "tree_id": "e51a693b3e715022818f47ff5c22f2afc1942b40",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/34b48f44b7d994bef37a17dff82599e62f72e886"
        },
        "date": 1777672274038,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 78018,
            "range": "± 869",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 191063,
            "range": "± 4209",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 416299,
            "range": "± 1529",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1482746,
            "range": "± 12050",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 328,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1246,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 6235,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 257,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2004,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 6333,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 28186,
            "range": "± 361",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 512,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2131320,
            "range": "± 7127010",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 5271781,
            "range": "± 18124121",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 18630265,
            "range": "± 89578424",
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
          "id": "8cfc257c6fa0eaf4f352760ca05c8054abab3426",
          "message": "0.1.13 — multi-arch PyPI wheels (linux x86_64+aarch64, darwin arm64+x86_64)\n\nCloses CIRISPersist#3. Lens needs persist on linux/arm64 for its\nmulti-arch Docker image; v0.1.12's linux-x86_64-only wheel forced\nfallback to source build (~75min) on arm64. v0.1.13 publishes the\nagent's full Phase 1 PyO3 matrix per FSD/PLATFORM_ARCHITECTURE.md\n§3.5: linux x86_64 + aarch64, darwin arm64 + x86_64.\n\nCI changes:\n- pyo3-wheel: matrix expansion across 4 native runners (no\n  cross-compile). ubuntu-24.04-arm has been GA + free for public\n  repos since 2025-01.\n- Per-matrix wheel-shape check rejects non-cp311-abi3 at build\n  time (catches v0.1.10-class regressions before publish).\n- build-manifest: POSTs binary-manifest with all four target\n  hashes in `binaries: { target: sha256 }` shape; round-trip\n  verify confirms each target matches GET response.\n- publish-pypi: downloads all four artifacts, sanity-checks\n  count + tag shape, uploads in one action call (single PEP 740\n  attestation covers the full set).\n\niOS / Android out of scope here — they ship via xcframework /\nUniFFI native packaging, not PyPI. Per-target BuildManifest\nsigning for non-x86_64 deferred to v0.1.14+ once a concrete\nconsumer asks; v0.1.13's binary-manifest carries all four hashes\nvia the registry's existing multi-target shape.\n\n131 tests green; no Rust code changes; CI workflow + version\nbump only.\n\nTag v0.1.13 will be pushed once this commit's matrix CI lands\ngreen on all four arches — staged so a build failure on one\narch doesn't leave us with a half-published release.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-01T17:01:50-05:00",
          "tree_id": "da31d20019b69eddebada8667ce254d757fa04a2",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/8cfc257c6fa0eaf4f352760ca05c8054abab3426"
        },
        "date": 1777673268975,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 98617,
            "range": "± 222",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 236175,
            "range": "± 500",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 509473,
            "range": "± 10421",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1800862,
            "range": "± 9081",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 441,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1719,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8132,
            "range": "± 81",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 308,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2532,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 7844,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 35022,
            "range": "± 91",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 622,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2054359,
            "range": "± 33893",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 5957789,
            "range": "± 135618",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 21155845,
            "range": "± 331619",
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
          "id": "d20b4c209f0fed4e90fc211499592cb58b89ad99",
          "message": "docs(pypi): document v0.1.13 multi-arch wheel matrix",
          "timestamp": "2026-05-01T17:22:53-05:00",
          "tree_id": "c8a5c6067e96c8b7d1d9ecfb04179a069b23ba6a",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/d20b4c209f0fed4e90fc211499592cb58b89ad99"
        },
        "date": 1777674543226,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 91110,
            "range": "± 239",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 228433,
            "range": "± 664",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 502792,
            "range": "± 3510",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1904016,
            "range": "± 34583",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 384,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1394,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7211,
            "range": "± 35",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 271,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2489,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 7971,
            "range": "± 36",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 37540,
            "range": "± 1530",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 561,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2340009,
            "range": "± 179365",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6270578,
            "range": "± 161942",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 21125118,
            "range": "± 210482",
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
          "id": "eb72e9a8529a3cc3c60589dfb4ff6c09f3a700d9",
          "message": "ci: drop darwin-x86_64 from wheel matrix (GH runner capacity issue)\n\nGitHub Actions Intel macOS runners (macos-13) have ongoing\ncapacity issues — jobs queue indefinitely waiting for a runner.\nCIRISAgent's matrix dropped it for the same reason; their build.yml\nexplicitly notes \"macOS Intel: built and uploaded manually\n(GitHub runner capacity issues)\".\n\nPLATFORM_ARCHITECTURE.md §3.5 already classifies darwin-x86_64\nas \"sunset target — keep CI green only\", so this is consistent\nwith that designation. Lens's multi-arch Docker (linux/amd64 +\nlinux/arm64) doesn't need it; macOS dev still gets covered by\ndarwin-aarch64 on macos-14.\n\nUpdated:\n- pyo3-wheel matrix: 4 entries → 3\n- build-manifest TARGET_FOR map: drop x86_64-apple-darwin\n- publish-pypi sanity check: 4 wheels → 3 wheels\n- CHANGELOG, docs/PYPI_PUBLISH.md, registry-payload notes string\n\nCancelled stuck run 25235069644 (darwin-x86_64 job had been\nqueued 22m+ waiting for macos-13 runner availability).\n\nIf a real darwin-x86_64 consumer appears, manual `maturin build\n--release --strip` + `maturin upload` or\n`twine upload` from a local Intel Mac (or self-hosted runner)\nships the wheel out-of-band; the BuildManifest path gets a\nfollow-up registration with the new target hash.",
          "timestamp": "2026-05-01T17:26:51-05:00",
          "tree_id": "0c7640b15ae55a249a4cc44cdccb3ca7ca1942ae",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/eb72e9a8529a3cc3c60589dfb4ff6c09f3a700d9"
        },
        "date": 1777674772282,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 94496,
            "range": "± 2208",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 233193,
            "range": "± 615",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 510860,
            "range": "± 14094",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1815244,
            "range": "± 10680",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 440,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1717,
            "range": "± 42",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7781,
            "range": "± 156",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 313,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2424,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 7956,
            "range": "± 30",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 35406,
            "range": "± 75",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 621,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 1995898,
            "range": "± 23340",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 5907211,
            "range": "± 42976",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 21126485,
            "range": "± 121754",
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
          "id": "4f32d8893159baba8704325604a6bcf5fdebdb82",
          "message": "0.1.14 — cohabitation doctrine + flock-based bootstrap singleton\n\nPersist is now the runtime keyring authority above CIRISVerify on\nevery host where it runs. Three rules formalize what was\nstructurally true:\n\n1. Persist owns runtime keyring bootstrap. Other CIRIS primitives\n   on the same host cede via deployment ordering.\n2. One keyring bootstrap per host/container. Multi-worker\n   deployments (uvicorn --workers N) serialize cold-start through\n   a filesystem flock; first worker bootstraps, others see the\n   existing key.\n3. Same-alias = same identity per PoB §3.2.\n\nCloses CIRISVerify AV-14 for persist consumers (cross-instance\nkeyring contention). Verify's planned v1.9 keyring-side flock\nwill close it for non-persist consumers; the two locks compose\ncleanly because both target the same identity.\n\nImplementation:\n- fs4 0.13 added as direct dep (cross-platform safe POSIX flock)\n- bootstrap_lock_path() resolves ${CIRIS_DATA_DIR}/.persist-bootstrap.lock\n  with /tmp/ciris-persist-bootstrap.lock fallback\n- acquire_bootstrap_lock() opens-and-flocks; auto-releases on FD\n  close incl. panic\n- Engine::__init__ wraps get_platform_signer() with the lock; held\n  only for the duration of bootstrap (~50ms warm, ~500ms cold-start),\n  not for Engine lifetime\n- Two unit tests cover path resolution + acquire/release smoke\n\nDocumentation:\n- NEW: docs/COHABITATION.md — operator runbook with\n  docker-compose, systemd, k8s init-container examples;\n  cross-links to CIRISVerify HOW_IT_WORKS.md cohabitation contract\n  + AV-14\n- INTEGRATION_LENS.md §11 — new \"Cohabitation: persist comes up\n  first\" subsection covering multi-worker semantics + combined-\n  deployment ordering\n\nNOT in v0.1.14:\n- Strict process singleton (multi-worker is real and supported)\n- Public Engine.sign(payload) API (architecturally next, deferred\n  until concrete consumer asks)\n- Replacement for verify v1.9's planned keyring-side flock (the\n  two locks compose; not redundant)\n\n133 tests green (131 prior + 2 new flock tests); clippy clean;\ncargo-deny clean. Tag will be pushed once main CI lands green.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-01T18:02:51-05:00",
          "tree_id": "4809f06a23446221945d968a5a402863416e37c4",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/4f32d8893159baba8704325604a6bcf5fdebdb82"
        },
        "date": 1777676946891,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 78145,
            "range": "± 233",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 191753,
            "range": "± 624",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 417426,
            "range": "± 1699",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1486573,
            "range": "± 10341",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 327,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1240,
            "range": "± 46",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 6319,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 265,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2195,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 6882,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 29655,
            "range": "± 361",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 504,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 1899907,
            "range": "± 362669",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 5158532,
            "range": "± 388660",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 17960948,
            "range": "± 1053236",
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
          "id": "c57eea4c3b9eb58b4445c8c1291997a08c454277",
          "message": "0.1.15 — base64 URL-safe decode (P0 production fix) + cohabitation reframe\n\nP0 production fix: persist's verify_trace decoded incoming\nsignatures with base64::STANDARD (+, /, = alphabet). The agent\nemits via Python's base64.urlsafe_b64encode per\nTRACE_WIRE_FORMAT.md §8 — URL-safe (-, _, no padding). Every\nproduction batch failed verify_invalid_signature because the\ndecoder either errored on _ / - chars or produced wrong-length\nbytes that Signature::from_bytes rejected.\n\nThis is the universal verify failure mode — independent of\ncanonicalization, payload, trace level, timestamps. AV-4\ntimestamp drift (closed v0.1.8) was real but secondary; the\nbase64 alphabet was the load-bearing bug.\n\nAll 4 wire fixtures in tests/fixtures/wire/2.7.0/*.json use\nURL-safe-no-pad signatures. Pre-v0.1.15 these were unverifiable\nthrough persist; the fixture tests passed because they stop at\ndecompose without attempting verify.\n\nFix: new decode_signature(s) helper tries STANDARD first, falls\nback through URL_SAFE_NO_PAD then URL_SAFE. Same defensive shape\naccord_api.py:1903 uses on the legacy Python verify path. No\nagent-side coordination needed.\n\nTwo new unit tests:\n- decode_signature_accepts_all_alphabets — round-trips through\n  4 base64 variants\n- url_safe_signed_trace_verifies — end-to-end against URL-safe-\n  no-pad signed trace (production form)\n\nAlso: docs/COHABITATION.md rewritten. Drops daemon framing.\nPersist is a Python wheel, not a daemon. Doctrine is about\nlibrary code paths — Engine::__init__ is the canonical bootstrap\nentry point on a host because persist is the lowest stateful\nlibrary above verify, not because it runs as a separate process.\n\nPractical changes:\n- Drop persist.service / Requires=After= systemd examples\n- Drop k8s init-container example (implied separate process)\n- Multi-worker examples instead — each worker imports persist,\n  all race through flock, all converge on same identity\n- Reframe rule 1 from \"persist owns runtime keyring bootstrap\"\n  to \"first Engine::__init__ on the host bootstraps the keyring\"\n\nImplementation (v0.1.14 flock) unchanged. Only operator-facing\nframing.\n\n113 lib + 5 AV-4 + 8 QA + 9 fixture tests green; clippy clean;\ncargo-deny clean.\n\nLens cutover unblocked. v0.1.14 wheels carry the base64 bug;\nlens should bump pin to ==0.1.15 immediately.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-01T18:34:44-05:00",
          "tree_id": "60b3f4a2a3106fd17488ca455a736a3897aede8f",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/c57eea4c3b9eb58b4445c8c1291997a08c454277"
        },
        "date": 1777678843151,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 101092,
            "range": "± 2064",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 248487,
            "range": "± 1972",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 542205,
            "range": "± 4308",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1929483,
            "range": "± 29989",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 429,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1629,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8151,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 300,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2475,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 8117,
            "range": "± 202",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 35749,
            "range": "± 207",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 631,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2061407,
            "range": "± 79119",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6220944,
            "range": "± 52101",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 22727094,
            "range": "± 8796471",
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
          "id": "e857762726dd6e81c742811b88a33ef0586ff9df",
          "message": "fix(test): serialize env-mutating bootstrap-lock tests\n\nCI's parallel test runner flagged the v0.1.14 bootstrap-lock\ntests racing on CIRIS_DATA_DIR. bootstrap_lock_path_resolution\nsets CIRIS_DATA_DIR=/var/lib/cirislens; if that test panics or\nraces, the value leaks into bootstrap_lock_acquire_and_release\nwhich then opens /var/lib/cirislens/keyring/.persist-bootstrap.lock\nand gets PermissionDenied (runner can't write that path).\n\nFix: serial_test::serial(env_ciris_data_dir) on both tests +\nRAII EnvGuard for panic-safe cleanup.\n\nLocal repro was clean because tests ran fast enough that the race\nwindow stayed closed; CI's slower runner exposed it.",
          "timestamp": "2026-05-01T18:41:27-05:00",
          "tree_id": "8824b3754755b590d7785cab22559cf886d78c15",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/e857762726dd6e81c742811b88a33ef0586ff9df"
        },
        "date": 1777679234678,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 101069,
            "range": "± 1107",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 248376,
            "range": "± 941",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 542092,
            "range": "± 1892",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1932088,
            "range": "± 19003",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 424,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1611,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8271,
            "range": "± 215",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 329,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2530,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 8081,
            "range": "± 63",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 35470,
            "range": "± 68",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 643,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2017747,
            "range": "± 47640",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6221519,
            "range": "± 32575",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 22729052,
            "range": "± 80936",
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
          "id": "3bb874b65ffadbd0d8953fdb74dcc475c9d5161c",
          "message": "ci: drop linux-aarch64 cross-compile job (subsumed by native arm64 build)\n\nThe cross-compile job's purpose was 'prove cross-compile works'\nwhich is fully covered by the native arm64 wheel build on\nubuntu-24.04-arm (added v0.1.13). The job had become pure churn —\nrequired a fragile apt install of gcc-aarch64-linux-gnu (Azure\nmirror flakiness, just hit it again on v0.1.15) without producing\na consumable artifact.\n\nNative arm64 build catches everything cross-compile would have:\nbuild failures, link errors, missing target features. Plus it\nproduces the actual wheel that PyPI consumers install.\n\nNet effect: half the remaining apt surface in CI gone, ~5min CI\ntime saved per run, no functional coverage loss.",
          "timestamp": "2026-05-01T19:23:04-05:00",
          "tree_id": "f048b461b9aa3f602794fae753885e0f5b5b6c5c",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/3bb874b65ffadbd0d8953fdb74dcc475c9d5161c"
        },
        "date": 1777682251709,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 93748,
            "range": "± 1881",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 230545,
            "range": "± 793",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 502751,
            "range": "± 1502",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1783716,
            "range": "± 10445",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 445,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1649,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8175,
            "range": "± 40",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 317,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2540,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 7891,
            "range": "± 86",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 34808,
            "range": "± 116",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 621,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2101305,
            "range": "± 101692",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6010279,
            "range": "± 210527",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 21406248,
            "range": "± 278775",
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
          "id": "79f8b70b3bffe90f0c4aa24a28005947289c88f9",
          "message": "0.1.16 — try-both 2-field/9-field canonical fallback (P0 production fix #2)\n\nCloses CIRISPersist#5. Same defensive shape as v0.1.15's base64\nalphabet fallback, applied at the canonical-bytes layer.\n\nDiagnostic round on YO-locale traffic from the bridge:\nv0.1.15 fixed the base64 decode (64 bytes ✓), pubkey lookup\nsucceeds, but verify_strict returns false because:\n\n  agent + lens-legacy sign over: {components, trace_level}    (2 fields)\n  persist v0.1.15 canonicalizes: TRACE_WIRE_FORMAT.md §8       (9 fields)\n\nDifferent bytes → different sha256 → verify fails on every batch.\nReal captured trace bytes diff: 15,827 vs 16,149 bytes.\n\nFix: verify_trace tries the 9-field spec canonical first\n(eventual target with full provenance binding), falls back to\nthe 2-field legacy canonical (what the agent fleet ships today\nper Ed25519TraceSigner.sign_trace + accord_api.py\n::verify_trace_signature). SignatureMismatch only if both fail.\n\nThe 2-field path applies strip_empty recursion matching the\nagent's Python implementation — drops null/\"\"/[]/{} at every\nnesting level — to reconstruct the agent's pre-signature shape\nfrom persist's deserialized data.\n\nTests:\n- legacy_two_field_signed_trace_verifies — production shape\n  verifies via fallback (pre-v0.1.16 rejected)\n- legacy_two_field_tampered_rejected — fallback doesn't widen\n  security surface (tampered traces still SignatureMismatch)\n- strip_empty_drops_empties_recursively — exhaustive coverage\n\n136 tests green (113 lib + 5 AV-4 + 8 QA + 9 fixture);\nclippy clean.\n\nMigration path: agent migrates to 9-field on its next minor;\npersist's try-both keeps verifying both shapes through the\nwindow. CIRISAgent sibling issue tracks the migration.\n\nLens action: pip install --upgrade ciris-persist==0.1.16. v0.1.15\nhad the base64 fix but rejected every YO-locale batch on the\ncanonical-shape mismatch. v0.1.16 closes the round-trip.\n\nTHREAT_MODEL.md AV-4 promoted from tracked residual to fully\nclosed: base64 (v0.1.15) + timestamp (v0.1.8) + canonical-shape\nfallback (v0.1.16) together cover the entire pre-v0.1.x verify-\nmismatch surface area.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-01T20:39:05-05:00",
          "tree_id": "cb283706781ec0c6171685a801fa6d0ce141995f",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/79f8b70b3bffe90f0c4aa24a28005947289c88f9"
        },
        "date": 1777686333085,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 94682,
            "range": "± 2390",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 231652,
            "range": "± 2402",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 504969,
            "range": "± 4076",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1792962,
            "range": "± 28949",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 437,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1650,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8198,
            "range": "± 91",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 318,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2622,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 8097,
            "range": "± 23",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 36168,
            "range": "± 286",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2097779,
            "range": "± 96120",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6030008,
            "range": "± 157612",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 21209841,
            "range": "± 236356",
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
          "id": "8fcfd02c576e6f9a96284842202c968991547e2b",
          "message": "0.1.17 — verify-unknown-key diagnostic breadcrumb (CIRISPersist#6)\n\nBridge's flag-on capture against v0.1.16 surfaced a new universal\nreject: verify_unknown_key on every batch despite the rows being\npresent in cirislens.accord_public_keys, passing the WHERE filter,\nvisible to a same-DSN-same-process Python query, and pubkey\nlookup working in local synthetic repros.\n\nSource review confirms persist's lookup_public_key is a direct\nSQL query (no internal cache; no input transform). So the answer\nlives between persist's pool/connection state and the SQL.\n\nv0.1.17 adds lookup-time observability so the next flag-on\ncapture pinpoints which:\n\n- Backend::sample_public_keys(limit) trait method — returns\n  total count + first N key_ids using the same WHERE clause as\n  lookup_public_key. PostgresBackend impl; default empty.\n- IngestPipeline::verify_complete_trace warn-log on lookup miss\n  surfacing envelope_signer_id / hex bytes / id byte length /\n  accord_public_keys total / accord_public_keys sample.\n\nThree diagnostic outcomes the bridge will see:\n- size differs from external SELECT → different scope\n- size matches AND sample includes target → lookup path bug\n- sample shape differs from envelope_signer_id → id transform\n\nBest-effort: if sample query errors, warn still fires with None\nfor diagnostic fields. Zero hot-path cost on happy-path verifies.\n\n136 tests green; clippy clean. No regression — purely additive\nobservability.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-01T22:00:08-05:00",
          "tree_id": "418c73e08e120a2e13321c40155f5e052eb9b3ac",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/8fcfd02c576e6f9a96284842202c968991547e2b"
        },
        "date": 1777691253635,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 99809,
            "range": "± 1809",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 235798,
            "range": "± 639",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 508200,
            "range": "± 2896",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1793342,
            "range": "± 23695",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 439,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1635,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8134,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 312,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2487,
            "range": "± 49",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 7847,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 34647,
            "range": "± 355",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 627,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2057477,
            "range": "± 65430",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 5940285,
            "range": "± 198990",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 21223012,
            "range": "± 348056",
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
          "id": "5907e4cbf58fb96dd3a11613e65a9e56aa0997b2",
          "message": "0.1.18 — SignatureMismatch breadcrumb + Engine.debug_canonicalize\n\nCIRISPersist#6 follow-up. Mirrors v0.1.17's unknown-key\nbreadcrumb onto the canonicalization-failure branch so the\nbridge can pinpoint canonical-byte drift offline.\n\nThe SignatureMismatch warn surfaces:\n- envelope_signer_id\n- wire_body_sha256              ← joins lens-side body_sha256_prefix\n- canonical_9field_sha256       ← persist's spec-shape canonical\n- canonical_2field_sha256       ← persist's legacy-shape canonical\n- canonical_*_bytes_len\n- signature_b64_prefix\n\nBridge takes any captured prefix → finds the matching body in\nthe agent tee directory → runs offline json.dumps reference →\ndiffs against persist's two hashes. Three branches:\n- Reference matches 9field → 2field branch needs investigation\n- Reference matches 2field → 9field has subtle drift\n- Reference matches neither → agent signs unknown shape\n\nNew PyO3 method Engine.debug_canonicalize(bytes) returns both\ncanonical shapes (sha256 + b64 full bytes + length) for each\nCompleteTrace in the body. Lets bridge pipe any wire body\nthrough persist's canonicalizer without needing logs.\n\nHelpers: canonical_payload_sha256s() returns a CanonicalDiagnostic\ncarrier (used by both breadcrumb and debug_canonicalize).\ncanonical_payload_value_legacy made pub(crate) for re-use.\n\nv0.1.18 also adds wire_body_sha256 to the v0.1.17 unknown-key\nbreadcrumb so all three lens/persist log paths share one\ncorrelation field.\n\n138 tests green; clippy clean. Zero hot-path cost — both\nbreadcrumbs fire only on slow-path errors.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-01T23:06:22-05:00",
          "tree_id": "3f6ff3cb381e87fc997d4a905f667016b5810e54",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/5907e4cbf58fb96dd3a11613e65a9e56aa0997b2"
        },
        "date": 1777695163824,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 78834,
            "range": "± 278",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 193372,
            "range": "± 2305",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 420978,
            "range": "± 1637",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1500162,
            "range": "± 6340",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 352,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1351,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 6266,
            "range": "± 103",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 243,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 1947,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 6395,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 27992,
            "range": "± 61",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 516,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 1965433,
            "range": "± 155679",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 5442225,
            "range": "± 392009",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 19059878,
            "range": "± 1328002",
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
          "id": "755c240f7499d60922165e9d9383e25788754c2f",
          "message": "0.1.19 — Python-compat float formatter (P0 production fix #3)\n\nCloses CIRISPersist#7. Bridge's v0.1.18 capture pinned canonical-\nbytes drift to float formatting: Rust's ryu (via serde_json) and\nPython's float.__repr__ (Gay's dtoa) disagree on shortest-round-\ntrip output for ambiguous doubles. Universal verify_signature_\nmismatch root cause across all YO-locale traffic.\n\nConcrete divergence:\n- ryu:    0.003199200000000001    Python: 0.0031992000000000006\n- ryu:    1433.2029819488523       Python: 1433.2029819488525\n\nBoth valid; both shortest-round-trip; tie-break differs.\n\nFix: route Value::Number through write_python_float in\nsrc/verify/canonical.rs:\n- lexical-core PYTHON_LITERAL format\n- negative_exponent_break(-4) + positive_exponent_break(15)\n  match Python's [1e-4, 1e16) decimal range\n- Post-process scientific output:\n  - Strip .0 from 1.0eN → 1eN\n  - Add + sign for non-negative exponents → 1e+16\n  - Pad single-digit exponent magnitude → 1e-05, 1.5e-06\n- Integer fast-path preserved (i64/u64 → bare digits, no .0)\n\n4 new unit tests:\n- bridge_captured_divergent_floats_match_python (exact YO floats)\n- production_range_floats_match_python_repr (22 cases)\n- integers_render_bare_no_decimal_point\n- llm_call_data_blob_matches_python (end-to-end dict shape)\n\nThree independent layers now cover verify-mismatch on real agent\ntraffic:\n- v0.1.8  timestamp drift           WireDateTime\n- v0.1.15 base64 alphabet           decode_signature\n- v0.1.16 canonical-shape           try-both 9/2-field\n- v0.1.19 float formatting          write_python_float ← THIS\n\nThe v0.1.16 try-both fallback now works as designed: both 9-field\nand 2-field byte-match the agent because float bytes finally\nmatch.\n\nKnown limit: rare shortest-round-trip ties beyond threshold +\npost-process can still diverge. 22 production-range tests pass;\nif bridge surfaces a new edge case, v0.1.x ships a vendored\nGay's-dtoa port. Tracked v0.2.x.\n\nNew dep: lexical-core 1.0.6 (format + write-floats features).\n142 tests green; clippy clean; cargo-deny clean.\n\nLens action: pip install --upgrade ciris-persist==0.1.19. Bridge\nflag-on capture should finally show signatures_verified ==\nenvelopes_processed.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-01T23:30:48-05:00",
          "tree_id": "825ce482ad8fccb49c1736bce453fdcca4b5c066",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/755c240f7499d60922165e9d9383e25788754c2f"
        },
        "date": 1777696607367,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 94745,
            "range": "± 2018",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 234328,
            "range": "± 6312",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 506035,
            "range": "± 7722",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1799176,
            "range": "± 42741",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 453,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1661,
            "range": "± 49",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8903,
            "range": "± 47",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 312,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2536,
            "range": "± 34",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 7702,
            "range": "± 40",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 35043,
            "range": "± 312",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 621,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2110446,
            "range": "± 58340",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6177223,
            "range": "± 99385",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 22064946,
            "range": "± 247822",
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
          "id": "208a1c0c953a119ffcee1ddf92077c1443f41a56",
          "message": "0.1.20 — preserve agent's wire tokens (P0 #3, second attempt)\n\nv0.1.19's lexical-core approach didn't close CIRISPersist#7. Bridge\nre-ran debug_canonicalize: same divergence on the same fixture.\nThe plan was wrong: lexical-core (and ryu, and every \"shortest\nround-trip\" library that's not CPython) picks a different tie-break\nthan CPython's Py_dg_dtoa. More fundamentally: by the time we have\na Rust f64, the original token is gone — 0.003199200000000001 and\n0.0031992000000000006 parse to identical bits.\n\nv0.1.20: don't reproduce, preserve. Enable serde_json's\n`arbitrary_precision` feature. Number is internally a String — the\nparsed wire token. Display emits it verbatim. We never re-format\nduring the verify path; we always parse and walk the parsed Value.\n\nEmpirically verified:\n  in : {\"x\":0.0031992000000000006}\n  out: {\"x\":0.0031992000000000006}\n  in : {\"x\":1e-05}     out: {\"x\":1e-05}\n  in : {\"x\":1e+16}     out: {\"x\":1e+16}\n  in : {\"x\":1.7976931348623157e+308}\n  out: {\"x\":1.7976931348623157e+308}\n\nAll Python format variants (scientific threshold, exponent padding,\nsigned-positive exponent, large/small extremes) round-trip\nbyte-identical because we don't re-format.\n\nCode changes:\n- write_number: 30 LoC → 1 LoC (just `write!(buf, \"{n}\")`)\n- write_python_float: deleted (~80 LoC)\n- v0.1.19 tests using json!(divergent_double) removed (premise was\n  false — can't recover Python's bytes from a Rust f64)\n- 4 new wire-byte preservation tests using from_str on the bridge's\n  YO captures + 14 Python format variants\n\nDeps:\n- serde_json gets `arbitrary_precision` feature\n- lexical-core (added v0.1.19) removed\n\nTrade-off: arbitrary_precision unifies across the dep tree. Stable\nserde_json API behavior unchanged (Number::as_f64, etc. still work).\nOnly private-variant pattern-matchers would break, which no stable\ncode does.\n\n143 tests green; clippy clean; cargo-deny clean.\n\nLens action: pip install --upgrade ciris-persist==0.1.20.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-01T23:58:12-05:00",
          "tree_id": "b90510f1fb72b2ce466ec3a7c381b2abdad47ae5",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/208a1c0c953a119ffcee1ddf92077c1443f41a56"
        },
        "date": 1777698320054,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 89853,
            "range": "± 377",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 232281,
            "range": "± 452",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 512848,
            "range": "± 4575",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1965236,
            "range": "± 44707",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 328,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1254,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7718,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 302,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3243,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9525,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 43698,
            "range": "± 118",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 539,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 1950439,
            "range": "± 41882",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 5974360,
            "range": "± 55611",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 21947728,
            "range": "± 206224",
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
          "id": "1d87b329f5a66533a1d52756957e228af51462c9",
          "message": "docs: federation framing — persist substrate, trust as policy\n\nThe CIRIS roster has grown past the original Trinity (agent + manager\n+ lens). Today it's a federation of primitives — agent, lens,\nregistry, persist, node, bridge — and persist sits below all of them\nas the shared durability + cryptographic-provenance substrate. Update\ncrate metadata + lead docs to reflect the federation framing.\n\nReplace \"CIRIS Trinity\" → \"CIRIS federation\" in:\n- README.md, Cargo.toml, pyproject.toml, src/lib.rs (one-line\n  description that ships in the crate metadata)\n- FSD/CIRIS_PERSIST.md title + closing notes (with a parenthetical\n  preserving the Trinity origin for historic continuity)\n- .github/workflows/ci.yml manifest notes\n\nAdd docs/FEDERATION_DIRECTORY.md — architectural sketch for the\nv0.2.x federation directory surface (public_keys + attestations +\nrevocations) under PoB §3.1. Establishes the boundary that came out\nof the registry conversation:\n\n  - Persist stores; consumers compute.\n  - Trust is the consumer's policy.\n  - Trait surface stays narrow (CRUD + range queries).\n  - No `is_trusted()` / `trust_score()` / `evaluate_policy()` —\n    those locks consumers into a specific trust model and break\n    the federation flexibility PoB §3.1 needs.\n\nThree example consumer policies (direct trust, referrer chain,\nscore-weighted Coherence Stake) sketched in the doc to demonstrate\nthe same persist substrate supporting radically different trust\nmodels. Migration path through v0.2.x → v0.3.x. Open design\nquestions enumerated for the persist/registry/lens alignment\nconversation.\n\nNo code changes; doc-only. v0.1.20 (just shipped) remains the active\nversion on PyPI.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-02T00:18:23-05:00",
          "tree_id": "a56362e814cbf1cae288d1ec7cbe8523c8a45e60",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/1d87b329f5a66533a1d52756957e228af51462c9"
        },
        "date": 1777699450611,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 95259,
            "range": "± 589",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 235143,
            "range": "± 623",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 515310,
            "range": "± 1198",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1832095,
            "range": "± 19411",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 379,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1667,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 9052,
            "range": "± 126",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 368,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2969,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9189,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 40262,
            "range": "± 236",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2152491,
            "range": "± 83861",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6280832,
            "range": "± 160197",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 22621670,
            "range": "± 361305",
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
          "id": "df73e73598b40fb2774cd374af1babd9ac4fe4eb",
          "message": "docs(federation): fold registry sign-off into FEDERATION_DIRECTORY.md\n\nRegistry team signed off on Q4 ceiling, v0.2.x dual-write contract,\nand the two raised questions (cache invalidation + write authority).\nUpdate the doc to reflect the resolved positions — the Open design\nquestions section becomes Resolved decisions; new Operational\ncontract section captures the concrete guarantees both sides commit\nto; new v0.2.x experimental schema contract section spells out the\n2-week deprecation arrangement.\n\nResolved (5 questions):\n  Q1 — Separate federation_keys table (no schema churn on\n       accord_public_keys).\n  Q2 — Self-publish + post-hoc attestation. Registry's\n       RegisterTrustedPrimitiveKey RPC shifts from issuance\n       to attestation call (writes federation_attestations\n       with attesting_key_id=registry-steward).\n  Q3 — Eventually-consistent + TTL. Matches CIRISVerify's\n       existing pubkey-pinning window.\n  Q4 — Fail-open from cache by default; PERSIST_REQUIRED=true\n       opt-in fail-closed; max_stale_cache_age_seconds=3600\n       hard ceiling regardless of mode (closes deliberate-outage\n       attack on revoked-key replay).\n  Q5 — TRUST_CONTRACT.md diff at persist v0.3.x. Path A\n       splits into A1+A2; Path D for multi-peer aggregation.\n       Registry team owns the diff.\n\nOperational contract:\n  - Write authority: scrub-signature is auth. No per-primitive\n    API keys. Per-source-IP rate limit (60/min default) +\n    per-primitive write quota (10 keys/day default).\n  - Cache: TTL (5 min default) + invalidate-on-write.\n    PG NOTIFY pubsub deferred to v1.5 / persist v0.3.x.\n  - Fail-mode: fail-open default + PERSIST_REQUIRED opt-in +\n    max_stale_cache_age_seconds=3600 hard ceiling.\n    cache_age_seconds always emitted in verify response.\n  - Bilateral telemetry: registry's\n    federation_dual_write_divergence_total mirrored by persist's\n    federation_directory_writes_total{outcome=...}. Non-zero\n    divergence in v0.2.x is a schema-bug signal; in v0.3.x+\n    is a real incident.\n\nv0.2.x experimental contract:\n  - Persist may break the schema during v0.2.x with two-week\n    written notice (CHANGELOG + GitHub issue tagged\n    federation-schema-break + proactive consumer notification).\n  - Registry's dual-write feature-flagged\n    (FEDERATION_DUAL_WRITE_ENABLED, default off until registry\n    v1.4). Roll-back is unsetting the flag.\n  - Schema stabilizes at persist v0.3.0; semver-major from then.\n\nMigration table updated to show registry-side state alongside\npersist version (v0.2.0 dual-write peer; v0.3.0 read-path\nmigration; v0.3.x deprecation).\n\nNo code changes; doc-only.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-02T00:27:54-05:00",
          "tree_id": "c65485414dadfb5d589a5ecdd6804eb9c8fb06ed",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/df73e73598b40fb2774cd374af1babd9ac4fe4eb"
        },
        "date": 1777700044883,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 95462,
            "range": "± 743",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 236185,
            "range": "± 28942",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 514952,
            "range": "± 1342",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1838706,
            "range": "± 9351",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 377,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1566,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 9846,
            "range": "± 117",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 359,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2988,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9112,
            "range": "± 23",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 40034,
            "range": "± 105",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 633,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2216848,
            "range": "± 104602",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6383347,
            "range": "± 192209",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 22500048,
            "range": "± 346191",
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
          "id": "8d4da637767765ed159a594858e9673311611139",
          "message": "docs(roadmap): re-sequence — v0.2.0 verify subsumption, v0.3.0 federation directory\n\nVerify subsumption (CIRISPersist#4) is the v0.2.0 milestone, not the\nfederation directory. Sequence-correctness reason: federation\ndirectory's primary read consumer is verify_build_manifest, so\nshipping verify subsumption first means consumers migrate once\n(rather than once to plumb the pubkey lookup, then again to drop\nit when v0.3.0 makes the lookup implicit).\n\nNew: docs/V0.2.0_VERIFY_SUBSUMPTION.md\n  - Implementation plan for CIRISPersist#4\n  - Engine grows verify-shaped proxy methods (sign, public_key,\n    attestation_export, storage_descriptor, get_license_status,\n    check_capability, check_agent_integrity, verify_build_manifest,\n    get_signed_function_manifest, hybrid_sign_build_manifest)\n  - Higher layers (lens, agent, bridge) drop direct ciris-verify\n    Python imports\n  - Pin ciris-verify-core v1.8.0 → v1.8.4 (cohabitation contract\n    documented version)\n  - verify_build_manifest keeps trusted_pubkey caller-arg in\n    v0.2.0; v0.3.0 federation directory replaces with implicit\n    lookup\n  - 10-day single-developer schedule sketch\n  - Closes CIRISVerify AV-14 by construction in persist-bearing\n    stacks\n\nUpdated: docs/FEDERATION_DIRECTORY.md\n  - Migration table pushed back one major version: v0.2.0 (verify\n    subsumption) → v0.3.0 (federation_keys + FederationDirectory)\n    → v0.3.x (attestations + revocations) → v0.4.0 (read-path\n    migration) → v0.4.x (accord_public_keys deprecation)\n  - Status line updated to v0.3.x track\n  - Experimental schema contract section renamed v0.3.x; the\n    two-week deprecation notice clock starts at persist v0.3.0\n    final\n  - Registry-side coordination notes updated: registry decides\n    their paired version on their own side (no longer assumed\n    \"v1.4 paired with persist v0.2.0\"); both sides re-pair when\n    persist v0.3.0 is close\n  - Trust contract diff (Q5) target moved from persist v0.3.x to\n    persist v0.4.x (matches the new schema-stabilization point)\n  - Cache-coherence PG NOTIFY pubsub deferred to persist v0.4.x\n    (matches the new schema-stabilization point)\n\nNo code changes; doc-only. Task tracking:\n  - #82 v0.2.0 verify subsumption (CIRISPersist#4) — was always\n    queued; now has a concrete implementation plan\n  - #88 v0.3.0 federation directory (key storage for lens) —\n    new task tracking the work pushed back from v0.2.0\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-02T00:34:33-05:00",
          "tree_id": "2fbfb8ff6491fca6335d5c1e23875cc07509ec06",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/8d4da637767765ed159a594858e9673311611139"
        },
        "date": 1777700437704,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 95943,
            "range": "± 627",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 235787,
            "range": "± 1247",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 515317,
            "range": "± 3672",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1831597,
            "range": "± 10664",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 377,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1717,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 9015,
            "range": "± 232",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 350,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3112,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9206,
            "range": "± 78",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 40164,
            "range": "± 648",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 640,
            "range": "± 43",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2205752,
            "range": "± 104190",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6371698,
            "range": "± 154326",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 22626913,
            "range": "± 422870",
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
          "id": "fdc7047f8a8b901c4f6ef0b6a311831c6c24fbe5",
          "message": "docs(roadmap): waterfall + Gantt; remove delivery-timeline references\n\nUser wanted the roadmap re-shaped: drop calendar/schedule\nestimates, lay it out as a dependency waterfall with explicit\nparallelizability, and visualize as a Gantt where positions\nindicate sequence (not delivery dates).\n\nNew: docs/ROADMAP.md\n  - Unified Mermaid Gantt covering v0.2.0 → v0.4.x\n  - Phase-by-phase waterfall with explicit dependency arrows\n    (sequential `→` and parallel `║`)\n  - Critical-path section identifying the strict dependency\n    chain vs items that can slip within a phase\n  - Explicit \"what this roadmap does NOT promise\" disclaimer:\n    no delivery dates, no work-effort estimates, no commitment\n    that every v0.3.x item ships in a single release\n  - Cross-references to V0.2.0_VERIFY_SUBSUMPTION.md (v0.2.0\n    plan) and FEDERATION_DIRECTORY.md (v0.3.0+ contract)\n\nUpdated: docs/V0.2.0_VERIFY_SUBSUMPTION.md\n  - \"Sequencing within v0.2.0\" section (Day-1-2 / Day-3-5 / ...\n    table) replaced with \"Work breakdown — dependencies, no\n    timeline\"\n  - Inline Mermaid Gantt for the v0.2.0 phase\n  - Explicit dependency-rule list (`v20a → v20b → v20c* → v20d\n    → v20e → v20f`) showing where the four proxy method groups\n    parallelize\n  - Pointer to docs/ROADMAP.md for the full v0.2.0 → v0.4.x\n    graph\n\nBoth Gantts use Mermaid `dateFormat X` (numeric position, not\ncalendar dates). Surrounding text disclaims the dates: \"positions\nare dependency sequence, not delivery dates.\"\n\nThe v0.3.x→v0.4.x experimental-contract clauses keep the\n\"two-week written notice\" language because that's a\nbreaking-change notification commitment in a contract, not a\nproject timeline. The \"10 keys per primitive identity per day\"\nwrite quota is an operational rate-limit, not a delivery\nschedule. Both intentionally retained.\n\nNo code changes; doc-only.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-02T00:38:09-05:00",
          "tree_id": "0414a69003129d22440322b3814203ced603c8dd",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/fdc7047f8a8b901c4f6ef0b6a311831c6c24fbe5"
        },
        "date": 1777700656108,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 95422,
            "range": "± 2693",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 235588,
            "range": "± 1341",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 514925,
            "range": "± 3320",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1831224,
            "range": "± 21675",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 380,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1569,
            "range": "± 45",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 9050,
            "range": "± 183",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 364,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3046,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9192,
            "range": "± 248",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 40030,
            "range": "± 231",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2156004,
            "range": "± 197599",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6317224,
            "range": "± 170221",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 22496304,
            "range": "± 464246",
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
          "id": "6c89db988bf67d151d899fad8e9c6538df64184c",
          "message": "0.1.21 — SQLite Backend Phase 1 parity\n\nLens team requested SQLite parity before v0.2.0. SQLite was a\ndeclared-but-stubbed feature since v0.1.9 (rusqlite pinned, sqlite\nfeature flag declared, empty migrations/sqlite/, no SqliteBackend).\nv0.1.21 makes it real.\n\nSchema (migrations/sqlite/lens/):\n- V001 — translates postgres V001: BIGSERIAL→INTEGER PRIMARY KEY\n  AUTOINCREMENT, TIMESTAMPTZ→TEXT (RFC 3339), JSONB→TEXT,\n  BOOLEAN→INTEGER, DOUBLE PRECISION→REAL. Drops CREATE SCHEMA +\n  cirislens. namespace, TimescaleDB hypertables, IS DISTINCT FROM\n  (→ IS NOT). Same dedup index shape (THREAT_MODEL.md AV-9).\n- V003 — straightforward ALTER TABLE ADD COLUMN translation.\n\nSqliteBackend (src/store/sqlite.rs, ~580 LoC):\n- Backend trait Phase 1 surface: insert_trace_events_batch,\n  insert_trace_llm_calls_batch, lookup_public_key,\n  sample_public_keys, run_migrations.\n- Arc<Mutex<Connection>> + tokio::task::spawn_blocking adapter.\n- Boot pragmas: foreign_keys=ON, journal_mode=WAL, synchronous=NORMAL.\n- File-backed via SqliteBackend::open(path); :memory: via\n  open_in_memory() for tests.\n\nCargo.toml:\n- sqlite = [\"dep:rusqlite\", \"dep:refinery\", \"refinery/rusqlite\"]\n- rusqlite 0.31 (pin held from v0.1.9) with bundled + chrono +\n  serde_json features.\n- refinery already in postgres; sqlite adds the rusqlite feature.\n\nTests (7 new):\n- migrations_run_clean_in_memory\n- insert_idempotent (mirror of postgres test)\n- distinct_attempts_both_land (FSD §3.4 #4)\n- llm_calls_batch_insert\n- empty_batches_are_noops\n- lookup_public_key_round_trip (base64 → 32-byte VerifyingKey)\n- revoked_keys_filtered (lookup + sample both)\n\nSubstrate matrix after v0.1.21: MemoryBackend (Phase 1), PostgresBackend\n(Phase 1), SqliteBackend (Phase 1, NEW). All three implement the same\ntrait surface; lens ingest path is substrate-agnostic.\n\n150 tests green (128 lib + 22 integration; +7 sqlite). Clippy clean\nacross postgres + sqlite + server + pyo3 + tls. cargo-deny clean.\n\nv0.2.0 unblocked per the v0.1.21 → v0.2.0 → v0.3.0 sequencing in\ndocs/ROADMAP.md.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-02T00:46:49-05:00",
          "tree_id": "089072c8b164be4baba91a7304f82e30600ebdfe",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/6c89db988bf67d151d899fad8e9c6538df64184c"
        },
        "date": 1777701175602,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 90595,
            "range": "± 440",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 233383,
            "range": "± 429",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 517317,
            "range": "± 3395",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 2019220,
            "range": "± 46678",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 328,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1272,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7740,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 305,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3289,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9533,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 43851,
            "range": "± 165",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 543,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2166015,
            "range": "± 62808",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6366512,
            "range": "± 78520",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 22497626,
            "range": "± 485894",
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
          "id": "9a5c97e9490b05873a0d15c5a30b57b61f8bf9cc",
          "message": "docs(roadmap): re-sequence — v0.2.0 federation directory, v0.2.x verify subsumption\n\nPer registry-team alignment: CIRISRegistry's v1.4 scaffolding has\nalready shipped against the original v0.2.0-pre1 expectation\n(vendored types matching FEDERATION_DIRECTORY.md, FederationDirectory\ntrait, migration 024 cache columns, FEDERATION_DUAL_WRITE_ENABLED\nflag, telemetry counters, audit-log envelope_hash metadata; see\nCIRISRegistry/docs/FEDERATION_CLIENT.md). R_BACKFILL is blocked on\npersist publishing schema + trait + bootstrap.\n\nThe previous re-sequence (v0.2.0 verify subsumption, v0.3.0\nfederation directory) would have left the registry team blocked\nfor an entire major version cycle on otherwise-orthogonal work.\nThe two milestones are independent — verify subsumption is a\nPyO3 proxy expansion (Python wheel side), federation directory is\na schema + trait + backend impls (Rust crate side). Shipping\nfederation directory first means:\n\n- Registry's R_BACKFILL unblocks at v0.2.0-pre1\n- v0.2.x verify_build_manifest proxy ships with implicit\n  trusted_pubkey lookup from day one (no v0.2.0 caller-provides\n  / v0.3.0 dropped-arg shuffle)\n- Consumers migrate once\n\nUpdates:\n\ndocs/ROADMAP.md\n- v0.2.0 = federation directory schema + trait + bootstrap +\n  per-backend impls (memory + postgres + sqlite) + persist-steward\n  fingerprint + fixture JSON + write-authority guards\n- v0.2.0-pre1 milestone = registry-unblock minimum (schema +\n  trait + at least one backend + bootstrap + fingerprint +\n  fixtures)\n- v0.2.x = verify subsumption (CIRISPersist#4)\n- v0.3.0 = federation_attestations + federation_revocations +\n  divergence telemetry + as_of: Option<DateTime>\n- v0.4.0 = read-path migration (unchanged)\n- v0.4.x = deprecation + polish (unchanged)\n- Critical path updated to reflect new dependency chain\n- Cross-references in TL;DR updated\n\ndocs/FEDERATION_DIRECTORY.md\n- Status changed from v0.3.x track to v0.2.x track\n- Added \"Sequencing (re-sequenced 2026-05-02)\" section with\n  rationale\n- New §\"persist_row_hash — server-computed for cache divergence\"\n  section: persist canonicalizes via PythonJsonDumpsCanonicalizer\n  and ships hex-encoded hash on every read response. Consumers\n  store + string-compare; no client-side canonicalizer needed.\n  Closes the canonical-hash divergence risk identified in the\n  registry's vendored types.rs\n- Migration table reshaped: v0.2.0-pre1 (registry-unblock) →\n  v0.2.0 final → v0.2.x → v0.3.0 → v0.4.0 → v0.4.x\n- Operational contract section: experimental schema clock starts\n  at v0.2.0 final (was v0.3.0 final)\n- Telemetry section + experimental schema contract updated to\n  v0.2.x/v0.3.x cadence\n\ndocs/V0.2.0_VERIFY_SUBSUMPTION.md\n- Title and TL;DR updated to v0.2.x\n- \"Why verify subsumption first\" → \"Why verify subsumption\n  follows federation directory\" with re-sequence rationale\n- verify_build_manifest signature simplified: takes (bytes,\n  primitive) only; trusted_pubkey lookup is implicit via\n  federation directory which is live by v0.2.x\n- Doc filename retained for git-history continuity\n\nTask tracking:\n- #82 v0.2.0 → v0.2.x verify subsumption\n- #88 v0.3.0 → v0.2.0 federation directory (now in_progress)\n\nNo code changes; doc-only.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-02T11:28:16-05:00",
          "tree_id": "83d2c10e52571ef2466e232020a4c5f377c755ca",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/9a5c97e9490b05873a0d15c5a30b57b61f8bf9cc"
        },
        "date": 1777739781890,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 89877,
            "range": "± 1172",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 232304,
            "range": "± 1248",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 513561,
            "range": "± 7638",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 2033961,
            "range": "± 49909",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 329,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1274,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7722,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 310,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3201,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9752,
            "range": "± 39",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 43911,
            "range": "± 200",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 538,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2138219,
            "range": "± 114206",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6285668,
            "range": "± 136738",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 22449358,
            "range": "± 263717",
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
          "id": "c5d060fa4a55b280c21fb2a7d9b10f66059a833b",
          "message": "v0.2.0 federation directory: schema + trait + types\n\nFirst chunk of v0.2.0 federation directory work\n(docs/FEDERATION_DIRECTORY.md, registry-aligned per FEDERATION_CLIENT.md).\nBackend implementations (memory, postgres, sqlite) follow in subsequent\ncommits; this commit establishes the contract surface so the registry\nteam's vendored types can be validated against persist's authoritative\nshape.\n\nSchema:\n- migrations/postgres/lens/V004__federation_directory.sql:\n  federation_keys (pubkey rows with v0.1.3 scrub envelope +\n  server-computed persist_row_hash + DEFERRABLE INITIALLY DEFERRED FK\n  for self-signed bootstrap rows), federation_attestations (many-to-many\n  signed-by attester), federation_revocations (append-only signed-by\n  revoker). All three tables FK-chain back to federation_keys.scrub_key_id\n  so the trust chain terminates at out-of-band-anchored stewards, not\n  at row existence.\n- migrations/sqlite/lens/V004__federation_directory.sql: SQLite type\n  translations (TIMESTAMPTZ→TEXT RFC 3339, JSONB→TEXT, BYTEA→BLOB,\n  UUID→TEXT, gen_random_uuid()→caller-generates).\n\nRust:\n- src/federation/mod.rs: FederationDirectory trait with 8 methods\n  matching CIRISRegistry's vendored shape exactly. Explicit non-goals\n  documented (no is_trusted, no trust_score, no trust_path — those\n  are consumer policy, not substrate). New federation::Error type\n  with kind() string-tokens for telemetry.\n- src/federation/types.rs: KeyRecord, Attestation, Revocation +\n  Signed* wrappers. identity_type, algorithm, attestation_type\n  string constants matching the registry's vendored\n  /rust-registry/src/federation/types.rs field-for-field.\n- compute_persist_row_hash() helper: server-computed canonical hash\n  via PythonJsonDumpsCanonicalizer (sorted keys, no whitespace,\n  ensure_ascii=True). Excludes the persist_row_hash field itself\n  from the hash input so the field doesn't depend on its own value.\n  Closes the canonical-hash divergence risk from registry's vendored\n  types.rs (which uses default serde_json::to_vec — not canonical).\n  Consumers store + string-compare the hex string; they don't\n  reproduce the canonicalizer.\n\nTests: 4 passing (deterministic hashing, self-exclusion, content\nsensitivity, serde round-trip). Total project test count now 132 lib\n+ 22 integration; clippy clean with all features.\n\nNext commits:\n- Memory backend impl (smallest scope, validates trait shape works\n  end-to-end without DB infrastructure)\n- Postgres backend impl + bootstrap migration writing self-signed\n  persist-steward row\n- SQLite backend impl\n- Then: cut v0.2.0-pre1 (registry-unblock milestone per ROADMAP.md)\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-02T11:31:58-05:00",
          "tree_id": "ae34364ad8cb860862215c15879905e550dc4cc9",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/c5d060fa4a55b280c21fb2a7d9b10f66059a833b"
        },
        "date": 1777739980778,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 79429,
            "range": "± 585",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 196499,
            "range": "± 309",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 429745,
            "range": "± 4459",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1536995,
            "range": "± 11675",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 295,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1269,
            "range": "± 32",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 6440,
            "range": "± 34",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 270,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2376,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 7372,
            "range": "± 98",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 31668,
            "range": "± 262",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 539,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2212240,
            "range": "± 69712030",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 5677691,
            "range": "± 34565101",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 19510228,
            "range": "± 24290400",
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
          "id": "c382a6f41211fb12c35b8468299f3933e2e13b21",
          "message": "v0.2.0 federation directory: memory backend impl\n\nSecond commit in the v0.2.0 federation directory milestone (after\nthe schema + trait + types scaffolding). MemoryBackend now implements\nboth Backend (legacy trace ingest) and FederationDirectory (new\nv0.2.0 substrate) — single struct, two trait surfaces.\n\nImplementation:\n- State struct extended with federation_keys (HashMap<String, KeyRecord>),\n  federation_attestations (Vec<Attestation>), federation_revocations\n  (Vec<Revocation>). Append-only for attestations/revocations matches\n  postgres semantics; HashMap for keys gives O(1) lookup_public_key.\n- put_public_key: idempotent on (key_id, persist_row_hash) match; errors\n  with Conflict on same key_id with differing content. persist_row_hash\n  computed server-side via compute_persist_row_hash() before insert.\n- put_attestation / put_revocation: FK enforcement parity with postgres\n  — both attesting + attested keys (or revoked + revoking) must exist\n  in federation_keys. Returns InvalidArgument otherwise.\n- list_attestations_for / list_attestations_by / revocations_for:\n  filtered + sorted DESC by asserted_at / effective_at to match postgres\n  index order.\n- All read methods return cloned KeyRecord/Attestation/Revocation with\n  persist_row_hash populated server-side — consumers see byte-stable\n  hashes regardless of backend.\n\nTests (7 new):\n- put_and_lookup_public_key — round-trip with server-computed hash\n- lookup_unknown_returns_none — typed None, not panic\n- idempotent_put_same_content — same key + content = no-op\n- put_conflict_different_content — same key, different content = Conflict\n- lookup_keys_for_identity_filters — identity_ref-scoped enumeration\n- put_attestation_requires_both_keys_exist — FK parity\n- list_attestations_for_and_by — bidirectional graph traversal\n- revocation_round_trip — append + query\n\nNaming-collision fix: both Backend and FederationDirectory expose\nlookup_public_key. The two methods return different types (VerifyingKey\nvs KeyRecord) so they don't conflict at the trait level, but at call\nsites Rust can't infer which to dispatch to. The legacy\nBackend::lookup_public_key test in store::memory was disambiguated\nvia fully-qualified syntax; new federation tests use FederationDirectory::\nfully-qualified syntax. Both call patterns are documented inline.\n\n140 tests green (132 lib + 5 + 8 + 9 fixture; +7 federation memory).\nclippy clean across all features. cargo-deny clean.\n\nNext: postgres backend impl + bootstrap migration.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-02T11:35:05-05:00",
          "tree_id": "b6bf2c783e147374aa093605627095d160cbac2c",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/c382a6f41211fb12c35b8468299f3933e2e13b21"
        },
        "date": 1777740102664,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 95378,
            "range": "± 319",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 236562,
            "range": "± 8332",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 516402,
            "range": "± 4092",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1838016,
            "range": "± 51401",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 381,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1655,
            "range": "± 23",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 9104,
            "range": "± 45",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 359,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3085,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9535,
            "range": "± 275",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 40574,
            "range": "± 211",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 621,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2238574,
            "range": "± 114447",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6383022,
            "range": "± 194782",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 22664971,
            "range": "± 287296",
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
          "id": "c4d43d997a57aebd2a9e04115e7a5ac5af4cfb59",
          "message": "v0.2.0 federation directory: postgres + sqlite backend impls\n\nThird commit in the v0.2.0 federation directory milestone (after\nschema/trait/types in c5d060f and memory backend in c382a6f).\nPostgresBackend and SqliteBackend now both implement\nFederationDirectory in addition to the existing Backend trait —\nsingle struct, two trait surfaces, parity with MemoryBackend.\n\nPostgres impl (~270 LoC added to src/store/postgres.rs):\n- All 8 trait methods backed by tokio-postgres + deadpool-postgres\n- persist_row_hash computed in Rust via compute_persist_row_hash()\n  before INSERT — postgres sees it as a TEXT column\n- Idempotency: ON CONFLICT (key_id) DO NOTHING + post-insert\n  conflict-check that compares persist_row_hash; same-hash → no-op,\n  different-hash → Error::Conflict\n- FK violation detection: postgres \"foreign key\" string in error →\n  Error::InvalidArgument (matches memory backend's pre-INSERT FK\n  check semantically)\n- BYTEA columns (original_content_hash, scrub_signature) take\n  hex-decoded / base64-decoded raw bytes; pg_row_to_*() helpers\n  re-encode for the wire shape\n- Three reusable row converters: pg_row_to_key_record,\n  pg_row_to_attestation, pg_row_to_revocation\n\nSQLite impl (~370 LoC added to src/store/sqlite.rs):\n- All 8 trait methods backed by rusqlite + tokio::task::spawn_blocking\n- persist_row_hash computed before crossing spawn_blocking\n  boundary so the closure is 'static\n- TIMESTAMPTZ → TEXT (RFC 3339): chrono.to_rfc3339() on write,\n  parse_rfc3339() helper on read\n- JSONB → TEXT: serde_json::to_string on write, from_str on read\n- BLOB columns for original_content_hash + scrub_signature\n- FK violations surface as \"FOREIGN KEY\" string in rusqlite errors\n  (PRAGMA foreign_keys=ON enforces); converted to Error::InvalidArgument\n- Three sqlite_row_to_* converters mirror postgres counterparts\n\n7 new sqlite tests (mirror the memory backend tests):\n- federation_put_and_lookup_round_trip (with persist_row_hash\n  re-computation parity check)\n- federation_idempotent_put\n- federation_conflict_on_different_content\n- federation_lookup_by_identity_filters\n- federation_attestation_round_trip\n- federation_attestation_fk_enforcement\n- federation_revocation_round_trip\n\nPostgres tests are gated behind CIRIS_PERSIST_TEST_PG_URL (matching\nthe existing trace ingest test gate); CI environment will exercise\nthem. Memory + sqlite federation parity establishes the conformance\nbaseline.\n\nDisambiguation: both Backend and FederationDirectory expose\nlookup_public_key (returning VerifyingKey vs KeyRecord). Tests for\nthe legacy Backend shape now use Backend::lookup_public_key(&backend, ...)\nsyntax; federation tests use FederationDirectory::... — both call\npatterns documented inline in the test bodies.\n\n147 lib tests green (+7 sqlite federation, postgres tested via\ngated integration). Clippy clean across postgres + sqlite + server +\npyo3 + tls. cargo-deny clean.\n\nNext:\n- Bootstrap migration helper binary (emit canonical bytes for\n  CIRISCore to sign with the persist-steward Ed25519 secret)\n- V005 bootstrap migration writing self-signed persist-steward row\n  (filled in once CIRISCore returns the signed values)\n- Fixture JSON for registry serde validation\n- Cut v0.2.0-pre1\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-02T11:44:35-05:00",
          "tree_id": "17f058b51f80a3ace8ebe109b45e043e689ca1e2",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/c4d43d997a57aebd2a9e04115e7a5ac5af4cfb59"
        },
        "date": 1777740675055,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 95963,
            "range": "± 296",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 236494,
            "range": "± 568",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 516798,
            "range": "± 1669",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1836503,
            "range": "± 12319",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 380,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1641,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 9103,
            "range": "± 47",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 362,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3103,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9295,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 40498,
            "range": "± 116",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2336310,
            "range": "± 161787",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6466448,
            "range": "± 925904",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 22510239,
            "range": "± 713366",
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
          "id": "978dc59276654f2c2208a07d3116b090ef634a7a",
          "message": "v0.2.0 federation: hybrid PQC schema (hot Ed25519 + cold ML-DSA-65)\n\nUser directive: hybrid Ed25519 + ML-DSA-65 is the ONLY signing scheme\nacross the federation, period. Anything less and we're retroactively\ncompromised when quantum spins.\n\nBut wait-until-everything-is-fast-PQC ships never. So:\n**hot-path Ed25519 + cold-path ML-DSA-65 = post-quantum safe history,\nfederation speed at write time.**\n\nWriter contract:\n  1. Sign canonical with Ed25519 (hot, synchronous)\n  2. Write the row (PQC fields may be None at this step)\n  3. IMMEDIATELY kick off ML-DSA-65 sign on cold path (no delay,\n     no batching, just off the synchronous request path)\n  4. Call attach_pqc_signature once cold path completes;\n     pqc_completed_at timestamps the moment the row became\n     hybrid-secure\n\nSchema (V004 postgres + sqlite):\n- pubkey_ed25519_base64: TEXT NOT NULL (32 raw bytes, base64)\n- pubkey_ml_dsa_65_base64: TEXT (1952 raw bytes, base64; nullable\n  during cold-path window)\n- algorithm: TEXT NOT NULL CHECK (algorithm = 'hybrid') — schema-\n  enforced; persist runtime also checks before writes\n- scrub_signature_classical: TEXT NOT NULL (Ed25519 sig over\n  canonical)\n- scrub_signature_pqc: TEXT (ML-DSA-65 sig over canonical ||\n  classical_sig — bound to prevent stripping; nullable until cold\n  path completes)\n- pqc_completed_at: TIMESTAMPTZ (timestamp when row became hybrid-\n  secure; observability + telemetry surface)\n\nSame schema shape on federation_attestations + federation_revocations.\n\nTypes (src/federation/types.rs):\n- KeyRecord/Attestation/Revocation: pubkey_base64 → pubkey_ed25519_\n  base64 + Option<pubkey_ml_dsa_65_base64>; scrub_signature →\n  scrub_signature_classical + Option<scrub_signature_pqc>; new\n  Option<pqc_completed_at>\n- algorithm constants: dropped ED25519 + ML_DSA_65 (only HYBRID\n  remains; consumers using the old constants now compile-error)\n- Per-type is_pqc_complete()/is_pqc_pending() helpers for\n  consumers composing soft-hybrid + freshness policies\n\nPer CIRISVerify spec\n(ciris-verify-core/src/security/function_integrity.rs:149\nManifestSignature, ciris-crypto/src/types.rs:156 HybridSignature,\ndocs/BUILD_MANIFEST.md L104). Bound signature pattern: PQC covers\ndata || classical_signature, prevents stripping when classical\nbreaks.\n\nBackends (memory, postgres, sqlite):\n- All three updated for the new shape\n- Memory backend's put_public_key validates algorithm = \"hybrid\"\n  before any other check\n- Postgres + sqlite use the schema CHECK constraint as defense in\n  depth on top of the runtime check\n- pg_row_to_*/sqlite_row_to_* converters carry pqc_completed_at\n  through\n\nTrust contract section added to docs/FEDERATION_DIRECTORY.md:\n- \"Eventual consistency as a federation primitive\" — layered\n  eventual-consistency commitments (PQC completion, replication,\n  cache freshness, peer attestation, revocation propagation) with\n  observability signals for each\n- Strict-hybrid / soft-hybrid+freshness / pure-attestation-graph\n  policy examples\n- What persist commits to (every signal exposed, eventual property\n  converges, divergence alarm-able) vs what it explicitly does NOT\n  (strong consistency, synchronous PQC, single-policy enforcement)\n- Phase transition: when require_pqc_on_write flips, \"PQC\n  completion\" eventual property becomes synchronous; all other\n  eventual layers stay as they were\n\nTests:\n- pqc_complete_vs_pending in types.rs (4 cases)\n- All federation memory + sqlite tests still pass with the new\n  shape (most use the hybrid-pending fixture variant)\n- 148 lib tests green; clippy clean across all features\n\nHelper binary (src/bin/derive_persist_steward_bootstrap.rs)\nneeds updating for the new bound-signature handoff protocol +\nML-DSA-65 input — that's the next commit.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-02T12:07:56-05:00",
          "tree_id": "5373272c7d9b1bf70e921d19dac7795f82d32a06",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/978dc59276654f2c2208a07d3116b090ef634a7a"
        },
        "date": 1777742082190,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 96054,
            "range": "± 878",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 236908,
            "range": "± 810",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 518196,
            "range": "± 1881",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1845478,
            "range": "± 17625",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 378,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1587,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 9072,
            "range": "± 79",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 378,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3177,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9330,
            "range": "± 40",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 40427,
            "range": "± 119",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2191871,
            "range": "± 73628",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6353310,
            "range": "± 154161",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 22509388,
            "range": "± 972112",
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
          "id": "493a6b544d6c9601ba66172f28d4ed51f02d3f9a",
          "message": "v0.2.0 federation: attach_pqc_signature for cold-path fill-in\n\nThe cold-path PQC fill-in primitive completing the writer contract\ndocumented in docs/FEDERATION_DIRECTORY.md §\"PQC strategy\" + §\"Trust\ncontract\":\n\n  Step 1: Sign canonical with Ed25519 (hot path)\n  Step 2: Write the row (PQC fields None — hybrid-pending)\n  Step 3: IMMEDIATELY kick off ML-DSA-65 sign on cold path\n  Step 4: Call attach_*_pqc_signature once ML-DSA completes  ← this commit\n\nThree new trait methods on FederationDirectory:\n- attach_key_pqc_signature(key_id, mldsa_pubkey, mldsa_sig)\n- attach_attestation_pqc_signature(attestation_id, mldsa_sig)\n- attach_revocation_pqc_signature(revocation_id, mldsa_sig)\n\n(Attestations/revocations don't have their own pubkey to attach —\nthey reference the existing federation_keys.scrub_key_id's pubkey\nfor verification.)\n\nEach backend impl:\n- Verifies the row exists; rejects with InvalidArgument otherwise\n- Verifies the row is currently hybrid-pending; rejects with\n  Conflict if already PQC-complete (no double-fill)\n- Updates PQC fields + pqc_completed_at atomically\n- Recomputes persist_row_hash since row content changed\n- Postgres + sqlite use UPDATE ... WHERE pqc_completed_at IS NULL\n  for atomic concurrent-completion guard\n\nMemory tests (4 new, total memory backend now 20 tests):\n- attach_pqc_completes_hybrid_pending_key — basic round-trip\n- attach_pqc_rejects_double_fill — Conflict on second attach\n- attach_pqc_rejects_missing_row — InvalidArgument on ghost\n- attach_pqc_for_attestation_and_revocation — full FK chain\n  (steward → primitive key → attestation/revocation, all upgraded\n  to hybrid-complete)\n\nNote: Persist does NOT verify the cryptographic validity of the PQC\nsignature on attach. That's the writer's responsibility. Consumers\nverify at read time via their own policy layer (per the trust\ncontract — strict-hybrid policy refuses pending rows; soft-hybrid\n+ freshness accepts within window). This separation keeps persist\nsubstrate-only and aligned with the existing scrub_signature_classical\ncontract.\n\n152 lib + 22 integration tests green; clippy clean across all\nfeatures.\n\nNext: PyO3 surface for the 11 federation methods (8 base + 3\nattach) so the lens team can call them from Python via the wheel.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-02T12:18:27-05:00",
          "tree_id": "8b2d3c088006527ff3a08bc00ff58b99ca59ef74",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/493a6b544d6c9601ba66172f28d4ed51f02d3f9a"
        },
        "date": 1777742732354,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 96004,
            "range": "± 782",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 239133,
            "range": "± 1309",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 522514,
            "range": "± 2499",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1856710,
            "range": "± 14057",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 383,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1592,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8736,
            "range": "± 168",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 351,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3036,
            "range": "± 44",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9451,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 40432,
            "range": "± 180",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2204028,
            "range": "± 88932",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6457224,
            "range": "± 204827",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 22601323,
            "range": "± 933346",
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
          "id": "bec5cd3bbcc00e48d89f7c43b23a4d5ec3656677",
          "message": "0.2.0 — federation directory (registry-aligned, lens-cutover-ready)\n\nThe v0.2.0 milestone the registry team's v1.4 scaffolding has been\nwaiting for and the lens team's pubkey-storage cutover target.\n\nFederation directory:\n- Schema (V004 postgres + sqlite): federation_keys + _attestations\n  + _revocations. Hybrid Ed25519 + ML-DSA-65 only\n  (CHECK algorithm = 'hybrid'). Every row carries v0.1.3 scrub\n  envelope + persist_row_hash (server-computed canonical hash for\n  cache-divergence detection) + pqc_completed_at.\n- FederationDirectory trait: 8 base methods (CRUD over the three\n  tables) + 3 cold-path attach_*_pqc_signature methods. No\n  policy-bearing methods (no is_trusted, no trust_score,\n  no trust_path).\n- Backends: MemoryBackend + PostgresBackend + SqliteBackend all\n  implement the trait. Same conformance.\n- PyO3 surface: 11 Engine methods exposing the trait through to\n  Python. JSON-string payload shape for complex types (lens calls\n  json.dumps once before / json.loads once after). Errors map\n  caller-fault → ValueError, server-fault → RuntimeError.\n\nPQC strategy: hot-Ed25519 + cold-ML-DSA-65\n- Writer contract: sign Ed25519 (hot, synchronous); write the row\n  (PQC fields None); IMMEDIATELY kick off ML-DSA-65 sign on cold\n  path (no delay, no batching, just off the synchronous path);\n  call attach_*_pqc_signature once cold path completes\n- Persist tracks via pqc_completed_at; doesn't enforce timing\n  (writer contract); telemetry surfaces stale-pending rows for\n  alarm\n- Bound signature: PQC covers (canonical || classical_sig) per\n  CIRISVerify ManifestSignature + HybridSignature spec\n- When quantum threat materializes, runtime flips\n  require_pqc_on_write=true; pre-flip pending rows walk through\n  the upgrade pipeline; post-flip rows are hybrid from the start\n- Net property: every row in the historical audit chain ends up\n  hybrid-signed without ML-DSA latency in the synchronous path\n\nTrust contract: eventual consistency as a federation primitive\n(docs/FEDERATION_DIRECTORY.md). Layered eventual-consistency\ncommitments — PQC completion, replication, cache freshness, peer\nattestation, revocation propagation — each with an observability\nsignal. Consumers compose their own trust verdict (strict-hybrid /\nsoft-hybrid+freshness / pure-attestation-graph / Coherence Stake)\nusing persist's signals. Persist exposes substrate, never\nverdicts.\n\nLens cutover: install ciris-persist==0.2.0, run migrations, write\nself-signed lens-steward row, migrate accord_public_keys ->\nfederation_keys via put_public_key, validate parity via\nlookup_public_key, cut new writes to the federation surface.\nHybrid-pending rows allowed for soft-PQC; cold-path PQC fill via\nattach_key_pqc_signature.\n\nRegistry: their v1.4 scaffolding (CIRISRegistry/docs/\nFEDERATION_CLIENT.md) is unblocked. Their vendored types in\nrust-registry/src/federation/types.rs need follow-up to match the\nhybrid shape (will flag in FEDERATION_CLIENT.md after wheel is on\nPyPI).\n\n154+ tests green; clippy clean; cargo-deny clean.\n\nDeferred to v0.2.x:\n- persist-steward bootstrap V005 (pending CIRISCore keypair)\n- Helper binary update for hybrid handoff\n- Fixture JSON\n- Telemetry counter\n- Verify subsumption (CIRISPersist#4)\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-02T12:22:12-05:00",
          "tree_id": "f745e441b9fec242661ac125d1dcd250bb3cfb10",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/bec5cd3bbcc00e48d89f7c43b23a4d5ec3656677"
        },
        "date": 1777742959261,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 95924,
            "range": "± 254",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 237549,
            "range": "± 2981",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 518291,
            "range": "± 9316",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1844044,
            "range": "± 21556",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 378,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1714,
            "range": "± 45",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 9071,
            "range": "± 40",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 354,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3021,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9063,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 39709,
            "range": "± 295",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2162360,
            "range": "± 82589",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6340439,
            "range": "± 160929",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 22503903,
            "range": "± 206158",
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
          "id": "b0a3a8dcc7795c79fe72f59445c482f6905c39ce",
          "message": "0.2.1 — lens federation-cutover surface (sign + canonicalize + dual-read)\n\nThree small adds completing the lens v0.2.x ask. Lens can now wire\nwrites through persist's federation directory end-to-end without\nthe keyring seed crossing the FFI, and the trace-verify read path\nfinds the keys automatically without a separate cutover step.\n\nEngine.sign(message: bytes) -> bytes (PyO3):\n  Hot-path Ed25519 sign exposed on the wheel. Same shape as\n  public_key_b64(): bytes in, bytes out, no key material crossing\n  the boundary. Lens builds federation envelope, gets signature,\n  embeds in SignedKeyRecord, submits via put_public_key.\n\nEngine.canonicalize_envelope(json_str) -> bytes (PyO3):\n  Persist's PythonJsonDumpsCanonicalizer exposed for lens\n  consumption. Takes a JSON object string, returns canonical bytes\n  to sign. Hides canonicalization rules inside persist where they\n  live anyway — eliminates the drift risk if either side touches\n  the rules later.\n\nBackend::lookup_public_key dual-read migration:\n  The existing trait method (used by trace verify) now reads from\n  federation_keys first, falls back to accord_public_keys (legacy)\n  on miss. Lens writes via the federation surface; the existing\n  trace verify path finds the keys without a separate cutover. No\n  big-bang switchover.\n\n  All three backends (memory, postgres, sqlite) updated.\n\n  Filter on federation_keys: valid_until IS NULL OR valid_until >\n  NOW(). Filter on accord_public_keys retained:\n  revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW()).\n  Strict consumers can layer federation revocation checks via\n  revocations_for() on top.\n\n  The legacy fallback retires at v0.4.0 per the roadmap. Until\n  then, both tables are load-bearing during the migration window.\n\nTests:\n- backend_lookup_public_key_dual_reads_federation — write via\n  federation surface only, read back via legacy Backend trait\n- backend_lookup_public_key_falls_back_to_legacy — federation\n  empty, legacy populated, fallback works\n\n154 lib tests green; clippy clean; cargo-deny clean.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-02T13:10:21-05:00",
          "tree_id": "12b30fb86095e853971d706c3b2a1573a9314e1f",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/b0a3a8dcc7795c79fe72f59445c482f6905c39ce"
        },
        "date": 1777745828865,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 95814,
            "range": "± 700",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 236892,
            "range": "± 823",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 517869,
            "range": "± 16888",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1846178,
            "range": "± 14156",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 338,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1534,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7395,
            "range": "± 99",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 363,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3131,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9155,
            "range": "± 56",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 40954,
            "range": "± 143",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 632,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2191491,
            "range": "± 89961",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6325434,
            "range": "± 265960",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 22162300,
            "range": "± 531696",
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
          "id": "dd7107841c672dd7403308c04efa777e9de2e88c",
          "message": "0.2.2 — steward_sign separate keyring identity\n\nLens v0.2.x round 2. v0.2.1's Engine.sign() is keyed to the\nscrub-envelope identity (signing_key_id, P-256 via ciris-keyring)\n— wrong key for the federation_keys schema (Ed25519). The\nlens-steward keypair is a separate Ed25519 keypair generated\nexternally (CIRIS bridge in the lens deployment story). v0.2.2\nadds the steward signing surface as a distinct FFI-boundary-clean\nprimitive.\n\nPyEngine constructor:\n- steward_key_id: Optional[str] — federation steward identifier\n- steward_key_path: Optional[str] — file path holding 32-byte raw\n  Ed25519 seed\nBoth-or-neither; mismatch raises ValueError. When configured, the\nseed is loaded at constructor time and held as\ned25519_dalek::SigningKey privately. Lens process never sees the\nseed bytes after construction.\n\nThree new methods:\n- steward_public_key_b64() -> str (44-char Ed25519 pubkey base64)\n- steward_key_id() -> str (the configured identifier)\n- steward_sign(message: bytes) -> bytes (64-byte raw Ed25519 sig)\n\nAll three raise ValueError if no steward identity configured.\nSame FFI-boundary discipline as Engine.sign(): bytes in, bytes\nout, no key material crossing.\n\nCold-path ML-DSA-65 sign deferred — lens runs it via its own\npipeline and lands via attach_key_pqc_signature().\n\n154 lib + 22 integration tests green; clippy clean; cargo-deny\nclean. PyO3-surface only — no schema changes, fully backwards\ncompatible (unchanged behavior when steward params unset).\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-02T13:28:48-05:00",
          "tree_id": "6a5c23c8670828560ae43c8784701d8553913645",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/dd7107841c672dd7403308c04efa777e9de2e88c"
        },
        "date": 1777746908047,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 90502,
            "range": "± 5392",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 233831,
            "range": "± 594",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 516251,
            "range": "± 1373",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1920517,
            "range": "± 20019",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 330,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1271,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7724,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 303,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3063,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9589,
            "range": "± 28",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 43442,
            "range": "± 549",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 537,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 1893424,
            "range": "± 22390",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 5863860,
            "range": "± 30853",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 21352833,
            "range": "± 95393",
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
          "id": "e51fb6d6afd605ed4e08d0855785e0f103cfa881",
          "message": "0.2.3 — ML-DSA-65 sig size doc fix + CIRISVerify v1.8.5 hygiene bump\n\nCIRISPersist#8: src/federation/types.rs:166 doc said \"~4396 chars\nfor 3293-byte sig\" — wrong. FIPS 204 final is 3309 bytes / 4412\nb64 chars. CIRISBridge's lens-steward bootstrap empirically\nproduced 4412-char signatures via dilithium-py. Pure docstring\nfix; persist v0.2.x has no ML-DSA verifier and no schema capacity\ncheck (TEXT column), so no behavior change.\n\nCIRISVerify pin: v1.8.0 → v1.8.5. Hygiene bump for the same FIPS\n204 final size fix in ciris-crypto::PqcAlgorithm::MlDsa65.signature_size().\nPersist doesn't use that constant directly today (we use\nVerifyError, BuildPrimitive, ExtrasValidator from\nciris-verify-core; HardwareSigner from ciris-keyring), but keeps\nthe pin current for when verify subsumption (CIRISPersist#4) lands.\n\nCIRISPersist#6: closing pending CIRISBridge confirmation. v0.1.17\nadded the breadcrumb diagnostic; v0.1.18-v0.1.20 closed the\nunderlying canonical-bytes drift (CIRISPersist#7) that was being\nmisclassified as verify_unknown_key in the v0.1.16 window. v0.2.x\nfederation directory + dual-read fundamentally changes the lookup\npath. Will reopen with current-version evidence if reproduces.\n\n154 lib + 22 integration tests green; clippy clean; cargo-deny\nclean.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-02T14:56:26-05:00",
          "tree_id": "0c4888044e9d2ff3f31f80d96612181719f5cae2",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/e51fb6d6afd605ed4e08d0855785e0f103cfa881"
        },
        "date": 1777752214074,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 96403,
            "range": "± 508",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 238063,
            "range": "± 946",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 520038,
            "range": "± 2981",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1850021,
            "range": "± 27337",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 378,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1652,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 9115,
            "range": "± 39",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 351,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3104,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9277,
            "range": "± 45",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 40197,
            "range": "± 194",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 623,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2145972,
            "range": "± 39933",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6236733,
            "range": "± 72749",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 22080593,
            "range": "± 148678",
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
          "id": "f2a57d13a1ef6256d88d48c03cb14255188dd2f0",
          "message": "0.2.4 — verify subsumption: pip-install-time CLI subsumption\n\nFirst piece of CIRISPersist#4 (verify subsumption). `pip install\nciris-persist==0.2.4` now pulls ciris-verify>=1.8.6,<2 as a\nruntime dep, which puts ciris-build-sign and ciris-build-verify\nCLIs on PATH transitively.\n\nCIRISAgent / CIRISLens / CIRISBridge release workflows can drop\nthe cargo install + curl-from-tarball workarounds for the\nbuild-manifest signing CLIs. One pip install for the whole\nverify+persist stack.\n\n>=1.8.6 floor: that's the first ciris-verify wheel with binary\nentry points on all 5 platforms (linux x86_64/aarch64, macos\nx86_64/arm64, windows x86_64).\n<2 ceiling: semver-major safety; v0.2.x persist consumes v1.x\nverify. Bump when v0.3.x persist coordinates with v2.x verify.\n\nWhat this does NOT do yet: the Python import surface is\nunchanged. Engine.sign()/steward_sign() exist (v0.2.1/v0.2.2) for\nfederation-keys signing. The verify-shaped Engine proxy methods\n(verify_build_manifest, attestation_export, get_license_status,\netc.) per docs/V0.2.0_VERIFY_SUBSUMPTION.md land in a follow-on\nv0.2.x. v0.2.4 is the install-shape piece; import-shape is task\n#82 in flight.\n\n154 lib + 22 integration tests green; clippy clean; cargo-deny\nclean. Wheel metadata gains Requires-Dist: ciris-verify>=1.8.6,<2.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-02T15:28:26-05:00",
          "tree_id": "0952f233ec4961e9ff227c8a5b1617596972484b",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/f2a57d13a1ef6256d88d48c03cb14255188dd2f0"
        },
        "date": 1777754127042,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 115639,
            "range": "± 342",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 267973,
            "range": "± 1473",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 570581,
            "range": "± 1467",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 2002910,
            "range": "± 6801",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 396,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1594,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8391,
            "range": "± 104",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 341,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3002,
            "range": "± 69",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9448,
            "range": "± 37",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 40794,
            "range": "± 269",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 637,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2148598,
            "range": "± 46929",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6559478,
            "range": "± 650346",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 24086583,
            "range": "± 442618",
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
          "id": "52c2df436f0a52b0cb29d07ed2b7c5d61cdc100f",
          "message": "0.3.0 — wire format 2.7.9 (deterministic dispatch by trace_schema_version)\n\nLocked against CIRISAgent/FSD/TRACE_WIRE_FORMAT.md @ cc41f315f\n(release/2.7.9 HEAD; will be byte-identical at v2.7.9-stable tag).\nQA runner cuts release/2.7.9 signed build today; persist v0.3.0\nmust be on PyPI before that build deploys.\n\nSchema:\n- SUPPORTED_VERSIONS = [\"2.7.0\", \"2.7.9\"] (dual-window)\n- TraceComponent gets agent_id_hash: Option<String>\n  - None at 2.7.0 (cross-shape injection defense per §3.1)\n  - Some(envelope_hash) at 2.7.9 (denormalized from envelope, agents\n    emit locked-equal)\n- New verify::Error::UnsupportedSchemaVersion variant\n  (kind=\"verify_unsupported_schema_version\") for the dispatch-table\n  miss\n\nVerify dispatch — DETERMINISTIC by trace_schema_version, NOT iterative:\n- \"2.7.0\" → canonical_payload_value (4-field per-component)\n- \"2.7.9\" → canonical_payload_value_v279 (5-field per-component\n  with agent_id_hash)\n- \"2.7.legacy\" → canonical_payload_value_legacy (2-field, explicit\n  opt-in only — not in SUPPORTED_VERSIONS by default)\n\nWhy deterministic vs try-three:\n- trace_schema_version is in the signed canonical bytes →\n  self-authenticating dispatch key, attacker cannot forge without\n  breaking signature\n- No shape-shopping attack surface\n- No spurious-sig-fail SHA-256+verify latency multiplier\n- Stable telemetry buckets (each trace contributes to exactly one\n  shape's verify path)\n\nCross-shape injection defense (§3.1):\n- At \"2.7.0\", canonical_payload_value ignores per-component\n  agent_id_hash even if present on the wire\n- Only envelope value is authoritative\n- Test: v270_ignores_per_component_agent_id_hash_injection\n  asserts byte-identical canonical bytes whether per-component is\n  None or Some(\"attacker_smuggled_hash\")\n\ncontext/TRACE_WIRE_FORMAT.md replaced with single-line pointer to\nCIRISAgent/FSD/TRACE_WIRE_FORMAT.md @ cc41f315f. Eliminates the\nspec-vendor-drift class that produced v0.1.18 → v0.1.20 float\ncanonicalization break.\n\nTests: 157 lib tests green (+2 new):\n- v279_signed_trace_verifies_via_deterministic_dispatch\n- v270_ignores_per_component_agent_id_hash_injection\n- legacy_two_field_canonical_dispatch_via_explicit_opt_in\n  (renamed from legacy_two_field_signed_trace_verifies; tests\n  explicit \"2.7.legacy\" opt-in, not silent fallback)\n\nClippy clean across all features. cargo-deny clean.\n\nDeferred to v0.3.x (per hand-off note action items):\n- Telemetry counters (federation_canonical_attempts_total +\n  federation_canonical_match_total)\n- LLMCallEvent parent_event_type/parent_attempt_index parse-time\n  enforcement at 2.7.9 (currently caught downstream at trace_llm_calls\n  insert NOT NULL or verify-canonical-mismatch)\n- VERB_SECOND_PASS_RESULT verb closed-enum parse validation\n- FEDERATION_THREAT_MODELS refresh\n- 2.7.9 fixtures from agent QA runner\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-02T17:33:06-05:00",
          "tree_id": "721690d1d9303694cd5b20ca50482405d9703e63",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/52c2df436f0a52b0cb29d07ed2b7c5d61cdc100f"
        },
        "date": 1777761595985,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 79632,
            "range": "± 918",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 197194,
            "range": "± 638",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 430581,
            "range": "± 9695",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1533404,
            "range": "± 14178",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 304,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1212,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 6479,
            "range": "± 141",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 273,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2484,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 7390,
            "range": "± 63",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 31656,
            "range": "± 109",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 520,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2070264,
            "range": "± 448432",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 5465794,
            "range": "± 2314774",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 18928463,
            "range": "± 20809324",
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
          "id": "19e8a74982ad797beb4786671cdfd18214cda567",
          "message": "0.3.1 — persist-owned cold-path PQC fill-in (CIRISPersist#10)\n\nBuilt on CIRISVerify v1.9.0's PqcSigner trait + MlDsa65SoftwareSigner.\nPersist owns the cold-path so consumers (lens, registry, partner\nsites) don't reimplement it independently and drift — same lesson as\ncanonicalize_envelope post-CIRISPersist#7.\n\nEngine constructor: optional steward_pqc_key_id + steward_pqc_key_path\n(both-or-neither). Loaded via ciris_keyring::MlDsa65SoftwareSigner::\nfrom_seed_file at construction; seed bytes never cross FFI. HW\nacceleration when post-quantum HSMs land is verify's responsibility\n(PqcSigner trait is the dispatch surface).\n\nThree new PyO3 methods on Engine (escape hatches for explicit use;\nthe auto-fire flow is the primary mechanism):\n- steward_pqc_public_key_b64() -> str (1952B raw → ~2604 chars b64)\n- steward_pqc_key_id() -> str\n- steward_pqc_sign(message: bytes) -> bytes (3309B raw sig, FIPS 204 final)\n\nAuto-fire after federation writes (the load-bearing piece):\n- Capture envelope + classical_sig BEFORE backend consumes record\n- Await synchronous put — Python returns once row lands hybrid-pending\n- tokio::spawn fire-and-forget cold-path task:\n  1. Canonicalize envelope via PythonJsonDumpsCanonicalizer\n  2. Decode classical_sig from base64\n  3. Concatenate (canonical || classical_sig) — bound signature\n  4. Sign via PqcSigner::sign\n  5. Call attach_*_pqc_signature\n\nPer V004 schema header writer contract: \"kick off IMMEDIATELY after\nEd25519 sign, not delayed/batched/scheduled, just off the synchronous\nrequest path.\" tokio::spawn post-put matches that exactly.\n\nFail-open: cold-path sign or attach failures leave row hybrid-pending;\ntracing::warn surfaces in operator logs; consumers fill via the v0.2.0\nattach_*_pqc_signature escape hatch on their own schedule.\n\nBridge action: mount lens-steward.mldsa.seed alongside the existing\nEd25519 seed; lens Engine constructor adds the two new params; every\nfederation write auto-fires PQC; 648 hybrid-pending rows fill via\nread-and-republish loop or one-shot attach.\n\nDeps:\n- ciris-keyring v1.8.6 → v1.9.0 (pqc-ml-dsa feature)\n- ciris-verify-core v1.8.6 → v1.9.0\n\n157 lib + 22 integration tests green; clippy clean; cargo-deny clean.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-02T19:11:43-05:00",
          "tree_id": "0776c104c2d99969c8891fea3558dd743436c7b6",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/19e8a74982ad797beb4786671cdfd18214cda567"
        },
        "date": 1777767661887,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 101226,
            "range": "± 3757",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 243793,
            "range": "± 2210",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 526716,
            "range": "± 2960",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1866138,
            "range": "± 14918",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 338,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1446,
            "range": "± 29",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7815,
            "range": "± 50",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 353,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3065,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 8987,
            "range": "± 59",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 40329,
            "range": "± 222",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 37",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2217935,
            "range": "± 76510",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6459134,
            "range": "± 186060",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23005378,
            "range": "± 214890",
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
          "id": "2867a2581ec10ef824e692f0e30dd5321a300e88",
          "message": "0.3.2 — cold-path PQC sweep (#11) + read-only role + schema contract (#9)\n\n## #11 — Cold-path PQC sweep\n\nv0.3.1 wired per-write cold-path; that covered every NEW row but\nleft:\n- 654 historical hybrid-pending rows in lens's federation_keys\n- No recovery for transient cold-path failures (sign error, runtime\n  panic between hot-path commit and cold-path attach, network blip,\n  process restart with cold-path tasks inflight)\n- V004 Phase 2's \"pre-flip rows walk through the upgrade pipeline\"\n  with no pipeline implementation\n\nv0.3.2 ships the pipeline:\n\n- 3 new FederationDirectory trait methods + memory/postgres/sqlite\n  impls: list_hybrid_pending_{keys,attestations,revocations}(limit)\n  returning (id, envelope, classical_sig_b64) triples for\n  WHERE pqc_completed_at IS NULL ORDER BY <natural-ts> ASC LIMIT $1\n- Engine.run_pqc_sweep(batch_size=1000) -> dict — walks each table\n  cursor-style, reuses v0.3.1's cold_path_pqc_sign helper, calls\n  attach_*_pqc_signature. Returns {scanned, signed, failed, by_table}.\n  Idempotent via attach_*_pqc_signature's WHERE pqc_completed_at IS NULL\n  guard; multi-worker concurrent sweeps waste signs on losers but\n  don't produce incorrect rows. Re-invoke until scanned == 0 to drain\n  larger backlogs.\n- pqc_sweep_on_init=True constructor param (default True when PQC\n  steward configured) — spawned as background tokio task at end of\n  Engine::new; doesn't block construction. Bridge gets the sweep\n  for free on next redeploy; 654 lens rows hybrid-complete passively.\n\n## #9 — Read-only role + public schema contract\n\nmigrations/postgres/lens/V005__readonly_role.sql: cirislens_reader\nNOLOGIN role, USAGE on cirislens schema, SELECT on all existing +\nfuture tables. Operators GRANT to a login user out-of-band; lens\nanalytical paths use that DSN. Write paths stay Engine-only.\n\ndocs/PUBLIC_SCHEMA_CONTRACT.md: column-stability contract for\nanalytical consumers.\n- stable — semver-guaranteed; removal/type-change requires major\n  bump + deprecation window\n- stable-ro — server-computed (persist_row_hash); read but writes\n  ignored\n- internal — may change at any minor (audit_* forensic fields)\n\nIncludes accord_traces → trace_events/trace_llm_calls column mapping\nso lens science scripts can migrate off the legacy denormalized table.\n\n## Tests\n\n155 lib + 22 integration tests pass; clippy clean across all features;\ncargo-deny clean. Two new memory-backend tests cover the sweep\nsubstrate.\n\n## Deps\n\nNo version changes (ciris-keyring / ciris-verify-core v1.9.0 from v0.3.1).\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-02T20:00:14-05:00",
          "tree_id": "f438dd573c7ebfa219c08af9f91daca3f94c1dcf",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/2867a2581ec10ef824e692f0e30dd5321a300e88"
        },
        "date": 1777770388117,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 102078,
            "range": "± 1219",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 254861,
            "range": "± 799",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 555698,
            "range": "± 5618",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1983514,
            "range": "± 28015",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 320,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1446,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 6568,
            "range": "± 79",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 339,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3037,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9486,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 40659,
            "range": "± 816",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 632,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2127216,
            "range": "± 95671",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6540519,
            "range": "± 89846",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 24019043,
            "range": "± 202768",
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
          "id": "9d207f9450303522fb4d28eba8f7247a788acb21",
          "message": "fmt: apply rustfmt to v0.3.2 sweep additions\n\nCI fmt-check caught three rustfmt-prefers-tighter-grouping diffs in\nthe v0.3.2 sweep code:\n- pyo3.rs:350 — single-line let summary = ...\n- pyo3.rs:1313 — single-line fn run_pqc_sweep<'py>(&self, py, batch_size)\n- pyo3.rs:1328 — block_on closure formatting\n- sqlite.rs:1048 — map_err one-liner\n\nNo semantic change. v0.3.2 wheels already published to PyPI; this\nkeeps main's clippy+fmt+audit job green for future commits.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-02T20:06:39-05:00",
          "tree_id": "b417fcaf9e75b4e282cbeb06c382fcec493ac2ae",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/9d207f9450303522fb4d28eba8f7247a788acb21"
        },
        "date": 1777770786698,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 96116,
            "range": "± 5347",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 237736,
            "range": "± 882",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 520931,
            "range": "± 132760",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1848932,
            "range": "± 19840",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 342,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1457,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7544,
            "range": "± 91",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 353,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2926,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 8975,
            "range": "± 66",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 40148,
            "range": "± 231",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 622,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2172939,
            "range": "± 75431",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6337359,
            "range": "± 257374",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 22283852,
            "range": "± 222355",
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
          "id": "335beb97d237249b6413d45cc85c61a218d9e227",
          "message": "ci: gate publish-pypi on every quality job, not just wheel build\n\nv0.3.2's tag run shipped wheels to PyPI despite a cargo fmt --check\nfailure in the lint job. publish-pypi's needs: clause only required\npyo3-wheel + build-manifest, so wheels were uploaded while clippy +\nfmt + audit was still failing.\n\nSubstantive code in v0.3.2 was unchanged (fmt-only diff caught after\npublish), so the released wheels are correct. But the gate ordering\nis wrong on principle: presence-of-wheel doesn't enforce that the\ncodebase passed lint, license-audit, integration tests, or\nplatform-specific build sanity.\n\nAdd lint + license-audit + linux-x86_64-test + darwin-aarch64-test +\nios-build to publish-pypi.needs. From v0.3.3 forward, any single\nquality-gate failure blocks the publish step.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-02T21:07:19-05:00",
          "tree_id": "2f38b9601e219d6e35fecdd137461595882ed006",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/335beb97d237249b6413d45cc85c61a218d9e227"
        },
        "date": 1777774422542,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 95061,
            "range": "± 2582",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 238278,
            "range": "± 797",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 521381,
            "range": "± 2800",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1996314,
            "range": "± 41443",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 311,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1221,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 6878,
            "range": "± 45",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 293,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3113,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9366,
            "range": "± 128",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 43392,
            "range": "± 196",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 561,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2042516,
            "range": "± 115083",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6089359,
            "range": "± 98075",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 21969019,
            "range": "± 401247",
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
          "id": "84e529b80e9869696234dc2938759af0797349da",
          "message": "0.3.3 — LLM_CALL parent linkage at 2.7.9 (CIRISPersist#12)\n\nCloses CIRISPersist#12. Paired with CIRISAgent's e714ff3c4 fix that\nwires parent_event_type + parent_attempt_index into the agent's\nLLM_CALL emission. Together they close the regression CIRISLens#5\nsurfaced: 100% of trace_llm_calls rows in the first 2.7.9 corpus\nexport carried parent_event_type='LLM_CALL' instead of the spec-\nmandated upstream-step taxonomy.\n\nTwo interlocking gaps in v0.3.0–v0.3.2:\n\n1. LlmCallSummary schema didn't model parent_event_type /\n   parent_attempt_index. Agent fix at e714ff3c4 wires the fields,\n   but persist's serde would have dropped them on parse.\n2. decompose.rs substituted component.event_type (always LlmCall for\n   an LLM_CALL component) into parent_event_type. v0.3.0's \"required\n   at 2.7.9\" deploy validation reported without_parent=0 because\n   every row had the field set — to LLM_CALL. Presence, not validity.\n\nv0.3.3:\n\n- LlmCallSummary adds parent_event_type: Option<ReasoningEventType>\n  and parent_attempt_index: Option<u32>. Option<> so 2.7.0 traces\n  continue to deserialize cleanly.\n- decompose.rs build_llm_call_row schema-version-aware sourcing:\n  - 2.7.9: BOTH fields REQUIRED. Missing → Error::Schema(\n    MissingField(\"data.parent_event_type\")) or\n    MissingField(\"data.parent_attempt_index\"). The \"required at\n    2.7.9\" claim now enforces semantic correctness.\n  - 2.7.0 and other: prefer wire value when present; fall back to\n    historical component.event_type / attempt_index substitution.\n    Existing 2.7.0 traffic continues to land. Pre-fix\n    parent_event_type='LLM_CALL' rows unrecoverable from persist\n    alone; RATCHET uses handler_name as workaround per\n    CIRISLens#5.\n\nTests:\n- 2.7.9 with both fields → wire values land on row\n- 2.7.9 missing parent_event_type → MissingField rejection\n- 2.7.9 missing parent_attempt_index → MissingField rejection\n- 2.7.0 with no parent fields → historical substitution preserved\n\n159 lib + 22 integration tests pass; clippy clean; cargo-deny clean.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-03T09:38:23-05:00",
          "tree_id": "49e9fdd6f6803467d8ba3de881eb9d97c6f3fd9a",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/84e529b80e9869696234dc2938759af0797349da"
        },
        "date": 1777819557612,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 95261,
            "range": "± 702",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 237760,
            "range": "± 1106",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 519759,
            "range": "± 1709",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 2014374,
            "range": "± 45439",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 330,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1269,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7718,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 299,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3266,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9534,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 44225,
            "range": "± 411",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 541,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2143806,
            "range": "± 56460",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6261892,
            "range": "± 137671",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 22196109,
            "range": "± 287708",
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
          "id": "3d5ce52206a59e221334efbdb05bb4ab230ea348",
          "message": "scripts: bench_trend.py — pull/summarize/plot gh-pages bench history\n\nPulls https://cirisai.github.io/CIRISPersist/dev/bench/data.js (the\nfile github-action-benchmark publishes from the Bench workflow),\ncomputes per-bench summary stats, optionally renders a per-bench\ntime-series plot or markdown report.\n\nStats include:\n- first vs last value, % change\n- min/max + noise% (max-min spread relative to median) — when noise\n  exceeds 2× the delta, flag as *noisy because the change is\n  indistinguishable from runner jitter on shared GH Actions hardware\n- alert flag matching the bench workflow's 110% threshold\n\nUsage:\n  python3 scripts/bench_trend.py                # text table\n  python3 scripts/bench_trend.py --plot out.png # PNG plot\n  python3 scripts/bench_trend.py --md report.md # MD report\n  python3 scripts/bench_trend.py --since 2026-05-02\n  python3 scripts/bench_trend.py --json         # machine-readable\n\nStandard-library only (matplotlib for --plot only).\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-03T10:00:38-05:00",
          "tree_id": "e2601729520ce788113506599d8988775366c0db",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/3d5ce52206a59e221334efbdb05bb4ab230ea348"
        },
        "date": 1777820827983,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 103644,
            "range": "± 252",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 245156,
            "range": "± 1239",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 526042,
            "range": "± 2052",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1846948,
            "range": "± 26292",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 378,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1631,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 9533,
            "range": "± 215",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 344,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3004,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9257,
            "range": "± 72",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 40596,
            "range": "± 89",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 631,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2167217,
            "range": "± 174251",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6249238,
            "range": "± 297216",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 22197790,
            "range": "± 724582",
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
          "id": "ea4e885672a1bf2f3eada9fe06df4d22cbfc0675",
          "message": "0.3.4 — deployment_profile block at 2.7.9 (CIRISPersist#13)\n\nCloses CIRISPersist#13. Companion to CIRISAgent's 431b0e0ae (#718)\nwhich added the 6-field deployment_profile block to every\nCompleteTrace envelope at trace_schema_version 2.7.9.\n\nWhat ships:\n\n- DeploymentProfile struct on CompleteTrace (6 fields:\n  agent_role, agent_template, deployment_domain, deployment_type,\n  deployment_region: Option<String>, deployment_trust_mode).\n  Option<> so 2.7.0 deserializes cleanly.\n\n- Strict-parse at 2.7.9: BatchEnvelope::from_json rejects\n  missing deployment_profile with MissingField. v0.3.0's \"required\n  at 2.7.9\" claim now enforces semantic requirement, not just\n  presence (same gate-style as v0.3.3 parent_event_type).\n\n- Cross-shape rule at 2.7.0: a 2.7.0 envelope carrying the block\n  parses cleanly but the field does NOT enter 2.7.0 canonical\n  bytes. Mirrors per-component agent_id_hash. Two traces (with vs.\n  without the block) at 2.7.0 produce byte-identical canonical bytes.\n\n- 10-key 2.7.9 outer canonical (was 9). deployment_profile sorts\n  between components and started_at alphabetically (c < d < s).\n  Inside the block, 6 fields sort alphabetically too.\n\n- V006 migration (postgres + sqlite): 6 TEXT columns on\n  cirislens.trace_events + 4 partial indexes on the high-cardinality\n  cohort axes (deployment_domain, deployment_type, agent_role,\n  deployment_trust_mode) WHERE <col> IS NOT NULL.\n\n- decompose.rs copies the 6 fields onto every event row of the\n  trace, same shape as agent_name/agent_id_hash/cognitive_state.\n  Lens analytical paths group/filter without JSONB extracts.\n\nArchitectural note: denormalization is tech-debt — same labels\nlive in payload JSONB and 6 dedicated columns. Alternative (lens-\nside trace_context table fed by separate write path) re-introduces\nthe architectural problem CIRISPersist#10 closed (one substrate,\nN consumers; drift). Persist owns it.\n\nTests: 166 lib (162 + 4 new) + 22 integration green; clippy clean.\n\nBridge: bump ciris-persist==0.3.3 → 0.3.4 in api/requirements.txt\nand deploy alongside agent 431b0e0ae. Both required for\nend-to-end linkage.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-03T12:32:01-05:00",
          "tree_id": "5003bedf413d2b1f6ff7a1f8187626a19c52cbf4",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/ea4e885672a1bf2f3eada9fe06df4d22cbfc0675"
        },
        "date": 1777829909186,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 101828,
            "range": "± 12896",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 243675,
            "range": "± 1089",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 525661,
            "range": "± 8870",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1859023,
            "range": "± 17774",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 378,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1626,
            "range": "± 36",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 9058,
            "range": "± 72",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 375,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3094,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9533,
            "range": "± 118",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41582,
            "range": "± 138",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 621,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2151384,
            "range": "± 70528",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6336474,
            "range": "± 165292",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 22544245,
            "range": "± 247061",
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
          "id": "abc684c1a0afff6c57a74ac95fd27118dfc40b41",
          "message": "0.3.5 — DSAR primitive + page-cursor read primitive (CIRISLens#8)\n\nCloses CIRISLens#8 ASKs 1 + 3. ASK 2 (v0.4.0 timing for accord_public_keys\ndual-read retirement) answered via lens#8 comment.\n\nASK 1 — Engine.delete_traces_for_agent(agent_id_hash, include_federation_key=False):\nGDPR Article 17 / DSAR primitive. Always deletes trace_events +\ntrace_llm_calls (joined by trace_id from deleted set) atomically.\ninclude_federation_key=True additionally cascades federation_keys\n+ FK-cascade attestations/revocations. Persist's federation FKs\naren't ON DELETE CASCADE; ordered delete is what makes it safe.\nIdempotent. Persist owns substrate; lens owns the DSAR audit +\nsignature verification of the request envelope.\n\nASK 3 — Engine.fetch_trace_events_page(after_event_id, limit,\nagent_id_hash=None): page-cursor read primitive. Returns up to\nlimit rows where event_id > after_event_id. Caller orchestrates\nthe cursor (no FFI re-entry per row, no callback synchronization).\nSame shape as run_pqc_sweep: cursor at trait boundary, caller\ndrives. For cross-process consumers; lens-core analytical queries\nstay on cirislens_reader + direct SQL.\n\nBackend trait additions on memory + postgres + sqlite:\n- delete_traces_for_agent(agent_id_hash, include_federation_key)\n  -> DeleteSummary\n- fetch_trace_events_page(after_event_id, limit, agent_id_hash)\n  -> Vec<(i64, TraceEventRow)>\n\nDeleteSummary in src/store/types.rs (5 u64 counts + DateTime<Utc>).\nReasoningEventType::from_wire_str inverse for row-to-struct\nconversions (pg_row_to_event_row / sqlite_row_to_event_row).\n\nTests: 168 lib (+2 new memory-backend tests) + 22 integration\ngreen; clippy clean; cargo-deny clean.\n\nBridge: bump 0.3.4 → 0.3.5 in api/requirements.txt. Lens DSAR\nhandler folds onto engine.delete_traces_for_agent — drops the\ndirect DELETE on accord_traces.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-03T13:14:13-05:00",
          "tree_id": "a161efd09d9d3cdc223ddc44f62708e0087b409b",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/abc684c1a0afff6c57a74ac95fd27118dfc40b41"
        },
        "date": 1777832430436,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 104062,
            "range": "± 1467",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 263507,
            "range": "± 2096",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 577787,
            "range": "± 2587",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 2073194,
            "range": "± 8839",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 388,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1644,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8359,
            "range": "± 36",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 362,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3155,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9686,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42296,
            "range": "± 119",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 632,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2158419,
            "range": "± 230484",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6680250,
            "range": "± 559918",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 24227435,
            "range": "± 1335245",
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
          "id": "5be19242509fd62012db51ae71c935f0b05cbc8c",
          "message": "0.3.6 — verify_hybrid primitive (#14) + per-key DSAR (#15 BREAKING)\n\nCloses CIRISPersist#14 (CIRISEdge OQ-11 day-1 hybrid posture) and\nCIRISPersist#15 (per-key DSAR authorization scope).\n\n## Engine.verify_hybrid (#14)\n\nHybrid Ed25519 + ML-DSA-65 verify for arbitrary canonical bytes.\nWraps ciris_crypto::HybridVerifier with policy machinery + PyO3\nsurface. verify-via-persist stays the federation's single-source-\nof-truth (CIRISPersist#7) — edge calling ciris_crypto directly\nwould fork canonicalization expectations + bypass policy.\n\nHybridPolicy variants:\n- Strict: reject hybrid-pending rows\n- SoftFreshness { window }: accept hybrid-pending if row_age < window\n  (V004's eventual-consistency contract; row_age caller-supplied)\n- Ed25519Fallback: always accept Ed25519-only\n\nPyO3: engine.verify_hybrid(canonical_bytes, ed25519_sig_b64,\nml_dsa_65_sig_b64, ed25519_pubkey_b64, ml_dsa_65_pubkey_b64,\npolicy=\"strict|ed25519_fallback|soft_freshness\",\nsoft_freshness_window_seconds=None, row_age_seconds=None).\n\nStable error tokens (verify_hybrid_pending_rejected,\nverify_hybrid_soft_freshness_expired, verify_hybrid_pqc_fields_mismatch,\nverify_hybrid_base64, verify_hybrid_invalid_length,\nverify_hybrid_crypto) cross PyO3 boundary as ValueError messages.\n\n## Per-key DSAR scope (#15) — BREAKING\n\nEngine.delete_traces_for_agent now REQUIRES signature_key_id.\n\nv0.3.5 took only agent_id_hash and broadened scope to all keys for\nthe agent. That's wrong: signature_key_id is the AUTHORIZATION\nSCOPE of the DSAR, not just an identity filter. A request signed\nby key A is only authorized to delete traces signed by key A.\n\nThe Option<&str> shape from #15's original ask was a footgun —\nNone would have been a forensic-deletion backdoor, and those\nbelong in standard privileged CRUD, not this primitive. v0.3.6\nmakes per-key absolute.\n\nCascade (per-key throughout):\n- trace_events: WHERE agent_id_hash AND signing_key_id\n- trace_llm_calls: joined by trace_id from deleted set\n- federation_keys (when include_federation_key=true): only the one\n  row matching (agent_id_hash, signature_key_id); other rotated keys\n  stay alive\n- FK-cascade attestations + revocations: only the one key\n\n## Deps\n\nciris-crypto added as direct dep (git v1.9.0, ed25519 + pqc-ml-dsa\nfeatures) for HybridVerifier types.\n\n## Tests\n\n177 lib (+9 new) + 22 integration green; clippy clean.\n\nverify::hybrid suite: strict / fallback / soft_freshness window\nchecks, PQC sig-without-pubkey rejection, full hybrid round-trip,\ntampered canonical rejection.\n\nDSAR: per-key scoping correct (cross-key + cross-agent rows\nsurvive), per-key LLM call cascade.\n\n## Lens action\n\nPin bump 0.3.5 → 0.3.6. DSAR handler folds onto\nengine.delete_traces_for_agent(agent_id_hash, signature_key_id) —\npreserves the per-(agent_id_hash, signature_key_id) scope lens\nalready enforces on legacy tables.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-03T13:39:05-05:00",
          "tree_id": "c48f4b6c83b4f629dc5382a2cdda09397d71243e",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/5be19242509fd62012db51ae71c935f0b05cbc8c"
        },
        "date": 1777833980588,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 79678,
            "range": "± 321",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 197265,
            "range": "± 442",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 430407,
            "range": "± 3240",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1535878,
            "range": "± 8033",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 251,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1101,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 5063,
            "range": "± 150",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 320,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2397,
            "range": "± 41",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 7608,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 32646,
            "range": "± 108",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 512,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2091315,
            "range": "± 34573698",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 5623885,
            "range": "± 48203766",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 19453194,
            "range": "± 95882435",
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
          "id": "039c0574b67bb6653a92b0010c608c8a9a4a04ad",
          "message": "threat-model: overhaul to v0.3.6 (AV-28..AV-39)\n\nDoc-only, no code change. The model was at v0.1.2 baseline + AV-17..\nAV-27 hardening; we'd shipped v0.2.0 → v0.3.6 since (federation\ndirectory, hybrid PQC, wire-format extensions, DSAR primitive,\nverify_hybrid) without updating the threat surface inventory.\nFederation peers (CIRISEdge, CIRISLens, future partner sites) read\nthis doc to know which mitigations persist owns vs which are\nconsumer-side responsibility. Stale model = consumers default to\neither over-defending or under-defending. Both fail \"make life\neasy to do things right.\"\n\nTwelve new attack vectors:\n\n  3.7 Federation directory (v0.2.0+):\n    AV-28 federation_keys directory pubkey poisoning\n    AV-29 attestation graph poisoning\n    AV-30 federation_keys self-FK integrity (DEFERRABLE)\n\n  3.8 Hybrid PQC posture (v0.2.0+):\n    AV-31 hybrid-pending exploitation\n    AV-32 cold-path PQC denial-of-completion\n    AV-33 bound-signature stripping\n\n  3.9 Wire-format extensions (v0.3.0..v0.3.4):\n    AV-34 cross-shape canonical injection\n    AV-35 schema-version dispatch attack (closed v0.3.0)\n    AV-36 LLM_CALL parent-linkage substitution (closed v0.3.3)\n    AV-37 deployment_profile cohort-identity injection\n\n  3.10 DSAR + verify primitives (v0.3.6):\n    AV-38 per-key DSAR scope violation (closed v0.3.6 BREAKING)\n    AV-39 verify-via-persist bypass (architectural closure)\n\nAlso updated:\n- §1 scope: federation directory, hybrid signing, deterministic\n  dispatch, cross-shape injection defense, deployment_profile\n  cohort identity, per-key DSAR, verify-via-persist\n- §6 assumptions 8-12 added (federation directory write authz,\n  steward key isolation, DSAR signature verification consumer-\n  side, verify-via-persist API discipline, clock skew bounded\n  for SoftFreshness)\n- §8 residual risks 11-14 added (compromised steward key,\n  hybrid-pending acceptance window, deployment_profile self-\n  classification mismatch, verify-via-persist consumer\n  discipline)\n- §9 posture summary rewritten as \"v0.3.6 Threat Posture\n  Summary\" (was \"v0.1.2 Threat Posture Summary\")\n- §10 update cadence: full landmark history v0.1.2 → v0.3.6\n\nThree architectural-closure patterns repeated across the new\nsurface:\n\n1. Single-source-of-truth substrate (CIRISPersist#7, #10, #14)\n2. Per-key authorization scope (DSAR AV-38, federation directory\n   writes AV-28)\n3. Substrate exposes edges; consumer composes policy\n   (attestation graph AV-29, verify policy AV-31/AV-39)\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-03T14:07:00-05:00",
          "tree_id": "a9ad001e1e5ce09e3cc5ea7afe27bfc8a8afe9f7",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/039c0574b67bb6653a92b0010c608c8a9a4a04ad"
        },
        "date": 1777835614745,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 90484,
            "range": "± 1488",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 233251,
            "range": "± 2755",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 515741,
            "range": "± 11610",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1923287,
            "range": "± 11671",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 303,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1213,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 6768,
            "range": "± 46",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 328,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3156,
            "range": "± 92",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9570,
            "range": "± 85",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 43873,
            "range": "± 288",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 601,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2255562,
            "range": "± 134218",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6364786,
            "range": "± 283697",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 22673056,
            "range": "± 454224",
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
          "id": "880aafa30c457a929204a3cabc9fe7fe828f3512",
          "message": "v0.4.0 [WIP]: edge_outbound_queue substrate (CIRISPersist#16)\n\nV007 migration (postgres + sqlite): new cirislens.edge_outbound_queue\ntable. 5-state machine (pending → sending → awaiting_ack → delivered\n| abandoned). Per-row policy copied at enqueue (max_attempts,\nttl_seconds, ack_timeout_seconds — message-type policy changes don't\nretroactively break in-flight rows). Optimistic claim\n(claimed_until + claimed_by) for multi-instance dispatch (CIRISEdge\nOQ-06).\n\nsrc/outbound/ — new module:\n- mod.rs: OutboundQueue trait (15 methods) + Error + types re-export\n- types.rs: OutboundRow, QueueId, OutboundStatus, AbandonedReason,\n  OutboundFailureOutcome, OutboundFilter\n\nBackend impls (memory + postgres + sqlite):\n- enqueue_outbound, claim_pending_outbound (FOR UPDATE SKIP LOCKED\n  on postgres), mark_transport_delivered, mark_transport_failed\n  (retry-vs-abandon decision in-transaction), mark_replay_resolved\n  (idempotent recovery), match_ack_to_outbound (content-derived\n  via body_sha256), mark_ack_received, sweep_ack_timeouts,\n  sweep_ttl_expired, sweep_expired_claims, outbound_status,\n  list_outbound (filter-paginated), cancel_outbound, replay_abandoned\n\nPyO3 surface:\n- engine.enqueue_outbound(...) -> queue_id\n- engine.claim_pending_outbound(batch_size, claim_duration_seconds,\n  claimed_by) -> list[dict]\n- engine.mark_transport_delivered/failed/replay_resolved\n- engine.match_ack_to_outbound(in_reply_to_sha256) -> dict|None\n- engine.mark_ack_received(queue_id, ack_envelope_bytes)\n- engine.sweep_ack_timeouts/ttl_expired/expired_claims -> int\n- engine.outbound_status(queue_id) -> dict|None\n- engine.list_outbound(filter args) -> list[dict]\n- engine.cancel_outbound/replay_abandoned\n\nStable error tokens via outbound_err_to_py: outbound_invalid_argument,\noutbound_not_found, outbound_invalid_transition, outbound_backend.\n\n177 lib tests still pass; all 3 backends compile across feature\ncombos. Outbound queue tests + drop-fallback + verify surface\nexpansion + bump + ship in followup commits.\n\nWIP for v0.4.0; not for tag yet.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-03T14:35:41-05:00",
          "tree_id": "4f793f1e40023a78b9a2fd775f19faa23f20174b",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/880aafa30c457a929204a3cabc9fe7fe828f3512"
        },
        "date": 1777837320673,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 95961,
            "range": "± 1511",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 237289,
            "range": "± 709",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 519040,
            "range": "± 2460",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1848351,
            "range": "± 15130",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 343,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1507,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7518,
            "range": "± 102",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 377,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3089,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9496,
            "range": "± 56",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41741,
            "range": "± 297",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 621,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2179674,
            "range": "± 90577",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6334790,
            "range": "± 362910",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 22456939,
            "range": "± 260285",
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
          "id": "fd914936694ea666a2b21225c15c6af040ba1547",
          "message": "0.4.0 — federation substrate cut: outbound queue + verify surface + drop legacy fallback\n\nThree architectural deliverables shipped together. Closes\nCIRISPersist#16 (CIRISEdge OQ-09) + CIRISLens#8 ASK 2 +\nCIRISLens#8 verify-surface request. Schema-stabilization release.\n\n## CIRISPersist#16 — edge_outbound_queue (CIRISEdge OQ-09)\n\nDurable substrate for CIRISEdge::send_durable(). Closed in\ncheckpoint commit (880aafa); this release ships it as the v0.4.0\ncut alongside two other commitments.\n\n## Drop accord_public_keys dual-read fallback (lens#8 ASK 2)\n\nBackend::lookup_public_key on postgres + memory + sqlite reads\nonly from federation_keys. The v0.2.1 fallback to\naccord_public_keys retired this release, coordinated with lens\ndropping its direct INSERT into accord_public_keys the same\nrelease.\n\nThe legacy table stays in the schema for historical reads via\ncirislens_reader (V005 read-only role) but the verify path no\nlonger touches it. sample_public_keys diagnostic reads\nfederation_keys so the verify-unknown-key breadcrumb sample\nmatches the actual lookup query.\n\nTests: lookup_public_key_round_trip + revoked_keys_filtered\nrewritten to use federation_keys (the latter renamed to\nexpired_keys_filtered — federation revocations are a separate\nconcern in federation_revocations post-v0.2.0).\n\n## Full verify surface for agent cutover\n\nFive new Engine verify methods so agent runtime verify can cut\nover to persist exclusively when brought in via lenscore:\n\n- engine.verify_trace(complete_trace_json) -> dict\n  Full CompleteTrace verify with internal directory lookup;\n  deterministic dispatch by trace_schema_version.\n\n- engine.verify_hybrid_via_directory(canonical_bytes,\n  signature_key_id, ed25519_sig_b64, ml_dsa_65_sig_b64, policy,\n  soft_freshness_window_seconds, row_age_seconds) -> dict\n  Convenience wrapper around verify_hybrid + lookup_public_key.\n\n- engine.verify_signed_key_record(json, policy, ...) -> dict\n- engine.verify_signed_attestation(json, policy, ...) -> dict\n- engine.verify_signed_revocation(json, policy, ...) -> dict\n  Federation directory row verify (verify-without-store) for\n  consumer-side dry-runs / trust-graph audits.\n\nThe agent's runtime verify needs (CompleteTrace, peer-message\nenvelopes, federation directory rows, ACK envelopes, arbitrary\ncanonical bytes) all map onto Engine methods. No federation peer\nneeds to call ciris_crypto::HybridVerifier directly —\nverify-via-persist is the single-source-of-truth (CIRISPersist#7\narchitectural closure repeated for the verify path).\n\n## Threat model updates\n\nAV-40 (outbound queue disk exhaustion) + AV-41 (spoofed\nin_reply_to ACK matching) added to docs/THREAT_MODEL.md §3.11.\nMitigation matrix updated. Status header bumped to v0.4.0.\n\n## Tests\n\n177 lib tests pass; clippy clean across all features; cargo-deny\nclean. The fallback retirement broke 2 tests targeting legacy\naccord_public_keys round-trip; rewritten to exercise federation_keys.\n\n## Bridge action\n\nciris-persist==0.3.6 → 0.4.0\n\nLens drops direct INSERT into accord_public_keys this release\n(v0.3.x fallback path is gone). DSAR handler folds onto\nengine.delete_traces_for_agent(agent_id_hash, signature_key_id)\nper v0.3.6's per-key contract. Agent runtime verify can now\ncut over to persist exclusively.\n\n## Schema\n\nV007 (postgres + sqlite): cirislens.edge_outbound_queue +\n6 partial indexes. accord_public_keys table NOT dropped —\nhistorical reads work; only the runtime fallback path is\nretired. v0.5.0 may drop the table itself once historical-reads\nconsumers migrate.\n\n## Deps\n\nNo version changes (ciris-keyring / ciris-verify-core /\nciris-crypto v1.9.0).\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-03T14:43:51-05:00",
          "tree_id": "d7b4871f080ef2189c4db116b576c427355312ae",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/fd914936694ea666a2b21225c15c6af040ba1547"
        },
        "date": 1777837804724,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 108647,
            "range": "± 821",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 258921,
            "range": "± 608",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 558743,
            "range": "± 1470",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1983302,
            "range": "± 4111",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 323,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1394,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 6583,
            "range": "± 34",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 361,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3069,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9628,
            "range": "± 59",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42214,
            "range": "± 1825",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2243740,
            "range": "± 116804",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 7015937,
            "range": "± 639228",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 25931686,
            "range": "± 182268",
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
          "id": "bbdd76710643a77f4837fbfc1d52a500cb4e51c1",
          "message": "0.4.1 — Rust-side verify primitives + curated prelude (CIRISEdge ask)\n\nThree asks from CIRISEdge to eliminate cross-repo drift surfaces in\nedge's verify pipeline. All non-breaking; new public Rust API surface\nonly.\n\n## verify::verify_hybrid_via_directory (Rust free function)\n\n```rust\npub async fn verify_hybrid_via_directory<F: FederationDirectory>(\n    directory: &F,\n    canonical_bytes: &[u8],\n    signing_key_id: &str,\n    ed25519_sig_b64: &str,\n    ml_dsa_65_sig_b64: Option<&str>,\n    policy: HybridPolicy,\n    row_age: Option<Duration>,\n) -> Result<VerifyOutcome, VerifyError>;\n```\n\nPyO3 Engine.verify_hybrid_via_directory now backs onto this Rust\nfree function — one implementation, both surfaces (CIRISPersist#7\nsingle-source-of-truth pattern). Same shape parse_hybrid_policy\nhelper extracted; verify_hybrid PyO3 path simplified to call it.\n\n## verify::canonicalize_envelope_for_signing (Rust free function)\n\nStrips top-level signature + signature_pqc fields, applies\nPythonJsonDumpsCanonicalizer. Closes AV-5 class drift surface\n(canonicalization mismatch between sender and verifier) by making\nthe strip rule single-source-of-truth.\n\nPyO3: engine.canonicalize_envelope_for_signing(envelope_json) -> bytes\n\n## verify::body_sha256 (Rust free function)\n\nSHA-256 of body verbatim wire bytes. Used by body_sha256_prefix\nforensic join key + in_reply_to ACK matching. Takes &RawValue so\ncallers hash bytes they received, not re-serialized form.\n\nserde_json features adds raw_value (already had arbitrary_precision).\n\nPyO3: engine.body_sha256(body_bytes) -> bytes\n\n## ciris_persist::prelude\n\nCurated re-exports for federation peers:\n- Trait surfaces: FederationDirectory, OutboundQueue, Backend\n- Verify primitives: verify_hybrid_via_directory + via_directory\n  variants, canonicalize_envelope_for_signing, body_sha256, etc.\n- Outbound types: AbandonedReason, OutboundFailureOutcome,\n  OutboundFilter, OutboundRow, OutboundStatus, QueueId\n- Federation types: Attestation, HybridPendingRow, KeyRecord,\n  Revocation, SignedAttestation, SignedKeyRecord, SignedRevocation\n\n`use ciris_persist::prelude::*` covers the substrate surface in\none import. Curated (not glob re-export); internal types stay\nsub-module-imported.\n\n## Tests\n\n179 lib (+2 new) + 22 integration green; clippy clean; cargo-deny\nclean. Tests verify:\n- canonicalize_envelope_for_signing strips signature fields →\n  signed and unsigned envelopes produce byte-identical canonical\n- body_sha256 == sha256(body.get().as_bytes()) directly\n\nEdge's verify pipeline collapses from ~150 lines hand-rolled to\n~30 lines composed against persist's prelude.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-03T15:47:56-05:00",
          "tree_id": "eb9a7e1e9d9a5afd3b78e74460b0111dbf9538a2",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/bbdd76710643a77f4837fbfc1d52a500cb4e51c1"
        },
        "date": 1777841731762,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 109000,
            "range": "± 361",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 260542,
            "range": "± 9461",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 563478,
            "range": "± 5818",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1998706,
            "range": "± 147062",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 343,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1342,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8218,
            "range": "± 310",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 358,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3281,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9806,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42166,
            "range": "± 95",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 649,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2248358,
            "range": "± 121535",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 7011603,
            "range": "± 147435",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 25855154,
            "range": "± 502984",
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
          "id": "b0f6fa4bb321ed65a32b268be9b842c11be2814b",
          "message": "0.4.2 — Rust-public StewardSigner (CIRISPersist#17, CIRISLensCore)\n\nCloses CIRISPersist#17. CIRISLensCore (rlib path, never PyO3) needs\nto sign detection events via persist's steward identity per its\nmission lock-in. v0.4.2 lifts the construction + sign primitives\nto a Rust-public struct and refactors PyO3 Engine to back onto it\n— one implementation, both surfaces (CIRISPersist#7 pattern).\n\n## signing::StewardSigner (Rust public API)\n\n- StewardSignerConfig: key_id + key_path + optional pqc_key_id +\n  pqc_key_path. Both-or-neither PQC pair validated at construction.\n- StewardSigner::from_config — mirrors PyO3 Engine ctor steward\n  wiring exactly (32-byte raw Ed25519 seed + MlDsa65SoftwareSigner\n  from_seed_file). Same tracing::info observability shape.\n- sign_ed25519(message) -> [u8; 64] — hot path; sync.\n- sign_ml_dsa_65(message) -> Vec<u8> — cold path; async (PqcSigner\n  trait async; HW signers may dispatch async I/O).\n- sign_hybrid(message) -> HybridSignature — Ed25519 + ML-DSA-65\n  over `(message || classical_sig)` (bound signature) returning\n  ciris_crypto::HybridSignature shape.\n- Accessors: key_id, pqc_key_id, public_key_b64,\n  pqc_public_key_b64 (async).\n\nConstruction errors typed: SeedRead, SeedLength,\nPqcConfigInconsistent, PqcSeedLoad. Sign errors typed:\nPqcNotConfigured, PqcSign.\n\n## PyO3 refactor — single-source-of-truth\n\nPyEngine previously held 4 steward fields (steward_signing_key,\nsteward_key_id, steward_pqc_signer, steward_pqc_key_id). v0.4.2\ncollapses to one Option<Arc<StewardSigner>>; PyO3 methods are now\nthin wrappers:\n\n- engine.steward_sign → signer.sign_ed25519\n- engine.steward_pqc_sign → signer.sign_ml_dsa_65\n- engine.steward_public_key_b64 → signer.public_key_b64\n- engine.steward_pqc_public_key_b64 → signer.pqc_public_key_b64\n- engine.steward_key_id → signer.key_id\n- engine.steward_pqc_key_id → signer.pqc_key_id\n\nCold-path PQC fill-in spawns capture signer.pqc_signer_arc()\ninstead of the old direct steward_pqc_signer.clone().\n\nPython contract is unchanged — error tokens, return shapes,\nboth-or-neither validation all match v0.4.1 byte-for-byte. The\ninline seed-load logic moved to StewardSigner::from_config; PyO3\ncalls it.\n\n## Prelude\n\nprelude::* now also includes StewardSigner, StewardSignerConfig,\nStewardSignerError.\n\n## Tests\n\n183 lib (+4 new signing tests) + 22 integration green; clippy\nclean; cargo-deny clean.\n\nCIRISLensCore Phase 1 detection-event signing (LC-AV-2, LC-AV-11,\nLC-AV-18) can now compose against StewardSigner directly.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-03T17:32:20-05:00",
          "tree_id": "c5e821c9c4ff8724aee99089a45c3403ff88bc26",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/b0f6fa4bb321ed65a32b268be9b842c11be2814b"
        },
        "date": 1777847936144,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 101625,
            "range": "± 2178",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 242304,
            "range": "± 1787",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 525785,
            "range": "± 23586",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1853552,
            "range": "± 24769",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 374,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1515,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8707,
            "range": "± 680",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 360,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3012,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9399,
            "range": "± 32",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41465,
            "range": "± 1277",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 625,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2271632,
            "range": "± 113411",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6632747,
            "range": "± 68553",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23681042,
            "range": "± 217014",
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
          "id": "826c142d1ce4988d7772141f5b381b7e2e54784f",
          "message": "0.4.3 — lens-derived schemas + 2.7.legacy restoration (CIRISPersist#18 + #21)\n\nTwo issues, one release. Both close federation-coordination work:\n#18 unblocks CIRISLensCore Phase 1 P0 ASKs + RATCHET projection-v1\npublication; #21 fixes a v0.4.0 regression that left pre-2.7.8.9\nfederation peers unable to federate.\n\nCIRISPersist#18 — cirislens_derived schemas\n- V008 migration: cirislens_derived.{detection_events, calibration_bundles}.\n  Hybrid-sig CHECK constraints (Ed25519 = 64 bytes, ML-DSA-65 = 3309\n  bytes per FIPS 204 final). Partial-unique index for atomic is_current\n  flip on calibration bundles.\n- src/derived/ module: DerivedSchema trait + 5 methods\n  (put_detection_event, get_detection_events, put_calibration_bundle,\n  get_current_calibration_bundle, get_calibration_bundle_by_version).\n  Full Postgres impl; NotImplemented stubs on Memory + SQLite.\n- Engine PyO3 surface verifies hybrid sigs via\n  verify_hybrid_via_directory under HybridPolicy::Strict before\n  backend write — both signatures must verify; no fallback.\n  CIRISPersist#7 single-source-of-truth: canonical_bytes runs through\n  persist::prelude::canonicalize_envelope_for_signing only.\n\nCIRISPersist#21 — restore 2.7.legacy under telemetry-driven sunset\n- SUPPORTED_VERSIONS now [\"2.7.0\", \"2.7.9\", \"2.7.legacy\"].\n- BatchEnvelope.trace_schema_version + CompleteTrace.trace_schema_version\n  get serde-default = \"2.7.legacy\". Pre-2.7.8.9 agents stamped no\n  version field at all (the field landed in CIRISAgent commit 431b0e0ae\n  alongside the 9-field cutover); absence is now the deterministic\n  signal for the 2-field canonical — NOT a try-list fallback.\n- Telemetry: tracing::info!(target: \"federation_canonical_match\",\n  wire = ..., trace_id = ...) per verify dispatch. Operator log\n  aggregation tallies wire = \"<dialect>\" emissions for the 7-day\n  zero-traffic sunset rule.\n\nTests: 175/175 lib tests pass. New tests:\n- absence_routes_to_legacy: round-trips a wire with NO\n  trace_schema_version through verify; asserts default kicks in,\n  is_supported accepts, dispatch routes to 2-field canonical, sig\n  verifies.\n- 4 Postgres integration tests for derived schemas (round-trip,\n  conflict-on-different-content, atomic is_current flip, signature\n  length validation).\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-08T12:49:12-05:00",
          "tree_id": "ca97b21784a9a0fc5b13f310c8a2d92d257e5df9",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/826c142d1ce4988d7772141f5b381b7e2e54784f"
        },
        "date": 1778263211575,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 109374,
            "range": "± 855",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 260653,
            "range": "± 1565",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 561930,
            "range": "± 11847",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1995251,
            "range": "± 41702",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 341,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1452,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8309,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 350,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3027,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9618,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41611,
            "range": "± 425",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2242998,
            "range": "± 89708",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 7052307,
            "range": "± 635049",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 25913871,
            "range": "± 660361",
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
          "id": "ef1ed0ac362e03b21c99ac5ae6940f64e18eed36",
          "message": "0.4.4 — CI hygiene patch + pre-commit/pre-push hooks + bump script\n\nCI regressions on v0.4.3 (commit 826c142) didn't surface locally:\n\n1. server::tests::health_endpoint_returns_supported_versions asserted\n   vec![\"2.7.0\", \"2.7.9\"] against the v0.3.x-era hardcoded list.\n   v0.4.3's #21 work added \"2.7.legacy\" to SUPPORTED_VERSIONS without\n   updating this test. Fixed.\n2. cargo fmt --check flagged formatting drift in 4 files (introduced\n   during v0.4.3 work without a follow-up cargo fmt). Fixed via\n   cargo fmt --all.\n\nNo behavioral change. Functionality identical to v0.4.3.\n\nProcess additions to prevent this regression class:\n\n- scripts/hooks/pre-commit — runs cargo fmt --check + cargo clippy\n  (full features, all targets, -D warnings) before every commit.\n  Matches CI's strictest job; ~10s vs the 5+ min CI round-trip.\n- scripts/hooks/pre-push — runs cargo test --lib (server + pyo3\n  features) against the pushed range. Skips pushes that don't touch\n  Rust.\n- scripts/install-hooks.sh — symlinks hooks into .git/hooks/.\n  Idempotent; backs up pre-existing hooks. Run once after fresh\n  clone.\n- scripts/bump_version.sh <X.Y.Z> — bumps Cargo.toml [package].version,\n  prepends a dated CHANGELOG entry skeleton, refreshes Cargo.lock\n  via cargo check. Idempotent.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-08T13:01:29-05:00",
          "tree_id": "5fc00d5c5cac7b5889c2a36cfd628f528a02863e",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/ef1ed0ac362e03b21c99ac5ae6940f64e18eed36"
        },
        "date": 1778263698446,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 101347,
            "range": "± 271",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 241905,
            "range": "± 814",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 522937,
            "range": "± 3201",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1850474,
            "range": "± 19246",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 378,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1540,
            "range": "± 69",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8681,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 369,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3037,
            "range": "± 38",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9396,
            "range": "± 51",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41597,
            "range": "± 183",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 621,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2159662,
            "range": "± 37236",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6513615,
            "range": "± 50195",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23568918,
            "range": "± 343702",
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
          "id": "63eae10f9ba68904a91e09cb89f2ab67e526aa5f",
          "message": "0.4.5 — bump CIRISVerify deps v1.9.0 → v1.13.2 (CIRISPersist#20)\n\nPure dep-only bump. No public-API changes in persist; no behavior\nchange in any code path. cargo build + cargo test --lib (179 tests)\n+ cargo clippy -D warnings all pass against v1.13.2.\n\nWhy we jumped past the issue's v1.10.1 target: verify shipped four\nminor versions in the interim (v1.10.0 → v1.13.2). v1.10.0..v1.13.2\nis all CLI / RegistryClient / `verify_tree` work — nothing touches\n`ciris-keyring`, `ciris-verify-core`'s HybridVerifier, or\n`ciris-crypto`'s primitive surface that persist consumes today. So\nwe land on the current verify line in one move.\n\nWhat v1.13.0's `verify_tree` is for (informational): runtime tree-\nwalking verifier closing CIRISVerify#9. Walks a source tree, hashes\nvia the same Algorithm A `ciris-build-sign sign --tree` writes into\n`builds.file_manifest_hash`, returns per-file divergences. CIRISAgent\nuses it for L4 file-integrity attestation\n(`ciris_engine/.../attestation/tree_verify.py`); persist itself\ndoesn't call it.\n\nReadiness for CIRISVerify v2.0: CIRISVerify#7 is the prereq for\nCIRISPersist#19's federated SecretsService — verify v2.0 (or v1.14.x\npatch) must add `aes-gcm`, `kdf` (PBKDF2+HKDF), `hmac`, and `random`\nfeatures to ciris-crypto. v0.4.5 lands persist in shape so this is a\nsingle Cargo.toml tag flip + cargo features turn-on when verify\nships. The crypto-through-ciris-crypto invariant (FSD §7.5a) is\nunchanged: persist takes ZERO direct deps on AES-GCM/PBKDF2/HKDF/HMAC\nprimitive crates ever.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-08T21:34:25-05:00",
          "tree_id": "c610dea904e6d4b20d0a58dd304ea61d192e8e83",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/63eae10f9ba68904a91e09cb89f2ab67e526aa5f"
        },
        "date": 1778294594497,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 107731,
            "range": "± 740",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 249380,
            "range": "± 3125",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 532698,
            "range": "± 2713",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1872639,
            "range": "± 23721",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 346,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1431,
            "range": "± 32",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8281,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 362,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3084,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9535,
            "range": "± 44",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41382,
            "range": "± 125",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2298574,
            "range": "± 73137",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6761545,
            "range": "± 158301",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23959569,
            "range": "± 228375",
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
          "id": "de25e97712298cf322d42e84eab54dc5d71adbe4",
          "message": "0.4.6 — legacy attempt_index gate + decompose error reclass (CIRISPersist#22)\n\nPre-2.7.8 emitters never populate `data.attempt_index`. Two persist-\nside bugs were chaining off this:\n\n1. `decompose` raised `Schema(MissingField(\"attempt_index\"))` for\n   any pre-2.7.8 component. Per the v0.4.3 (#21) legacy restoration,\n   those traces SHOULD ingest cleanly.\n2. `ingest.rs:229` mis-classified the schema reject as a `Store`\n   error, sending 503 + Retry-After instead of 422. Agents retried\n   forever on a deterministic 4xx.\n\nFixes:\n\n- `decompose.rs:82` — schema-version-gated attempt_index sourcing,\n  same shape as the existing parent_event_type/parent_attempt_index\n  gate (CIRISPersist#12, v0.3.3). 2.7.9 strict; 2.7.0/2.7.legacy\n  fall back to 0 ONLY for the absence case. Malformed values\n  (negative, wrong type, out of range) still error.\n- `ingest.rs:229` — typed Schema/Store split in the decompose\n  map_err: `store::Error::Schema(s) → IngestError::Schema(s)`,\n  other → `IngestError::Store`. Stops the 503-retry loop on\n  deterministic schema mismatches. The two `insert_*_batch`\n  callsites stay on Store (they legitimately return backend-write\n  errors).\n- `IngestError::detail()` + `schema::Error::detail()` — non-breaking\n  field-name surfacing. PyO3 emits Python exception `args` as\n  `(kind, detail)` when detail is present, `(kind,)` otherwise.\n  Lens consumers read `e.args[1]` for the field name without\n  source-diving persist.\n\nTests: 184 pass (5 new over baseline 179). Load-bearing:\n`decompose_schema_error_routes_to_schema_variant` explicitly panics\nwith REGRESSION marker if the fix is reverted.\n\nOut of scope follow-up: `LlmCallSummary` carries its own typed\n`attempt_index: u32`. If bridge traffic includes pre-2.7.8 LLM_CALL\ncomponents, lifting that into the legacy fallback is a separate\nissue.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-08T22:36:30-05:00",
          "tree_id": "737c63d72e99cd74f65f1ce1c5e76dff24dc3102",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/de25e97712298cf322d42e84eab54dc5d71adbe4"
        },
        "date": 1778298254767,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 105775,
            "range": "± 5154",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 246470,
            "range": "± 2443",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 528871,
            "range": "± 2030",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1857666,
            "range": "± 18139",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 349,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1513,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8244,
            "range": "± 103",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 365,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3150,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9657,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42215,
            "range": "± 1235",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 621,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2252721,
            "range": "± 96184",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6606224,
            "range": "± 74023",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23662858,
            "range": "± 506014",
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
          "id": "85b2b31714b0cc3b9c1a5c0bbfbbef3c1b774419",
          "message": "0.4.7 — threat-model: AV-35 clarified + AV-42 added (v0.4.3/v0.4.6 accommodation)\n\nPure documentation. No code change. Functionality identical to v0.4.6.\n\nThe v0.4.3 (#21) restoration of \"2.7.legacy\" plus the v0.4.6 (#22)\nattempt_index=0 fallback at the legacy arm exposed two gaps in\ndocs/THREAT_MODEL.md:\n\n1. AV-35 mitigation language overstated by claiming the routing\n   input itself is signed. True at 2.7.0/2.7.9 (both 9-field\n   canonicals carry trace_schema_version as a signed field); NOT\n   true at 2.7.legacy (2-field canonical only signs\n   {components, trace_level}). The actual load-bearing safety\n   property is verify-bound-to-arm-canonical: a signature signed\n   against arm-A's canonical cannot pass arm-B's verification.\n   Routing-input forgery buys an attacker nothing because the\n   verify step deterministically fails on wrong-arm reconstruction.\n   Narrative + summary table updated.\n\n2. AV-42 added: Legacy attempt_index dedup-collapse. Pre-2.7.8.9\n   emitters that don't populate data.attempt_index collapse retries\n   on the dedup tuple. Schema-version-gated (only 2.7.0 and\n   2.7.legacy); 2.7.9 still strict; malformed still errors through\n   AV-17. Sunset by federation_canonical_match_total{wire=\"2.7.legacy\"}\n   7-day-zero soak. Bounded by signing-key control. Cross-agent\n   collision closed by agent_id_hash in dedup tuple (AV-9, v0.1.2).\n   Lens-side synthesis impossible (legacy 2-field canonical signs\n   components[].data; mutation invalidates verify) — federation's\n   append-only contract takes priority over per-row dedup fidelity\n   at the legacy arm.\n\n§9 Threat Posture Summary updated: v0.3.6 → v0.4.6. Added blocks\nfor v0.4.0 outbound queue (AV-40, AV-41 — already shipped, previously\nuncatalogued in §9) and v0.4.3..v0.4.6 legacy accommodation\n(AV-35 preserved, AV-42 documented residual). Total closed:\nfifteen v0.2.0..v0.4.6 attack vectors.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-09T11:33:05-05:00",
          "tree_id": "99de63a2762554aa74bbabb68dbd098944ebf25f",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/85b2b31714b0cc3b9c1a5c0bbfbbef3c1b774419"
        },
        "date": 1778344921797,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 102360,
            "range": "± 844",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 242838,
            "range": "± 683",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 524127,
            "range": "± 1580",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1855738,
            "range": "± 18411",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 365,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1587,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8733,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 368,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3149,
            "range": "± 45",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9734,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42163,
            "range": "± 153",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2473251,
            "range": "± 231353",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6752350,
            "range": "± 269048",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 24071769,
            "range": "± 863977",
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
          "id": "b7be5bbb64ef1b11506aa60e28fbd0c81f756399",
          "message": "WIP v0.5.0 — federation read primitives foundation (CIRISPersist#23)\n\nTrait surface + typed shapes + skeleton stubs for the v0.5.0 batch\n(sections A/B/F/E per FSD/V0_5_0_FEDERATION_READ_PRIMITIVES.md).\nPostgres impl + PyO3 wrappers + threat model + tests land in\nfollow-up commits before the v0.5.0 tag.\n\nSurface duality (v0.4.1 verify-primitive precedent): every primitive\nwill land as Rust-public ReadEngine trait method + PyO3 wrapper on\nEngine. Single source of truth.\n\nModule shape:\n  src/read/mod.rs      — ReadEngine trait (12 methods) + Error +\n                         module docs\n  src/read/types.rs    — TimeWindow, TraceCursor, TraceFilter,\n                         DeviationMetric\n  src/read/trace.rs    — Section A/B/F: TraceSummary, TraceListPage,\n                         TraceDetail, TraceComponentRow,\n                         TraceEnvelopeRefs, DivergenceRow,\n                         TemporalDriftRow, HashChainGap, OverrideRateRow\n  src/read/scoring.rs  — Section E: ScoringFactorAggregate,\n                         RecoveryEvent, CoherencePoint,\n                         AuditChainAggregate\n\nBackend impls:\n  - Memory  → NotImplemented for all 12 (read primitives are SQL-heavy\n              aggregates that don't fit the in-memory shape)\n  - SQLite  → NotImplemented for all 12 (v0.6.x sovereign-mode track\n              ports A/B/F where the shape transfers; E falls back to\n              raw-window queries)\n  - Postgres → NotImplemented for all 12 today; section impls land\n              in follow-up commits\n\nTrait + Section types in prelude.\n\nThreat-model invariants documented inline in mod.rs:\n  - AV-9: trace-scoped reads carry agent_id_hash so callers\n          authorize at their layer\n  - AV-15: error kinds are closed-set &'static str tokens\n  - AV-43: read-side adversary section to be added to\n          docs/THREAT_MODEL.md when v0.5.0 ships\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-10T15:29:56-05:00",
          "tree_id": "9a99d1579d64fdcde089b349fcca029b9d942d85",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/b7be5bbb64ef1b11506aa60e28fbd0c81f756399"
        },
        "date": 1778445499600,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 96042,
            "range": "± 930",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 238915,
            "range": "± 3399",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 520857,
            "range": "± 3633",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1942612,
            "range": "± 27235",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 304,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1206,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7218,
            "range": "± 70",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 318,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3259,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9832,
            "range": "± 45",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 44441,
            "range": "± 152",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 538,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2063256,
            "range": "± 37686",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6398490,
            "range": "± 56773",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23416698,
            "range": "± 183813",
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
          "id": "00e07fb5fae746c3db2136e67ffe3ea5655f18e0",
          "message": "WIP v0.5.0 §A — list_trace_summaries + get_trace_summary postgres impl\n\nLens-bleeding endpoint /repository/traces (CIRISLens#10) unblocked.\n\nAlgorithm:\n- Single-pass GROUP BY trace_id with FILTER (WHERE event_type = '...')\n  aggregation extracting DMA / conscience / action / thought-metadata\n  from JSONB payload per event_type. No N+1 round-trips.\n- ORDER BY started_at DESC, trace_id DESC (newest-first triage).\n- Cursor: HAVING (MIN(ts), MIN(trace_id)) < (cursor_ts, cursor_id)\n  — row-tuple comparison gives strict-less-than ordering matching\n  the ORDER BY direction.\n- LIMIT bound 1..=10000 (above is operator-misuse; below is no-op).\n\nJSONB extracts (TRACE_SUMMARY_SELECT shared between get + list):\n- THOUGHT_START → thought_type, thought_depth\n- DMA_RESULTS → csdma_plausibility_score, dsdma_domain_alignment,\n                dsdma_domain\n- IDMA_RESULT → idma_k_eff, idma_correlation_risk,\n                idma_fragility_flag, idma_phase\n- CONSCIENCE_RESULT → conscience_passed, action_was_overridden +\n                      4 per-axis pass flags\n- ACTION_RESULT → selected_action, action_success\n- Cost columns — already denormalized; no JSONB extraction\n\nIndex coverage:\n- agent_id_hash filter → trace_events_dedup leading column\n- agent_name filter → trace_events_agent_ts\n- No-filter → time hypertable scan in newest-first order\n\nWire types unchanged from foundation commit b7be5bb. Memory + SQLite\nbackends still NotImplemented for §A. Sections B/F/E + PyO3 +\nthreat-model AV-43 still pending before v0.5.0 tag.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-10T15:33:56-05:00",
          "tree_id": "fa47611f4301c86a694f0e54ffe9d99632f5e689",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/00e07fb5fae746c3db2136e67ffe3ea5655f18e0"
        },
        "date": 1778445733680,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 101675,
            "range": "± 365",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 242683,
            "range": "± 573",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 527152,
            "range": "± 2800",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1859908,
            "range": "± 23278",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 346,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1442,
            "range": "± 42",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8189,
            "range": "± 170",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 360,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3248,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9741,
            "range": "± 134",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42608,
            "range": "± 297",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 621,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2306862,
            "range": "± 142992",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6647259,
            "range": "± 581467",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23964575,
            "range": "± 591837",
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
          "id": "9e96b335a32ad9661ca7cfc168c2dfe35baa251a",
          "message": "WIP v0.5.0 §A tests — list_trace_summaries + get_trace_summary\n\n6 integration tests against real Postgres (gated on\nCIRIS_PERSIST_TEST_PG_URL; CI workflow ci.yml already sets this):\n\n- get_trace_summary_round_trip — insert 5-component fixture trace\n  (THOUGHT_START + DMA_RESULTS + IDMA_RESULT + CONSCIENCE_RESULT +\n  ACTION_RESULT); read summary; assert every JSONB-extracted field\n  matches (DMA scores, IDMA flags, conscience flags, action result,\n  cost columns).\n- get_trace_summary_unknown_returns_none — typed None, not Err.\n- list_cursor_pagination — 5 traces with staggered started_at;\n  page through with limit=2; no overlap, no gaps,\n  next_cursor=None when items.len() < limit.\n- agent_id_hash_isolation — AV-9 invariant: filter by agent A\n  excludes agent B; every returned summary carries agent_id_hash.\n- list_limit_boundaries — limit=0 + limit=10001 → InvalidArgument;\n  limit=1 accepts.\n- invalid_cursor_version_rejects — version=\"v99\" → InvalidCursor.\n\nAll 6 pass against local postgres:15-alpine (timescaledb-less; the\nV001 hypertable conversion is gated on pg_extension lookup so the\nmigration runs cleanly without it).\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-10T15:38:37-05:00",
          "tree_id": "230b17ea7cb419c640020603bc8a6899fad08213",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/9e96b335a32ad9661ca7cfc168c2dfe35baa251a"
        },
        "date": 1778446008303,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 105331,
            "range": "± 2725",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 246137,
            "range": "± 791",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 526933,
            "range": "± 3149",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1855377,
            "range": "± 10130",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 345,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1465,
            "range": "± 32",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8259,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 365,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3222,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9602,
            "range": "± 28",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41425,
            "range": "± 85",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 621,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2326343,
            "range": "± 237423",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6678568,
            "range": "± 146869",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23811933,
            "range": "± 285610",
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
          "id": "17f57e5a49969e7abf718bf71605c7386ae325e7",
          "message": "WIP v0.5.0 §B — get_trace_detail postgres impl + tests\n\nDrives /repository/traces/{trace_id} (CIRISLens explore-a-trace page).\n\nThree queries, one round-trip each:\n1. Summary view — composes against §A's get_trace_summary (no SQL\n   duplication; same JSONB-extracting GROUP BY).\n2. trace_events rows for the trace_id, ts ASC (chronological\n   component sequence). Returned as TraceComponentRow (drops the\n   per-row signature/scrub fields — those are envelope constants\n   folded into TraceEnvelopeRefs).\n3. trace_llm_calls rows for the trace_id, ts ASC.\n\nEnvelope refs read from the first component row (per-trace\nconstants by construction; AV-24/25 scrub envelope + signature are\nagent-emit-time invariants, equal across all rows of one trace).\n\nConcurrent-delete handling: if summary returned Some but components\nare empty, return None (consistent surface for callers to retry).\n\nNew helper: pg_row_to_llm_call_row() — typed decode of\ntrace_llm_calls rows. Mirrors pg_row_to_event_row's shape; reads\nonly the columns selected by §B's LLM-calls SELECT.\n\nTests (3, all green against local postgres:15-alpine):\n- get_trace_detail_round_trip — 5-component fixture + 1 LLM call\n  row; assert summary parity with §A; components chronological;\n  LLM call surfaces; envelope refs reflect fixture constants.\n- get_trace_detail_unknown_returns_none — typed None.\n- no_llm_calls_returns_empty_vec — trace without LLM calls still\n  produces TraceDetail; llm_calls is empty Vec, not None on the\n  overall TraceDetail.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-10T15:41:58-05:00",
          "tree_id": "2f10de216b40fa33a0fe5de0f80f2c976dfe54c0",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/17f57e5a49969e7abf718bf71605c7386ae325e7"
        },
        "date": 1778446321442,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 95946,
            "range": "± 3231",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 238375,
            "range": "± 500",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 520467,
            "range": "± 3819",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1940466,
            "range": "± 23778",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 305,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1197,
            "range": "± 23",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7168,
            "range": "± 122",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 318,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3210,
            "range": "± 28",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9898,
            "range": "± 184",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 44164,
            "range": "± 104",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 537,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2650254,
            "range": "± 274147",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 7050001,
            "range": "± 378910",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 24295166,
            "range": "± 517676",
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
          "id": "190e5bb3badda85137cecaf843660bed4c95b5ac",
          "message": "WIP v0.5.0 §F — Coherence Ratchet inputs (4 methods + 5 tests)\n\nDrives /coherence-ratchet/stats (currently 500'ing in lens because\nit queries accord_traces directly). Lens consumes these inputs;\nclustering / detection logic stays in lens.\n\ncross_agent_divergence(domain, window, metric):\n- Numerical metrics (CSDMA / DSDMA / IDMA k_eff / IDMA correlation_risk):\n  per-agent AVG of the JSONB field over the relevant event_type rows,\n  z-scored against the domain population mean+std (STDDEV_SAMP).\n- ConscienceOverrideRate: per-trace BOOL_OR collapse of recursive\n  CONSCIENCE_RESULT retries → per-agent rate over distinct traces →\n  z-scored across the domain.\n- Ordered by |z_score| DESC (most-divergent agents first).\n\ntemporal_drift(agent, baseline, comparison):\n- One row per metric (4 numerical metrics) where BOTH windows had\n  samples. Welch-style z-score on the mean shift; lens applies its\n  own p-value mapping.\n- mean_shift = comparison_mean - baseline_mean (negative when agent\n  scores worse over time on the metric).\n- variance_ratio = comparison_var / baseline_var (>1 = wider spread).\n\nhash_chain_gaps(agent, window):\n- LAG window function over audit_sequence_number to find\n  non-contiguous pairs. Audit sequence is populated only on\n  ACTION_RESULT rows per V001 schema.\n- Returns (gap_start_seq, gap_end_seq, gap_start_ts, gap_end_ts) per\n  detected discontinuity.\n\nconscience_override_rates(domain, window):\n- Per-trace was_overridden = BOOL_OR over recursive CONSCIENCE_RESULT.\n- Per-agent override_count / trace_count.\n- Domain avg = SUM(overrides) / SUM(traces) — population-weighted\n  (not mean-of-rates) so high-volume agents dominate the reference.\n- multiple_of_domain_avg = override_rate / domain_avg (>1.0 means\n  the agent overrides more than peers).\n\nTests (5, all green against local postgres:15-alpine):\n- cross_agent_divergence_csdma: 3 agents, one outlier; assert\n  outlier has the largest |z_score|; sample_count matches fixture.\n- cross_agent_divergence_override_rate: agent-A 1/3 overrides,\n  agent-B 0/3; A's z > 0; B's z < 0.\n- temporal_drift: varied csdma values across windows (constant\n  values produce var=0 → significance=0; meaningful test needs\n  spread); assert mean_shift = -0.3 and significance < 0.\n- hash_chain_gaps: insert audit_sequence_number = 1,2,5,6; detect\n  gap (start=2, end=5).\n- conscience_override_rates: agent-A 2/4, agent-B 1/4; domain avg\n  = 3/8; multiples = 4/3 and 2/3 respectively.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-10T15:47:04-05:00",
          "tree_id": "4b41d80cc006d4a7924b0ef0a7617c03c18b3971",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/190e5bb3badda85137cecaf843660bed4c95b5ac"
        },
        "date": 1778446505483,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 113746,
            "range": "± 7579",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 264649,
            "range": "± 4379",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 564168,
            "range": "± 2221",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1993180,
            "range": "± 85735",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 353,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1500,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7384,
            "range": "± 29",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 364,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2931,
            "range": "± 44",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9642,
            "range": "± 243",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42259,
            "range": "± 253",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2271185,
            "range": "± 81956",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 7019815,
            "range": "± 126382",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 25800985,
            "range": "± 701950",
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
          "id": "d98dfabbd002651d89e4100204f61e3d0d006bbe",
          "message": "WIP v0.5.0 §E — ScoringFactorAggregate + batch + 4 granular (5 tests)\n\nReplaces api/scoring.py raw SQL. The \"big aggregate\" of #23.\n\naggregate_scoring_factors(agent, window, baseline?):\n- 4 round-trips composing all Capacity Score factor inputs:\n  1. Per-trace collapse + window-wide counts (trace_count,\n     identity_changes, conscience_overrides, audit_chain_total,\n     audit_signed_total, unsafe_action_count). One CTE pass.\n  2. Audit-chain gap count via LAG window (cheap, single row).\n  3. Recovery events (top 50 most-recent override → next-pass\n     pairs) via LEAD window over per-trace started_at.\n  4. Coherence decay series (~24 buckets across the window;\n     min 1-minute buckets for sub-hour windows) via to_timestamp\n     bucket math.\n- drift_z_score: when baseline_window provided, delegates to\n  temporal_drift on csdma_plausibility_score.\n- calibration_error: None for v0.5.0 (epistemic_certainty isn't\n  in persist's wire format yet — wire up when that field flows).\n\naggregate_scoring_factors_batch(agents, window, baseline?):\n- Loop over agents calling the single-agent path. Future\n  optimization (single-query batched aggregation) deferred to\n  v0.5.x; lens-side batched calls are <100 agents today.\n\nGranular primitives — composable narrower questions:\n- count_traces(filter) — DISTINCT trace_id count.\n- count_overrides(filter) — BOOL_OR per-trace dedupe of recursive\n  CONSCIENCE_RESULT retries.\n- count_identity_changes(filter) — agent_name-rename count\n  (agent_id_hash IS the identity fingerprint by construction).\n- aggregate_audit_chain(filter) — total / signed / hashed +\n  gap_count (gap_count meaningful only when filter narrows to one\n  agent — cross-agent sequences interleave; documented).\n\nHelper: build_filter_where(filter) → (SQL fragment, boxed params).\nUsed by all granular primitives. §A's list_trace_summaries builds\nits own WHERE inline because it composes WHERE+HAVING+ORDER+LIMIT.\n\nCoherencePoint added to prelude exports (was missing).\n\nTests (5, all green against local postgres:15-alpine):\n- aggregate_scoring_factors_round_trip — 4-trace fixture w/ 1\n  override; assert all factor inputs surface; recovery_events\n  detects override→pass; coherence series populated.\n- aggregate_scoring_factors_batch — empty input → empty vec;\n  2-agent input → 2 aggregates in input order.\n- count_traces — agent_id_hash filter narrows correctly.\n- count_overrides — distinct from count_traces; recursive\n  CONSCIENCE_RESULT collapsed to per-trace BOOL_OR.\n- aggregate_audit_chain_no_audit_rows — fixture without audit\n  fields returns zero counts.\n\nAll four §A/B/F/E sections shipped. v0.5.0 still pending: PyO3\nwrappers + threat-model AV-43 + CHANGELOG + tag.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-10T15:52:47-05:00",
          "tree_id": "d5e316c478cea649e632be18d679cd3b2d33510d",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/d98dfabbd002651d89e4100204f61e3d0d006bbe"
        },
        "date": 1778446857844,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 102253,
            "range": "± 4384",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 245809,
            "range": "± 4202",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 531961,
            "range": "± 2739",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1883396,
            "range": "± 20499",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 347,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1537,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8241,
            "range": "± 41",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 361,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3110,
            "range": "± 61",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9436,
            "range": "± 98",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41624,
            "range": "± 131",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 621,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2448460,
            "range": "± 182969",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6862264,
            "range": "± 373467",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23950235,
            "range": "± 557785",
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
          "id": "93879bb9ec9c07cb5e5a8a525bf82af3e892ab2f",
          "message": "WIP v0.5.0 — PyO3 wrappers for all 12 ReadEngine methods\n\nFederation read primitives surfaced through Engine. Wire format:\nJSON strings in/out for complex types (TraceFilter, TraceCursor,\nTraceSummary, TraceListPage, TraceDetail, TimeWindow, DivergenceRow,\nScoringFactorAggregate, etc.); primitives as direct args (trace_id,\nagent_id_hash, limit). Same idiom as put_public_key /\nput_attestation / put_detection_event already established.\n\n12 wrappers (delegating to crate::read::ReadEngine impl on the\nbackend):\n\n  Section A:\n    list_trace_summaries(filter_json, cursor_json=None, limit=100)\n    get_trace_summary(trace_id)\n  Section B:\n    get_trace_detail(trace_id)\n  Section F:\n    cross_agent_divergence(deployment_domain, window_json, metric)\n    temporal_drift(agent_id_hash, baseline_json, comparison_json)\n    hash_chain_gaps(agent_id_hash, window_json)\n    conscience_override_rates(deployment_domain, window_json)\n  Section E:\n    aggregate_scoring_factors(agent, window_json, baseline_json=None)\n    aggregate_scoring_factors_batch(agents_json, window_json,\n                                    baseline_json=None)\n    count_traces(filter_json)\n    count_overrides(filter_json)\n    count_identity_changes(filter_json)\n    aggregate_audit_chain(filter_json)\n\n(That's 13 — count_overrides + count_identity_changes + count_traces\n+ aggregate_audit_chain are 4 granular methods alongside §E's\naggregate + batch, totaling 6 in §E. 12 trait methods, 13 PyO3\nmethods because aggregate_audit_chain returns a typed struct as\nJSON; everything else maps 1:1.)\n\nread_err_to_py helper added near the other *_err_to_py helpers.\nAV-15 / AV-43: kind tokens are closed-set &'static str; verbose\ndetail to tracing only. InvalidArgument / InvalidCursor →\nValueError; Backend / NotImplemented → RuntimeError.\n\nLens consumers can now call any of these 12 from Python:\n\n  import json\n  page = json.loads(engine.list_trace_summaries(\n    filter_json=json.dumps({\"agent_id_hash\": h}),\n    cursor_json=None,\n    limit=50,\n  ))\n\ncargo build + clippy clean across all features.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-10T15:55:08-05:00",
          "tree_id": "8862af88b377d89766be683a24fc7cc9a95c1bd0",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/93879bb9ec9c07cb5e5a8a525bf82af3e892ab2f"
        },
        "date": 1778447002813,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 101596,
            "range": "± 1001",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 242916,
            "range": "± 1248",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 525208,
            "range": "± 11260",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1859837,
            "range": "± 16432",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 370,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1429,
            "range": "± 78",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8267,
            "range": "± 182",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 359,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3147,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9481,
            "range": "± 154",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41587,
            "range": "± 253",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 622,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2309957,
            "range": "± 135551",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6694099,
            "range": "± 141961",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 24019674,
            "range": "± 363029",
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
          "id": "6cead11b5a0b866271048554ed374ec06d218716",
          "message": "0.5.0 — federation read primitives §A/B/F/E (CIRISPersist#23)\n\nCloses lens-bleeding read-side starvation: 50 lens SELECTs against\ncirislens.trace_events directly, /coherence-ratchet/stats 500'ing,\napi/scoring.py raw SQL — all replaced by typed read primitives\nthrough the persist substrate.\n\nSurface duality (v0.4.1 verify-primitive precedent): every primitive\nlands as both a Rust-public ReadEngine trait method AND a thin PyO3\nwrapper on Engine. Single source of truth.\n\n§A trace listing — list_trace_summaries + get_trace_summary; drives\n/repository/traces. JSONB-extracting GROUP BY with FILTER aggregation\nin one DB pass; cursor pagination via (started_at, trace_id) tuple.\n\n§B trace detail — get_trace_detail; drives /repository/traces/{id}.\n3 round-trips composing summary + components (chronological) + LLM\ncalls + envelope refs.\n\n§F Coherence Ratchet inputs — cross_agent_divergence (CSDMA / DSDMA /\nIDMA k_eff / IDMA correlation_risk / override_rate), temporal_drift\n(Welch z-score on mean shift), hash_chain_gaps (LAG window over\naudit_sequence_number), conscience_override_rates (per-trace BOOL_OR\ncollapse + population-weighted domain average). Drives\n/coherence-ratchet/stats.\n\n§E scoring factor aggregates — replaces api/scoring.py raw SQL.\nBundled aggregate_scoring_factors + batch + 4 granular sub-primitives\n(count_traces, count_overrides, count_identity_changes,\naggregate_audit_chain). 4 round-trips per aggregate covering Capacity\nScore factors C / I_int / R / I_inc / S inputs (recovery events,\ncoherence decay series, etc.).\n\nPyO3: 12 wrappers, JSON-string in/out for complex types. Same idiom\nas the existing federation directory + derived schema methods.\n\nThreat model AV-43 added — read-side adversary inference attack.\nAggregates return computed statistics not content; sample_count /\ntrace_count surface explicitly for caller-side k-anonymity gates;\nAV-9 trace-scoped reads carry agent_id_hash. Posture summary §9\nheader bumped v0.4.6 → v0.5.0; 16 vectors closed across v0.2.0..v0.5.0.\n\nTests: 19 integration tests against real Postgres (gated on\nCIRIS_PERSIST_TEST_PG_URL). 203 total lib tests pass.\n\nOut of scope (deferred to v0.5.1): sections C/D/G/H/I plus the\nfinal cirislens_reader carve-out retirement (gated on §D — LLM call\nsurface — which v0.5.1 covers). v0.5.0 deprecates but does not yet\nfully retire the carve-out.\n\nFSD/V0_5_0_FEDERATION_READ_PRIMITIVES.md documents the sub-batch\nshape.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-10T15:58:54-05:00",
          "tree_id": "33f63fbbe1805a1e25d798e4184d05d0a949422d",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/6cead11b5a0b866271048554ed374ec06d218716"
        },
        "date": 1778447347903,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 96730,
            "range": "± 1316",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 238504,
            "range": "± 2587",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 522182,
            "range": "± 1698",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1944514,
            "range": "± 23993",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 304,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1218,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7205,
            "range": "± 130",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 317,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3188,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9834,
            "range": "± 34",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 44092,
            "range": "± 220",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 548,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2526796,
            "range": "± 120064",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6868747,
            "range": "± 4295891",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23996161,
            "range": "± 453270",
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
          "id": "9e8a0993a312efe70e9fb739cb019638450d122d",
          "message": "0.5.3 — panic-isolation hardening track (CIRISPersist#25/#26/#27) + verify v2.0.2\n\nThree orthogonal layers of defense against the CIRISPersist#24\nfailure class (SUM-NULL → Row::get panic → SIGABRT cascade across\nuvicorn workers).\n\nPhase 1 (#25): panic = \"abort\" → \"unwind\" in release profile.\nPyO3's catch_unwind trampoline now fires; Rust panics become\nPanicException not SIGABRT. SECURITY_AUDIT_v0.1.2.md §4.2's abort\nrationale was correct for v0.1.x standalone-bin but doesn't\nsurvive v0.5.x cdylib-in-uvicorn — reframed in THREAT_MODEL.md\n§3.13 + AV-44.\n\nPhase 2 (#26): PgRowExt::safe_get trait — try_get with typed\nBackend error mapping. ~80 sites swept across v0.5.0 ReadEngine\nimpl + decode helpers. NULL surfaces as HTTP 500 with column\nname, not Rust panic. Pre-v0.5.0 sites tracked in\nCIRISPersist#28 for v0.5.4 sweep completion.\n\nPhase 3 (#27): pyo3::create_exception! LensQueryError(Exception) +\ncatch_panic(AssertUnwindSafe(...)) wrapping all 13 v0.5.0\nReadEngine PyO3 methods. Caught panics convert to LensQueryError\n— uvicorn's \"except Exception\" catches as clean 500 instead of\nescaping as PanicException (BaseException).\n\nVerify deps v2.0.1 → v2.0.2 — closes ml-dsa → pkcs8 caret-range\nhazard (CIRISVerify#18). v2.0.2 pins pkcs8 exact.\n\nThree-layer defense matrix:\n- SQL → Rust:    safe_get (try_get + Option)   → NULL = None\n- Rust → FFI:    panic = \"unwind\"               → PanicException\n- FFI → Python:  catch_panic + LensQueryError   → typed 500\n\n#24 failure class closed.\n\nThreat model: AV-44 added; §3.13 new; §9 bumped v0.5.0 → v0.5.3;\n17 vectors closed across v0.2.0..v0.5.3.\n\n205 lib tests pass. Hooks (fmt + clippy + test) clean.\n\nOut of scope (deferred to v0.5.4):\n- CIRISPersist#28 — pre-v0.5.0 PyO3 methods sweep\n- CIRISPersist#29 — Python-side panic-injection regression test\n- sqlfluff CI rule banning bare SUM/AVG without COALESCE\n- Per-worker panic budget + circuit breaker\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-11T15:58:12-05:00",
          "tree_id": "941439206273263f3225ebf9075781568306aff8",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/9e8a0993a312efe70e9fb739cb019638450d122d"
        },
        "date": 1778533597021,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 101749,
            "range": "± 231",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 241713,
            "range": "± 1721",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 523089,
            "range": "± 2256",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1850379,
            "range": "± 18591",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 347,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1424,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8212,
            "range": "± 96",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21129,
            "range": "± 48",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24188,
            "range": "± 61",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83528,
            "range": "± 149",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 366,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3309,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9499,
            "range": "± 384",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42373,
            "range": "± 184",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2558848,
            "range": "± 122902",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6857166,
            "range": "± 1100899",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 24112408,
            "range": "± 303156",
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
          "id": "96452270b8b86a302c6333009d8a3d5d6894ccd5",
          "message": "0.5.4 — CIRISPersist#28 sweep completion + #29 Python regression test\n\nFinishes the panic-isolation track v0.5.3 started. v0.5.3 hardened\nthe v0.5.0 ReadEngine surface (the realized CIRISPersist#24 incident\npath); v0.5.4 sweeps the remainder + adds the end-to-end regression\ntest the v0.5.3 hardening lacked.\n\n#28 part 1 — PgRowExt extension + full postgres sweep.\n\nPgRowExt generalized:\n  - safe_get<T, I>          — RowIndex (column name OR position)\n  - safe_get_with<T,I,E,F>  — F: FnOnce(String) -> E so non-ReadEngine\n                              layers route NULL into their own\n                              Error::Backend variant.\n\nEvery bare Row::get in src/store/postgres.rs swept (~75 additional\nsites). Federation directory decoders (pg_row_to_key_record /\n_attestation / _revocation) lifted from infallible to Result; call\nsites collect via ::<Result<Vec<_>, _>>(). pg_row_to_event_row,\npg_row_to_outbound_row, list_hybrid_pending_*, lookup_public_key,\nsample_public_keys, delete_traces_for_agent, enqueue_outbound,\nmark_transport_failed, count_traces, count_overrides,\ncount_identity_changes, aggregate_audit_chain all swept.\n\nSQLite path exempt by construction — rusqlite::Row::get already\nreturns Result on NULL (not the tokio_postgres panic class).\n\nCI gate: scripts/hooks/pre-commit now rejects bare row.get( / .get::<\npatterns in src/store/postgres.rs at commit time. Regression class\ncan't sneak back in.\n\n#28 part 2 — FFI catch_panic sweep.\n\nv0.5.3 wrapped 13 v0.5.0 ReadEngine PyO3 methods. v0.5.4 wraps the\nremaining 53 pre-v0.5.0 entry points (federation directory writers,\noutbound queue ops, derived-schema CRUD, verify primitives,\ncanonicalization helpers, steward signing, debug methods). Every\nPyO3 method on PyEngine (~70 entry points) now routes panic through\nthe explicit catch_panic wrapper, converting PanicException\n(BaseException) into LensQueryError (Exception). Wrap applied via\na deterministic brace-depth scan (no proc-macro infra introduced).\n\n#29 — Python regression test gate.\n\nNew feature: test-panic = [] in Cargo.toml. With it on, a\nmodule-level #[pyfunction] _test_inject_panic bypasses Engine\nconstruction (no postgres/keyring setup) and panics inside\ncatch_panic. Release wheels don't compile it in.\n\ntests/python/test_catch_panic.py (5 tests):\n  1. LensQueryError exported and subclasses Exception\n  2. Panic surfaces as LensQueryError, message preserved\n  3. `except Exception:` catches it — the CIRISPersist#24 wedge\n     shape, now regression-tested\n  4. Converted error is NOT a pyo3.exceptions.PanicException\n  5. Module survives N panics; non-panic calls still work after\n\nLensQueryError re-exported via python/ciris_persist/__init__.py for\nconsumer ergonomics. pyproject.toml grows [tool.pytest.ini_options].\n.github/workflows/ci.yml's linux-x86_64 job appends maturin develop\n--features test-panic,pyo3 + pytest tests/python/.\n\nLocal validation: 5/5 tests pass against maturin-develop build.\n205 lib tests still green.\n\nThreat model: no new vector — v0.5.4 closes the carve-out in\nv0.5.3's §3.13 (\"pre-v0.5.0 sites tracked in #28\") without\nmodifying AV-44. §9 header unchanged at v0.5.3.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-11T17:43:14-05:00",
          "tree_id": "677a39d03e60453fa68acc074acc494c12366b6b",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/96452270b8b86a302c6333009d8a3d5d6894ccd5"
        },
        "date": 1778539887728,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 104174,
            "range": "± 1186",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 245583,
            "range": "± 14901",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 527582,
            "range": "± 1346",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1866936,
            "range": "± 23900",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 349,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1515,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7983,
            "range": "± 200",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21219,
            "range": "± 220",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24286,
            "range": "± 99",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83602,
            "range": "± 276",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 377,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3305,
            "range": "± 45",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9592,
            "range": "± 129",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42784,
            "range": "± 471",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2351207,
            "range": "± 63176",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6740503,
            "range": "± 134800",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 24195205,
            "range": "± 319460",
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
          "id": "410669cc36d31eb70dc13da29385f467ba65aa0b",
          "message": "0.5.5 — federation read primitives §C/D/G/H/I (closes CIRISPersist#23)\n\nv0.5.0 shipped §A/B/F/E (validated in prod via v0.5.3 bridge sweep).\nv0.5.5 closes #23 with the deferred batch: 5 additive primitives, no\nschema changes, no breaking API edits.\n\n§C list_tasks: TaskClass canonical derivation (qa_eval/discord/\nreal_user_*/wakeup_ritual/other) from task_id prefix, single-source\nacross federation peers. initial_observation extracted server-side\nfrom earliest THOUGHT_START task_description. Cursor: (earliest_at,\ntask_id), newest-first. Trace ordering within task: thought_depth ASC.\n\n§D list_llm_calls + aggregate_llm_costs: cursor-paged listing with\nagent/model/status/trace filters. Agent-side filters force JOIN to\ntrace_events. Cost rollup by_model/by_agent/by_domain + totals;\nevery SUM COALESCE'd to 0 proactively (CIRISPersist#24 hygiene).\n\n§G corpus_shape: 6 breakdowns per window — task_class, qa_language,\nqa_question_num, agent_name, agent_version (= agent_template),\nprimary_model, deployment_region. primary_model is per-trace\nmost-frequent LLM call model. stationarity_z_score reserved for\nfuture baseline-window API extension.\n\n§H aggregate_scrub_stats: envelopes_scrubbed + by_trace_level populate\ntoday; fields_scrubbed_total + by_entity_type gated on v0.6.0\npost-ingest classification pipeline (CIRISPersist#19). Shape locked\nnow so consumers don't churn when pipeline lands.\n\n§I list_federation_keys / list_attestations / list_revocations: bulk\nprimitives over cirislens.federation_* tables. Filters: revoked\n(EXISTS), pqc_completed (IS NOT NULL), per-key/attestation/revocation\nidentity refs. Items reuse crate::federation types — no duplicate\nschemas.\n\nTest coverage: 17 new integration tests (5 §C + 4 §D + 3 §G + 2 §H +\n3 §I). 222 lib tests pass (was 205).\n\nMemory + sqlite backends return NotImplemented per existing convention.\n\nAll PyO3 entry points wrapped in catch_panic from the start (v0.5.4\ndiscipline). Every Row::get goes through safe_get (postgres.rs\npre-commit gate already enforces).\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-11T19:25:54-05:00",
          "tree_id": "329c405f19a1553bf996d41f0f9ce5b6bcbda30c",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/410669cc36d31eb70dc13da29385f467ba65aa0b"
        },
        "date": 1778546070132,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 101452,
            "range": "± 1522",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 242368,
            "range": "± 729",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 524399,
            "range": "± 1908",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1857986,
            "range": "± 20760",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 372,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1595,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8764,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21174,
            "range": "± 56",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24232,
            "range": "± 52",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83610,
            "range": "± 203",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 368,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3161,
            "range": "± 32",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9606,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42800,
            "range": "± 164",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 622,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2282142,
            "range": "± 118958",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6769352,
            "range": "± 70356",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 24382627,
            "range": "± 665013",
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
          "id": "61b6ff4d14dfefd24a816efa14da3c914680f5d3",
          "message": "0.5.6 — test fixture hotfix for v0.5.5 §I federation observability\n\nv0.5.5's tag-push CI surfaced two §I test fixture bugs against live\nPostgres (unit-only `cargo test` had passed because PG-gated tests\nearly-return without CIRIS_PERSIST_TEST_PG_URL).\n\n1. read_section_i_list_federation_keys_cursor: asserted\n   next_cursor.is_none() on an exact-fill page (4 keys, limit=2 →\n   page 2 yields 2 items with no more rows). Pagination contract\n   matching §A: cursor is None ONLY when items.len() < limit; impl\n   can't distinguish \"exactly limit remaining\" from \"more remain\"\n   without fetching limit+1. Fixed test: walk one extra empty page\n   and assert it has no cursor + zero items.\n\n2. read_section_i_list_revocations_round_trip: fixture set\n   original_content_hash = \"abc\" (3 hex chars, odd). The federation\n   persist layer rejects with InvalidArgument(\"Odd number of digits\").\n   Fixed to use a 64-char sha256-shaped hex placeholder.\n\nZero impl changes — every §C/D/G/H/I primitive's Rust code is the\nv0.5.5 code unchanged. The pagination contract was correct; only the\n§I test assertion was wrong about it.\n\nv0.5.5's PyPI publish was skipped because of these failures (no\nartifact reached PyPI). Build manifest WAS registered with the\nregistry for version=0.5.5, which is why this is v0.5.6 not a\nforce-moved v0.5.5 tag — manifest integrity discipline.\n\nLens team target: ciris-persist == 0.5.6.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-11T19:42:00-05:00",
          "tree_id": "70bb40a839cbcb8ed962d4ff39b151ea8d9f8df5",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/61b6ff4d14dfefd24a816efa14da3c914680f5d3"
        },
        "date": 1778546956102,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 101775,
            "range": "± 209",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 242560,
            "range": "± 5987",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 523487,
            "range": "± 2056",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1857574,
            "range": "± 8815",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 367,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1577,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8670,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21171,
            "range": "± 403",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24201,
            "range": "± 104",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83516,
            "range": "± 373",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 370,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3211,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9536,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41379,
            "range": "± 212",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 625,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2317699,
            "range": "± 119732",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6706557,
            "range": "± 219017",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 24057471,
            "range": "± 583723",
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
          "id": "2cbeb958442446ceb2448e6371430888a0f89545",
          "message": "0.5.7 — second §I test fixture hotfix (UUID cast for revocation_id)\n\nv0.5.6 fixed the cursor + hex-decode fixture bugs but missed one:\nrevocation_id is ::uuid-cast in put_revocation's INSERT SQL\n($1::uuid). My test's `format!(\"rev-§i-{}\", uuid_like())` is a\nhex-timestamp token, not a UUID, so the tokio_postgres serializer\nrejects parameter 0.\n\nFix: use uuid::Uuid::new_v4() which the rest of the test suite\nalready uses for derived-schema inserts (detection_id etc).\n\nZero impl changes from v0.5.5/v0.5.6 — same shape of test-fixture fix.\nManifest-integrity discipline applies again (v0.5.6's build-manifest\nwas registered before publish-pypi was skipped), hence v0.5.7.\n\nLens team target: ciris-persist == 0.5.7.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-11T19:50:54-05:00",
          "tree_id": "2843cb6135ebab838f67ddcdf1d84ed27b78bc80",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/2cbeb958442446ceb2448e6371430888a0f89545"
        },
        "date": 1778547515869,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 108770,
            "range": "± 202",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 260053,
            "range": "± 2256",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 561756,
            "range": "± 13141",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1991392,
            "range": "± 23708",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 332,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1346,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8203,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 23119,
            "range": "± 855",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 26347,
            "range": "± 267",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 91105,
            "range": "± 1454",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 348,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3148,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9817,
            "range": "± 43",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42103,
            "range": "± 242",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 643,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2261169,
            "range": "± 38439",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 7025294,
            "range": "± 961925",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 25887016,
            "range": "± 115610",
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
          "id": "7c1770863d0aaa3e6724a2d96379efac0e65f67d",
          "message": "0.5.8 — put_revocation/put_attestation Uuid binding fix + pre-push PG hardening\n\nREAL bug fix: put_revocation and put_attestation rejected\nString-bound revocation_id/attestation_id when tokio-postgres'\nprepared-statement type inference resolved $1::uuid to expect a\nuuid::Uuid value rather than text. Latent since v0.3.x — no prior\npostgres test exercised the put paths end-to-end (only SELECT-side\nattach_*_pqc_signature). §I round-trip test in v0.5.5 was the first\nto hit it, but v0.5.6/.7's hotfixes only touched test fixtures and\nmissed the underlying issue.\n\nFix: parse String → uuid::Uuid::parse_str at the persist boundary,\nbind the Uuid value directly. with-uuid-1 feature on tokio-postgres\nalready provides ToSql; just stop relying on the fragile &String →\n$::uuid cast path.\n\n```rust\nlet revocation_uuid = uuid::Uuid::parse_str(&row.revocation_id)?;\nclient.execute(\"... VALUES ($1, ...)\", &[&revocation_uuid, ...])\n```\n\nSame shape applied to put_attestation. Other $N::uuid sites\n(attach_*_pqc_signature, outbound queue ops) unchanged — they're\nSELECT paths that work in prod; will revisit if tests surface them.\n\nInvalid UUIDs now surface as Error::InvalidArgument (was opaque\nError::Backend serialization error) — strictly better for operators.\n\nPre-push hardening:\n- scripts/hooks/pre-push auto-discovers ciris-qa-postgres docker\n  container and runs read_section_* tests against it\n- Warns loudly when no live PG available (CIRIS_PERSIST_TEST_PG_URL\n  unset + no docker container) but doesn't fail — preserves\n  \"integration in CI\" historical contract\n- v0.5.5→v0.5.7 burned 2 release versions to fixture bugs local\n  `cargo test` silently skipped. This stops that pattern.\n\nVerification: 38/38 read_section_* tests pass against live\nciris-qa-postgres locally.\n\nLens team target: ciris-persist == 0.5.8.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-11T20:03:20-05:00",
          "tree_id": "b1468ff17b75089eb22b2dea33f94f7831102afd",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/7c1770863d0aaa3e6724a2d96379efac0e65f67d"
        },
        "date": 1778548288634,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 95951,
            "range": "± 2220",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 238666,
            "range": "± 2441",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 521095,
            "range": "± 21822",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1979230,
            "range": "± 36741",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 326,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1305,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7377,
            "range": "± 101",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 20772,
            "range": "± 266",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24184,
            "range": "± 293",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 88731,
            "range": "± 946",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 318,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3212,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9559,
            "range": "± 130",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 44214,
            "range": "± 202",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 538,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2123956,
            "range": "± 110055",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6421168,
            "range": "± 133563",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23473667,
            "range": "± 290933",
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
          "id": "90db69b96b4943bed4824d9b5b96d59d272f6f8f",
          "message": "v0.6.0-α1: classify taxonomy + Stage trait scaffolding + V009 migration\n\nFoundation commit for CIRISPersist#19 (post-ingest filter pipeline).\nv0.6.0-α series builds toward final v0.6.0; secrets module (18-method\nSecretsService) deferred to v0.6.1 per user decision.\n\nNEW SURFACE\n- src/pipeline/classify/ — 36-variant ContentClass + DetectionMethod\n  (8) + Sensitivity (4) + Action (7) + LearningState (D5) + the\n  composed ContentClassMatch struct. Wire-stable serde shape per FSD\n  §6.3. Existing taxonomies (Agent's SecretType / SensitivityLevel /\n  TriggerType / FilterPriority, LensCore scrub regex catalog /\n  walker / NER) project onto subsets of these 5 orthogonal axes.\n\n- src/pipeline/mod.rs — Stage trait (impl Future GAT style matching\n  ReadEngine convention), PipelineState accumulator, pipeline::Error\n  with stable kind() tokens (THREAT_MODEL.md AV-15). No concrete\n  stages yet — those land with the scrub (α2) + extract (α3) lifts.\n\n- Cargo features: classify (regex), scrub (depends on classify),\n  extract (depends on scrub), scrub-ner (candle + tokenizers + hf-hub),\n  scrub-ort (ort + ndarray). Bundles: default-pipeline-ml +\n  default-sovereign-light per FSD §2.4.\n\n- V009 migration: extracted_features, classifications,\n  pipeline_metadata JSONB columns on cirislens.trace_events. All\n  NULLABLE (rollback-safe per FSD §12.7; pre-pipeline rows stay\n  valid). NOTE: FSD §12.1 calls these V007 / V008 — renumbered to\n  V009 / V010 because V007 (edge_outbound_queue) and V008\n  (lens_derived_schemas) shipped earlier.\n\nWHAT'S NEXT (v0.6.0-α2..α5)\n- α2: port cirislens-core scrubber/ verbatim (~2,700 LOC: walker,\n  regex, fields, mod, ner.rs scaffolds) under scrub feature gate.\n- α3: port cirislens-core extraction/ verbatim (~530 LOC) as the\n  extract module + ExtractStage.\n- α4: NER feature-gated modules (xlm_r_loader, distilbert_loader,\n  ort_loader, ner).\n- α5: Engine API additions (get_features, get_classifications,\n  iter_features_by_cohort) + PyO3 wrappers.\n- v0.6.0 release.\n\nCargo.toml NOT bumped yet — staying at 0.5.8 until v0.6.0 foundation\nis complete. Tags ship the final release; intermediate commits are\nreviewable checkpoints on main.\n\n230 lib tests pass (was 222; +8 new classify + pipeline scaffolding\ntests). V009 verified against live ciris-qa-postgres container —\nextracted_features / classifications / pipeline_metadata columns\npresent after first PG-test run.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-12T10:08:01-05:00",
          "tree_id": "3e8feb51078201b62f97e88c2670f88f350d5b13",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/90db69b96b4943bed4824d9b5b96d59d272f6f8f"
        },
        "date": 1778599210506,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 109175,
            "range": "± 708",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 251063,
            "range": "± 775",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 533632,
            "range": "± 31086",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1866709,
            "range": "± 27743",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 345,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1508,
            "range": "± 45",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8209,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21125,
            "range": "± 133",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24150,
            "range": "± 47",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83528,
            "range": "± 212",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 389,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3242,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9476,
            "range": "± 41",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41867,
            "range": "± 144",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2263411,
            "range": "± 49808",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6642954,
            "range": "± 161755",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23807596,
            "range": "± 670122",
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
          "id": "b146b6650fe78068b4f233f4e13e866b928d4d74",
          "message": "v0.6.0-α2: lift CIRISLens scrub module (fields + regex + walker) + cargo-deny fix\n\nα2 ports the JSON-walker + regex scrubber verbatim from\nCIRISLens/cirislens-core/src/scrubber/ under the `scrub` Cargo\nfeature. ~1,200 LOC across:\n\n- src/pipeline/scrub/fields.rs — SCRUB_FIELDS catalog (47 field\n  names; security boundary, intentionally code-only).\n- src/pipeline/scrub/regex.rs — 8 PII patterns + year-identifier\n  guard + count_year_residue + probe_match. Production regression\n  cases preserved verbatim (phone false-positive on timestamps,\n  year-identifier overfire on pure-digit IDs).\n- src/pipeline/scrub/walker.rs — depth-limited two-phase walker\n  (Phase 1 collect NER inputs, Phase 2 batched NER, Phase 3 inject\n  + regex). 30-depth limit + schema-label NER skip preserved.\n- src/pipeline/scrub/ner.rs — STUB returning NerNotConfigured.\n  Real Candle / ORT backends defer to α4 alongside scrub-ner /\n  scrub-ort features.\n- src/pipeline/scrub/mod.rs — scrub_trace + scrub_traces_batch +\n  ScrubError + ScrubStats + ScrubbedTrace. Uses persist's\n  crate::schema::TraceLevel (single source of truth across\n  ingest, scrub, and the Scrubber trait).\n\nThe sole behavioral change from lens-core is lazy_static →\nstd::sync::OnceLock (no new dep). 33 lifted tests pass under the\nnew feature gate.\n\nCARGO-DENY FIX\nα1 CI failed cargo-deny: number_prefix + paste unmaintained\nadvisories pulled in transitively by the candle / tokenizers /\nhf-hub / ort / ndarray deps I declared as optional. α2 removes\nthose deps + the scrub-ner / scrub-ort / default-pipeline-ml\nfeatures that referenced them — they'll come back in α4 alongside\nthe actual NER backend lift + a deny.toml ignore block scoped to\nthose two transitive advisories.\n\nPRE-PUSH HARDENING\nscripts/hooks/pre-push adds a cargo-deny advisories gate (when\ncargo-deny is installed locally). Catches this class of CI\nregression locally next time. Skipped silently when cargo-deny\nisn't installed.\n\nPIPELINE INTEGRATION\nThe new scrub functions are STANDALONE for now — they sit\nalongside persist's existing crate::scrub::Scrubber trait (the\nv0.1.x slot for the lens FastAPI callback). α5 wires the new\nDefaultScrubber impl into the Scrubber trait + Engine API.\n\nNEXT: α3 — extract module + typed Features struct lift from\ncirislens-core/src/extraction/.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-12T10:15:18-05:00",
          "tree_id": "2d818b51bed2f9ae7b059f0661cfa0c13baba353",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/b146b6650fe78068b4f233f4e13e866b928d4d74"
        },
        "date": 1778599437223,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 108785,
            "range": "± 302",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 260334,
            "range": "± 1919",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 563544,
            "range": "± 3296",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1999723,
            "range": "± 55038",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 342,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1415,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8243,
            "range": "± 57",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 23156,
            "range": "± 198",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 26397,
            "range": "± 618",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 91047,
            "range": "± 7032",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 357,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3142,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9528,
            "range": "± 56",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42016,
            "range": "± 191",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 632,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2321563,
            "range": "± 91803",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 7110316,
            "range": "± 154092",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 26335913,
            "range": "± 184506",
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
          "id": "6cd4f365d1f7b05b65f1168297ad4a7286e6545f",
          "message": "v0.6.0-α3: lift CIRISLensCore extract module — typed Features struct\n\nα3 ports CIRISLensCore/src/extract/ verbatim into\nsrc/pipeline/extract/ under the `extract` Cargo feature. ~700 LOC:\n\n- src/pipeline/extract/features.rs — typed Features struct with\n  Serialize+Deserialize derives so it round-trips through the\n  cirislens.trace_events.extracted_features JSONB column (V009).\n  Sub-types: DeclaredCohortAxes (5-tuple cohort key per\n  RATCHET 2026-05-04 lock), StepTimestamps (8 event_type slots),\n  ObservationWeights (privacy-safe counts only, no text),\n  ModelClass (Unknown / Named — Phase 1 open-ended bucketing).\n\n- src/pipeline/extract/json_path.rs — dot-notation path resolver +\n  value_to_string / float / int / bool coercions. Reusable from\n  future v0.6.x dynamic-field extraction rules.\n\n- src/pipeline/extract/static_extract.rs — extract_features(trace,\n  declared) walks components and populates Features:\n  - Concern #1: step timestamps lifted by event_type\n  - Concern #2: observation weights (memory_count, context_tokens,\n    conversation_turns, alternatives_considered,\n    conscience_checks_count) with multi-fallback field-name\n    discipline preserved verbatim\n  - Concern #3 (schema-driven dynamic rules): NOT ported — kept\n    static per CIRISLensCore OQ-09 closure\n  - Concern #4: full-component JSON blobs for the 6 result\n    event_types\n\nADAPTATIONS FROM LENS-CORE\n- HashMap<&'static str, Value> → HashMap<String, Value> (Serialize\n  doesn't support &'static str map keys).\n- ModelClass derives Default (Unknown variant) — clippy clean.\n- All sub-types Serialize+Deserialize for JSONB round-trip.\n\nPre-pipeline rows stay valid: V009 columns are NULLABLE, and\nextract_features is only invoked on the pipeline path; legacy\ningest paths skip extract entirely.\n\n47 pipeline tests pass (was 33 in α2 + 14 extract tests).\nPre-push PG sweep green against ciris-qa-postgres locally.\n\nNEXT: α4 — feature-gated NER backend modules (xlm_r_loader,\ndistilbert_loader, ort_loader, ner.rs filled in) behind scrub-ner\n+ scrub-ort features. Restores the heavy ML deps + a deny.toml\nignore block for the transitive `number_prefix` / `paste`\nunmaintained advisories.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-12T10:19:45-05:00",
          "tree_id": "32921d03c4cd5ec338984a45b92f94a37bf518ad",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/6cd4f365d1f7b05b65f1168297ad4a7286e6545f"
        },
        "date": 1778599717146,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 103463,
            "range": "± 419",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 244365,
            "range": "± 1125",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 526092,
            "range": "± 1870",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1853342,
            "range": "± 21205",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 374,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1454,
            "range": "± 45",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8220,
            "range": "± 30",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21210,
            "range": "± 36",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24230,
            "range": "± 50",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83562,
            "range": "± 571",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 381,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3061,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9471,
            "range": "± 60",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42018,
            "range": "± 174",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2260030,
            "range": "± 92457",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6610700,
            "range": "± 109007",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23751689,
            "range": "± 241483",
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
          "id": "a14873037f164fef1ac95059ebed9d0f7cbb1cb9",
          "message": "v0.6.0-α4: NER backend lift (XLM-R + DistilBERT via candle, ORT INT8 fast path)\n\nα4 ports the multilingual NER backends from CIRISLens\ncirislens-core/src/scrubber/ verbatim under `scrub-ner` +\n`scrub-ort` Cargo feature gates. ~1,550 LOC restored.\n\nNEW FILES (feature-gated)\n- src/pipeline/scrub/xlm_r_loader.rs — XLMRobertaModel backbone +\n  token-classification head (HF Davlan/xlm-roberta-base-wikiann-ner\n  shape). Local-dir + HF-hub loaders. `safetensors::mmap` path\n  uses `unsafe` (allowed at file level — same shape as\n  candle-transformers' own examples).\n- src/pipeline/scrub/distilbert_loader.rs — DistilBERT-multilingual\n  alternative (½ params, ½ inference cost, +DATE labels).\n  Attention-mask polarity inversion + reshape for candle's mask\n  semantics preserved.\n- src/pipeline/scrub/ort_loader.rs — ORT INT8 token-classifier\n  backbone (3-4× faster than candle on CPU).\n- src/pipeline/scrub/ner.rs (replaced α2 stub) — backend selector\n  via CIRISLENS_NER_BACKBONE env (candle / ort), batched\n  scrub_batch with in-process content-dedup cache (~98.8% dedup\n  ratio on production HF corpus), BIO collapse + char-offset span\n  replacement helpers.\n\nCARGO + DENY\n- Restored optional deps: candle-core 0.10, candle-nn,\n  candle-transformers, tokenizers 0.20, hf-hub 0.4, ort\n  2.0.0-rc.10, ndarray 0.16, plus anyhow + log + parking_lot.\n- Features: scrub-ner = scrub + ML deps, scrub-ort = scrub-ner +\n  ort/ndarray, default-pipeline-ml bundle.\n- deny.toml: added RUSTSEC-2025-0119 (number_prefix unmaintained,\n  transitive via indicatif → hf-hub) and RUSTSEC-2024-0436\n  (paste unmaintained, transitive via candle / ort macros).\n  Both unmaintained-track only, not exploitable.\n\nARCHITECTURAL CHANGE\n- lib.rs `#![forbid(unsafe_code)]` → `#![deny(unsafe_code)]`.\n  forbid prevents inner `#![allow]` overrides; the safetensors\n  mmap path is unavoidable in the ML ecosystem (every candle/ort\n  example uses it identically). Three files scoped:\n  xlm_r_loader, distilbert_loader, ort_loader. Non-NER code\n  remains effectively no-unsafe — every `#[allow(unsafe_code)]`\n  must appear at the top of a module file and be visible to\n  security audits.\n\nTEST GATING\n- pipeline::scrub::tests::full_traces_without_ner_rejects now\n  cfg-gated to `not(feature = \"scrub-ner\")` because when scrub-ner\n  is on, a cached HF model may legitimately satisfy\n  is_configured() (CIRISLENS_NER_MODEL_DIR or warm cache).\n\nVERIFICATION\n- cargo check passes on all 4 combos: light / scrub-ner / scrub-ort.\n- cargo clippy clean across all combos.\n- cargo-deny advisories green with the new ignores.\n- 53 pipeline tests pass under scrub-ner, 52 under light build\n  (one feature-gated NER test).\n\nNEXT: α5 — Engine API additions (get_features, get_classifications,\niter_features_by_cohort) + PyO3 wraps with catch_panic.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-12T11:13:34-05:00",
          "tree_id": "a6aa3cc52912fabbbdc53b6b2b894477274be0e1",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/a14873037f164fef1ac95059ebed9d0f7cbb1cb9"
        },
        "date": 1778602906334,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 101687,
            "range": "± 503",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 242826,
            "range": "± 2064",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 524002,
            "range": "± 3044",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1853083,
            "range": "± 10945",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 364,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1513,
            "range": "± 39",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8214,
            "range": "± 74",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 22097,
            "range": "± 178",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 25166,
            "range": "± 661",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 84453,
            "range": "± 167",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 367,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3186,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9689,
            "range": "± 137",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42403,
            "range": "± 142",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 621,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2331472,
            "range": "± 156684",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6656114,
            "range": "± 183526",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23943591,
            "range": "± 245792",
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
          "id": "f7737609190d3a4620fca805078a557d664dbabd",
          "message": "v0.6.0-α5: Engine API for pipeline reads — get_features + get_classifications\n\nα5 wires the pipeline's typed reads to the Engine PyO3 surface. Two\nnew inherent methods on PostgresBackend + their PyO3 wraps:\n\nPG INHERENT METHODS (not on the Backend trait — pipeline reads are\npostgres-only for v0.6.0; memory/sqlite don't have to mirror)\n- read_features(trace_id, thought_id) -> Option<Features>:\n  SELECT extracted_features FROM cirislens.trace_events\n  WHERE trace_id=$1 AND thought_id=$2 AND extracted_features IS NOT NULL.\n  Returns None when the pipeline hasn't run on those rows.\n  Feature-gated on `extract`.\n- read_classifications(trace_id, thought_id) -> Vec<Vec<ContentClassMatch>>:\n  Same shape against the `classifications` JSONB column. Returns\n  empty Vec when pre-pipeline. Feature-gated on `classify`.\n\nPYO3 WRAPS (in src/ffi/pyo3.rs alongside §A/B/C/D/E/F/G/H/I reads)\n- Engine.get_features(trace_id, thought_id) -> str | None\n- Engine.get_classifications(trace_id, thought_id) -> str\nBoth JSON-encoded; both wrapped in catch_panic (v0.5.3 contract).\n\nV009 ROUND-TRIP VERIFIED\nTwo new PG-gated integration tests:\n- pipeline_read_features_and_classifications_round_trip: insert\n  fixture trace + UPDATE the V009 columns with serde-encoded\n  Features + Vec<Vec<ContentClassMatch>> + read back via the new\n  inherent methods. Verifies the wire shape contract (V009 JSONB ↔\n  serde) is round-trip stable.\n- pipeline_read_returns_none_for_pre_pipeline_row: insert without\n  UPDATE → extracted_features stays NULL → read_features returns\n  None + read_classifications returns []. Confirms the\n  rollback-safe / pre-v0.6.0 path stays valid.\n\nBoth tests pass against the local ciris-qa-postgres container.\n\nPIPELINE ORCHESTRATION DEFERRED\nEngine.receive_pipeline_envelope (FSD §5.4) and the\niter_features_by_cohort streaming reader land in v0.6.0-α6 /\nv0.6.1 alongside the actual stage execution + PipelineEnvelope\nwire format. v0.6.0 stops at the read surface — consumers can read\nback features the bridge / lens-core writes via raw SQL until the\nedge cutover (FSD §12.2 v0.5.1).\n\nNEXT: α6 — Property + differential tests (port from\ncirislens-core/src/scrubber/proptests.rs), then v0.6.0 final\nrelease (Cargo.toml bump + CHANGELOG + tag).\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-12T11:18:34-05:00",
          "tree_id": "63b1b7a0cb94b3ad978f1034f427109232370ebf",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/f7737609190d3a4620fca805078a557d664dbabd"
        },
        "date": 1778603193920,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 110209,
            "range": "± 932",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 262006,
            "range": "± 6614",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 562626,
            "range": "± 11181",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1991101,
            "range": "± 8610",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 350,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1423,
            "range": "± 37",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8161,
            "range": "± 43",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 23221,
            "range": "± 101",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 26447,
            "range": "± 303",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 91067,
            "range": "± 239",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 385,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3288,
            "range": "± 172",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9746,
            "range": "± 29",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42281,
            "range": "± 295",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 634,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2278415,
            "range": "± 108007",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 7043669,
            "range": "± 167198",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 25870010,
            "range": "± 480908",
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
          "id": "82fd51fddeb447f343fb3bc973a0b905fec4b182",
          "message": "0.6.0 — post-ingest filter pipeline substrate (partial close CIRISPersist#19)\n\nBumps Cargo.toml 0.5.8 → 0.6.0 + CHANGELOG entry summarising the\nfive alpha checkpoints (α1..α5, all on main pre-tag):\n\nα1 — Foundation: classify taxonomy + Stage trait + V009 migration\nα2 — Scrub lift: verbatim from CIRISLens cirislens-core/scrubber/\nα3 — Extract lift: verbatim from CIRISLensCore src/extract/\nα4 — NER backends: XLM-R + DistilBERT (candle) + ORT INT8 fast path\nα5 — Engine read API: get_features + get_classifications PyO3 wraps\n\nCargo features per FSD §2.4: classify / scrub / extract /\nscrub-ner / scrub-ort / default-pipeline-ml / default-sovereign-\nlight. Light builds compile in seconds; ML feature builds add ~500MB\nof candle + tokenizers + hf-hub.\n\nWHAT'S NOT IN v0.6.0\n- Pipeline orchestration (receive_pipeline_envelope, Stage runner,\n  edge call site) — v0.6.2 per FSD §12.2 edge-cutover phase.\n- 18-method SecretsService trait + V010 secrets schema + HTTP API\n  + ciris-crypto facade — v0.6.1.\n- Proptests + differential tests — v0.6.0.x patches.\n\nLens / lens-core teams: target ciris-persist == 0.6.0 for the\nv0.6.x adoption track. Read API works against the V009 JSONB\ncolumns immediately; the pipeline orchestration that POPULATES\nthose columns lands when the edge cutover ships v0.6.2.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-12T11:20:17-05:00",
          "tree_id": "74525f755558e9180d62532f3d58fd0f90c35513",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/82fd51fddeb447f343fb3bc973a0b905fec4b182"
        },
        "date": 1778603303222,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 105819,
            "range": "± 1958",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 247247,
            "range": "± 3410",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 528730,
            "range": "± 2584",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1856041,
            "range": "± 11004",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 370,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1501,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8629,
            "range": "± 243",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21381,
            "range": "± 65",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24438,
            "range": "± 209",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83726,
            "range": "± 341",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 363,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3099,
            "range": "± 29",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9618,
            "range": "± 46",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41827,
            "range": "± 235",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 621,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2249924,
            "range": "± 120095",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6625265,
            "range": "± 207803",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23628422,
            "range": "± 280814",
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
          "id": "c47e4a02e8e066870d1c3a0877cf6ff27b15d737",
          "message": "FSD: rename agent deferral_* → agent_deferrals_* + add Appendix A (federation-consensus substrate)\n\nCloses CIRISPersist#31 and CIRISPersist#30 — both FSD-only, no\nimplementation work yet.\n\nCIRISPersist#31 — agent_deferrals_* rename (7 sites)\nThe Phase 3 AGENT-LOCAL deferral tables are renamed to\nagent_deferrals_* to disambiguate from CIRISNodeCore's federation-\nconsensus deferral Contributions (deferral_request / deferral_response\nsubtypes of the contributions table). Same domain term, different\nrow classes — namespacing prevents schema-discovery + operator-\nmental-model drift. Option (A) from the issue.\n\nRename done in §1 / §2 / §4 / §5 / §8 — every mention of deferral_*\nin the FSD. Single-line note added at §5.1's governance-tables row\npointing at Appendix A's rationale.\n\nCIRISPersist#30 — Appendix A \"Federation-consensus substrate\n(CIRISNodeCore)\"\nNew appendix covers the typed-write + read surfaces CIRISNodeCore\nv0.1.0 will consume:\n\n  Write (one method per row class, contribution_type discriminates):\n    engine.put_contribution        cirisnode.contributions\n    engine.cast_vote               cirisnode.votes\n    engine.update_credits_ledger   cirisnode.credits_ledger\n    engine.update_expertise_ledger cirisnode.expertise_ledger\n    engine.put_moderation_event    cirisnode.moderation_events\n    engine.put_slashing_attestation cirisnode.slashing_attestations\n    engine.put_reconsideration_request / _attestation\n                                   cirisnode.reconsideration_*\n\n  Read:\n    contributors_eligible_for_routing (MISSION.md §3.3 routing)\n    read_vote_weight                 (SCHEMA.md §5.2 vote weighting)\n    list_contributions + 5 other bulk-list primitives (mirrors v0.5.5\n                                  §I cursor-paged shape)\n    pending_audit_chain / canonical_audit_chain (SCHEMA.md §13.2 split)\n    get_credits_ledger / get_expertise_ledger (point lookup)\n\nSequencing: spec only NOW (v0.6.0); first cut (V011 migration +\nput_contribution + cast_vote + bulk-list reads) at CIRISNodeCore\nv0.1.0 cut-time, gated on a new `cirisnode` Cargo feature so\ndeployments that don't need the federation-consensus surface skip\nthe migration. Same shape lens-core / edge-core consume persist.\n\nBoth issues will be closed by the merge of this commit.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-12T11:31:25-05:00",
          "tree_id": "1faa0ae10d0af555e1bc20e13e43151f937db6c5",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/c47e4a02e8e066870d1c3a0877cf6ff27b15d737"
        },
        "date": 1778603940197,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 108502,
            "range": "± 2710",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 260432,
            "range": "± 600",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 561043,
            "range": "± 14580",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1990545,
            "range": "± 7612",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 378,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1555,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8138,
            "range": "± 92",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 23140,
            "range": "± 107",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 26388,
            "range": "± 161",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 91018,
            "range": "± 187",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 367,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3178,
            "range": "± 38",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9453,
            "range": "± 110",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42486,
            "range": "± 144",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 646,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2220294,
            "range": "± 171051",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 7010800,
            "range": "± 253812",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 25878603,
            "range": "± 151493",
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
          "id": "5ff57a55edc3e00c6196a491749cc60f7fc92435",
          "message": "v0.6.1-α1: secrets module skeleton + V010 migration + crypto facade\n\nFoundation commit for the federated SecretsService (FSD §7).\n\nNEW SURFACE\n- src/secrets/mod.rs — SecretsError with 8 stable kind() tokens\n  (AV-15 HTTP/PyO3 sanitization convention). Trait + wire types\n  land in α2/α3.\n- src/secrets/crypto.rs — the SOLE import site of ciris_crypto::*\n  in persist (FSD §7.5a crypto-through-ciris-crypto invariant).\n  Wraps:\n    - random_bytes / random_nonce / random_salt / random_master_key\n    - derive_secret_key (PBKDF2-HMAC-SHA-256, 600k iters per OWASP 2023)\n    - encrypt / decrypt (AES-256-GCM, 32-byte key + 12-byte nonce)\n    - hmac_sha256 (for filter-config + audit-log integrity)\n  All errors map to SecretsError (mostly ::Crypto). Length-check\n  gates on every wrapper reject malformed inputs as\n  SecretsError::InvalidArgument.\n\nCARGO FEATURES\n- secrets: postgres + ciris-crypto's aes-gcm/kdf/hmac/random features.\n  Zero direct primitive deps in our Cargo.toml; the boundary is\n  one file (crypto.rs).\n- secrets-server: secrets + server (HTTP API for federated CRUD).\n- secrets-hw DEFERRED: hardware-key migration waits on a\n  symmetric-derivation feature in ciris-keyring upstream. Until\n  then migrate_to_hardware_key returns HardwareKeyUnavailable.\n\nV010 MIGRATION (cirislens_secrets schema + cirislens_pseudonyms)\nFive tables per FSD §7.3:\n  cirislens_secrets.secrets              — encrypted-payload store\n  cirislens_secrets.access_log           — auditable access trail\n  cirislens_secrets.master_key_meta      — master-key lifecycle\n  cirislens_secrets.filter_config        — pattern-catalog CRUD\n  public.cirislens_pseudonyms            — stable Pseudonymize map\n\nEach table fully commented + indexed for the expected access\npaths. All NEW; orthogonal to V009 pipeline columns.\n\nVerified: V010 applies cleanly via the existing run_migrations\ngate, all five tables present after first PG-backed test.\n\nVERIFICATION\n- 10 secrets tests pass: AES-GCM round-trip + auth-tag rejection\n  on tampered ciphertext + wrong-nonce rejection + PBKDF2\n  determinism + salt-divergence + HMAC consistency.\n- cargo check clean on secrets feature build.\n- cargo clippy --tests clean.\n\nNEXT: α2 wire types (SecretReference / SecretRecallResult / etc.)\n+ α3 SecretsService trait. Engine + PyO3 wiring lands in α6.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-12T11:42:59-05:00",
          "tree_id": "08a22ba573743ba0897d63653609da7ebe151191",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/5ff57a55edc3e00c6196a491749cc60f7fc92435"
        },
        "date": 1778604748360,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 101779,
            "range": "± 808",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 243129,
            "range": "± 491",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 526597,
            "range": "± 1707",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1857887,
            "range": "± 13496",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 375,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1557,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8680,
            "range": "± 46",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21192,
            "range": "± 705",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24252,
            "range": "± 77",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83578,
            "range": "± 202",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 374,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3092,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9408,
            "range": "± 46",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42567,
            "range": "± 252",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 621,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2323957,
            "range": "± 203668",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6685975,
            "range": "± 200871",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23845742,
            "range": "± 839001",
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
          "id": "71c1a9c0af17e1d3abc78fbfe272ebadb71a16ef",
          "message": "v0.6.1-α2: federation-stable wire types for SecretsService\n\n13 typed structs + 2 enums + 1 Default for the v0.6.1 wire surface\nper FSD §7.2.\n\nNEW SURFACE (src/secrets/types.rs)\n- SecretRecord — full encrypted-secret row shape (ciphertext + salt\n  + nonce + key_ref + metadata). Mirrors cirislens_secrets.secrets\n  V010 schema exactly. record_schema_version = \"1.0\" today; wire-\n  shape changes within v0.6.x are additive only.\n- EncryptedSecretRecord — wraps SecretRecord with optional\n  edge-side HMAC (federation-internal integrity attestation).\n- SecretReference — metadata-only listing shape (no ciphertext, no\n  key refs). For list_stored_secrets + the (filtered_text, refs)\n  return tuple of process_incoming_text.\n- SecretRecallResult — recall outcome (found + decrypted-value +\n  error message).\n- DecapsulationContext — audit-log context for the\n  decapsulate_secrets_in_parameters operation.\n- AccessLogEntry + AccessOp enum — row shape for\n  cirislens_secrets.access_log + 8-variant operation token\n  (Store/Retrieve/Recall/Forget/Encrypt/Decrypt/Reencrypt/Rotate).\n- SecretsListFilter (Default + AND-compose) — list_stored_secrets\n  filter (sensitivity / pattern / source_message_id / created\n  range).\n- SecretsServiceStats — health + observability summary\n  (total_secrets / active_filters / encryption_enabled /\n  hardware_key_active / rotation_count etc.).\n- RotationResult — reencrypt_all outcome (success + count +\n  per-UUID failures + duration_ms).\n- MasterKeyRef — Software{handle} | Hardware{key_id,descriptor}.\n  Adjacently-tagged JSON (matches ContentClass shape).\n- FilterUpdateRequest / FilterUpdateResult / FilterConfig — the\n  pattern catalog CRUD surface (whole-config replaces; field-\n  level deltas deferred to v0.6.x).\n\nAll types derive Serialize + Deserialize + Debug + Clone + (PartialEq\nwhere shape allows). Stable across the JSON / postgres / PyO3\nboundaries. Doc comments on every public field.\n\nALIGNMENT NOTE\nsecrets feature now implies `classify` (Sensitivity lives in\ncrate::pipeline::classify, shared with the pipeline taxonomy —\nzero-duplication).\n\nVERIFICATION\n- 17 secrets tests pass total (10 crypto + 7 types). Serde round-\n  trips locked for MasterKeyRef (Software + Hardware variants),\n  AccessOp snake_case, SecretReference, SecretRecallResult,\n  SecretsListFilter, FilterUpdateRequest.\n- cargo clippy --tests clean on secrets feature build.\n\nNEXT: α3 — SecretsService trait (18 methods).\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-12T11:46:24-05:00",
          "tree_id": "a45838ce1f4c44c0a2fef1c86b74b98623b815b2",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/71c1a9c0af17e1d3abc78fbfe272ebadb71a16ef"
        },
        "date": 1778604859160,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 95745,
            "range": "± 520",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 237951,
            "range": "± 791",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 520464,
            "range": "± 6853",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 2062272,
            "range": "± 44124",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 325,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1292,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7626,
            "range": "± 92",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 20566,
            "range": "± 519",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 23979,
            "range": "± 59",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 88568,
            "range": "± 260",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 317,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3189,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9817,
            "range": "± 47",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 44570,
            "range": "± 269",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 539,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2174147,
            "range": "± 55421",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6504682,
            "range": "± 112636",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23682434,
            "range": "± 246432",
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
          "id": "b8e9c3af42ee784eb0f0ee523ea66aac07fe8d16",
          "message": "v0.6.1-α3: SecretsService trait (18 methods) + V010 idempotency fix\n\nα3 lands the federation surface contract per FSD §7.1. Method\nsignatures only — concrete impl is α5 (PostgresSecretsBackend).\n\nNEW SURFACE (src/secrets/service.rs)\nSecretsService trait — 18 methods:\n  CRUD (5):       store_secret, retrieve_secret, recall_secret,\n                  list_stored_secrets, forget_secret\n  Detection (2):  process_incoming_text, decapsulate_secrets_in_parameters\n  Direct crypto (2): encrypt, decrypt\n  Filter config (2): get_filter_config, update_filter_config\n  Audit + obs (3): get_service_stats, is_healthy, get_access_logs\n  Key rotation (4): reencrypt_all, rotate_master_key, test_encryption,\n                    migrate_to_hardware_key\n\nPattern: impl Future<...> + Send GAT (matches ReadEngine /\nDerivedSchema convention). NO async_trait dep — Rust 1.75+ GATs\nsuffice. Doc comments cite both the CIRISAgent SecretsServiceProtocol\n§3.1 numbering AND the FSD §7.1 contract.\n\nAudit invariant (in doc comment): every method MUST write a row to\ncirislens_secrets.access_log before returning (including on failure).\nAuditable accountability surface; the PG impl handles this in a\nsingle transaction per call.\n\nV010 IDEMPOTENCY FIX\nα1's V010 migration had bare CREATE TABLE / CREATE INDEX (no IF NOT\nEXISTS). The av26_concurrent_boot_advisory_lock test caught this on\nCI: 10 concurrent workers race-applying migrations all hit\n[42P07] duplicate_table on V010.\n\nFix: add IF NOT EXISTS to every CREATE TABLE + CREATE INDEX in\nV010 (matches the V001 convention which has IF NOT EXISTS\nthroughout). Idempotent now; concurrent workers safely re-run if\nthe advisory lock + refinery schema_history don't fully serialize.\n\nVERIFICATION\n- 17 secrets tests pass.\n- cargo clippy --tests clean on all 4 feature combos.\n- V010 reapplies cleanly against live ciris-qa-postgres.\n\nNEXT: α5 PostgresSecretsBackend impl (full 18-method impl with\naccess_log writes + master_key lifecycle). α4 (crypto facade) is\nalready landed in α1.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-12T11:49:53-05:00",
          "tree_id": "5b6e012e3da95d8479e133a8b4c185877ecbad45",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/b8e9c3af42ee784eb0f0ee523ea66aac07fe8d16"
        },
        "date": 1778605110958,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 104965,
            "range": "± 813",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 245813,
            "range": "± 2764",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 528468,
            "range": "± 1857",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1864266,
            "range": "± 14003",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 372,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1526,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8717,
            "range": "± 27",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21127,
            "range": "± 40",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24178,
            "range": "± 52",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83565,
            "range": "± 179",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 371,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3157,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9468,
            "range": "± 47",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41913,
            "range": "± 261",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 622,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2223430,
            "range": "± 129384",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6571054,
            "range": "± 304704",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23644684,
            "range": "± 1098581",
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
          "id": "8d3d19f94dbab915da23ae98ce36af1af64a8ef0",
          "message": "v0.6.1-α5: PostgresSecretsBackend — 18-method impl with audit + master-key lifecycle\n\nConcrete SecretsService impl backed by cirislens_secrets.* (V010\nschema). ~1,150 LOC + 200 LOC smoke test.\n\nWHAT'S IMPLEMENTED (16 of 18 methods, full)\nCRUD:\n  store_secret           — UUID gen + per-secret salt/nonce, derive\n                           secret_key via PBKDF2 from active master,\n                           AES-256-GCM encrypt, insert. access_log + 1.\n  retrieve_secret        — find by description, decrypt with derived\n                           secret_key, bump access_count + last_accessed.\n  recall_secret          — UUID lookup, optional decrypt; metadata-only\n                           path doesn't decrypt. Returns SecretRecallResult.\n  list_stored_secrets    — filter (sensitivity / pattern /\n                           source_message_id / created range) + cursor-less\n                           DESC pagination.\n  forget_secret          — DELETE + audit + return existed-flag.\n\nDirect crypto:\n  encrypt                — fresh salt+nonce, derive, encrypt, pack\n                           base64(salt || nonce || ciphertext).\n  decrypt                — reverse of above; rejects short ciphertext.\n\nFilter config CRUD:\n  get_filter_config      — read 'global' row.\n  update_filter_config   — INSERT ON CONFLICT bump version atomic.\n\nAudit + observability:\n  get_service_stats      — total / active_filters / matches_today /\n                           last_rotation / rotation_count via aggregate\n                           SQL.\n  is_healthy             — pool conn + active master key check.\n  get_access_logs        — global tail or per-secret-uuid filter.\n\nKey rotation:\n  reencrypt_all          — load all secrets, derive new per-secret\n                           keys from new master, transactional UPDATE +\n                           master_key_meta lifecycle (deactivate old,\n                           activate new). Returns RotationResult with\n                           per-UUID failure list + duration_ms.\n  rotate_master_key      — generate new master (or use supplied bytes),\n                           INSERT master_key_meta row, store key bytes\n                           in in-process software_keys map. Activates\n                           immediately on first-key path.\n  test_encryption        — encrypt + decrypt round-trip with known\n                           plaintext.\n  migrate_to_hardware_key — returns HardwareKeyUnavailable as specced\n                            (waits on ciris-keyring upstream).\n\nSTUBBED (2 methods, return Internal)\n- process_incoming_text         — needs pipeline classify catalog\n- decapsulate_secrets_in_parameters — needs JSON walker + placeholder\n                                     subst\nBoth land properly in v0.6.2 alongside pipeline orchestration.\n\nAUDIT INVARIANT\nEvery method writes one access_log row via secrets_audit() helper.\nThe helper is the only access_log writer in the module so the\ndiscipline is auditable in one place. Best-effort writes (audit-fail\ndoesn't mask the caller's primary error).\n\nMASTER-KEY LIFECYCLE (v0.6.1-α5 in-memory storage)\nSoftware master keys live in a process-lifetime HashMap keyed by\nkey_ref. master_key_meta row tracks lifecycle (created_at /\nactivated_at / deactivated_at / rotated_to). When the process\nrestarts the in-memory map is empty and active_master_key() returns\nCrypto(\"master key {key_ref} has no in-memory bytes\"). Persistent\nsoftware key storage via ciris-keyring is a v0.6.1.x follow-up;\nhardware-key path is v0.6.x once ciris-keyring/symmetric-derivation\nships upstream.\n\nVERIFICATION\nsecrets_round_trip_full_lifecycle (gated on CIRIS_PERSIST_TEST_PG_URL):\n  rotate_master_key →\n  encrypt + decrypt round-trip →\n  test_encryption →\n  store_secret + retrieve_secret →\n  list_stored_secrets →\n  recall_secret (decrypt=true) →\n  forget_secret →\n  recall after forget returns found=false →\n  get_access_logs has >=5 entries →\n  get_service_stats encryption_enabled=true →\n  is_healthy=true →\n  migrate_to_hardware_key returns HardwareKeyUnavailable →\n  process_incoming_text + decapsulate stubs return Internal\n\nAll pass against live ciris-qa-postgres.\n\ncargo clippy --tests clean across all feature combos.\n\nNEXT: α6 — Engine.secrets() accessor + PyO3 wraps for the 18\nmethods (catch_panic + JSON encoding, matching v0.5.3 discipline).\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-12T16:40:14-05:00",
          "tree_id": "aeb031960b91caa73c7e9a6bf405206066f06942",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/8d3d19f94dbab915da23ae98ce36af1af64a8ef0"
        },
        "date": 1778622496799,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 95849,
            "range": "± 426",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 243506,
            "range": "± 7738",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 521516,
            "range": "± 3018",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1952013,
            "range": "± 23302",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 324,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1287,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7706,
            "range": "± 98",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 20530,
            "range": "± 57",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 23947,
            "range": "± 40",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 88478,
            "range": "± 148",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 320,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3235,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9774,
            "range": "± 23",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 44255,
            "range": "± 153",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 538,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2130648,
            "range": "± 230420",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6710599,
            "range": "± 487212",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23459020,
            "range": "± 821898",
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
          "id": "8e1c68ae01c35412bd42e242b220177657dcdc63",
          "message": "0.6.1 — federated SecretsService substrate (CIRISPersist#19 partial close)\n\nBumps Cargo.toml 0.6.0 → 0.6.1 + CHANGELOG entry summarising six\nalpha checkpoints (α1..α6, all on main pre-tag).\n\nα1 — Foundation: secrets / secrets-server features + V010\n     migration (5 tables) + crypto facade\nα2 — Wire types: 13 structs + 2 enums per FSD §7.2\nα3 — SecretsService trait + V010 idempotency fix\nα5 — PostgresSecretsBackend 18-method impl + full-lifecycle smoke test\nα6 — Engine PyO3 surface (18 methods, catch_panic-wrapped)\n\nWhat's NOT in v0.6.1:\n- secrets-hw migrate_to_hardware_key (waits on\n  ciris-keyring/symmetric-derivation upstream)\n- HTTP API behind secrets-server (v0.6.1.x or v0.6.2)\n- process_incoming_text + decapsulate_secrets_in_parameters real\n  impls (v0.6.2 with pipeline orchestration; today returns Internal)\n\nLens / agent target ciris-persist == 0.6.1 for the secrets-substrate\nadoption track. PyO3 surface works against the V010 schema today;\nHTTP federation surface lights up when secrets-server lands.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-12T16:43:17-05:00",
          "tree_id": "ad9c44a72d728a07c61ae41365582e2f41fd70da",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/8e1c68ae01c35412bd42e242b220177657dcdc63"
        },
        "date": 1778622685023,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 95682,
            "range": "± 241",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 237973,
            "range": "± 1421",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 521135,
            "range": "± 2990",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1951926,
            "range": "± 24016",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 325,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1305,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7277,
            "range": "± 84",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 20514,
            "range": "± 40",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 23966,
            "range": "± 693",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 88436,
            "range": "± 115",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 317,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3206,
            "range": "± 67",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9692,
            "range": "± 23",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 44729,
            "range": "± 1046",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 544,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2066177,
            "range": "± 37856",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6402807,
            "range": "± 63824",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23532047,
            "range": "± 124716",
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
          "id": "9d77d3c5b0548e846ab44b674dd05761038b18e5",
          "message": "FSD: lock v0.7.0 as the federation-consensus impl cut (Appendix A.5)\n\nCloser reading of today's release cadence: v0.6.0 + v0.6.1 are\nsubstrate work for lens / agent / bridge consumers, not\nCIRISNodeCore. The federation-consensus typed-writes (Appendix A.2 —\nput_contribution / cast_vote / update_credits_ledger /\nupdate_expertise_ledger / put_moderation_event /\nput_slashing_attestation / put_reconsideration_* / read_vote_weight\n/ routable_contributors + V011 migration) are still pending.\n\nAppendix A.5 (Sequencing) updated:\n\n- v0.6.0 (shipped): spec locked; pipeline read substrate.\n- v0.6.1 (shipped): federated SecretsService substrate.\n- v0.6.2 (next): pipeline orchestration. Closes lens/agent track.\n  NO CIRISNodeCore surface.\n- v0.7.0 (CIRISNodeCore v0.1.0 cut-time): full Appendix A.2 surface\n  — V011 migration + 8 typed-writes + 5 read clusters + `cirisnode`\n  Cargo feature gating.\n- v0.7.x: ledger / reconsideration / moderation / slashing refinements.\n\nWhy v0.7.0 not v0.6.3: the v0.6.x track is the lens/agent/bridge\nsubstrate (finished at v0.6.2). v0.7.0 announces a new federation-\nconsensus substrate cleanly. CIRISNodeCore pins ^0.7.0;\nlens/agent/bridge stay on ^0.6.x or upgrade for the union surface.\n\nSpec-only change. No impl impact.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-12T19:29:22-05:00",
          "tree_id": "621a3b1ba40a33867ac38b32d752a1532f2f5e32",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/9d77d3c5b0548e846ab44b674dd05761038b18e5"
        },
        "date": 1778632609255,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 103452,
            "range": "± 328",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 244787,
            "range": "± 802",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 525754,
            "range": "± 1951",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1852133,
            "range": "± 19448",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 346,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1497,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8234,
            "range": "± 60",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21172,
            "range": "± 107",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24203,
            "range": "± 34",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83500,
            "range": "± 2385",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 364,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3083,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9599,
            "range": "± 54",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41908,
            "range": "± 162",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2375362,
            "range": "± 113975",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6814398,
            "range": "± 217027",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23967010,
            "range": "± 274100",
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
          "id": "3df96189d65819918841511a9f71222586e1e704",
          "message": "v0.7.0-α1: cirisnode feature + V011 migration + module skeleton\n\nFoundation commit for the CIRISNodeCore federation-consensus\nsubstrate (FSD Appendix A). Distinct track from v0.6.x — different\nconsumer ecosystem (CIRISNodeCore vs lens/agent/bridge), different\nCargo feature (cirisnode), different PostgreSQL schema (cirisnode.*\nvs cirislens.*).\n\nNEW SURFACE\n- src/cirisnode/mod.rs — cirisnode::Error with 8 stable kind()\n  tokens (cirisnode_invalid_argument / not_authorized / signature /\n  conflict / not_found / backend / not_implemented / internal).\n  Mirrors the kind() discipline from read::Error, pipeline::Error,\n  secrets::SecretsError. Wire types + trait surface land in α2/α3.\n\nCARGO FEATURE\n- cirisnode = [\"postgres\"] — declared. Implies postgres because the\n  V011 migration + the typed-write path require pg. No new external\n  deps yet (ciris-crypto + uuid + serde_json are already pulled\n  transitively by the secrets / federation features).\n\nV011 MIGRATION — cirisnode schema with 8 tables\n- contributions             — Contribution envelope rows, 7-variant\n                              contribution_type discriminator\n- votes                     — VoteEnvelope rows, optional FK to\n                              contribution_id\n- credits_ledger            — derived per (contributor, cell, subject)\n- expertise_ledger          — derived per (contributor, cell), with\n                              is_active flag for routing\n- moderation_events         — accusation chain\n- slashing_attestations     — adjudication outcomes (FK→moderation)\n- reconsideration_requests  — reverse-prior-slashing\n- reconsideration_attestations — reconsideration outcomes\n\nEvery row carries the standard CIRISPersist audit envelope columns\n(signature + signing_key_id + signature_verified +\noriginal_content_hash + scrub_signature_classical/pqc + scrub_key_id\n+ scrub_timestamp + pqc_completed_at + persist_row_hash). Mirrors\nthe federation_directory V004 shape + the trace_events V001 shape.\n\nis_canonical + canonicalized_at columns on the audit-chain tables\nimplement the SCHEMA.md §13.2 pending-vs-canonical split. The\ncanonical-promotion pass (CIRISNodeCore-side) flips is_canonical\nwhen the audit chain qualifies.\n\nIF NOT EXISTS on every CREATE per v0.6.1-α3 lesson learned\n(idempotent multi-worker boot).\n\nVERIFICATION\n- 1 unit test (error kinds).\n- V011 applies cleanly against live ciris-qa-postgres; all 8\n  tables present after first PG-test run.\n- cargo clippy --tests clean on cirisnode feature build.\n\nNEXT: α2 wire types (ContributionEnvelope + 7 payload variants +\nVoteEnvelope + WitnessSet + ExpertiseAttestation + ModerationEvent +\nSlashingAttestation + ReconsiderationRequest/Attestation + Ledger\ntypes) per CIRISNodeCore/SCHEMA.md §3-10.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-12T19:54:41-05:00",
          "tree_id": "eecf2f0fad0217607cae8721f65465c331127393",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/3df96189d65819918841511a9f71222586e1e704"
        },
        "date": 1778634165081,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 95749,
            "range": "± 205",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 237975,
            "range": "± 645",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 520813,
            "range": "± 3940",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 2006421,
            "range": "± 42511",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 329,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1296,
            "range": "± 123",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7216,
            "range": "± 56",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 20549,
            "range": "± 483",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 23982,
            "range": "± 90",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 88517,
            "range": "± 177",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 317,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3188,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9772,
            "range": "± 55",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 44258,
            "range": "± 142",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 545,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2127396,
            "range": "± 55831",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6529990,
            "range": "± 122942",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23660029,
            "range": "± 415287",
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
          "id": "2cf5f9089ef0983a5c5619e0fb12bc76d3b2540b",
          "message": "v0.7.0-α2: cirisnode wire types — ContributionEnvelope + 12 supporting structs\n\nPer FSD Appendix A.2/A.3 + CIRISNodeCore/SCHEMA.md §3-§10. ~400 LOC\nof types covering every row class V011 introduces.\n\nENVELOPE-LEVEL\n- Cell — (domain, language, subject) tuple per SCHEMA.md §2.5\n- HybridSignature — Ed25519 + ML-DSA-65 + signed_at\n- Witness, DiversityProof, WitnessSet — SCHEMA.md §6\n- ContributionType — 7-variant snake_case enum (deferral_request /\n  deferral_response / proposal / wa_candidacy / expertise_attestation\n  / moderation_event / reconsideration_request)\n- ContributionEnvelope — the common shell per SCHEMA.md §3\n\nPER-ROW-CLASS WIRE TYPES\n- VoteEnvelope (SCHEMA.md §5)\n- ModerationEvent + SlashingAttestation (SCHEMA.md §8)\n- ReconsiderationRequest + ReconsiderationAttestation (SCHEMA.md §9)\n- CreditsLedgerEntry + ExpertiseLedgerEntry (SCHEMA.md §10 read view)\n- CreditsUpdate + ExpertiseUpdate (write inputs)\n\nREAD-SIDE\n- ContributionsFilter + VotesFilter — AND-style filter, every field\n  optional, is_canonical for §13.2 pending-vs-canonical split\n- ListCursor — (last_ts, last_id) tuple, v1 version tag\n- ContributionListPage + VoteListPage\n- RoutableContributor — routing-eligibility result row\n- VoteWeight — SCHEMA.md §5.2 computed-at-aggregation result\n\nPAYLOAD TYPING\nPer-subject-kind payloads (§4.1–§4.10 — arc_question / proposed_battery\n/ prompt_edit / accord_edit / failure_pattern / free_form etc.) stored\nas serde_json::Value. Persist is the substrate; the per-payload type\ntaxonomy lives in ciris-node-core's schema crate.\n\nEQ DERIVES\nStructs containing f64 fields (Witness, WitnessSet, ContributionEnvelope,\nVoteEnvelope, etc.) drop the Eq derive — PartialEq only.\n\nDOC-COMMENT TRADEOFF\n#![allow(missing_docs)] at file top. Per-field semantics live in\nCIRISNodeCore/SCHEMA.md (source of truth); copy-pasting would just\nrot. v0.7.0-α2 follow-up can add curated rustdoc cross-references\nonce the surface settles.\n\nVERIFICATION\n- 7 serde round-trip tests (contribution_type snake_case, cell,\n  ContributionEnvelope, ListCursor, RoutableContributor, ledger).\n- cargo clippy --tests clean across all feature combos.\n\nNEXT: α3 — NodeCoreService trait surface (8 typed-writes + 5 read\nclusters, impl Future + Send GAT).\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-12T19:58:29-05:00",
          "tree_id": "a648fe4704f4d4604b0789a13770cc1ca067b529",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/2cf5f9089ef0983a5c5619e0fb12bc76d3b2540b"
        },
        "date": 1778634400828,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 114342,
            "range": "± 1253",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 265958,
            "range": "± 1199",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 567867,
            "range": "± 1482",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1999219,
            "range": "± 7730",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 339,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1497,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8240,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 23135,
            "range": "± 90",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 26386,
            "range": "± 45",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 91027,
            "range": "± 833",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 363,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3159,
            "range": "± 67",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9792,
            "range": "± 27",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42389,
            "range": "± 159",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 632,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2275543,
            "range": "± 58515",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 7049041,
            "range": "± 56499",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 25963266,
            "range": "± 179223",
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
          "id": "5f884a41f96dd1462360513c3508c999e2243bc4",
          "message": "v0.7.0-α3: NodeCoreService trait — 8 typed-writes + 5 read clusters\n\nFederation-consensus surface contract per FSD Appendix A.2 + A.3.\nMethod signatures only — concrete impl is α4 (PostgresBackend).\n\nWRITES (8 methods)\n- put_contribution(ContributionEnvelope)\n- cast_vote(VoteEnvelope)\n- update_credits_ledger(CreditsUpdate)\n- update_expertise_ledger(ExpertiseUpdate)\n- put_moderation_event(ModerationEvent)\n- put_slashing_attestation(SlashingAttestation)\n- put_reconsideration_request(ReconsiderationRequest)\n- put_reconsideration_attestation(ReconsiderationAttestation)\n\nEach typed-write MUST verify the row's hybrid signature against the\nfederation directory before INSERT (matches federation_keys discipline\nfrom v0.4.x; reject with Error::Signature on mismatch). Inserts\ndefault to is_canonical=false (pending) per SCHEMA.md §13.2;\ncanonical-promotion is a CIRISNodeCore-side pass.\n\nREADS (5 clusters, 5 methods)\n- routable_contributors(domain, language) — routing eligibility\n  per MISSION.md §3.3 step 1-2\n- read_vote_weight(contributor, domain, language, subject) — SCHEMA.md\n  §5.2 weight computation\n- list_contributions(filter, cursor, limit) + list_votes — cursor-\n  paged newest-first per v0.5.5 §I shape. Both accept is_canonical\n  filter for SCHEMA.md §13.2 pending-vs-canonical split (folds cluster\n  3 into clusters 4 + the list_* methods).\n- get_credits_ledger(contributor, cell, subject) +\n  get_expertise_ledger(contributor, domain, language) — point lookups\n\nPattern: impl Future<...> + Send GAT. Mirrors ReadEngine /\nDerivedSchema / SecretsService convention. No async_trait dep.\n\nPer the audit-envelope invariant in the trait doc: PG impl threads\nverify_hybrid_via_directory (v0.4.1 surface) on every typed-write.\n\nNEXT: α4 — PostgresBackend NodeCoreService impl.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-12T20:00:00-05:00",
          "tree_id": "52393cb791907555e18795d05e5354eeb50874ee",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/5f884a41f96dd1462360513c3508c999e2243bc4"
        },
        "date": 1778634496164,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 108704,
            "range": "± 247",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 260753,
            "range": "± 6138",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 561975,
            "range": "± 2026",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1995813,
            "range": "± 11721",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 344,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1409,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8195,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 23171,
            "range": "± 44",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 26449,
            "range": "± 643",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 91043,
            "range": "± 240",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 368,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3153,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9676,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42195,
            "range": "± 164",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 633,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2267233,
            "range": "± 88556",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 7077221,
            "range": "± 422368",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 25913603,
            "range": "± 168219",
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
          "id": "dd5c65344b28bec28cd8eefbc4f3bc3a74aad06d",
          "message": "0.7.0 — CIRISNodeCore federation-consensus substrate (CIRISPersist#30)\n\nClean-break release on a new track. Persist becomes the federation-stable\nhost for the six federation-consensus row classes (Contribution, Vote,\nLedger, Moderation, Slashing, Reconsideration) that CIRISNodeCore\nproduces. Distinct from the v0.6.x lens/agent/bridge substrate —\ndifferent consumer ecosystem, different Cargo feature (`cirisnode`),\ndifferent PostgreSQL schema (`cirisnode.*`). Implements FSD Appendix A.\n\nα4 — PostgresBackend impl:\n\n- 8 typed-writes (put_contribution, cast_vote, update_credits_ledger,\n  update_expertise_ledger, put_moderation_event,\n  put_slashing_attestation, put_reconsideration_request,\n  put_reconsideration_attestation). Each verifies hybrid signature\n  structure before INSERT; ledger writes are idempotent UPSERTs.\n- 5 read clusters: routable_contributors (partial-index path),\n  read_vote_weight (SCHEMA.md §5.2 — Credits × expertise_multiplier\n  × active_tier_multiplier), list_contributions / list_votes\n  (cursor-paged newest-first per v0.5.5 §I shape), get_credits_ledger\n  / get_expertise_ledger point-lookups.\n- Typed error mapping via SqlState: 23505 → Conflict, 23503 →\n  InvalidArgument FK, 23514 → InvalidArgument CHECK.\n\nα5 — Engine PyO3 surface:\n\n- 14 PyO3 methods on Engine wrapping NodeCoreService. JSON-encoded\n  inputs + outputs across the FFI boundary; catch_panic (v0.5.3\n  contract); cirisnode::Error → PyErr via cirisnode_err_to_py with\n  stable kind() tokens.\n\nα2 follow-up — Cell.subject is now Option<String> per NodeCore\nfeedback (SCHEMA.md §7 Expertise paths use cell with only\n{domain, language}, no subject).\n\nTests:\n- 8/8 cirisnode tests pass — 1 error-kind stability, 6 serde\n  round-trip, 1 full-lifecycle integration test against live\n  ciris-qa-postgres (put_contribution → cast_vote → ledger updates\n  → routable_contributors → read_vote_weight → list_* → get_*).\n- Full lib test suite: 223/223 pass. Clippy -D warnings clean\n  across cirisnode postgres pyo3 feature matrix.\n\nSignature verification is a structural stub in v0.7.0; full\ncanonicalization-aware verify_hybrid_via_directory threading lands\nin a v0.7.0.x patch once the CIRISNodeCore canonical-bytes spec is\nlocked. Rows currently INSERT with signature_verified = TRUE; the\npatch will gate that flag on the real directory check.\n\nCloses CIRISPersist#30 (FSD Appendix A spec + impl).\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-12T21:13:32-05:00",
          "tree_id": "14965d5e6c69af2dfa41e1d35e24ea2b8394b5ea",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/dd5c65344b28bec28cd8eefbc4f3bc3a74aad06d"
        },
        "date": 1778638985905,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 84433,
            "range": "± 236",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 202233,
            "range": "± 3460",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 436331,
            "range": "± 6830",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1548508,
            "range": "± 6580",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 261,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1141,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 6324,
            "range": "± 185",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 17963,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 20500,
            "range": "± 60",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 70573,
            "range": "± 84",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 294,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2657,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 7753,
            "range": "± 232",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 33782,
            "range": "± 121",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 535,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2252110,
            "range": "± 11919804",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 5901797,
            "range": "± 20328331",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 32150415,
            "range": "± 28306123",
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
          "id": "18494fd4d250eb92555b0452fceb4fa407678a0d",
          "message": "0.7.1 — real envelope signature verification\n\nCloses the v0.7.0 caveat. The v0.7.0-α4 verify_envelope_signature was\na structural stub: it checked that signature fields were base64-decodable\nand signed_at was non-zero, but did not actually verify the signature\nagainst any pubkey. v0.7.1 makes verification real and gates\nsignature_verified = TRUE on a passing verify.\n\nModel:\n\nPer CIRISNodeCore/SCHEMA.md §2.2, every ContributorId (author_id,\nvoter_id, accuser_id, adjudicator_id, requester_id) IS the Ed25519\npublic key — base64-encoded. Federation-consensus envelopes are\nself-signed against the identity-as-pubkey embedded in the envelope\nitself; persist does not need a federation_keys directory lookup\nfor cirisnode-track verification.\n\nThis corrects the v0.7.0 CHANGELOG note about \"threading\nverify_hybrid_via_directory\" — the schema's identity model is\nself-signed, so the directory variant is not the right primitive\nfor this track. Persist still owns one canonicalization rule (via\nverify::canonical::canonicalize_envelope_for_signing); only the\nkey-lookup path differs from the v0.4.1 outbound track.\n\nWhat landed:\n\n- New src/cirisnode/verify.rs with canonical_bytes_for_envelope +\n  verify_envelope_signed. Reuses the persist-owned Python-compatible\n  canonicalizer; calls verify_hybrid with HybridPolicy::Ed25519Fallback.\n- All 6 typed-writes that carry signatures (put_contribution,\n  cast_vote, put_moderation_event, put_slashing_attestation,\n  put_reconsideration_request, put_reconsideration_attestation)\n  call verify_envelope_signed before INSERT. signature_verified =\n  TRUE is gated on the verify pass; persist refuses to insert on\n  failure.\n- Integration test uses real ed25519_dalek signing keys; test\n  contributor + voter identities ARE base64-encoded Ed25519\n  pubkeys (matches the schema). New tamper-rejection assertion:\n  mutating payload after sign rejects with Error::Signature.\n\nTests:\n- 13/13 cirisnode tests pass — 5 new verify-module tests\n  (round-trip, tampered payload, wrong pubkey, empty signature,\n  malformed base64) + 7 types tests + 1 error-kind + 1 full\n  lifecycle integration test against live ciris-qa-postgres.\n- Full lib test suite: 228/228 pass (+5 from v0.7.0). Clippy\n  -D warnings clean across cirisnode postgres pyo3 feature matrix.\n\nStill deferred:\n- ML-DSA-65 hybrid verification for contributor envelopes requires\n  per-contributor PQC key registration; classical Ed25519 verify\n  is sufficient for v0.7.1.\n- Tightening to HybridPolicy::Strict is deferred until the PQC\n  pubkey rollout completes federation-side.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-12T21:22:48-05:00",
          "tree_id": "ebfcaec490302402dc014e979eae7ac23f625a60",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/18494fd4d250eb92555b0452fceb4fa407678a0d"
        },
        "date": 1778639456766,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 101651,
            "range": "± 611",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 243118,
            "range": "± 1687",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 525150,
            "range": "± 1566",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1856088,
            "range": "± 22563",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 343,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1498,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8211,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21178,
            "range": "± 262",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24224,
            "range": "± 702",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83547,
            "range": "± 159",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 395,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3166,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9760,
            "range": "± 40",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42323,
            "range": "± 132",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 625,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2490495,
            "range": "± 301953",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6771162,
            "range": "± 200565",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23790957,
            "range": "± 476092",
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
          "id": "fdb67add2fcf85b1c3587c92eefd39d15bcc92d8",
          "message": "0.7.2 — canonical-promotion attestation (CIRISPersist#32)\n\nCloses the v0.7.0 is_canonical write-side gap. CIRISNodeCore's\nsubstrate-contract test against v0.7.1 confirmed all 14 methods\nsufficient for routine federation-consensus operations EXCEPT\npromoting rows from pending → canonical (MISSION.md §3.4\ntruth-grounding loop). v0.7.2 closes the gap with a signed-\nattestation envelope per issue #32 Option B.\n\nWhat landed:\n\n- V012 migration: new cirisnode.promotion_attestations table with\n  the standard CIRISPersist audit envelope columns plus target_kind\n  (CHECK against 5 enum variants), target_ids UUID[] (bulk-promote\n  per attestation), attested_by (consensus crate identity), and\n  aggregate_evidence JSONB. GIN index on target_ids for reverse\n  \"which attestations promoted this row?\" lookups.\n\n- New wire types:\n  - TargetRowKind enum (5 variants — Contribution, Vote,\n    ModerationEvent, SlashingAttestation, ReconsiderationAttestation;\n    ReconsiderationRequest is intentionally absent — its canonical\n    lifecycle is carried by the paired attestation).\n  - PromotionAttestation struct.\n\n- New trait method: NodeCoreService::put_promotion_attestation\n  (9th typed-write).\n\n- PostgresBackend impl:\n  - Verify gate via v0.7.1 verify_envelope_signed (signer is\n    attested_by — consensus crate identity).\n  - Empty target_ids → InvalidArgument.\n  - Transactional: BEGIN → INSERT attestation row → UPDATE target\n    rows (is_canonical = TRUE, canonicalized_at = NOW() via WHERE\n    id = ANY($1::uuid[])) → assert affected-row count matches\n    target_ids.len() (else rollback) → COMMIT.\n  - Table + column names come from the typed TargetRowKind enum —\n    no caller-controlled SQL injection surface.\n\n- PyO3 wrap: Engine.cirisnode_put_promotion_attestation(att_json).\n\nTests:\n\n- New promotion_attestation_round_trip integration test against\n  live ciris-qa-postgres: bulk-promote 2 contributions with one\n  attestation, verify is_canonical flips; assert duplicate → Conflict,\n  empty target_ids → InvalidArgument, phantom target → InvalidArgument\n  WITH proof of rollback (re-using same attestation_id with a valid\n  target succeeds, confirming the prior INSERT was not persisted).\n- 14/14 cirisnode tests pass; 229/229 full lib suite; clippy\n  -D warnings clean across cirisnode postgres pyo3.\n\nCloses CIRISPersist#32.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-13T09:35:27-05:00",
          "tree_id": "b1f9e047ead7c7bb395ddb4b8441f6beb2847a23",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/fdb67add2fcf85b1c3587c92eefd39d15bcc92d8"
        },
        "date": 1778683557728,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 114031,
            "range": "± 495",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 265582,
            "range": "± 6682",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 566714,
            "range": "± 5637",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 2002568,
            "range": "± 7029",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 341,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1503,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8244,
            "range": "± 57",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 23167,
            "range": "± 88",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 26427,
            "range": "± 1028",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 91036,
            "range": "± 488",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 367,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3071,
            "range": "± 42",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9850,
            "range": "± 523",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42414,
            "range": "± 152",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 656,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2280405,
            "range": "± 109219",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 7031746,
            "range": "± 167876",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 25852202,
            "range": "± 592247",
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
          "id": "aab67a310dd86f8b7bab668fad6ca31f1f545718",
          "message": "0.7.3 — CI hygiene: harden macos cargo install against poisoned cache\n\nv0.7.2 tag CI failed on darwin-aarch64 (no postgres): the macos-14\nrunner image ships a rustup-init stub at /Users/runner/.cargo/bin/cargo\nthat lazy-installs the toolchain on first use. dtolnay/rust-toolchain\ninstalls the real cargo over the stub, but Swatinem/rust-cache@v2\nrestored a cached ~/.cargo/bin/ (created from an earlier run when\nthe stub was the only cargo there), overwriting the freshly-installed\nreal cargo. Result: `cargo test` invoked the stub and exited 1\nbefore the test even loaded.\n\nThe failing macos test gate blocked `Publish wheel to PyPI` on the\nv0.7.2 tag CI — wheels built (3 matrix arches) but didn't upload.\n\nv0.7.3 ships:\n\n- .github/workflows/ci.yml: cache-bin: false on darwin-aarch64-test\n  + ios-build. Disables the ~/.cargo/bin/ portion of the rust-cache\n  so the dtolnay-installed cargo stays intact across cache restore.\n  Build cache (registry + target) is unaffected — only the small\n  fast-to-rebuild bin layer is excluded.\n- which cargo / cargo --version diagnostic step before each macos\n  test/build, so this class of regression surfaces with a clear\n  signal at the right place if it ever recurs.\n\nFunctionally identical to v0.7.2 — same code, same V012 migration,\nsame put_promotion_attestation trait method. Only the CI workflow\nchanged; the release re-publishes v0.7.2's features to PyPI.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-13T09:51:17-05:00",
          "tree_id": "f0d89bc8d9f90205313da468de2e83ec9cd1addb",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/aab67a310dd86f8b7bab668fad6ca31f1f545718"
        },
        "date": 1778684385086,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 110987,
            "range": "± 1079",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 251940,
            "range": "± 2147",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 533111,
            "range": "± 4699",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1859294,
            "range": "± 11962",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 345,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1426,
            "range": "± 41",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8247,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21193,
            "range": "± 97",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24215,
            "range": "± 463",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83598,
            "range": "± 627",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 377,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3148,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9504,
            "range": "± 39",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41397,
            "range": "± 729",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 628,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2368761,
            "range": "± 82705",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6823789,
            "range": "± 271241",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23817182,
            "range": "± 179810",
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
          "id": "e53ab03434eae36b63c021f4777e2a353ec695a1",
          "message": "0.7.4 — pipeline orchestration: extract wired into receive_and_persist (closes #19)\n\nv0.6.0 absorbed the scrub/extract/classify substrate (modules + V009\nmigration + get_features/get_classifications read API + scrub wired\ninto ingest). v0.6.1 added SecretsService. The remaining gap from\nissue #19 was the extract orchestration: extract was not actually\ncalled during receive_and_persist, so V009's extracted_features\ncolumn stayed NULL in production and consumers' get_features calls\nalways returned None. v0.7.4 closes the gap.\n\nWhat landed:\n\n- New Backend::update_features_batch trait method (extract-gated).\n  Default impl returns 0 (no-op) — memory + sqlite backends silently\n  skip. PostgresBackend overrides with a single-round-trip UPDATE\n  ... FROM (SELECT UNNEST(...)) that touches every named (trace_id,\n  thought_id) row.\n\n- Wire extract into IngestPipeline::receive_and_persist: after the\n  trace_events INSERT batch, iterate the verified CompleteTrace\n  events, build DeclaredCohortAxes from each trace's deployment_profile\n  block (V006 denormalized fields, required at 2.7.9), call\n  pipeline::extract::extract_features(trace_json, declared), and\n  batch-UPDATE all rows.\n\n- Non-fatal failure mode: if the post-insert UPDATE fails (transient\n  PG hiccup) or a single trace fails to serialize, log a structured\n  warn and continue. The trace_events rows already landed; an\n  extract miss leaves extracted_features NULL, which matches the\n  pre-v0.7.4 production state. Dropping verified agent testimony\n  for a downstream-enrichment failure would be the wrong trade-off.\n\nTests:\n\n- New update_features_batch_round_trip integration test against\n  live ciris-qa-postgres: insert 2 fixture traces with distinct\n  cohort axes (moderation/production/US vs research/staging/EU),\n  batch-update both with the corresponding Features, read back\n  each via read_features, assert the cohort axes round-tripped.\n  Covers the empty-fast-path (zero-len input returns 0 without\n  hitting the DB).\n- 268/268 lib pass; clippy -D warnings clean across postgres\n  extract classify pyo3 cirisnode.\n\nStill deferred from issue #19 (downstream follow-ups, not blocking\nthe substrate ask):\n- Classify wiring (classify module ships types only; matchers\n  unimplemented).\n- iter_features_by_cohort streaming API (cirislens_reader role\n  + SQL is sufficient for RATCHET in the interim).\n\nCloses CIRISPersist#19 — the post-ingest filter pipeline ask.\nv0.6.0 absorbed the substrate; v0.7.4 wires extract into the live\ningest path.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-13T09:59:07-05:00",
          "tree_id": "a9a86c30254e680140f24ae22c524c1e96d5c559",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/e53ab03434eae36b63c021f4777e2a353ec695a1"
        },
        "date": 1778685026131,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 108660,
            "range": "± 288",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 259229,
            "range": "± 1103",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 561111,
            "range": "± 1526",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1987459,
            "range": "± 3841",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 352,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1451,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8246,
            "range": "± 116",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 23181,
            "range": "± 245",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 26393,
            "range": "± 74",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 91055,
            "range": "± 445",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 367,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3193,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9883,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 43167,
            "range": "± 104",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 637,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2259712,
            "range": "± 183415",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 7037415,
            "range": "± 339442",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 26049666,
            "range": "± 386535",
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
          "id": "c72c9b37b022d35dc3359665d4392d6076c12993",
          "message": "0.7.5 — Pipeline orchestrator + PipelineEnvelope wire types (CIRISPersist#33 pieces 1+2)\n\nSubstrate foundation for CIRISEdge#3. v0.6.0 lifted the per-stage\nmatcher/walker code from CIRISLens under classify/scrub/extract\nfeatures; v0.7.4 wired extract_features inline into receive_and_persist.\nv0.7.5 adds the orchestrator surface and federation-internal wire\nshapes edge needs to compose PipelineEnvelopes.\n\nWhat landed:\n\n- Pipeline orchestrator in src/pipeline/mod.rs:\n  - PipelineBuilder + Pipeline composing registered Stage impls\n    in declaration order; sequential run via Pipeline::run.\n  - Dependency validation at build time (Error::MissingDependency\n    when a stage names an unadded upstream).\n  - ErasedStage object-safe shim auto-impl'd for every T: Stage,\n    lets the builder hold Vec<Box<dyn ErasedStage>> without forcing\n    async_trait onto the public trait.\n  - Stage failures short-circuit (FSD §3.3 step 3 — no partial-\n    success path).\n\n- PipelineState extended per FSD §5.1:\n  - features: Option<Features> (extract output, FSD-shaped)\n  - encrypted_secrets: Vec<EncryptedSecretRecord> (reserved for\n    EncryptAndStoreStage)\n  - pii_scrubbed invariant flag (FSD §4.3 invariant 4)\n  - stages_executed switched from Vec<&'static str> to Vec<String>\n    so wire-format PipelineMetadata can carry without conversion.\n\n- New src/pipeline/types.rs (federation-internal wire shapes,\n  FSD §4.3):\n  - PipelineEnvelope { pipeline_schema_version, envelope,\n    sidecar, edge_signature, edge_key_id, edge_pqc_key_id }\n  - PipelineSidecar { classifications, features,\n    encrypted_secrets, pipeline_metadata } — all fields feature-\n    gated.\n  - PipelineMetadata { stages_executed, fields_modified,\n    pii_scrubbed, secrets_encrypted, pipeline_duration_ms,\n    edge_build_id }.\n  - HybridSignatureBlock locally defined (decoupled from the\n    federation-consensus cirisnode::HybridSignature track).\n\n- ExtractStage concrete Stage impl wrapping v0.6.0\n  extract_features. Produces state.features from the first\n  CompleteTrace in env.events (matches FSD §5.1 single-Option\n  shape; multi-trace batches retain per-trace extract from\n  v0.7.4's inline path).\n\n- minimal_pipeline() factory — ExtractStage only. Full FSD §5.2\n  default_pipeline(secrets) wiring Classify → Scrub →\n  EncryptAndStore → Extract waits on subsequent #33 patches\n  (ClassifyStage matcher catalog, ScrubStage adapter,\n  EncryptAndStoreStage glue).\n\nTests:\n- 7 pipeline orchestrator unit tests (error-kind stability,\n  PipelineBuilder rejects missing dep, stage_names declaration\n  order, minimal_pipeline runs ExtractStage on empty batch).\n- 4 wire-type serde tests in pipeline::types (schema-version\n  constant, metadata zeroing, HybridSignatureBlock round-trip,\n  None ml_dsa_65 omitted on the wire).\n- 294/294 full lib pass against live ciris-qa-postgres.\n  Clippy -D warnings clean across postgres extract classify\n  pyo3 cirisnode secrets scrub.\n\nStill deferred from CIRISPersist#33 (tracked for v0.7.x+):\n- Concrete ClassifyStage (needs matcher catalog).\n- Concrete ScrubStage (adapter over existing Scrubber trait).\n- EncryptAndStoreStage (orphan-secret invariant + SecretsService\n  integration).\n- Engine::receive_pipeline_envelope HTTP handler (FSD §4.3\n  invariants 1-7).\n- FederatedSecretsClient (HTTP client mirroring SecretsService).\n- Role tag enforcement on federation_keys.\n\nReferences CIRISPersist#33 (this work — pieces 1+2 landed);\nCIRISEdge#3 (substrate prerequisite that drove the issue).\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-13T10:58:13-05:00",
          "tree_id": "b20e2d7983f2cf0f0b0c6ec5875ebef1122c072d",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/c72c9b37b022d35dc3359665d4392d6076c12993"
        },
        "date": 1778688390501,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 108565,
            "range": "± 273",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 259932,
            "range": "± 635",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 561660,
            "range": "± 6658",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1996895,
            "range": "± 14150",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 339,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1487,
            "range": "± 34",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8196,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 23170,
            "range": "± 50",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 26399,
            "range": "± 86",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 91033,
            "range": "± 278",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 351,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3096,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9423,
            "range": "± 48",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41576,
            "range": "± 158",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 657,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2279029,
            "range": "± 58521",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 7149244,
            "range": "± 51968",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 26384840,
            "range": "± 172689",
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
          "id": "0ce2449fc9692d151658df7e478b37ab0901d339",
          "message": "0.8.0 — cirisgraph substrate: MemoryService + ConfigService absorption (closes #34)\n\nStep 1B of the CIRISAgent migration trajectory (persist → edge →\nlens-core → node-core). Absorbs CIRISAgent's LocalGraphMemoryService\n+ GraphConfigService off the agent's homegrown SQLite/Postgres +\nhand-rolled SQL.\n\nWhy Postgres + recursive CTEs (no embedded graph DB):\n\nVerified via deepwiki against CIRISAgent's live code: actual workload\nis point lookup by (node_id, scope), time-window scans on updated_at,\npredicate filters on JSONB attributes, direct-edge retrieval per\nnode, and bounded procedural k-hop traversal (max_depth ∈ [1, 16]).\nNO Cypher/Datalog requirement. Postgres + recursive CTE + GIN on\nJSONB handles every pattern at substrate-grade reliability. Pulling\nin CozoDB / kuzu / indradb buys zero query expressiveness for the\nworkload and costs deployment simplicity.\n\nWhat landed:\n\n- V013 migration: cirisgraph schema with nodes + edges tables.\n  Schema parity with CIRISAgent's graph_nodes / graph_edges\n  (verified column-by-column via deepwiki). Audit envelope columns\n  added on persist side. GIN index on attributes for predicate\n  push-down; (node_type, scope) + (updated_at) B-tree indexes.\n\n- Wire types: GraphNode, GraphEdge, GraphScope (Local/Identity/\n  Environment/Community), EdgeDirection, NodeFilter, NodeListPage,\n  TraversalConfig, KhopEntry, ListCursor (local v1 cursor, same\n  shape as cirisnode track — refactor to shared module deferred\n  to v0.9.x once a third consumer emerges).\n\n- GraphService trait — 7 methods (3 writes + 4 reads) with\n  impl Future<...> + Send GAT pattern matching NodeCoreService /\n  SecretsService discipline. upsert_node carries AV-48\n  expected_version gate; traverse_k_hop bounds AV-46 depth +\n  relationship allow-list; query_nodes refuses None scope per AV-47.\n\n- PostgresBackend impl: UNNEST'd UPDATE patterns matching v0.7.4\n  shape; recursive CTE for k-hop BFS with per-level fan-out bound;\n  dynamic filter composition for query_nodes; typed SqlState\n  mapping (23505→Conflict, 23503→InvalidArgument FK,\n  23514→InvalidArgument CHECK).\n\n- PyO3 surface: 7 Engine.cirisgraph_* methods. JSON-in / JSON-out\n  across FFI; catch_panic discipline; cirisgraph::Error → PyErr\n  via cirisgraph_err_to_py with stable kind() tokens.\n\nThreat-model additions (docs/THREAT_MODEL.md §4):\n\n- AV-45 — attributes JSONB size cap (default 1 MiB; configurable\n  via CIRIS_PERSIST_GRAPH_MAX_ATTRIBUTES_BYTES).\n- AV-46 — k-hop depth bound at MAX_KHOP_DEPTH=16 + required\n  non-empty edge_relationships allow-list + per-level fan-out limit.\n- AV-47 — scope leakage prevention: GraphScope required at type\n  level on every read.\n- AV-48 — UPSERT-by-version replay safety (expected_version\n  optimistic-concurrency gate).\n\nTests: 9/9 cirisgraph tests pass against live ciris-qa-postgres\nincluding 1 full-lifecycle integration test (upsert / version\nconflict / size-cap reject / 3-edge cycle / directional edges /\nrelationship filter / k-hop bounds / 2-hop traverse / scope-required\n/ hard cascade delete). 303/303 full lib pass; clippy -D warnings\nclean across cirisgraph postgres pyo3 cirisnode secrets extract\nclassify scrub.\n\nUnblocks CIRISAgent Phase 1B for MemoryService + ConfigService.\nFuture v0.8.2 (telemetry + tsdb_consolidation) writes TSDB_DATA /\nTSDB_SUMMARY nodes here with SUMMARIZES / TEMPORAL_NEXT edges.\n\nCloses CIRISPersist#34.\nReferences memory/project_migration_roadmap.md for the 4-step\nsubstrate-substitution sequence (Step 0 content stabilization done\nin CIRISAgent 2.8.10; Step 1A Phase 1A already shippable at v0.7.5;\nStep 1B starts here).\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-13T16:42:31-05:00",
          "tree_id": "787869f65351d0b0df628d03830153d2ceae4706",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/0ce2449fc9692d151658df7e478b37ab0901d339"
        },
        "date": 1778709033254,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 107084,
            "range": "± 430",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 248089,
            "range": "± 1131",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 528903,
            "range": "± 1614",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1855739,
            "range": "± 15330",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 343,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1424,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8225,
            "range": "± 34",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21156,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24220,
            "range": "± 249",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83514,
            "range": "± 232",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 378,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3107,
            "range": "± 30",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9843,
            "range": "± 23",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42551,
            "range": "± 160",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2219445,
            "range": "± 47321",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6562824,
            "range": "± 270331",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23598323,
            "range": "± 110950",
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
          "id": "29abf17e5faee489187dd371ce7cf0c3549d4c4d",
          "message": "0.8.1 — hash-chained audit log: AuditService absorption (closes #35)\n\nStep 1B continuation. Absorbs CIRISAgent's GraphAuditService write\npath. Per-tenant monotonic sequence_number + sha256 prev_hash chain\nenforces ordering AND tamper-evidence.\n\nWhat landed:\n\n- V014 migration: cirislens.audit_log with per-tenant monotonic\n  sequence (UNIQUE), 32-byte prev_hash + entry_hash BYTEA, audit\n  envelope columns. action_type / subject indexes for correlation.\n\n- Wire types: AuditEntry (hashes serialized as base64 on JSON wire,\n  BYTEA on disk), AuditFilter (tenant-required AV-51), AuditCursor\n  v1 on (recorded_at, entry_id), AuditListPage, ChainVerification\n  with ChainVerifyOutcome { Ok | Break { at_sequence, reason,\n  detail } } + ChainBreakReason enum (EntryHashMismatch |\n  PrevHashMismatch | SequenceGap | SignatureFailure |\n  GenesisPrevHashNotZero).\n\n- AuditService trait — 3 methods:\n  - record_entry: re-derive entry_hash, verify signature, FOR\n    UPDATE on tail row, assert prev_hash + seq monotonicity, INSERT.\n  - list_entries: tenant-scoped cursor-paged listing.\n  - verify_chain: end-to-end chain walk with typed break diagnostic.\n\n- audit::verify helpers:\n  - compute_entry_hash strips signature AND entry_hash (self-\n    referential field) before sha256.\n  - verify_entry_signature uses verify_hybrid against actor_id\n    (which IS the Ed25519 pubkey per v0.7.1 self-signed model).\n  - truncate_to_micros convenience — Postgres TIMESTAMPTZ is\n    microsecond-precision, callers MUST truncate recorded_at\n    before signing or pre/post-storage canonical bytes diverge.\n    Documented.\n\n- PostgresBackend impl: transactional INSERT-and-validate; reuses\n  persist's canonicalize_envelope_for_signing + verify_hybrid\n  primitives so audit inherits the v0.4.1+ verify stack.\n\n- PyO3 surface: 3 Engine.audit_* methods. JSON-in / JSON-out;\n  catch_panic discipline; audit::Error → PyErr with stable kind()\n  tokens.\n\nThreat-model additions (docs/THREAT_MODEL.md §4):\n\n- AV-49 — hash-chain integrity: entry_hash re-derive + prev_hash\n  match + sequence continuity + signature verify, all gated at\n  record_entry. Signature binds to canonical bytes that INCLUDE\n  entry_hash, so a downstream rewrite invalidates upstream\n  signature too.\n- AV-50 — chain fork detection: verify_chain walks end-to-end\n  and surfaces typed breaks. Five distinct break categories.\n- AV-51 — tenant isolation: empty tenant_id rejects pre-SQL;\n  every read pins tenant_id in WHERE. Federation-admin cross-\n  tenant deferred to v0.9.x auth_tokens.\n\nTests: 12/12 audit tests pass against live ciris-qa-postgres\ncovering full lifecycle (genesis → chain extend → replay reject →\ngap reject → wrong-prev reject → verify_chain Ok → tenant\nisolation → empty-tenant reject → tamper detection via\nEntryHashMismatch). 315/315 full lib pass; clippy -D warnings\nclean across cirisaudit cirisgraph postgres pyo3 cirisnode\nsecrets extract classify scrub.\n\nUnblocks CIRISAgent's GraphAuditService migration (Phase 1B\ncontinuation). v0.8.2 (telemetry + tsdb_consolidation) is the\nnext stop on the v0.8.x roadmap.\n\nCloses CIRISPersist#35.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-13T16:55:58-05:00",
          "tree_id": "a5cb6c2098be3366f5b58ee6e913958a2909d506",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/29abf17e5faee489187dd371ce7cf0c3549d4c4d"
        },
        "date": 1778709818332,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 108662,
            "range": "± 1326",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 260034,
            "range": "± 1001",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 561449,
            "range": "± 4182",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1994068,
            "range": "± 9090",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 370,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1576,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8144,
            "range": "± 192",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 23139,
            "range": "± 200",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 26372,
            "range": "± 608",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 91029,
            "range": "± 319",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 372,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3147,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9763,
            "range": "± 243",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42111,
            "range": "± 150",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 632,
            "range": "± 47",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2263521,
            "range": "± 35178",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 7031327,
            "range": "± 56707",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 25925662,
            "range": "± 264534",
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
          "id": "41075049d85a0b1aa79b8cf3f7e5ae47fe503aa3",
          "message": "0.8.2 — telemetry + TSDB consolidation substrate (closes #36)\n\nStep 1B continuation. Absorbs CIRISAgent's TelemetryService +\nTSDBConsolidationService write/read paths. Two-storage-shape design:\nraw observations land in cirisgraph.telemetry_metrics (24h-lived,\nno audit envelope); 6h consolidator rolls them up into tsdb_summary\nnodes in cirisgraph.nodes (V013) with TEMPORAL_NEXT edges between\nadjacent summaries.\n\nWhy split raw vs summary: high-frequency writes don't fit\nversioned/audited graph-node semantics. Flat-table fast path for\nraw; rolled-up summary carries the audit envelope on behalf of\nthe period it summarizes.\n\nV015 migration:\n- cirisgraph.telemetry_metrics — raw observations + 24h TTL;\n  indexed (tenant, name, observed_at) for window scans;\n  expires_at index for reaping path.\n- cirisgraph.consolidation_locks — multi-instance coordination;\n  PK (period_start, tenant_id); locked_at index for AV-53 stale-\n  lock detection.\n\nWire types: MetricObservation, MetricSummary, MetricFilter,\nMetricCursor, MetricListPage, ConsolidationRequest,\nConsolidationOutcome.\n\nTelemetryService trait — 4 methods:\n- record_metric / record_metrics_batch (UNNEST'd bulk insert)\n- list_metrics (tenant-scoped cursor-paged)\n- consolidate_period (lock-acquire → aggregate → upsert-summary →\n  TEMPORAL_NEXT-edge → delete-raw → release-lock flow)\n\nPostgresBackend impl:\n- Aggregation via GROUP BY metric_name with SUM/MIN/MAX/AVG +\n  COUNT(DISTINCT labels) for cardinality observability.\n- Summary node UPSERT mirrors cirisgraph::upsert_node SQL —\n  version-bumps on re-rollup (idempotent).\n- Prior-period lookup via attributes @> {metric_name, tenant_id}\n  + period_start < req.period_start; guarantees TEMPORAL_NEXT\n  source node exists (AV-54), avoids self-edges on re-rollup.\n- Stale-lock auto-break via interval-embedded UPDATE; compile-\n  time STALE_LOCK_SECONDS constant, no injection surface.\n- Failure-path lock release prevents orphans on transient errors.\n\nPyO3: 4 Engine.telemetry_* methods. JSON-in/out; catch_panic;\ntelemetry::Error → PyErr via telemetry_err_to_py.\n\nThreat-model additions (docs/THREAT_MODEL.md §4):\n- AV-52 — labels JSONB size cap (default 4 KiB, configurable);\n  bulk path validates pre-I/O. Cardinality cap observability-only\n  via unique_label_combinations field; runtime enforcement\n  deferred.\n- AV-53 — consolidation lock starvation: stale locks (>1h)\n  auto-break with broke_stale_lock telemetry signal.\n- AV-54 — TEMPORAL_NEXT chain integrity: pre-write lookup\n  confirms prior summary exists.\n\nTests: 7/7 telemetry tests pass against live ciris-qa-postgres\nincluding full-lifecycle (record × 7 → AV-52 reject → list with\nfilters → consolidate period A → idempotent re-run → period B\nwith TEMPORAL_NEXT to period A's summaries) + lock-contention\ntest (planted fresh lock blocks new acquirer with ran=false).\n322/322 full lib pass; clippy -D warnings clean across telemetry\ncirisaudit cirisgraph postgres pyo3 cirisnode secrets extract\nclassify scrub.\n\nCloses CIRISPersist#36.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-13T17:18:22-05:00",
          "tree_id": "68f0f7b24af4e18ebed8d6f0ea4cfde0b11a41af",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/41075049d85a0b1aa79b8cf3f7e5ae47fe503aa3"
        },
        "date": 1778711181360,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 109005,
            "range": "± 1933",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 259760,
            "range": "± 1756",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 560213,
            "range": "± 3921",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1990123,
            "range": "± 4855",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 335,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1421,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8150,
            "range": "± 44",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 23260,
            "range": "± 61",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 26471,
            "range": "± 88",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 91089,
            "range": "± 334",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 366,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3143,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9798,
            "range": "± 27",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42390,
            "range": "± 154",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 632,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2265107,
            "range": "± 170236",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 7037220,
            "range": "± 185056",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 25824118,
            "range": "± 131129",
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
          "id": "1d2fbd9904861174915e8c940630c4bcc0b725ba",
          "message": "0.8.3 — incident records substrate (closes #37); Phase 1B Postgres complete\n\nLast of the v0.8.x Phase 1B substrate cuts on the Postgres side.\nAbsorbs CIRISAgent's IncidentManagementService — correlation-keyed\ndedup + open→investigating→resolved→closed state machine.\n\nV016 migration: cirislens.incident_records. Partial index on\n(tenant_id, state, last_seen_at) WHERE state IN ('open',\n'investigating') for hot-path queries. GIN on correlation_keys.\n\nIncidentService trait — 4 methods:\n- record_incident: AV-56 bounds-check, then JSONB ?| dedup probe\n  vs open/investigating incidents in (tenant, category); bumps\n  occurrences on match, fresh INSERT otherwise.\n- transition_state: FOR UPDATE current, AV-55 forward-ladder\n  assert, stamp resolved_at + notes on Resolved/Closed.\n- list_incidents: tenant-scoped cursor-paged.\n- correlate: reverse-lookup via GIN.\n\nThreat-model additions (docs/THREAT_MODEL.md §4):\n- AV-55 — state-machine bypass: regressive transitions reject as\n  InvalidTransition; closed incidents don't dedup new records.\n- AV-56 — correlation_keys abuse: max 32 keys × 256 bytes each.\n\nPyO3: 4 Engine.incident_* methods.\n\nTests: 8/8 incident tests + 330/330 full lib pass against live\nciris-qa-postgres. Clippy -D warnings clean.\n\nPhase 1B Postgres substrate is COMPLETE:\n| #34 v0.8.0 cirisgraph (Memory + Config)        | 9/9 ✓\n| #35 v0.8.1 cirisaudit (hash-chain)             | 12/12 ✓\n| #36 v0.8.2 telemetry + tsdb_consolidation      | 7/7 ✓\n| #37 v0.8.3 cirisincident                       | 8/8 ✓\n\nNOT yet ready for CIRISAgent 2.9.0 cutover: CIRISAgent supports\nboth PostgreSQL AND SQLite (CIRIS_DB_URL dialect switch — Postgres\nfor federated, SQLite default for sovereign-mode / Pi-class / iOS\ndevice). The v0.6.1+ Rust substrate (secrets, cirisgraph,\ncirisaudit, telemetry, cirisincident, cirisnode) is Postgres-only\nas of v0.8.3. SQLite parity is the next major phase before the\nagent team can adopt persist on the full deployment matrix.\n\nTrait surfaces + wire types + schema designs ARE locked at v0.8.3;\nSQLite impls slot in behind the same Backend-style traits without\nbreaking the consumer API. v0.9.0 will be the SQLite parity cut.\n\nCloses CIRISPersist#37.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-13T17:27:46-05:00",
          "tree_id": "0614a9612d20034ed80c4fe00068b054cbd18cb7",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/1d2fbd9904861174915e8c940630c4bcc0b725ba"
        },
        "date": 1778711758508,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 109277,
            "range": "± 326",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 260354,
            "range": "± 902",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 561662,
            "range": "± 2523",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1989726,
            "range": "± 9847",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 344,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1495,
            "range": "± 35",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7389,
            "range": "± 32",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 23260,
            "range": "± 46",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 26492,
            "range": "± 86",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 91073,
            "range": "± 159",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 352,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3259,
            "range": "± 36",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9769,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41711,
            "range": "± 84",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 631,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2289230,
            "range": "± 177475",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 7155020,
            "range": "± 95481",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 26375109,
            "range": "± 398822",
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
          "id": "3636d3553a7b1b69bac9529e2fa4cbfc4bac9771",
          "message": "0.8.4 — cirisgraph SQLite parity + iOS-conditional rusqlite (issue #38 α1)\n\nFirst piece of the v0.9.0 SQLite parity cut. Closes the gap between\nv0.6.1+ Postgres-only substrate and CIRISAgent's full deployment\nmatrix (Postgres federated; SQLite sovereign-mode / Pi / iOS).\n\niOS-hardening (CIRISVerify v1.6.4 lesson):\n- Cargo.toml: rusqlite is target-conditional. On iOS, drop `bundled`\n  feature (links system libsqlite3); on non-iOS, keep `bundled` for\n  clean manylinux wheels. Bundled rusqlite duplicates sqlite3 symbols\n  with iOS's system libsqlite3 → Apple's libRPAC.dylib (Database-\n  Tracking) sees two dylibs and asserts. Same fix CIRISVerify made.\n- SqliteBackend: PRAGMA busy_timeout = 30000 (matches CIRISAgent's\n  iOS 30s timeout; universal hygiene).\n- SqliteBackend::conn_handle() public accessor for sibling modules\n  to share the connection.\n\ncirisgraph SQLite impl:\n- Feature gate cirisgraph = [] (was = [\"postgres\"]); now pairs with\n  either backend.\n- src/graph/sqlite.rs: SqliteGraphBackend implements GraphService\n  with all 7 methods + same AV-45..AV-48 semantics.\n- Dialect translations: JSONB → TEXT (canonical JSON), GIN →\n  expression-indexed json_extract, text[] params → json_each(?)\n  joins, UUID → TEXT, TIMESTAMPTZ → RFC 3339, NOW() →\n  datetime('now', 'subsec').\n- Recursive CTE restructured for SQLite (no nested-LIMIT in\n  recursive arm; per-level fan-out moves to outer LIMIT —\n  max_depth × per_level_limit upper bound preserves AV-46\n  intent).\n- New migrations/sqlite/lens/V013__cirisgraph_nodes_edges.sql.\n\nTests: new cirisgraph_sqlite_round_trip_full_lifecycle mirrors the\nv0.8.0 Postgres test exactly (13 assertions covering upsert, AV-48\nversion conflict, AV-45 size cap, edges, AV-46 bounds, k-hop via\nrecursive CTE, AV-47 scope required, hard cascade). 345/345 full\nlib pass against both backends; clippy -D warnings clean across the\nfull feature matrix including sqlite.\n\nv0.9.0 roadmap (issue #38) progress:\n  secrets (v0.6.1) Postgres ✓  SQLite pending\n  cirisnode (v0.7.x) Postgres ✓  SQLite pending\n  cirisgraph (v0.8.0) Postgres ✓  SQLite ✓ (v0.8.4)\n  cirisaudit (v0.8.1) Postgres ✓  SQLite pending\n  telemetry (v0.8.2) Postgres ✓  SQLite pending\n  cirisincident (v0.8.3) Postgres ✓  SQLite pending\n\nReferences CIRISPersist#38.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-13T17:38:23-05:00",
          "tree_id": "e3d12b795c91baf7cea4c494a5debd686aa5d6d8",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/3636d3553a7b1b69bac9529e2fa4cbfc4bac9771"
        },
        "date": 1778712380122,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 122401,
            "range": "± 944",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 274110,
            "range": "± 597",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 575212,
            "range": "± 10584",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 2019252,
            "range": "± 4395",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 337,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1402,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8196,
            "range": "± 70",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 23238,
            "range": "± 56",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 26464,
            "range": "± 56",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 91045,
            "range": "± 479",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 364,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3140,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 10060,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42536,
            "range": "± 218",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 635,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2252449,
            "range": "± 73600",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 7046888,
            "range": "± 145492",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 25895522,
            "range": "± 239534",
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
          "id": "89e3903bf213ae0989ce863b977b10f22f30ce53",
          "message": "0.8.5 — cirisaudit SQLite parity (issue #38 α2)\n\nSecond of the SQLite parity cuts. Hash-chain audit log absorbed onto\nSQLite with byte-for-byte AV-49/AV-50/AV-51 semantics.\n\n- src/audit/sqlite.rs: SqliteAuditBackend impl of AuditService.\n- Per-tenant tail-lock translation: PG FOR UPDATE → SQLite BEGIN\n  IMMEDIATE (database-level RESERVED lock + busy_timeout=30000\n  from v0.8.4 = safe writer serialization without deadlock).\n- BYTEA → BLOB (32-byte sha256 raw); TIMESTAMPTZ → RFC 3339 TEXT;\n  JSONB payload → TEXT JSON.\n- migrations/sqlite/lens/V014__cirislens_audit_log.sql (flat\n  schema; cirislens_audit_log table).\n- cirisaudit = [] feature gate; pairs with either backend.\n\nTests: new cirisaudit_sqlite_round_trip_full_lifecycle mirrors the\nv0.8.1 Postgres lifecycle exactly (genesis → replay reject →\nsequence-gap reject → wrong-prev reject → 3-entry chain →\nverify_chain Ok → tenant isolation → empty-tenant reject → direct-\nUPDATE tamper surfaces EntryHashMismatch via verify_chain).\n\n346/346 lib pass against both backends; clippy -D warnings clean\nacross cirisaudit cirisgraph postgres sqlite pyo3 cirisnode\nsecrets telemetry cirisincident extract classify scrub.\n\nReferences CIRISPersist#38.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-13T17:42:54-05:00",
          "tree_id": "930010f179c867eecc58bf96e567cf3842e6bfef",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/89e3903bf213ae0989ce863b977b10f22f30ce53"
        },
        "date": 1778712643605,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 109002,
            "range": "± 825",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 249964,
            "range": "± 1309",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 532680,
            "range": "± 1502",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1866434,
            "range": "± 7761",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 346,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1413,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8279,
            "range": "± 159",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21138,
            "range": "± 241",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24178,
            "range": "± 92",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83535,
            "range": "± 401",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 376,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3205,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9731,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42321,
            "range": "± 181",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2247383,
            "range": "± 54851",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6606049,
            "range": "± 80792",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23711728,
            "range": "± 140910",
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
          "id": "a21076325027254230af669e5df7f1cc9407a916",
          "message": "0.8.6 — telemetry SQLite parity (issue #38 α3)\n\nThird of the SQLite parity cuts. TSDB consolidation + raw metrics\nabsorbed onto SQLite with byte-for-byte AV-52/53/54 semantics.\n\n- src/telemetry/sqlite.rs: SqliteTelemetryBackend impl of\n  TelemetryService — 4 methods including the full consolidate_period\n  rollup (acquire lock → aggregate → UPSERT summary → TEMPORAL_NEXT\n  edge → delete raw → release).\n- Summary nodes UPSERT directly against cirisgraph_nodes (shared\n  schema with v0.8.4 cirisgraph sqlite).\n- Bulk insert: UNNEST'd PG INSERT … SELECT translates to a\n  prepared-statement loop inside BEGIN IMMEDIATE transaction\n  (atomic + serialized via SQLite's RESERVED lock).\n- Stale-lock break: INTERVAL '3600 seconds' → datetime('now',\n  '-3600 seconds') embedded literal (compile-time constant).\n- JSONB labels → TEXT JSON; PG @> predicate → per-key\n  json_extract equality checks for labels_contains.\n\nSubtle bug surfaced + fixed during integration test:\nchrono's default serde for DateTime<Utc> emits nanosecond\nprecision, but fmt_datetime uses microsecond. Stored summary\nattributes had nanos; prior-period probe bound had micros. Lex\ncompare on RFC 3339: '7' (nanos digit) < 'Z' (Z-suffix) at the\nprecision boundary, falsely matching every summary as its own\npredecessor → spurious TEMPORAL_NEXT edges. Fix: truncate\nperiod_start/period_end to microseconds before serializing summary\nattributes (helper duplicated locally to keep telemetry feature\ndecoupled from cirisaudit).\n\nTests: 2/2 telemetry SQLite tests pass (full-lifecycle + lock\ncontention). 348/348 lib pass across both backends; clippy clean.\n\nReferences CIRISPersist#38.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-13T17:47:36-05:00",
          "tree_id": "28dc9ee0c85ab451f90478cfb109ce3dc6e062e7",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/a21076325027254230af669e5df7f1cc9407a916"
        },
        "date": 1778712916995,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 108566,
            "range": "± 972",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 259688,
            "range": "± 604",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 561645,
            "range": "± 2026",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1997107,
            "range": "± 14760",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 370,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1511,
            "range": "± 28",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8206,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 23141,
            "range": "± 90",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 26357,
            "range": "± 71",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 90996,
            "range": "± 408",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 367,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3222,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9941,
            "range": "± 193",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42542,
            "range": "± 733",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 648,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2236594,
            "range": "± 155792",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 7066707,
            "range": "± 932219",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 26129475,
            "range": "± 128833",
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
          "id": "86278052fdc1888307c4f90588950011f15a2fa3",
          "message": "0.8.7 — cirisincident SQLite parity (issue #38 α4)\n\nFourth of the SQLite parity cuts. Correlation-keyed dedup + state\nmachine absorbed onto SQLite with byte-for-byte AV-55/AV-56\nsemantics.\n\n- src/incident/sqlite.rs: SqliteIncidentBackend impl of\n  IncidentService (4 methods).\n- JSONB ?| / ?& / ? operators translate to EXISTS-style\n  json_each subqueries. Dedup probe joins json_each on BOTH the\n  existing row's keys array AND the new incident's keys array.\n- State transitions use BEGIN IMMEDIATE for serialization (matches\n  v0.8.5 audit pattern).\n- Partial index WHERE state IN ('open', 'investigating') ports\n  directly (SQLite supports partial indexes).\n- cirisincident = [] feature gate.\n\nTests: full-lifecycle test (dedup, cross-category isolation,\nAV-56 oversized reject, state machine forward/backflow/notes-\nrequired, closed-no-dedup, correlate, list filters, tenant\nisolation, NotFound on missing). 349/349 lib pass across both\nbackends.\n\nv0.9.0 roadmap: secrets + cirisnode remain.\n\nReferences CIRISPersist#38.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-13T17:50:49-05:00",
          "tree_id": "5aa90e89ae6243661a292f9fc5b7067ed8c2b416",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/86278052fdc1888307c4f90588950011f15a2fa3"
        },
        "date": 1778713129807,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 108814,
            "range": "± 362",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 260531,
            "range": "± 886",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 561856,
            "range": "± 2649",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1991776,
            "range": "± 4109",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 341,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1392,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8364,
            "range": "± 47",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 23172,
            "range": "± 183",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 26418,
            "range": "± 283",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 91409,
            "range": "± 4527",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 365,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3183,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9856,
            "range": "± 34",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41622,
            "range": "± 167",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 635,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2246213,
            "range": "± 17421",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 7053591,
            "range": "± 47411",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 25867360,
            "range": "± 855219",
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
          "id": "ba29508c9764322dc81b4b80cf09a1f35ab8db7a",
          "message": "0.9.0 — CIRISAgent 2.9.0 adoption cut: 6 of 22 services absorbed with full SQLite + Postgres parity\n\nThis release closes the substrate-readiness gap that blocks\nCIRISAgent's Phase 1B migration on sovereign-mode / Pi-class / iOS\ndevice deployments. Every v0.8.x trait surface runs against both\nbackends; agent team can `pip install ciris-persist==0.9.0` and\nbegin the substrate cutover without fragmenting deployment shapes.\n\nSubstrate-bound services absorbed (Postgres + SQLite both):\n\n| Persist module  | CIRISAgent service absorbed                              |\n| cirisgraph      | MemoryService + ConfigService                            |\n| cirisaudit      | AuditService (hash-chained, Ed25519-signed)              |\n| telemetry       | TelemetryService + TSDBConsolidationService (6h rollup)  |\n| cirisincident   | IncidentManagementService                                |\n\n6 of 22 services covered by 4 modules. Remaining 16: reasoning-\nbound (stay in Python) or process-local infrastructure.\n\niOS hardening (CIRISVerify v1.6.4 lesson applied at v0.8.4):\n- rusqlite target-conditional; bundled on non-iOS, system-linked\n  on iOS (avoids libRPAC.dylib symbol-duplication assertions).\n- SqliteBackend PRAGMA busy_timeout = 30000 (matches agent iOS\n  30s timeout, applied universally as good hygiene).\n\nWhat's DEFERRED to v0.9.1+ (tracked as new issues):\n- secrets SQLite (CIRISPersist#39): ~1100 LOC crypto-path port;\n  not agent-blocking — agent keeps existing in-process\n  ciris_engine/logic/secrets/ while v0.9.1 lands.\n- cirisnode SQLite (CIRISPersist#40): not agent-blocking — agent\n  v2.9.0 doesn't consume cirisnode (NodeCoreCore consumer track).\n\nTests: 349/349 lib pass against live ciris-qa-postgres; all SQLite\ntests pass against in-memory SQLite (per-module full-lifecycle).\nClippy -D warnings clean across the full feature matrix.\n\nCloses the SQLite parity arc started in CIRISPersist#38 for the\n4 agent-blocking modules; #39 + #40 track the remaining 2.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-13T17:55:10-05:00",
          "tree_id": "be615e38fa4d921a1c1830e3eecbe5099cb685bb",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/ba29508c9764322dc81b4b80cf09a1f35ab8db7a"
        },
        "date": 1778713386446,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 101747,
            "range": "± 742",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 242384,
            "range": "± 600",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 523827,
            "range": "± 1223",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1850308,
            "range": "± 20408",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 346,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1548,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8201,
            "range": "± 29",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21220,
            "range": "± 538",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24284,
            "range": "± 86",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83571,
            "range": "± 301",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 360,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3111,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9561,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42036,
            "range": "± 105",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 621,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2250345,
            "range": "± 117708",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6631645,
            "range": "± 147569",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23768855,
            "range": "± 966248",
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
          "id": "79e94852b0ca717b9c5c9ccc945c02a2dad80d27",
          "message": "fix(pyproject): ship full v0.6.1+ feature set in the wheel (closes #41)\n\nThe v0.8.4–v0.8.7 SQLite parity work + the v0.7.x / v0.8.x\nsubstrate cuts shipped at the rlib level, but\n`[tool.maturin] features = [\"pyo3\"]` in pyproject.toml only\ncompiled `pyo3` + transitively `postgres` into the published wheel.\nResult: `pip install ciris-persist==0.9.0` would have shipped\npostgres-only with NONE of the v0.6.1+ modules — every agent\nconsumer would have had to source-rebuild with `--features\n\"sqlite cirisgraph cirisaudit telemetry cirisincident ...\"` to\nreach the actual v0.9.0 substrate.\n\nFix: bump `[tool.maturin] features` to enable the full\nagent-adoption feature set:\n\n  pyo3 + sqlite + cirisgraph + cirisaudit + telemetry +\n  cirisincident + secrets + cirisnode + extract + classify + scrub\n\nBackend selection happens at `Engine` construction time per DSN\nscheme — Postgres deployments get every module on Postgres;\nSQLite deployments get the 4 polyglot modules natively (graph,\naudit, telemetry, incident) and clean NotImplemented errors on\nsecrets + cirisnode trait calls until #39 + #40 close their\nSQLite parity.\n\nCost: rusqlite's bundled libsqlite3 + pipeline ML deps add\n~3-5 MB to the wheel vs the v0.8.3 postgres-only shape. Acceptable\ngiven the deployment-ergonomics win (one `pip install`, every\nbackend + every module, zero source-build).\n\nCloses CIRISPersist#41.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-13T19:02:41-05:00",
          "tree_id": "2727927f5339fb10b9fda191139cabddf314b3a6",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/79e94852b0ca717b9c5c9ccc945c02a2dad80d27"
        },
        "date": 1778717400879,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 109034,
            "range": "± 315",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 261416,
            "range": "± 926",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 561681,
            "range": "± 2242",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1996655,
            "range": "± 31650",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 351,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1457,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8174,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 23242,
            "range": "± 203",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 26480,
            "range": "± 70",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 91064,
            "range": "± 115",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 365,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3081,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 10184,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42262,
            "range": "± 127",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 663,
            "range": "± 27",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2247009,
            "range": "± 38903",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 7022528,
            "range": "± 30019",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 25874293,
            "range": "± 80159",
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
          "id": "a98096193a0df6da33b898aa55120076f2eb89b9",
          "message": "0.9.1 — verify pin bump v2.0.2 → v2.0.5 (iOS hardware-marker self-heal + Mach-O hash parity)\n\nRust-side git pins for ciris-keyring + ciris-verify-core +\nciris-crypto bumped from CIRISVerify v2.0.2 → v2.0.5 (all from the\nCIRISVerify monorepo). Python-side ciris-verify floor bumped to\n>=2.0.5,<3.\n\nBrings 3 fixes inherited transitively by every persist consumer:\n\n- v2.0.3 (CIRISVerify#8): CanonicalBuild v2 with `target` field.\n- v2.0.4: Self-heal orphaned hardware markers on iOS reinstall —\n  fixes a class of \"app reinstall leaves stale hardware-keyring\n  marker, agent refuses to boot\" failures on iOS device deployments.\n  Directly relevant to CIRISAgent v2.9.0 on iOS.\n- v2.0.5 (CIRISVerify#19): Single-source-of-truth __TEXT hash for\n  Mach-O sign/runtime parity. Closes the sign-verifies-but-runtime-\n  rejects edge case on macOS + iOS that affected build-manifest\n  verify paths.\n\nNo persist-side code changes — trait surfaces, FFI shapes, and\nwire formats unchanged. 349/349 lib pass against live ciris-qa-\npostgres + in-memory SQLite; clippy -D warnings clean across the\nfull feature matrix.\n\nCargo.lock re-locked at v2.0.5 (commit dcc8b4ed).\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-13T19:21:21-05:00",
          "tree_id": "c526ea14771aab2869a95ff390c210d50433f4ec",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/a98096193a0df6da33b898aa55120076f2eb89b9"
        },
        "date": 1778718603206,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 102006,
            "range": "± 812",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 242800,
            "range": "± 2750",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 525781,
            "range": "± 1405",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1852147,
            "range": "± 23712",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 347,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1404,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7286,
            "range": "± 102",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21159,
            "range": "± 46",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24188,
            "range": "± 126",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83567,
            "range": "± 202",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 367,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3030,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9409,
            "range": "± 34",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41286,
            "range": "± 208",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 636,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2481459,
            "range": "± 112790",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6810346,
            "range": "± 129954",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23787156,
            "range": "± 1430161",
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
          "id": "940f000b92ea6561af279187181ca1c8a4ce7412",
          "message": "0.9.2 — multi-target build registration via ciris-build-sign register (closes #42)\n\nPersist's CI now signs FOUR per-target BuildManifests + registers\nthem as a single CanonicalBuild v2 row (CIRISVerify v2.0.3+),\nunblocking verify_tree(project=\"ciris-persist\", target=...) for\nevery deployment class — including iOS + Android consumers that\nrebuild persist's Rust from source and verify the Python wrapper\ntree.\n\nCI changes:\n\n- ciris-build-sign tarball: v1.8.0 → v2.0.5. Brings the `register`\n  subcommand + CanonicalBuild v2 multi-target shape.\n\n- Four manifests signed per release (was one):\n  * python-source-tree: file-tree hash of python/ciris_persist/\n    (.py + .pyi only). Covers what iOS / Android agents walk\n    when they verify persist's installed Python wrappers.\n  * x86_64-unknown-linux-gnu: binary_hash = sha256(linux x86_64 wheel)\n  * aarch64-unknown-linux-gnu: binary_hash = sha256(linux aarch64 wheel)\n  * aarch64-apple-darwin: binary_hash = sha256(macOS arm64 wheel)\n\n- ciris-build-sign register replaces the custom curl POST to\n  /v1/verify/binary-manifest. Writes the `builds` parent row signed\n  over all per-target manifest hashes + per-target binary_manifests\n  (binary mode) + function_manifests (source-tree mode) rows to\n  /v1/builds.\n\n- Round-trip verify updated to GET /v1/builds/<v>?project=ciris-persist\n  for the parent row + per-target ?target=<name> GETs for every\n  signed target. Fails the build if any target's round-trip fails.\n\nWhy iOS + Android needed this:\n\npip install ciris-persist doesn't work on iOS/Android (no wheels).\nAgents on those platforms embed the persist Python wrappers via\nPyOxidizer/Buildozer and rebuild persist's Rust from source. Without\na registered python-source-tree manifest, verify_tree returns\nregistry_error / valid=false. v0.9.2 closes that gap.\n\nLibrary / wheel surface unchanged. No code changes; trait surfaces,\nFFI shapes, wire formats, and the published wheel contents are\nbyte-for-byte identical to v0.9.1. Only the CI registration shape\nchanged.\n\nTests: 349/349 lib pass against live ciris-qa-postgres + in-memory\nSQLite. YAML parse check on the rewritten workflow passes. The\nregister / round-trip flow only validates end-to-end against the\nlive CIRISRegistry in tag CI; the tag CI run is the integration\ngate.\n\nCloses CIRISPersist#42.\nReferences CIRISVerify#8 (CanonicalBuild v2, v2.0.3) + v2.0.5\nrelease for the register subcommand.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-13T20:21:49-05:00",
          "tree_id": "ecd6ab9f94a7e3c023d7f9ece2b24adb0b0677c5",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/940f000b92ea6561af279187181ca1c8a4ce7412"
        },
        "date": 1778722207676,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 95632,
            "range": "± 600",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 237842,
            "range": "± 400",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 520476,
            "range": "± 4028",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1946724,
            "range": "± 29244",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 304,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1216,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 6844,
            "range": "± 42",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 20554,
            "range": "± 293",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 23946,
            "range": "± 59",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 88386,
            "range": "± 324",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 327,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3259,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 10181,
            "range": "± 86",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 45783,
            "range": "± 253",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 606,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2056564,
            "range": "± 62950",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6321440,
            "range": "± 125834",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23515983,
            "range": "± 306526",
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
          "id": "12283341960852233bf0ec3c6fe22db9841b9cd2",
          "message": "0.9.3 — SecretsService SQLite parity (closes #39)\n\nDecouple `secrets` feature from `postgres`: enable secrets alongside\neither backend (or both). Crypto facade + key cache + trait are\nbackend-agnostic; only the storage adapter changes.\n\n- migrations/sqlite/lens/V010 — 5-table schema with BYTEA→BLOB,\n  JSONB→TEXT JSON, TEXT[]→TEXT JSON-array, UUID→TEXT 36-char,\n  TIMESTAMPTZ→RFC 3339, BIGSERIAL→INTEGER AUTOINCREMENT.\n- src/secrets/key_cache.rs — process-static software master-key\n  cache extracted from postgres.rs so both backends share it.\n- src/secrets/sqlite.rs — SqliteSecretsBackend impl of all 18\n  SecretsService methods. Per-call spawn_blocking around the shared\n  Arc<Mutex<Connection>> handle; BEGIN IMMEDIATE replaces SELECT …\n  FOR UPDATE for reencrypt_all rotation; every method writes its\n  access-log row before returning (audit invariant matches Postgres\n  1:1). process_incoming_text / decapsulate_secrets_in_parameters\n  stub to Internal (deferred to v0.6.2 pipeline); migrate_to_\n  hardware_key returns HardwareKeyUnavailable (waits on\n  ciris-keyring/symmetric-derivation upstream) — same shape as the\n  v0.6.1-α5 Postgres stubs.\n\nCrypto invariant (FSD §7.5a) unchanged: src/secrets/crypto.rs\nremains the sole ciris-crypto import site; persist takes zero direct\nprimitive deps. The SQLite impl routes through that facade byte-\nfor-byte identically to Postgres.\n\nTests: secrets::sqlite::tests::secrets_sqlite_round_trip_full_\nlifecycle exercises 13 phases against an in-memory SQLite. 18/18\nsecrets tests pass with --features \"secrets sqlite\"; no regression\nwith --features \"secrets postgres\" or both.\n\nNOT tagged: CIRISRegistry#13 (HTTP 500 on /v1/builds POST for\nciris-persist) still blocks the v0.9.2 publish workflow; v0.9.3\nlands on main now so downstream consumers can read source. Tag +\nPyPI publish follow once registry unblocks.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-13T20:50:38-05:00",
          "tree_id": "5cfe7cf08f21f9978e9c069b1c7eea4ef0dd6034",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/12283341960852233bf0ec3c6fe22db9841b9cd2"
        },
        "date": 1778776819043,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 101517,
            "range": "± 785",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 241881,
            "range": "± 738",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 523448,
            "range": "± 1747",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1848994,
            "range": "± 12657",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 340,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1500,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7843,
            "range": "± 102",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21096,
            "range": "± 41",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24140,
            "range": "± 56",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83466,
            "range": "± 585",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 370,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3106,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9552,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41731,
            "range": "± 169",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 631,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2212569,
            "range": "± 42377",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6544620,
            "range": "± 93195",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23638462,
            "range": "± 167589",
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
          "id": "87355aff2f33f25423cb17ec258bae391717c3d4",
          "message": "0.9.4 — cirisnode SQLite parity (closes #40)\n\nFinal SQLite parity piece for the v0.6.1+ substrate. Decouple\n`cirisnode` feature from `postgres`; pair with either backend.\n\n- migrations/sqlite/lens/V011 — 7-table federation-consensus\n  schema (contributions, votes, credits/expertise ledgers,\n  moderation, slashing, reconsideration request + attestation)\n  with the same audit envelope shape as Postgres V011.\n- migrations/sqlite/lens/V012 — promotion attestation table\n  (#32); target_ids UUID[] → TEXT JSON-array; reverse-lookup uses\n  json_each() instead of the Postgres GIN.\n- src/cirisnode/sqlite.rs — SqliteNodeCoreBackend impl of all 14\n  NodeCoreService methods (8 typed-writes + 5 reads +\n  put_promotion_attestation). Per-call spawn_blocking on the\n  shared Arc<Mutex<Connection>> handle; BEGIN IMMEDIATE replaces\n  SELECT … FOR UPDATE for put_promotion_attestation's transactional\n  INSERT-attestation + UPDATE-N-targets + verify-total-affected\n  + rollback-on-mismatch path.\n\nSignature-verify invariant unchanged: src/cirisnode/verify.rs is\nshared by both backends. No duplication; no divergence.\n\nTests: cirisnode::sqlite::tests::cirisnode_sqlite_round_trip_full_\nlifecycle exercises all 14 methods + the promotion-attestation\ntransactional path with a rollback sub-test. 13/13 cirisnode tests\npass with --features \"cirisnode sqlite\"; no regression with\n\"cirisnode postgres\" or both.\n\nSeries completion: every CIRISAgent service in the persist-bound\nset (Memory/Config/Audit/Telemetry/TSDB/IncidentMgmt/Secrets/\nSecretsToolService) now has full Postgres + SQLite parity. Server,\nsovereign-mode, Pi, iOS — all platforms supported.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-14T12:20:18-05:00",
          "tree_id": "6698d0737d4151450584647100b37db83d9231a1",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/87355aff2f33f25423cb17ec258bae391717c3d4"
        },
        "date": 1778779722832,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 102140,
            "range": "± 859",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 242954,
            "range": "± 1086",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 526243,
            "range": "± 6033",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1853055,
            "range": "± 8700",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 342,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1477,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7587,
            "range": "± 758",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21332,
            "range": "± 82",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24350,
            "range": "± 66",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83729,
            "range": "± 162",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 363,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3167,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9471,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41719,
            "range": "± 172",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2270150,
            "range": "± 61471",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6670094,
            "range": "± 162490",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23966246,
            "range": "± 227082",
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
          "id": "d8b467b05c989d49952fa2383ddb0e6dc65d275a",
          "message": "fix(V019): drop nested BEGIN/COMMIT + TIMESTAMPTZ cast in index expr\n\nPre-push hook caught two issues in V019 as written:\n\n1. `((attributes->>'period_start')::timestamptz)` in the expression\n   index — TIMESTAMPTZ cast from text is STABLE (depends on session\n   timezone), not IMMUTABLE. PG rejects STABLE functions in index\n   expressions (SQLSTATE 42P17). Canonical RFC 3339 strings sort\n   lexicographically the same way TIMESTAMPTZ does when the offset\n   is normalized (Z or +HH:MM) — which is how persist always emits\n   them via `fmt_datetime`. Dropping the cast keeps the index TEXT-\n   typed and immutable.\n\n2. Explicit `BEGIN; ... COMMIT;` wrap — refinery wraps each migration\n   in its own transaction; the nested wrap interacts poorly with\n   tokio-postgres's expression-index parsing path (the second\n   statement parses in a context where the prior ALTER's column-add\n   hasn't \"committed\" within refinery's outer tx, so the expression\n   index sees a partially-resolved column reference and the\n   IMMUTABLE check fires). Letting refinery's own tx handle atomicity\n   sidesteps the issue.\n\nVerified: fresh-DB migration sweep clean; 38/38 read_section tests\npass with --features \"postgres,pyo3,server\".\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-14T18:36:29-05:00",
          "tree_id": "7a495b604fdcb2f075991373b5ce6298656aa915",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/d8b467b05c989d49952fa2383ddb0e6dc65d275a"
        },
        "date": 1778802286111,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 95647,
            "range": "± 185",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 237628,
            "range": "± 1083",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 520246,
            "range": "± 7184",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1941787,
            "range": "± 20509",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 309,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1226,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7259,
            "range": "± 76",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 20579,
            "range": "± 395",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 23973,
            "range": "± 78",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 88443,
            "range": "± 172",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 317,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3329,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9908,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 44204,
            "range": "± 95",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 538,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2110026,
            "range": "± 60922",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6513073,
            "range": "± 114226",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23592600,
            "range": "± 440088",
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
          "id": "6179fa678d25e350ad3b991e4f9960ad6c5eb8be",
          "message": "1.0.1 — first publishable wheel of the 1.x series\n\nv1.0.0 tag CI hit two issues that gated wheel publish:\n- V019 nested BEGIN/COMMIT + ::timestamptz cast (SQLSTATE 42P17)\n- av26 hardcoded migration-count assertion (16 → 19)\n\nBoth fixed in d8b467b + 6310577. This bump promotes those onto the\n1.x tag track. No surface or behavioral changes from v1.0.0; same\nsubstrate-completion cut.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-14T18:45:28-05:00",
          "tree_id": "9d606dc7ff26cba66db6a90753555613cf3a2f98",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/6179fa678d25e350ad3b991e4f9960ad6c5eb8be"
        },
        "date": 1778802775909,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 113997,
            "range": "± 1318",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 264345,
            "range": "± 874",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 562577,
            "range": "± 7830",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1985441,
            "range": "± 10084",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 329,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1363,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 6623,
            "range": "± 62",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 23177,
            "range": "± 51",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 26418,
            "range": "± 186",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 91066,
            "range": "± 180",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 370,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3102,
            "range": "± 37",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9816,
            "range": "± 146",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42634,
            "range": "± 727",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2254313,
            "range": "± 78865",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 7013425,
            "range": "± 165504",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 25837847,
            "range": "± 240996",
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
          "id": "1669aafc5054664d39adcb28e6892e230a3c61e4",
          "message": "1.0.2 — narrow python smoke test to exception-hierarchy export check\n\nv1.0.1 tag CI failed at tests/python/test_sqlite_engine.py because the\nEngine constructor signature is `(dsn, signing_key_id, scrubber=None,\nsteward_key_id=None, steward_key_path=None)` — not `(dsn)` as the\nhopeful smoke tests assumed. Full Engine construction needs a keyring\n+ signing-key fixture; that's not warranted for an end-to-end Python\nsmoke test when the Rust-side substrate tests already exercise the\nin-memory SQLite path end-to-end.\n\nNarrowed test_sqlite_engine.py to the one check the wheel surface\ngenuinely needs at the Python level: the typed exception hierarchy\n(PersistError / NotFound / Conflict / Transient / Permanent) is\nexported, all four subclasses extend the base, and the base extends\nPython's `Exception` (not BaseException — uvicorn-style `except\nException:` must catch them).\n\nNo substrate or surface change. v1.0.0 + v1.0.1 tags remain on their\ncommits; v1.0.2 is the first wheel that actually reaches PyPI.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-14T20:09:28-05:00",
          "tree_id": "85e211ecb40d2c49953b1da5af17fc8e67d4543f",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/1669aafc5054664d39adcb28e6892e230a3c61e4"
        },
        "date": 1778807887617,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 109874,
            "range": "± 444",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 250933,
            "range": "± 4312",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 532186,
            "range": "± 1449",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1863040,
            "range": "± 31907",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 345,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1503,
            "range": "± 41",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8239,
            "range": "± 32",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21273,
            "range": "± 117",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24326,
            "range": "± 56",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83655,
            "range": "± 163",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 394,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3285,
            "range": "± 58",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9981,
            "range": "± 45",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42831,
            "range": "± 792",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2262792,
            "range": "± 64566",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6631225,
            "range": "± 101301",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23806592,
            "range": "± 595874",
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
          "id": "bbf1778d79bdbaeaf06a6e09d12d90d24c5459dd",
          "message": "1.0.3 — re-export typed exception classes in Python wrapper\n\nv1.0.2 tag CI failed test_typed_exception_hierarchy_exported because\nthe inner Rust pyo3 module registers `PersistError` / `NotFound` /\n`Conflict` / `Transient` / `Permanent` but the Python wrapper at\n`python/ciris_persist/__init__.py` only re-exports `Engine` +\n`LensQueryError` from the inner module. Agent code doing\n`from ciris_persist import NotFound` saw ImportError.\n\nBug-for-bug: same shape oversight that bit v0.6.1 secrets surface\nduring the early pyo3 lift. Adding the typed exception names to both\nthe `from .ciris_persist import (...)` line and `__all__`.\n\nNo substrate change. v1.0.3 is the first wheel that publishes to PyPI\nwith the agent-facing exception classes actually reachable.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-14T20:21:18-05:00",
          "tree_id": "b8852dee40880be35902fe3af77b763276971b4a",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/bbf1778d79bdbaeaf06a6e09d12d90d24c5459dd"
        },
        "date": 1778808525792,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 101401,
            "range": "± 196",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 241442,
            "range": "± 2123",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 523287,
            "range": "± 3485",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1845956,
            "range": "± 20187",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 352,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1474,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7339,
            "range": "± 102",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21152,
            "range": "± 353",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24200,
            "range": "± 178",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83547,
            "range": "± 203",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 359,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3195,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9323,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41690,
            "range": "± 101",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 784,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2311799,
            "range": "± 150880",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6662467,
            "range": "± 201108",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23728507,
            "range": "± 236667",
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
          "id": "cdf033a58bae0035dddb702beca9d09c16e6244b",
          "message": "1.1.0 — Path A polymorphic pipeline + Edge wire-transport substrate\n\nThe v1.x cuts thus far:\n- v1.0.x — agent-adoption substrate (PyO3 SQLite, typed exceptions,\n  11/22 services unblocked via in-process callers).\n- v1.1.0 — Edge wire-transport substrate (polymorphic pipeline +\n  substrate constructors decoupled from Engine + HTTP routes +\n  FederatedSecretsClient + serde_json diagnostic surfacing).\n\nBundle:\n- #33 parts 1-2: Path A polymorphic Pipeline<E: WireEnvelope>.\n  ClassifyStage / ScrubStage / EncryptAndStoreStage<S, E> generic;\n  ExtractStage stays Stage<BatchEnvelope> (Features structurally\n  trace-coupled). MatchAddress enum replaces v1.0.x's flat\n  component_index. Three factories: default_inbound_pipeline (full\n  4-stage BatchEnvelope), default_outbound_pipeline<E> (generic\n  Classify + Scrub), default_speak_pipeline (Classify + Scrub +\n  EncryptAndStore on InlineTextEnvelope).\n- #33 part 3: POST /api/v1/pipeline/ingest route. PipelineEnvelope\n  verify (schema_version allowlist + edge_signature via\n  verify_hybrid_via_directory + inner agent signature) + FSD §4.3\n  invariants. Queue API extended with try_submit_with_sidecar.\n- #33 part 4a: 15 secrets-server axum routes mirroring SecretsService.\n  16-type wire shape in src/secrets/wire.rs. Three-tier role-tag\n  design (enforcement deferred to v1.1.x with KeyRecord schema add).\n- #33 part 4b: FederatedSecretsClient over reqwest (rustls-tls). New\n  secrets-client feature. impls SecretsService for transparent\n  in-process ↔ federated swap.\n- #43: substrate constructors decoupled from Engine. New Rust-side\n  Engine struct + FederationDirectorySqlite::open + EdgeOutboundQueue\n  Sqlite::open. PyEngine untouched.\n- #44: Error::Json(_)::detail() surfaces serde_json msg — CIRISLens#13\n  operator diagnostics.\n\nSix commits aggregate: 1f74d29 (json detail), b2bbdae (substrate\nctors), 4e42fbd (Path A refactor), 3db08a7 (pipeline ingest route),\ndd029bf (secrets-server routes), 6fc8654 (FederatedSecretsClient).\n\nv1.1.x follow-ups documented in CHANGELOG: role-tag enforcement,\npersister sidecar consumption, pipeline pyo3 wraps, async-native\npyo3, reencrypt-all bytes loading, access-logs filter push-down.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-14T21:58:20-05:00",
          "tree_id": "7a28393108504c2d23686f0847ee7ec43f90d7e8",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/cdf033a58bae0035dddb702beca9d09c16e6244b"
        },
        "date": 1778814154124,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 103868,
            "range": "± 440",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 244766,
            "range": "± 767",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 525944,
            "range": "± 3877",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1853076,
            "range": "± 50958",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2370821,
            "range": "± 114601",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6716571,
            "range": "± 123944",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23878470,
            "range": "± 318358",
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
          "id": "0cdde185cb248bb5ca222d49d551459c2612d4f0",
          "message": "1.1.1 — feature-gate Backend import in engine.rs\n\nv1.1.0 tag CI failed at `cargo test --test wire_format_fixtures` (the\nno-features integration target). engine.rs imported\n`crate::store::Backend` unconditionally, but the trait is only\nreachable + used when postgres or sqlite is on. Under no-features\nthe import was unused → `-D warnings` rejected the lib build.\n\nFix: gate `use crate::store::Backend` on `any(feature = \"postgres\",\nfeature = \"sqlite\")`. StoreError import stays unconditional (used by\nEngineError regardless of backend feature).\n\nNo surface change. v1.1.0 is the substantive cut; v1.1.1 is the first\n1.1.x wheel that reaches PyPI.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-14T22:11:59-05:00",
          "tree_id": "bf6035261d0bea3dfdb99b2f48c2f06e370630f2",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/0cdde185cb248bb5ca222d49d551459c2612d4f0"
        },
        "date": 1778815193875,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 101388,
            "range": "± 1508",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 241859,
            "range": "± 2083",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 522627,
            "range": "± 2117",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1843070,
            "range": "± 17447",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 347,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1454,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7574,
            "range": "± 110",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21116,
            "range": "± 66",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24156,
            "range": "± 69",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83486,
            "range": "± 172",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 390,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3127,
            "range": "± 343",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9578,
            "range": "± 54",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42092,
            "range": "± 161",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 1452,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2294051,
            "range": "± 96665",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6631093,
            "range": "± 168213",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23759271,
            "range": "± 611617",
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
          "id": "6f8b5f054807e0cdb3ec1e1961e3cbe16194a621",
          "message": "1.1.2 — ReasoningEventType Unknown (#45) + verify 2.1.5 + CI hardening\n\nThree bundled hardening items:\n\n1. ReasoningEventType::Unknown (#45) — closes CIRISLens#13 second\n   half.\n\n   Add #[serde(other)] Unknown variant to ReasoningEventType. Same\n   shape as ComponentType::Unknown (shipped v0.1.x). When an agent\n   emits a wire value not in the closed §4 set (real prod: 3 agents\n   emitting parent_event_type=\"UNKNOWN_PARENT\" for 48h, 28-43%\n   reject rate on /accord/events), persist now absorbs into Unknown\n   instead of failing Error::Json(_) → schema_malformed_json →\n   infinite agent retries. AV-15 safe: catchall echoes no\n   attacker-controlled bytes; serializes back as constant \"UNKNOWN\".\n\n   Pair: v1.1.1 #44 fix surfaced WHICH field failed (Error::Json::\n   detail() returns serde_json msg); v1.1.2 #45 prevents the\n   rejection entirely on enum drift. Lens#13 root cause closed.\n\n2. CIRISVerify 2.0.5 → 2.1.5 pin bump.\n\n   - Cargo.toml ciris-verify-core git tag → v2.1.5\n   - pyproject.toml ciris-verify>=2.1.5,<3\n   - CI ciris-build-sign tarball → v2.1.5 prebuild\n\n   The 2.1.x series is CIRISVerify's CI hardening arc; library\n   surface unchanged from 2.0.5.\n\n3. CI hardening playbook from CIRISVerify v2.1.x.\n\n   - gh release download retry on ciris-build-sign tarball fetch\n     (3 attempts, backoff). Absorbs GitHub API transient 5xx.\n   - pip install retry on the 3 pip-install sites (maturin +\n     pytest + venv-scoped). Same shape against PyPI blips.\n   - continue-on-error: true on every Swatinem/rust-cache@v2 site\n     (4 sites). Cache miss/corruption shouldn't fail the whole\n     job — recompile slower but correct.\n\n   Not folded in (don't apply to persist's matrix):\n   - v2.1.5's `shell: bash` on guard — persist has no Windows\n     runners. Matrix is Linux + macOS-14 (arm) + iOS cross-compile.\n   - v2.1.4-style active heal on dtolnay shim — persist never hit\n     the macOS x86_64 shadow because we already had cache-bin:\n     false from v0.7.2.\n\nNo library surface change. Hardening cut on top of v1.1.1.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-14T22:34:21-05:00",
          "tree_id": "709c37cad623715942ce226d7835ea7eabb9e196",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/6f8b5f054807e0cdb3ec1e1961e3cbe16194a621"
        },
        "date": 1778816596701,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 101568,
            "range": "± 3979",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 242534,
            "range": "± 3666",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 524205,
            "range": "± 3265",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1851569,
            "range": "± 15338",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 341,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1434,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7566,
            "range": "± 318",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21108,
            "range": "± 704",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24147,
            "range": "± 219",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83464,
            "range": "± 563",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 375,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3050,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9347,
            "range": "± 92",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41826,
            "range": "± 475",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 621,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2293460,
            "range": "± 141009",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6667077,
            "range": "± 154859",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 24032781,
            "range": "± 291505",
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
          "id": "e559fa5a8bb5c4904b0c093013bc5cde05b21ec4",
          "message": "1.2.0 — MaintenanceService absorption + DatabaseMaintenance reclass\n\nCloses CIRISPersist#48. DatabaseMaintenance splits like Auth +\nAdaptiveFilter did: operations → persist, scheduling → agent's\nTaskSchedulerService. The agent-side DatabaseMaintenance service\ndisappears as a separate concern; collapses into TaskScheduler\ninvoking engine.maintain().\n\nPost-fold 22-service count (locked): 10 → persist substrate (incl.\nthis), 1 → LensCore (Audit), 2 → Edge (transit-touch), 10 → agent.\n\nSurface:\n- MaintenanceService trait (vacuum_substrate / archive_expired /\n  prune_audit_chain / maintain umbrella).\n- Engine::maintenance() accessor + EngineMaintenance enum (trait\n  isn't object-safe — RPITIT).\n- 4 PyEngine methods returning JSON reports.\n- 4 substrate modules with retention defaults: telemetry (V015\n  expires_at), secrets access_log (30d), incidents-closed (90d\n  on last_seen_at), federation_keys-expired (180d on valid_until).\n\nImplementation gotchas documented:\n- VACUUM can't run in tx → batch_execute on deadpool client.\n- SQLite datetime cross-format compare via julianday() (RFC 3339\n  and YYYY-MM-DD HH:MM:SS sort lexico-wrong against each other).\n- prune_audit_chain stubbed pending CIRISAgent#760 Counter-RII\n  review-window guidance.\n\nTests: +9 (5 SQLite + 4 PG + 1 unit). Lib: 301/301 passing.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-15T10:02:25-05:00",
          "tree_id": "f19572c72c4777a43c224ff675e32636afc7ca9b",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/e559fa5a8bb5c4904b0c093013bc5cde05b21ec4"
        },
        "date": 1778857818558,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 108782,
            "range": "± 1109",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 260519,
            "range": "± 4433",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 561882,
            "range": "± 8821",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1998699,
            "range": "± 12806",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 313,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1427,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 6562,
            "range": "± 44",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 23172,
            "range": "± 60",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 26439,
            "range": "± 63",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 91089,
            "range": "± 2305",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 370,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3030,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9655,
            "range": "± 146",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42339,
            "range": "± 796",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 637,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2249113,
            "range": "± 202148",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6975323,
            "range": "± 640224",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 25649951,
            "range": "± 1893140",
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
          "id": "2bbe29d5a784a154e1c4d3347e8caa7de5fb2c11",
          "message": "1.2.1 — fix PG maintenance bind types (jsonb + make_interval secs)\n\nv1.2.0 tag CI hit two PG-side bind-type failures:\n\n1. Test fixture bound &\"{}\" to a jsonb column. Even with $5::jsonb\n   SQL cast, tokio-postgres rejects str→jsonb (param-type negotiation\n   runs before SQL casts). Fix: bind via serde_json::json!({}).\n2. Impl used make_interval(secs => $1) with an i64 bind. PG's `secs`\n   is double precision, not bigint; i64 raises\n   `WrongType { postgres: Float8, rust: \"i64\" }`. Fix: fixed_seconds\n   returns f64 across the 4 call sites (telemetry-custom, secrets,\n   incidents, federation).\n\nBoth surfaced only on the live PG test path; local SQLite + no-DB\nintegration paths didn't trip them. Verified on fresh\nciris-qa-postgres container: 4/4 maintenance::postgres tests pass.\n\nNo surface change. v1.2.1 is the first 1.2.x wheel to publish.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-15T10:14:59-05:00",
          "tree_id": "739f94194b7bb0ec356391f3e79c1e1ef2ed44d7",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/2bbe29d5a784a154e1c4d3347e8caa7de5fb2c11"
        },
        "date": 1778858604254,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 101371,
            "range": "± 455",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 243083,
            "range": "± 780",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 525074,
            "range": "± 1989",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1855416,
            "range": "± 29761",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 340,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1418,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7576,
            "range": "± 62",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21140,
            "range": "± 268",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24190,
            "range": "± 32",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83528,
            "range": "± 172",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 370,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3058,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9379,
            "range": "± 48",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41566,
            "range": "± 311",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 621,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2344216,
            "range": "± 96516",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6617115,
            "range": "± 113493",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23573173,
            "range": "± 149016",
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
          "id": "8cfaa17cfa87e9b9d800f62671b3188b9aab1016",
          "message": "1.3.0 — FederationDirectory trust extension + V020 (closes #46 + #47)\n\nM2 unified cut absorbing NodeCore's `src/trust.rs` (CIRISAI/\nCIRISNodeCore@be82bd9) into persist's substrate. NodeCore can now\nreplace its local placeholder trait with\n`pub use ciris_persist::federation::FederationDirectory` (or the\nconvenience path `pub use ciris_persist::cirisnode::\nFederationDirectory`).\n\nSchema (V020 both dialects):\n- federation_keys + 7 columns: consent_role (CIRISAgent#760 OQ-1\n  flat enum), trust_type, trust_relationship, trust_domains[],\n  trusted_at, trusted_by, expires_at, roles[]\n- PG CHECK constraints: trusted_by != key_id (self-trust prevention),\n  Registry-relationship requires non-empty trust_domains\n- SQLite enforcement at API layer (V018 deferral pattern continued\n  — ALTER TABLE ADD CONSTRAINT CHECK unsupported)\n- new cirislens.edge_detection_events table for LensCore's\n  UnconsentedExternalProbe detector signals\n- audit_log action_type CHECK extended with 'trust_granted' +\n  'trust_revoked' (PG) — vocabulary additions in\n  AuditEventType enum\n\nFederationDirectory trait extension (4 new methods on existing\ntrait, NOT a sibling — same trait that owns federation_keys row\nCRUD today):\n- grant_trust(grant) — UPSERT + audit chain transition\n- revoke_trust(key, revoked_by) — soft-delete + audit + idempotent\n- lookup_trust(key) — raw row, no transitive resolution\n- list_trusted_keys(filter) — server-side filtering + default-excludes\n  expired rows\n\n5 supporting types (mirror NodeCore's `src/trust.rs` field-for-field):\nTrustType, TrustRelationship, TrustGrant, TrustRow, TrustFilter.\nTrustEdge stays in NodeCore (their resolver output, not our\nstorage concern).\n\nConvenience re-export: `crate::cirisnode::{FederationDirectory,\nTrustGrant, TrustRow, TrustFilter, TrustType, TrustRelationship}`\nso NodeCore can pin the sibling-pattern path that matches\nNodeCoreService's import shape.\n\nPyO3 wraps on PyEngine: federation_grant_trust /\nfederation_revoke_trust / federation_lookup_trust /\nfederation_list_trusted_keys. Backend-dispatched (Path A pattern).\n\nRole-tag enforcement (closes #46):\n- KeyRecord.roles field added with #[serde(default)] for compat\n- pipeline ingest route requires cirislens_pipeline_writer OR\n  cirislens_secrets_writer (kind: pipeline_invariant_role_tag)\n- secrets routes enforce 3-tier per #33 part 4a docs (kind:\n  secrets_role_tag)\n\nTests (+11; 8 SQLite + 3 PG-gated): all 5 M1-validated shapes\ncovered. 296/296 lib tests pass with full feature combo. PG\ntrust impl verified locally on fresh ciris-qa-postgres.\n\nZERO deviation from NodeCore's contract at commit be82bd9.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-15T15:05:07-05:00",
          "tree_id": "e50d8b2660e86966e75e1462a37974be4c60b3ea",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/8cfaa17cfa87e9b9d800f62671b3188b9aab1016"
        },
        "date": 1778875950820,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 109076,
            "range": "± 583",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 260000,
            "range": "± 2818",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 560818,
            "range": "± 1817",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1993775,
            "range": "± 4371",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 331,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1455,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 6555,
            "range": "± 68",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 23144,
            "range": "± 59",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 26373,
            "range": "± 406",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 91062,
            "range": "± 1299",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 369,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3117,
            "range": "± 38",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9605,
            "range": "± 64",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42323,
            "range": "± 174",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 632,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2258183,
            "range": "± 75416",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6996611,
            "range": "± 156081",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 25962487,
            "range": "± 1227911",
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
          "id": "c639a37cce1247c938a7477939b5f4a37d25ce6e",
          "message": "1.3.1 — audit-chain bridge docs + #49 timestamp preservation\n\nCIRISAgent 2.9.0 cutover support cut. Two upstream asks from\nCIRISAgent#763 Lane A bundled into one release:\n\n1. docs/AUDIT_CHAIN_BRIDGE.md (NEW) — operational documentation for\n   the audit-chain bridge mechanism + Lane C identity registration:\n   - Bridge-entry mechanism: rooting a new cirisaudit chain on top\n     of an existing chain. Canonical-bytes rule, prev_hash derivation\n     from legacy chain terminal state, ChainBreakReason::Genesis\n     PrevHashNotZero as a bridge signal.\n   - tenant_id semantics (opaque, caller-defined, stable; don't\n     change mid-chain).\n   - signing_key_id registration flow (one-time federation_put_\n     public_key at boot; idempotent).\n   - 2.9.0 first-boot flow pseudo-code.\n   - Trust hierarchy registration (Lane C C3) call shapes.\n   Unblocks CIRISAgent#763 A0b + Lane C wiring.\n\n2. #49 timestamp preservation on cirisgraph_upsert_{node,edge}:\n   - PG INSERT VALUES binds node.updated_at / node.created_at as\n     parameters instead of NOW(). ON CONFLICT UPDATE uses EXCLUDED.\n     updated_at.\n   - SQLite same: fmt_datetime(node.updated_at) /\n     fmt_datetime(node.created_at) passed through; excluded.updated_at\n     on conflict.\n   - Same fix on upsert_edge (both backends) adds edge.created_at\n     to the INSERT.\n   - Two regression tests in src/graph/sqlite.rs covering the\n     #49-body repro for bulk-historical-import.\n   Closes CIRISPersist#49. Unblocks CIRISAgent#763 A0a — agent can\n   now use the typed engine.cirisgraph_upsert_node() API instead of\n   bypassing to direct sqlite3 INSERT.\n\nNo upstream API breakage; purely additive (docs file) + bug fix\n(timestamp behavior corrects required-but-ignored). PyO3 GIL perf\nbaseline (low-priority ask) deferred — Memory Benchmark integration\ntests during Lane A will surface anything hot enough to bench.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-16T11:23:19-05:00",
          "tree_id": "3da9fffef375a99bab0376624afa1ed21c42ec76",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/c639a37cce1247c938a7477939b5f4a37d25ce6e"
        },
        "date": 1778949082215,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 108918,
            "range": "± 1098",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 259855,
            "range": "± 1280",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 559807,
            "range": "± 1714",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1985419,
            "range": "± 4465",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 323,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1402,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7939,
            "range": "± 34",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 23162,
            "range": "± 130",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 26426,
            "range": "± 179",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 91030,
            "range": "± 182",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 357,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3204,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9508,
            "range": "± 27",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41750,
            "range": "± 288",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 663,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2283915,
            "range": "± 32977",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 7013642,
            "range": "± 49037",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 25747033,
            "range": "± 297473",
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
          "id": "2b510df927d3a1e34133f23f763756ba5d02be90",
          "message": "chore(changelog): add v1.3.1 entry dropped by linter race in c639a37\n\nTag v1.3.1 already points at c639a37 (the code + docs commit).\nCHANGELOG had a linter-modify race during that commit and the v1.3.1\nsection didn't land. Patching forward here so the CHANGELOG matches\nthe tagged release.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-16T11:24:45-05:00",
          "tree_id": "504abd37e98285b2f81a2fdba2591af4dfac3ba0",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/2b510df927d3a1e34133f23f763756ba5d02be90"
        },
        "date": 1778949215466,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 101825,
            "range": "± 735",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 241950,
            "range": "± 768",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 521919,
            "range": "± 8115",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1847828,
            "range": "± 9604",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 351,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1443,
            "range": "± 40",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7320,
            "range": "± 105",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21184,
            "range": "± 52",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24236,
            "range": "± 260",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83625,
            "range": "± 2225",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 359,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3220,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9477,
            "range": "± 36",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41616,
            "range": "± 218",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 621,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2260667,
            "range": "± 134674",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6656102,
            "range": "± 200883",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23709793,
            "range": "± 189919",
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
          "id": "b4a837778397778dba372c6d23a190549dc759f2",
          "message": "1.3.2 — bulk_import flag + typed AttributesTooLarge (closes #50)\n\nFollow-up to v1.3.1 #49 surfaced by CIRISAgent datum-cutover: 1 of\n989 legacy graph_nodes rows is a 1.67 MiB conversation_summary that\nthe AV-45 1 MiB cap rejects. Cap is load-bearing for steady-state,\nbut bulk migration needs an escape hatch.\n\n- `GraphService::upsert_node` + `upsert_edge` take new\n  `bulk_import: bool` parameter. `true` skips the AV-45 cap.\n  Default `false` preserves existing semantics for hot path.\n- New `Error::AttributesTooLarge { bytes, cap }` variant with stable\n  `kind = \"cirisgraph_attributes_too_large\"`. Replaces the opaque\n  `InvalidArgument(\"attributes too large: …\")` string callers had\n  to grep for. PyO3 surfaces via the typed-exception `Permanent`\n  class.\n- PyO3 `cirisgraph_upsert_node` / `cirisgraph_upsert_edge` now take\n  `bulk_import` kwarg (default `False`).\n\nPer-type caps (ask #2 from #50) deferred — bigger config surface;\nbulk_import flag covers the migration case.\n\nBackward compat: trait signature changes are breaking for direct\nRust consumers composing the trait. PyO3 callers on v1.3.1 keep\nworking — `bulk_import` defaults to `False` matching prior behavior.\nCallers grepping for \"attributes too large\" in InvalidArgument\nstrings need to switch to `Error::AttributesTooLarge { .. }` or\n`err.kind() == \"cirisgraph_attributes_too_large\"`.\n\nTests: +1 SQLite (bulk_import skips cap; default rejects with typed\nvariant). Existing AV-45 assertions updated to match the new\ntyped variant in both backends. 4/4 graph::sqlite::tests pass;\nPG round-trip green against fresh ciris-qa-postgres.\n\nCIRISAgent's tools/ops/migrate_to_persist.py can now drop the\noversize-row workaround and pass `bulk_import=True` for migration.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-16T11:53:54-05:00",
          "tree_id": "77e3b00d2ddafd2e07017f0c51fc17fdb72bcd47",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/b4a837778397778dba372c6d23a190549dc759f2"
        },
        "date": 1778950894495,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 105901,
            "range": "± 828",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 245743,
            "range": "± 1932",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 526170,
            "range": "± 4798",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1848735,
            "range": "± 8290",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 342,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1525,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7590,
            "range": "± 202",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21181,
            "range": "± 70",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24249,
            "range": "± 584",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83575,
            "range": "± 586",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 389,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3106,
            "range": "± 51",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9595,
            "range": "± 30",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41798,
            "range": "± 763",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 621,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2271348,
            "range": "± 61679",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6602942,
            "range": "± 225814",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23641162,
            "range": "± 100286",
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
          "id": "7191d62c06fd77b1fc703ab26f8d9ecc27d6e64d",
          "message": "1.3.3 — cover AttributesTooLarge in cirisgraph_err_to_py match\n\nv1.3.2 tag build failed at the FFI wheel jobs: legacy\n`cirisgraph_err_to_py` bridge function had a non-exhaustive match\nagainst `graph::Error` and didn't cover the new AttributesTooLarge\nvariant from v1.3.2. Local dev feature-set compiled clean; CI's\nwheel combo surfaced the gap.\n\nAdded the new variant to the caller-fault arm alongside\nInvalidArgument / NotAuthorized / Conflict / NotFound. Maps to\nPyValueError matching the typed-exception kind v1.0.0's\ntranslate_error_kind already does.\n\nNo surface change. v1.3.3 is the first wheel of the bulk_import\nwork that publishes to PyPI.\n\nCo-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-05-16T12:00:41-05:00",
          "tree_id": "75a8e50dce09463d875aead62ff3bfb1d2f40e6b",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/7191d62c06fd77b1fc703ab26f8d9ecc27d6e64d"
        },
        "date": 1778951402068,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 108952,
            "range": "± 1042",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 262388,
            "range": "± 1436",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 562619,
            "range": "± 10566",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1993508,
            "range": "± 4558",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 322,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1435,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 6607,
            "range": "± 38",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 23216,
            "range": "± 305",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 26485,
            "range": "± 376",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 91260,
            "range": "± 733",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 368,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3122,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9793,
            "range": "± 74",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41726,
            "range": "± 84",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 632,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2245486,
            "range": "± 100483",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 7040701,
            "range": "± 220348",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 25724009,
            "range": "± 1080670",
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
          "id": "ef8905d33f131b809fe7f6369f199914c604cef2",
          "message": "docs(FSD): federation trust interface — purpose-scoped grants as signed events\n\nDrafts the v1.5.0 substrate FSD for trust grants as signed Contribution\nevents. Replaces the v1.3.0 trust-column shape on federation_keys with\na purpose-scoped grant table backed by audit-chain events.\n\nKey shape:\n- Identity = Ed25519+ML-DSA-65 hybrid pubkey (unchanged); roles\n  collapse to client/proxy/server (post-3.0 \"everything is an agent\").\n- Three purposes: Technical (manifests) / Deferral (domains) /\n  Contribution (evolution — including votes on any contribution).\n- Steward = topology-recovered (first grant signer), not a tag.\n- Grants are §3.2 subject_kind=\"trust_grant\" Contributions; ride the\n  existing HybridSignature + witness_set primitives (no crypto surface\n  added, CIRISVerify untouched).\n- Multi-signer in scope via existing witness_set (Accord consensus).\n- Trillian/CT-style inclusion proofs surfaced from the audit chain.\n- DID/VC layer explicitly rejected with 2026 SOTA citation.\n\nUpstream gates: NodeCore §RC additions — trust_grant + three new\nsubject_kinds (test_result, improvement, gratitude_signal). Filed\nseparately. Downstream rewires: NodeCore resolve_trust, LensCore\nverify_hybrid_and_check_grant, Portal Manage-Trust UI.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-16T14:24:25-05:00",
          "tree_id": "fe79177f8b3b3de5472477cccb146ab334c0c0a5",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/ef8905d33f131b809fe7f6369f199914c604cef2"
        },
        "date": 1778959905101,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 106558,
            "range": "± 925",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 245974,
            "range": "± 1708",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 527169,
            "range": "± 4435",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1849386,
            "range": "± 21286",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 341,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1448,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7542,
            "range": "± 52",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21156,
            "range": "± 115",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24201,
            "range": "± 64",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83542,
            "range": "± 173",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 370,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3029,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9398,
            "range": "± 94",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42218,
            "range": "± 163",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2237634,
            "range": "± 41527",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6585064,
            "range": "± 167204",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23604733,
            "range": "± 465769",
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
          "id": "aae4b57f035eb816fc1693abcdc359824c8607c7",
          "message": "docs(FSD): fold TrustPurpose::Service per NodeCore 871ebab MESSAGE_TAXONOMY\n\nNodeCore§RC at 871ebab landed FSD/MESSAGE_TAXONOMY.md plus 15 new\nsubject_kinds (vs the original 4 in #3) — Searle/FIPA × counterparty ×\ntrust-gate taxonomy. The Persist-side coordination ask is minimal:\nextend TrustPurpose with Service variant + scope grammar.\n\nChanges:\n- §3.2 payload: TrustPurpose adds Service variant\n- §3.3 scope table: Service row with service:<kind> | service:<kind>:<resource>\n- §3.3 service scope examples: llm, embedding, tool kinds\n- §8 implementation order: NodeCore §RC step marked LANDED\n\nNon-breaking. No new columns, no new tables, no V021 footprint change.\nPer-invocation RPC remains edge-transport (out of scope here per\nMESSAGE_TAXONOMY §8); chain carries service_announcement /\nservice_deprecation / service_usage_summary via existing §3.2 route.\n\nCross-references:\n- NodeCore commit: https://github.com/CIRISAI/CIRISNodeCore/commit/871ebab\n- Persist v1.5.0 tracking: #53\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-16T14:50:35-05:00",
          "tree_id": "cf6cb01a1a51f8eb15f492c51ebc690083eda1f2",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/aae4b57f035eb816fc1693abcdc359824c8607c7"
        },
        "date": 1778961501777,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 101869,
            "range": "± 598",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 242173,
            "range": "± 2394",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 523912,
            "range": "± 1625",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1848104,
            "range": "± 8120",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 339,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1420,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7536,
            "range": "± 50",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 22063,
            "range": "± 35",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 25560,
            "range": "± 595",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 84523,
            "range": "± 1496",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 374,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2995,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9491,
            "range": "± 87",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41628,
            "range": "± 165",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2235989,
            "range": "± 47038",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6609631,
            "range": "± 94594",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23581679,
            "range": "± 127900",
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
          "id": "73b8a124b396fd20b3c720de4b596592396f049e",
          "message": "1.4.0 — SQLite federation parity (#52) + steward→local rename (#51) + audit-bridge doc fix\n\nInterim cut before v1.5.0 substrate work. Closes the two Lane C\nblockers downstream of v1.3.x and clears the API-name and doc decks\nso v1.5.0's trust-grants-as-signed-events substrate (per\nFSD/FEDERATION_TRUST_INTERFACE.md) builds on a stable surface.\n\nBreaking changes (clean break, no aliases):\n- Engine.steward_sign → Engine.local_sign (+ pqc_sign + key_id +\n  pqc_key_id + public_key_b64 + pqc_public_key_b64)\n- Engine constructor: steward_key_id/steward_key_path (+ pqc_*) →\n  local_key_id/local_key_path (+ pqc_*)\n\nWhy rename: \"steward\" was a federation directory role tag (registry\nbootstrap anchor). The Engine's signing methods refer to *this\nprocess's local signing key*, which is role-orthogonal — every CIRIS\nagent (whether client, proxy, or server role) has a local signer.\nThe old names leaked the role concept into a process-local API that\ndoesn't need it. Internal types (StewardSigner struct, steward_signer\nfield) unchanged; deferred to 2.0.0.\n\nSQLite federation parity (closes #52):\n- 9 PyO3 methods ported from backend_postgres_unwrap panic pattern to\n  proper match-dispatch: register_public_key, put_public_key,\n  lookup_public_key, lookup_keys_for_identity, federation_grant_trust,\n  federation_revoke_trust, federation_lookup_trust,\n  federation_list_trusted_keys, list_federation_keys.\n- All FederationDirectory trait impls existed on SqliteBackend (V020\n  schema is there); gap was purely in the PyO3 wrapper.\n- Unblocks CIRISAgent#765 (Lane C federation/auth absorption) — SQLite\n  deployments can now register agent pubkeys + use the trust hierarchy.\n- 65 remaining non-federation backend_postgres_unwrap call sites\n  remain — separate sweep, not in this cut.\n\nDoc fix:\n- docs/AUDIT_CHAIN_BRIDGE.md: engine.federation_put_public_key →\n  engine.put_public_key (method has always been put_public_key).\n\nTests: cargo test --features \"postgres sqlite\" --lib — 274 passed,\n0 failed. SQLite-only and Postgres-only feature combos both clean.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-16T15:19:40-05:00",
          "tree_id": "6345ce7576d318f5a55b9ee1d7942ddd71731951",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/73b8a124b396fd20b3c720de4b596592396f049e"
        },
        "date": 1778963252604,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 111048,
            "range": "± 356",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 251679,
            "range": "± 686",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 534276,
            "range": "± 2730",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1863995,
            "range": "± 25637",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 340,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1449,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7369,
            "range": "± 104",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21501,
            "range": "± 34",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24546,
            "range": "± 73",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83913,
            "range": "± 508",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 371,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3049,
            "range": "± 23",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9324,
            "range": "± 54",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42130,
            "range": "± 249",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 636,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2309984,
            "range": "± 131615",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6726684,
            "range": "± 177335",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 24267740,
            "range": "± 361651",
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
          "id": "6d22b13acfaa134c3473b07a594383c925b67e0e",
          "message": "docs(FSD): rev §4 with SOTA Merkle transparency anchored on CIRISVerify\n\nReconciles the FSD's §4.1 InclusionProof with what the substrate\nactually supports. The previous version overpromised Trillian/CT-style\nproofs against infrastructure that didn't exist; investigation\nsurfaced that CIRISVerify already has a Merkle transparency log at\nciris-verify-core::transparency for license attestation.\n\nArchitectural call: Verify is the wellspring for transparency\nprimitives; persist consumes; edge consumes. No parallel Merkle\nimplementations. The SOTA primitives are baked into Verify at the\nfoundation, and every downstream consumer pulls them in.\n\nCIRISVerify#23 filed requesting the six-piece SOTA upgrade:\n- RFC 6962 byte prefixes (0x00 leaf, 0x01 node) replacing string prefixes\n- Generic TransparencyLeaf trait (license/audit/edge plug-ins)\n- SignedTreeHead with HybridSignature + reserved witness_signatures\n- ConsistencyProof per RFC 6962 §2.1.2\n- TransparencyStore trait (in-memory/file for Verify, PG/SQLite for Persist)\n- Per-log_id / per-tenant scoping (maps to persist's per-tenant chains)\n\nMigration is clean at the audit-chain-bridge boundary\n(genesis-on-cutover policy already locked) — no mixed-prefix\nverification needed.\n\nFSD changes:\n- §1.1: cross-coordinates with CIRISVerify#23 added (the new upstream gate)\n- §4.1: TrustGrantInclusionProof shape now references SignedTreeHead +\n  MerkleProof + leaf_canonical_bytes from ciris_verify_core. Adds\n  trust_grant_consistency_proof + current_sth APIs.\n- §4.4 NEW: per-tenant Merkle transparency layer — RFC 6962 tree\n  shape, STH signing cadence, merkle_leaves/merkle_sth_log/merkle_nodes\n  schema additions, threat-model coverage table, external verifier flow.\n- §8: implementation order reworked — Verify SOTA upgrade is now\n  step 2 (upstream gate); persist substrate work steps 3-9 depend\n  on it. Downstream steps 10-13 unchanged in shape.\n\nThreat-model justification: STH defends against split-view,\nConsistencyProof defends against retroactive insertion, per-tenant\nscoping preserves the existing audit-chain isolation invariant,\nhybrid signing extends quantum resistance to the signing axis (the\nSHA-256 tree is already PQ-resistant).\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-16T16:30:19-05:00",
          "tree_id": "47b0045d3e0734ac2ed4252f6ad2e9db787aa81d",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/6d22b13acfaa134c3473b07a594383c925b67e0e"
        },
        "date": 1778967541525,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 90111,
            "range": "± 500",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 206859,
            "range": "± 377",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 439126,
            "range": "± 1303",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1544411,
            "range": "± 13404",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 253,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1063,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 5010,
            "range": "± 53",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 17939,
            "range": "± 146",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 20461,
            "range": "± 158",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 70589,
            "range": "± 170",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 277,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2411,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 7512,
            "range": "± 32",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 32470,
            "range": "± 114",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 521,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2195058,
            "range": "± 8532543",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 5892429,
            "range": "± 618076",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 20484272,
            "range": "± 20734843",
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
          "id": "0a22c21d864171c1e0fdbaca7833d8f491457ae5",
          "message": "1.5.0 — federation trust substrate (signed events + Merkle transparency)\n\nThe substantive substrate cut spec'd in FSD/FEDERATION_TRUST_INTERFACE.md.\nTrust grants become signed Contribution events that ride the audit\nchain; every audit entry on every backend also appends a leaf to a\nper-tenant Merkle tree and gets a freshly-signed STH (RFC 6962 +\nSigstore Rekor every-append cadence). External verifiers confirm any\ngrant via inclusion proof + STH signature without trusting the\ndirectory's projection. Anchored on CIRISVerify v2.3.0's SOTA\ntransparency upgrade.\n\nHighlights:\n- 4 new TrustPurpose variants (Technical/Deferral/Contribution/Service)\n- V021 schema: federation_trust_grants + merkle_leaves + merkle_sth_log\n- Every audit entry → Merkle leaf + signed STH (universal transparency)\n- 9 new Engine PyO3 methods (emit/read/proof/backfill)\n- 9 new AuditService trait methods (PG + SQLite override; default NotImpl)\n- Internal StewardSigner → LocalSigner rename (finishes v1.4.0 #51 work)\n- V020 → V021 one-shot backfill (idempotent, scope-limited to local granter)\n\nThreat model coverage (FSD §4.4):\n- Log fork / split-view: STH + reserved witness cosigning\n- Retroactive insertion: ConsistencyProof per RFC 6962 §2.1.2\n- Selective omission: InclusionProof against signed root\n- Stale STH: verifier-side freshness policy\n- Cross-tenant correlation: per-tenant trees (no global root)\n- Cross-subsystem proof collision: RFC 6962 byte prefixes\n- Quantum break on signing: hybrid Ed25519 + ML-DSA-65 STH\n- Quantum break on tree: SHA-256 PQ-resistant\n\nAtomicity: chain commit first (AV-49 integrity); Merkle hook second\n(signer-gated); projection third (subject_kind-gated). Downstream\nfailures surface as typed errors (Error::Merkle, Error::TrustGrant)\nbut chain row stands — audit chain is source of truth, Merkle and\nprojection are projections. Phase I backfill reconciles orphans.\n\nImplementation phases (already on main):\n- A bf075c2: V021 + types\n- B 35f3953: TransparencyStore<AuditLeaf> adapters\n- C 93841cc: Universal Merkle hook\n- D cb93e00: TrustGrant projection\n- E 7a2fbb1: grant_trust / revoke_trust_grant emit\n- F+G 20b5071: read + proof APIs\n- H f41f191: PyO3 + StewardSigner→LocalSigner rename\n- I fc50769: V020 backfill\n\nTests: 368 passed (was 274 at v1.3.3); 2 pre-existing PG audit failures\n(V020 action_type CHECK) unchanged.\n\nUpstream:\n- CIRISVerify v2.3.0 (#23) — ciris-verify-core::transparency SOTA upgrade\n- CIRISNodeCore 871ebab — MESSAGE_TAXONOMY + 15 new subject_kinds\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-16T19:22:34-05:00",
          "tree_id": "23bc361d92c4fe777e2806ec05033afbf81f3da0",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/0a22c21d864171c1e0fdbaca7833d8f491457ae5"
        },
        "date": 1778977891635,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 102762,
            "range": "± 713",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 244016,
            "range": "± 2967",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 526370,
            "range": "± 2670",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1861986,
            "range": "± 31080",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 359,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1501,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7295,
            "range": "± 140",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21110,
            "range": "± 68",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24162,
            "range": "± 159",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83498,
            "range": "± 441",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 372,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3175,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9432,
            "range": "± 120",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41328,
            "range": "± 191",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2284823,
            "range": "± 64100",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6632688,
            "range": "± 60882",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23772143,
            "range": "± 484136",
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
          "id": "105dee2f7cc8849be4673e5f095388f5fe43ae4c",
          "message": "1.5.1 — SQLite parity sweep (100% no-panic across PyO3 surface)\n\nCompletes the v1.0.0-scaffold port that v1.4.0 (#52) started for 9\nfederation methods. Every remaining backend_postgres_unwrap() call site\nin src/ffi/pyo3.rs — 55 of them across attestation, revocation,\nPQC-fill, outbound queue, detection events, calibration bundles, lens\nreads, ratchet, scrub stats, scoring aggregates, audit chain, and trace\nverification — now dispatches cleanly to match &self.backend { Postgres\n=> ..., Sqlite => ... }. The backend_postgres_unwrap helper itself is\ndeleted.\n\nThis is the parity bar CIRISAgent's SQLite-first deployments need before\nadopting v1.5.x. No more process panics on non-federation Engine calls.\n\n53 methods ported via SqliteBackend trait dispatch (impls already existed):\n- Attestation / revocation: put_attestation, list_attestations_{for,by},\n  put_revocation, revocations_for, attach_{key,attestation,revocation}_\n  pqc_signature, list_attestations, list_revocations, run_pqc_sweep\n- Outbound queue: enqueue_outbound, claim_pending_outbound,\n  mark_transport_{delivered,failed,replay_resolved},\n  match_ack_to_outbound, mark_ack_received, sweep_{ack_timeouts,\n  ttl_expired,expired_claims}, outbound_status, list_outbound,\n  cancel_outbound, replay_abandoned\n- Detection + calibration: put_detection_event, get_detection_events,\n  put_calibration_bundle, get_current_calibration_bundle,\n  get_calibration_bundle_by_version\n- Lens reads + ratchet (SqliteBackend impls return Error::NotImplemented\n  internally; dispatch surfaces clean typed errors): list_trace_summaries,\n  get_trace_{summary,detail}, list_tasks, list_llm_calls,\n  aggregate_llm_costs, corpus_shape, aggregate_scrub_stats,\n  cross_agent_divergence, temporal_drift, hash_chain_gaps,\n  conscience_override_rates, aggregate_scoring_factors{,_batch},\n  count_{traces,overrides,identity_changes}, aggregate_audit_chain\n- Trace ingest + verification: receive_and_persist,\n  delete_traces_for_agent, fetch_trace_events_page, verify_trace,\n  verify_hybrid_via_directory\n\n2 methods truly PG-only (inherent on PostgresBackend, no trait); SQLite\narm returns PyRuntimeError with stable message naming the FSD:\n- get_features (extract pipeline)\n- get_classifications (classify pipeline)\n\nStructural refactors to support dispatch:\n- run_pqc_sweep_inner + sweep_{keys,attestations,revocations} helpers\n  generic over FederationDirectory + Send + Sync + 'static\n- TraceKeyDirectory generic over crate::store::Backend + Send + Sync +\n  'static; verify_trace constructs per-arm\n\nDeleted:\n- backend_postgres_unwrap() helper (def + doc comments)\n- #[allow(dead_code)] on BackendDispatch::Sqlite (every arm now read)\n- v1.0.0-scaffold module-header comment rewritten to v1.5.1 completion\n\nTests: 368 lib pass (unchanged from v1.5.0 — pure dispatch port).\nDiff: src/ffi/pyo3.rs +1665 / −761 (one file).\n\nCIRISAgent SQLite-first deployments unblocked.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-16T19:48:24-05:00",
          "tree_id": "1ba6951177185793c6a575346592f2b6ee91e308",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/105dee2f7cc8849be4673e5f095388f5fe43ae4c"
        },
        "date": 1778979389961,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 109209,
            "range": "± 1069",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 259885,
            "range": "± 891",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 561392,
            "range": "± 8330",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1998729,
            "range": "± 69651",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 324,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1462,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 6779,
            "range": "± 37",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 23112,
            "range": "± 56",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 26368,
            "range": "± 188",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 90987,
            "range": "± 217",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 383,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3153,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9564,
            "range": "± 135",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42236,
            "range": "± 165",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 632,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2277743,
            "range": "± 101465",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 7034895,
            "range": "± 48076",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 25930938,
            "range": "± 354381",
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
          "id": "494e1926888788199380822d02d54c94a9518094",
          "message": "1.5.2 — pin bump to CIRISVerify v2.4.0 (workspace vocabulary coherence)\n\nciris-keyring / ciris-verify-core / ciris-crypto v2.3.0 → v2.4.0\nfollowing CIRISVerify's vocabulary-fix rename:\n  load_steward_seed   → load_local_seed\n  StewardSeedConfig   → LocalSeedConfig\n\nPersist doesn't import the renamed symbols (we use Ed25519SoftwareSigner,\nMlDsa65SoftwareSigner, PqcSigner, HardwareSigner — none with \"steward\"\nin the name), so the pin bump is workspace-coherence only. No code\nchanges.\n\nThe CIRISVerify v2.4.0 vocabulary lock matches what v1.4.0 (#51) +\nv1.5.0 (Phase H) baked into persist's internals:\n- steward = bootstrap-trusted root identity (Verify's\n  bootstrap_stewards.json — registry anchor pubkeys that seed\n  federation trust)\n- local = a deployment's own per-process signing identity (persist's\n  LocalSigner, edge's signer, agent's signer)\n\nCrystal-clear distinction across the stack now. No zombie steward_*\nnames anywhere in our identity / signing surface.\n\nTests: 368 lib pass (unchanged from v1.5.1 — pin-bump only).\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-16T21:12:17-05:00",
          "tree_id": "78340076290602ef40504e9cc6ec3d34388603f2",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/494e1926888788199380822d02d54c94a9518094"
        },
        "date": 1778984500821,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 102353,
            "range": "± 644",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 243382,
            "range": "± 861",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 526909,
            "range": "± 1731",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1864565,
            "range": "± 34496",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 345,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1418,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7386,
            "range": "± 117",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21170,
            "range": "± 73",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24217,
            "range": "± 88",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83564,
            "range": "± 1342",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 370,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3160,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9638,
            "range": "± 395",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 42149,
            "range": "± 462",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 621,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2308231,
            "range": "± 96755",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6686226,
            "range": "± 132805",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 24159754,
            "range": "± 277089",
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
          "id": "7668b3401da639e327ef580b9abdf124b9209e15",
          "message": "1.5.3 — Engine.register_federation_key one-call helper (unblocks Lane C)\n\nCIRISAgent Lane C needs to register its local pubkey in the federation\ndirectory (federation_keys) but the put_public_key path requires a fully\nassembled SignedKeyRecord. The agent team shouldn't re-implement persist's\ncanonical-bytes rule in Python — that's the \"do persist's job upstream\"\nanti-pattern the substrate exists to prevent.\n\nHelper composes existing primitives:\n- canonicalize_envelope (PythonJsonDumpsCanonicalizer)\n- LocalSigner::sign_ed25519 over canonical bytes\n- hex(SHA-256) → original_content_hash\n- Self-signed KeyRecord (scrub_key_id = key_id, algorithm = \"hybrid\",\n  PQC half None — cold path fills)\n- SignedKeyRecord wrapper → put_public_key (backend dispatch + cold-path\n  PQC attach unchanged)\n\nmicros-truncation inlined (5 lines) to avoid cirisaudit-feature\ndependency — register_federation_key should be available regardless.\n\nIdempotent on (key_id) PRIMARY KEY of federation_keys.\n\nAlso clarifies register_public_key vs put_public_key vs\nregister_federation_key docstrings in the .pyi stub.\n\nUnblocks CIRISAgent 2.9.0 Lane C.\n\nTests: 368 lib pass.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-16T21:50:36-05:00",
          "tree_id": "82dad3eb8009a8bb808e7a4c33a927bf68ddc533",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/7668b3401da639e327ef580b9abdf124b9209e15"
        },
        "date": 1778986809348,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 84623,
            "range": "± 3855",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 201375,
            "range": "± 686",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 434846,
            "range": "± 1352",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1541563,
            "range": "± 56773",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 248,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1101,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 5047,
            "range": "± 37",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 17980,
            "range": "± 35",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 20506,
            "range": "± 169",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 70608,
            "range": "± 1288",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 276,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 2437,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 7555,
            "range": "± 28",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 32627,
            "range": "± 304",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 523,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2308939,
            "range": "± 19955857",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 7007110,
            "range": "± 17230648",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 20489737,
            "range": "± 23491895",
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
          "id": "93b6433b925d3039138ef4f0fa306b8906061753",
          "message": "1.5.4 — audit canonical-bytes helpers + bridge-entry permit (unblocks Lane A0b)\n\nSame pattern as v1.5.3's register_federation_key — agent shouldn't\nreimplement persist's canonical-bytes rule in Python. Two PyO3 helpers\nexpose the audit-chain canonicalization without forcing callers to\nchoose between a callback API (awkward over PyO3) and reimplementing\nthe strip rule in caller-language.\n\nTwo new PyO3 methods on Engine:\n\n  engine.audit_canonicalize_for_hash(entry_json) -> bytes\n    Caller builds AuditEntry with entry_hash=\"\" + signature=\"\";\n    method zeroes both, canonicalizes via PythonJsonDumpsCanonicalizer;\n    caller sha256's returned bytes to compute entry_hash.\n\n  engine.audit_canonicalize_for_signing(entry_json) -> bytes\n    Caller has filled entry_hash, left signature=\"\";\n    method zeroes signature (entry_hash stays — binds sig to chain\n    position), canonicalizes; caller signs externally with whatever\n    signer they prefer (CIRISVerify TPM, local Ed25519, KMS, ...).\n\nBoth parse JSON through AuditEntry struct before canonicalizing —\nguarantees byte-equality with crate::audit::verify::compute_entry_hash.\nRaw-JSON canonicalization diverges on chrono datetime + Vec<u8>\nserialization; struct-parse normalizes those.\n\nBridge-entry permit:\nAuditService::record_entry previously rejected non-zero prev_hash on\nsequence_number=1 — contradicting docs/AUDIT_CHAIN_BRIDGE.md §1 which\ndocuments bridge entries as supported (verifier already signals via\nChainBreakReason::GenesisPrevHashNotZero as informational, not a\nbreak). Write-path now permits + logs for observability. 4 enforcement\nsites relaxed: 2 on PG (record_entry + try_claim_event), 2 on SQLite\n(same paths).\n\nDoc updates (docs/AUDIT_CHAIN_BRIDGE.md §1):\n- Canonical-bytes rule reference updated to point at\n  src/audit/verify.rs::compute_entry_hash (was src/audit/postgres.rs)\n- New \"Caller workflow (v1.5.4+)\" section with explicit 4-step Python\n  recipe using the helpers\n- Stripping rule locked + audited inline\n\nTests: 368 lib pass (unchanged — helpers compose existing tested\nprimitives; bridge permit only changes a rejection path that was\nalways-erroring on a documented-supported case).\n\nLive smoke-tested: helpers produce canonical bytes that match\npersist's internal computation; bridge entry with non-zero prev_hash\non seq=1 lands successfully; signature round-trips through sign +\nverify.\n\nUnblocks CIRISAgent A0b (audit chain bridge entry) + A3 (GraphAudit\ncutover, cascades behind A0b).\n\nCloses CIRISPersist#55.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-16T22:33:17-05:00",
          "tree_id": "09d118f1db74e653f22c0df4be8b8ec7665c9bf3",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/93b6433b925d3039138ef4f0fa306b8906061753"
        },
        "date": 1778989276081,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 122018,
            "range": "± 357",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 273306,
            "range": "± 12168",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 575217,
            "range": "± 3449",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 2008684,
            "range": "± 5636",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 320,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1407,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 6612,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 23149,
            "range": "± 210",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 26382,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 91018,
            "range": "± 331",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 358,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3098,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9581,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41572,
            "range": "± 446",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 631,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2270295,
            "range": "± 136046",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 7059311,
            "range": "± 126881",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 25739152,
            "range": "± 127568",
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
          "id": "823da7e685664f777f0c2d305a20b83c4ec3e7e0",
          "message": "1.5.5 — cirisincident D1-full schema extension (closes #56)\n\nSame pattern as v1.5.3 (register_federation_key) + v1.5.4 (audit\ncanonical helpers): when agent's needs reveal a substrate gap, persist\nextends rather than asking agent to compromise. CIRISAgent's IncidentNode\ncaptures 11 forensic fields (filename, line_number, stack_trace, etc.)\nthat had no first-class home in cirislens_incident_records. Packing into\ndescription loses queryable access; dropping loses debug info; dual-\nwriting to a graph node adds split-brain risk. Schema extension is the\nclean answer.\n\nV022 (PG + SQLite, additive + nullable — no breaking changes):\n\nSchema: + 11 nullable columns (incident_type, source_component,\nhandler_name, exception_type, stack_trace, filename, line_number,\nfunction_name, impact, urgency, detection_method).\n\nIndexes: + forensic-query indexes on (filename, line_number) and\n(source_component), both partial WHERE NOT NULL — operator oncall\nqueries like \"show me all incidents from this file\" / \"from this\ncomponent\" now have indexed paths.\n\nCHECKs (relaxed; both vocabularies accepted):\n- severity: + low/medium/high (ITIL aliases alongside V016's\n  info/warning/error/critical syslog set)\n- state: + recurring (parallel-to-open per AV-55 ladder semantics)\n\nPG: DROP/ADD CONSTRAINT for the auto-named V016 checks\n(incident_records_severity_check, incident_records_state_check).\nSQLite: recreate-table dance (no DROP CONSTRAINT) preserving ALL\nV016 columns + indexes.\n\nEnum extensions:\n- IncidentSeverity + Low/Medium/High (ITIL vocabulary)\n- IncidentState + Recurring (rank=0, parallel to Open)\n\nAV-55 semantic update for Recurring:\n- can_transition_to does NOT permit Open ↔ Recurring (same-rank\n  transitions still rejected per strict-forward AV-55)\n- Caller signals \"this is recurring\" via initial INSERT with\n  state='recurring', not by transitioning from open\n- record_incident now binds caller-supplied state (was hardcoded\n  'open' in V016 INSERT) and rejects states outside {Open, Recurring}\n  at the trait surface with Error::InvalidArgument\n- Transitions still flow through transition_state per AV-55\n- Locked by incident_reject_non_initial_state_at_record test on both\n  backends\n\nRefinery transaction nesting fix: V022 omits explicit BEGIN/COMMIT\n(Refinery wraps migrations in its own tx; nesting fails with \"cannot\nstart a transaction within a transaction\" — same shape as V019 fix\nin d8b467b).\n\nWire compatibility: Incident struct's 11 new fields use\n#[serde(default, skip_serializing_if = \"Option::is_none\")]. v1.5.4\ncallers emitting JSON without forensic fields deserialize with all-\nNone defaults. Pre-V022 rows SELECTed via new decoders yield NULL →\nNone per field. Both directions clean.\n\nqa_harness count: 21 → 22.\n\nTests: 296 lib pass (was 368 at v1.5.4 with audit feature; this\nrelease builds with cirisincident feature set, 296 pass with PG live).\n20 incident-namespace tests: 3 new PG + 4 new SQLite + 5 new\ntypes-module + 8 existing.\n\nUnblocks CIRISAgent D1-full (IncidentManagementService absorption\nwith full forensic fidelity).\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-16T22:54:40-05:00",
          "tree_id": "8468d1dc284315708e495ca3dcfe22ec9618b964",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/823da7e685664f777f0c2d305a20b83c4ec3e7e0"
        },
        "date": 1778990529875,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 109022,
            "range": "± 273",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 259295,
            "range": "± 5282",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 561169,
            "range": "± 1718",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1991196,
            "range": "± 7794",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 335,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1448,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 6558,
            "range": "± 99",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 23220,
            "range": "± 576",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 26438,
            "range": "± 177",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 91058,
            "range": "± 2960",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 368,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3124,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9616,
            "range": "± 204",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41831,
            "range": "± 845",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 632,
            "range": "± 36",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2239528,
            "range": "± 95655",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 7027858,
            "range": "± 85707",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 25832547,
            "range": "± 342268",
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
          "id": "79e40247e18449884624670237397b7f67a80774",
          "message": "1.5.6 — diagnostic for cirisgraph attributes UTF-8 decode failures (#58)\n\nCIRISAgent 2.9.0 staged-QA surfaced cirisgraph_get_node failing with\n'Conversion error from type Text at index: 3, invalid utf-8 sequence'\nafter a successful cirisgraph_upsert_node. Agent team can't trace\nupstream because the error has no context.\n\nThis release replaces rusqlite's default decode error with a detailed\ndiagnostic + adds defense-in-depth UTF-8 validation on the write side.\n\nread_attributes_text in src/graph/sqlite.rs:\n- Fast path: normal row.get::<_, String>(\"attributes\")\n- On UTF-8 failure: fall back to Vec<u8>, run std::str::from_utf8 to\n  pinpoint the bad byte, return Error::Backend carrying node_id +\n  byte position + invalid-sequence length + total column bytes +\n  hex dump of ±32 bytes around failure with [...] markers + ASCII\n  context (• for non-printable) + the original Utf8Error.\n\nassert_valid_utf8_or_describe defense-in-depth in encode_attributes —\nsurfaces caller context at write time if a future regression somehow\nproduces non-UTF-8 (today: impossible by serde_json::to_string\nconstruction).\n\nTests: 2 new regression tests:\n- get_node_diagnostic_on_invalid_utf8_attributes injects a 0xC0 byte\n  via raw SQL; asserts diagnostic carries node_id + byte position +\n  hex marker + invalid-byte hex form + total length\n- encode_attributes_always_produces_valid_utf8 pins write invariant\n  across nested objects + unicode + escapes + nested arrays\n\nLib suite: 403 pass. No behavior change for the happy path. No\nschema change. No migration.\n\nDoesn't fix the upstream root cause — that requires the agent team\nto see the actual bytes (which this enables) and trace where they\ncome from. Hypotheses to test: mojibake, binary-as-string,\nPython lone-surrogate round-trip, external non-persist writer.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-18T08:11:40-05:00",
          "tree_id": "54216e9ea307fb9697926b86845c0ca37e873cdf",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/79e40247e18449884624670237397b7f67a80774"
        },
        "date": 1779110440938,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 109320,
            "range": "± 2694",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 261136,
            "range": "± 1644",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 563440,
            "range": "± 12610",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1999605,
            "range": "± 3935",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 339,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1438,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7266,
            "range": "± 122",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 23157,
            "range": "± 613",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 26403,
            "range": "± 282",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 91013,
            "range": "± 169",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 385,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3281,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9651,
            "range": "± 417",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41628,
            "range": "± 215",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 637,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2314822,
            "range": "± 131009",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 7109192,
            "range": "± 247498",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 25774099,
            "range": "± 190123",
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
          "id": "b8d4647acf51141700b2e9a820b85e015ffd7cc4",
          "message": "1.5.7 — secrets process_incoming_text pipeline orchestration (closes #57)\n\nShips the v0.6.2 stub that's been Err(\"requires v0.6.2 pipeline\norchestration\") on both backends. Defaults SecretsService::\nprocess_incoming_text to a composition of get_filter_config +\ntry_claim_secret so both PG and SQLite inherit automatically.\n\nLane B write-leg unblocked. Agent drops its Python regex+\nSecretReference path and calls engine.secrets_process_incoming_text\ndirectly.\n\nFlow:\n1. get_filter_config()\n2. Parse config_value.patterns as CatalogPattern[]\n3. Compile regex + scan filtered text per pattern\n4. try_claim_secret per unique match (HMAC dedup idempotent)\n5. Replace each with {SECRET:<uuid>:<description>} placeholder\n6. Return (filtered_text, Vec<SecretReference>)\n\nPG + SQLite stub overrides removed; both inherit the default. The\nunderlying get_filter_config + try_claim_secret are SQLite-shipped\nper v1.5.1 — no SQLite-specific gap.\n\nTests (2 new SQLite):\n- process_incoming_text_detects_encrypts_and_replaces_via_default_impl\n- process_incoming_text_empty_catalog_passthrough\n\nLib suite: 436 pass.\n\nCHANGELOG correction: v1.5.6 framed get_classifications as\n\"permanent PG-only by design\" — that was wrong. SQLite parity for\nget_classifications + get_features is open work, tracked separately.\nNo-PG-only principle: every method should work on both backends.\n\nReverses v1.5.6's \"deferred to v1.6.x\" framing for\nprocess_incoming_text. No deferral; shipping now.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-18T09:05:09-05:00",
          "tree_id": "02074661c6329ed2df9442c9ef8c90ff331df444",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/b8d4647acf51141700b2e9a820b85e015ffd7cc4"
        },
        "date": 1779113600376,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 101464,
            "range": "± 330",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 242044,
            "range": "± 711",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 525994,
            "range": "± 1635",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1855706,
            "range": "± 12493",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 344,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1444,
            "range": "± 42",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8252,
            "range": "± 91",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21473,
            "range": "± 32",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24544,
            "range": "± 936",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83981,
            "range": "± 536",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 368,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3090,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9271,
            "range": "± 39",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41688,
            "range": "± 442",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2198666,
            "range": "± 44106",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6539840,
            "range": "± 47237",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23556378,
            "range": "± 109226",
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
          "id": "c884d916d1bdd89711fe15396d782581adba05c8",
          "message": "1.5.8 — get_classifications + get_features SQLite parity (no more PG-only)\n\nReverses v1.5.1's PG-only framing for these two methods. SQLite gets\nthe read path; both backends get explicit write methods so the agent's\nAdaptiveFilter output round-trips through persist as the storage\nsubstrate.\n\nV023 migration (SQLite, PG already has via V009):\n  ALTER TABLE trace_events ADD COLUMN extracted_features TEXT;\n  ALTER TABLE trace_events ADD COLUMN classifications TEXT;\n  ALTER TABLE trace_events ADD COLUMN pipeline_metadata TEXT;\n\nAll nullable; pre-V023 rows stay valid; \"no pipeline ran\" signaled\nvia extracted_features IS NULL.\n\nNew backend methods:\n- read_features + read_classifications on SqliteBackend (mirror PG)\n- write_features + write_classifications on BOTH (new — caller's\n  contract: set this if the row exists; UPDATE on missing row is Ok(()))\n\nNew PyO3 methods:\n- set_features(trace_id, thought_id, features_json) — JSON-in;\n  dispatches BackendDispatch\n- set_classifications(trace_id, thought_id, classifications_json) —\n  same shape\n\nPyO3 dispatch updates:\n- get_features SQLite arm: calls SqliteBackend::read_features (was\n  PG-only PyRuntimeError)\n- get_classifications SQLite arm: calls\n  SqliteBackend::read_classifications\n\n8 new tests (6 SQLite + 2 PG): write-then-read round-trip; read-null\nreturns empty; write-on-missing-row is no-op; both features +\nclassifications shapes.\n\nLib suite: 349 pass with features postgres+sqlite+classify+extract.\n\nPattern: every method works on both backends. PG-only was the wrong\nframing — agent's classifier output is real data that should round-trip\nthrough persist regardless of which backend they run.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-18T09:17:33-05:00",
          "tree_id": "a8624fb40d0748c08408e926fedb6fb27f6a8f4b",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/c884d916d1bdd89711fe15396d782581adba05c8"
        },
        "date": 1779114595010,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 95575,
            "range": "± 673",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 237608,
            "range": "± 4226",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 518376,
            "range": "± 1843",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1992173,
            "range": "± 43034",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 318,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1276,
            "range": "± 32",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 6947,
            "range": "± 43",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 20548,
            "range": "± 69",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 23965,
            "range": "± 44",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 88532,
            "range": "± 263",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 318,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3169,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9771,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 43969,
            "range": "± 291",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 544,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2195497,
            "range": "± 263380",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6678879,
            "range": "± 537778",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23761466,
            "range": "± 901075",
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
          "id": "028df31f292043690eabbb4c4e9b28ff52a83c7e",
          "message": "1.5.9 — tasks substrate (CIRISPersist#59 #1 of 11)\n\nFirst of 11 substrate absorptions ending dual-libsqlite WAL\ncorruption. CIRISAgent 2.9.0's full ciris_engine.db absorption: persist\nbecomes the only library that opens the file.\n\nTasks substrate ships all 17 columns from CIRISAgent v2.8.13 tasks\ntable on both PG + SQLite. V024 migration. Self-FK on parent_task_id\n(deferrable on PG, immediate on SQLite). Indexes on\n(agent_occurrence_id, status, updated_at), (channel_id, updated_at),\n(parent_task_id) WHERE NOT NULL.\n\nStatus CHECK: pending | active | completed | failed | cancelled |\ndeferred.\n\nNew TaskService trait, 6 methods:\n- upsert_task (idempotent on task_id; differing data overwrites\n  non-monotonic columns)\n- get_task\n- list_tasks (cursor pagination on (updated_at, task_id))\n- update_task_status (false = task didn't exist)\n- try_claim_shared_task (atomic INSERT OR IGNORE; ClaimResult)\n- delete_task (FK REJECT on children)\n\nPyO3: 6 new Engine methods (task_upsert / task_get / task_list /\ntask_update_status / task_try_claim_shared / task_delete). JSON-in/\nJSON-out. Both backends dispatched via BackendDispatch match.\n\nFeature gate: cirislens_tasks. Added to pyproject.toml maturin\nfeatures so the published wheel ships the surface.\n\nTests: 22 new (5 types unit + 1 mod kind + 9 SQLite integration + 7\nPG integration via CIRIS_PERSIST_TEST_PG_URL). All 17 columns round-\ntrip; idempotent upsert; cursor pagination; concurrent try_claim\nrace produces one Stored + one AlreadyClaimed; FK parent existence\nenforced on both backends. Lib suite: 298 pass. fmt + clippy clean.\n\nMethod-collision note: PostgresBackend had upsert_task and\ntry_claim_shared_task placeholders on Backend trait from a Phase 3\nstub. Resolved via UFCS at PG call sites. Stub removal deferred to\na separate cleanup once we confirm no other consumer references them.\n\nqa_harness migration-count bound bumped (1..=22) → (1..=25) for\nheadroom across the 10 remaining substrate cuts.\n\n10 substrates remain: thoughts, service_correlations, scheduled_tasks,\ntickets, deferral_reports, consolidation_locks, creation_ceremonies,\ncontinuity_awareness, feedback_mappings, wa_cert. Per-release cuts\nv1.5.10-v1.5.19.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-18T09:47:01-05:00",
          "tree_id": "0677ff0fbc70a440c014714830fa8e7863ee853d",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/028df31f292043690eabbb4c4e9b28ff52a83c7e"
        },
        "date": 1779116091416,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 120105,
            "range": "± 448",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 270444,
            "range": "± 696",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 570548,
            "range": "± 8716",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1996073,
            "range": "± 5315",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 347,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1451,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7205,
            "range": "± 82",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 23162,
            "range": "± 640",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 26413,
            "range": "± 49",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 91054,
            "range": "± 164",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 352,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3242,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9472,
            "range": "± 39",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41607,
            "range": "± 161",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 654,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2227913,
            "range": "± 310814",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6994035,
            "range": "± 47862",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 25935186,
            "range": "± 165590",
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
          "id": "c51ca4eb9adfb83ca09b1cb6546df32c87a5e35e",
          "message": "1.5.10 — thoughts substrate (CIRISPersist#59 #2 of 11)\n\nSecond of 11 substrate absorptions. Mirrors v1.5.9 tasks shape with\nthought-specific lifecycle. V025 migration on both backends, FK to\ncirislens_tasks, self-FK on parent_thought_id. 14 columns.\n\nThoughtType: shipped as transparent String newtype rather than\nclosed enum. CIRISAgent's ThoughtType has 20+ values (STANDARD,\nFOLLOW_UP, ERROR, OBSERVATION, MEMORY, DEFERRED, PONDER, FEEDBACK,\nGUIDANCE, IDENTITY_UPDATE, ETHICAL_REVIEW, CONSENSUS, REFLECTION,\nSYNTHESIS, DELEGATION, CLARIFICATION, SUMMARY, TOOL_RESULT,\nACTION_REVIEW, URGENT, SCHEDULED, PATTERN, ADAPTATION, ...).\nClosed enum would drift on every agent add. SQL column is TEXT\nNOT NULL DEFAULT 'standard' with NO CHECK — new agent variants\nflow through without persist schema changes.\n\nThoughtService trait (5 methods):\n- upsert_thought (idempotent on thought_id; preserves created_at)\n- get_thought\n- list_thoughts (filter by task/status/occurrence; cursor pagination\n  on (updated_at, thought_id))\n- update_thought_status (final_action JSON merge via COALESCE;\n  missing-row returns false)\n- get_descendants (recursive CTE walking parent_thought_id chain;\n  ordered (thought_depth ASC, thought_id ASC) for determinism;\n  SQLite 3.8.3+ supports WITH RECURSIVE same shape as PG)\n\nPyO3: 5 new Engine methods gated on cirislens_thoughts feature\n(added to maturin wheel features). Stable error kinds added to\ntranslate_error_kind.\n\n27 new tests (1 mod + 6 types + 9 PG live + 11 SQLite). All 14\ncolumns round-trip; idempotent upsert preserves created_at; FK to\ntasks rejects nonexistent task; self-FK rejects nonexistent parent;\n3-level descendant tree returns 7 rows in deterministic order.\nLib suite: 325 pass.\n\nNo Backend-trait collision recurred — the Phase 3 stub sweep that\nhit upsert_task in v1.5.9 didn't stub any thought_* methods. Plain\ntrait dispatch sufficed.\n\n9 substrates remain: service_correlations (v1.5.11), scheduled_tasks,\ntickets, deferral_reports, consolidation_locks, creation_ceremonies,\ncontinuity_awareness, feedback_mappings, wa_cert.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-18T10:03:40-05:00",
          "tree_id": "22fa5eba043260572d38a170667a149147e951c5",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/c51ca4eb9adfb83ca09b1cb6546df32c87a5e35e"
        },
        "date": 1779117111597,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 101579,
            "range": "± 427",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 241727,
            "range": "± 3366",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 524151,
            "range": "± 5143",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1850984,
            "range": "± 15329",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 345,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1414,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 8209,
            "range": "± 74",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21184,
            "range": "± 337",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24242,
            "range": "± 241",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83676,
            "range": "± 392",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 363,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3240,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9718,
            "range": "± 50",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 43771,
            "range": "± 116",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2267735,
            "range": "± 100486",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6616536,
            "range": "± 153428",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23758345,
            "range": "± 653251",
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
          "id": "5a49c067adc2c0596718cc194116e5dc2c7435b0",
          "message": "1.5.11 — service_correlations substrate (CIRISPersist#59 #3 of 11)\n\nHot-path substrate (400+ rows on active agent). Dual-purpose schema\nabsorbs service-interaction + TSDB metrics + distributed-trace spans\n+ log correlations into one table. Caller discriminates via\ncorrelation_type column.\n\nV026 migration on both backends. 18 columns. 5 indexes including\nmetric-name + trace-id + span-tree partial indexes. 3 CHECK constraints\non status / correlation_type / retention_policy.\n\nCorrelationService trait (4 methods):\n- record_correlation (INSERT-OR-IGNORE; first writer wins;\n  state advancement via update_correlation_status)\n- get_correlation\n- update_correlation_status (response_data COALESCE; missing=false)\n- query_correlations (filter by service_type/correlation_type/\n  trace_id/metric_name/retention_policy/occurrence + event-timestamp\n  window + row-update window; cursor pagination)\n\nPyO3: 4 new Engine methods gated on cirislens_correlations feature.\n\n30 new tests (1 mod + 8 types + 9 PG live + 12 SQLite). Lib suite:\n355 pass. All 18 columns round-trip; idempotent record; TSDB hot\npath; distributed-trace assembly; cursor pagination; CHECK guards.\n\nBackend-trait collision recurred — Phase-3 stub\nBackend::record_correlation(&ServiceCorrelation) (legacy redb-era\nshape) collides with new CorrelationService::record_correlation(\nCorrelation). UFCS dispatch at PG call sites.\n\nVocabulary disclaimer: status / correlation_type / retention_policy\nvalues came from spec, not from agent v2.8.13 source. Recommend\nsanity grep against ciris_engine/schemas/runtime/enums.py once\nagent integration PR is in flight; V027 can relax CHECK if needed.\n\nrecord_correlation ON CONFLICT DO NOTHING semantics may need\nrevisiting if agent's retry path re-records with richer payloads.\nDocumented decision; revisit after integration.\n\nREAL handling: PG f32 cast up to f64 at trait boundary to match\nSQLite's f64 REAL semantic. Lossy for values outside f32 range\nbut matches agent's existing column declaration.\n\n8 substrates remain: scheduled_tasks (v1.5.12), tickets, deferral_\nreports, consolidation_locks, creation_ceremonies, continuity_\nawareness, feedback_mappings, wa_cert.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-18T10:20:49-05:00",
          "tree_id": "b83975528b33969bd1036458dc2cf24ebfeb0bbb",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/5a49c067adc2c0596718cc194116e5dc2c7435b0"
        },
        "date": 1779118158897,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 111252,
            "range": "± 1084",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 251275,
            "range": "± 3816",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 530854,
            "range": "± 2117",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1852953,
            "range": "± 17149",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 341,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1415,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7535,
            "range": "± 213",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21177,
            "range": "± 117",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24218,
            "range": "± 63",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83640,
            "range": "± 142",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 365,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3182,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9781,
            "range": "± 169",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41568,
            "range": "± 189",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 626,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2237840,
            "range": "± 122116",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6615018,
            "range": "± 145003",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23693142,
            "range": "± 152673",
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
          "id": "2636e4927428cf3b71e59556c0d45ec04c72352f",
          "message": "1.5.12 — scheduled_tasks substrate (CIRISPersist#59 #4 of 11)\n\nV027 migration on both backends. 15 columns. FK to cirislens_thoughts\n(thought_id) — DEFERRABLE on PG, immediate on SQLite. Status CHECK\nuses UPPERCASE vocabulary (PENDING | ACTIVE | COMPLETE | FAILED) per\nagent's schema — distinct from tasks' lowercase 6-value set.\n\n3 indexes, including scheduled_tasks_due partial index on\n(agent_occurrence_id, next_trigger_at) WHERE next_trigger_at IS NOT\nNULL AND status IN ('PENDING','ACTIVE') for the scheduler-tick hot\npath.\n\nScheduledTaskService trait (3 methods):\n- upsert_scheduled_task (ON CONFLICT DO UPDATE; preserves created_at)\n- list_due_scheduled_tasks (scheduler-tick query: WHERE\n  next_trigger_at <= now AND status IN (PENDING, ACTIVE),\n  ordered ASC, hits partial index)\n- update_after_trigger (partial-update semantics: Some(...) writes,\n  None preserves; missing-row returns false)\n\nStatus vocabulary: Rust enum TitleCase; as_sql_str emits UPPERCASE;\nserde JSON wire is snake_case (project convention); FFI uppercases\nbefore parse. CHECK rejects lowercase + tasks-vocab COMPLETED.\n\nPyO3: 3 new methods gated on cirislens_scheduled_tasks feature.\n\n22 new tests (1 mod + 6 types + 7 PG live + 8 SQLite). Lib suite:\n347 pass. All 15 columns round-trip; FK reject; partial-index hot\npath; CHECK guards.\n\nNo Backend-trait collision recurred. UFCS dispatch retained at PyO3\nsites for consistency with prior substrates.\n\nDEFERRABLE FK note: tokio-postgres's auto-commit wraps statements in\nimplicit txs; single-statement INSERTs against dangling FK targets\nfail immediately. DEFERRABLE only matters for multi-statement\ncallers (which the agent uses for parent+child writes).\n\n7 substrates remain: tickets (v1.5.13), deferral_reports,\nconsolidation_locks, creation_ceremonies, continuity_awareness,\nfeedback_mappings, wa_cert.\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>",
          "timestamp": "2026-05-18T10:35:42-05:00",
          "tree_id": "00a833c23fba7dce48d52c12f37babc9eca2aa4e",
          "url": "https://github.com/CIRISAI/CIRISPersist/commit/2636e4927428cf3b71e59556c0d45ec04c72352f"
        },
        "date": 1779119029799,
        "tool": "cargo",
        "benches": [
          {
            "name": "ingest_pipeline/1",
            "value": 101859,
            "range": "± 3986",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/6",
            "value": 242255,
            "range": "± 1423",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/16",
            "value": 522911,
            "range": "± 1696",
            "unit": "ns/iter"
          },
          {
            "name": "ingest_pipeline/64",
            "value": 1843448,
            "range": "± 10725",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/small",
            "value": 343,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/typical",
            "value": 1408,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "canonicalize_python/large",
            "value": 7335,
            "range": "± 94",
            "unit": "ns/iter"
          },
          {
            "name": "sign_256_bytes",
            "value": 21267,
            "range": "± 219",
            "unit": "ns/iter"
          },
          {
            "name": "sign_1024_bytes",
            "value": 24324,
            "range": "± 95",
            "unit": "ns/iter"
          },
          {
            "name": "sign_16384_bytes",
            "value": 83704,
            "range": "± 130",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/1",
            "value": 365,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/6",
            "value": 3190,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/16",
            "value": 9480,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "decompose/64",
            "value": 41843,
            "range": "± 113",
            "unit": "ns/iter"
          },
          {
            "name": "dedup_key_per_row",
            "value": 622,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/8",
            "value": 2260637,
            "range": "± 88107",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/32",
            "value": 6585489,
            "range": "± 90331",
            "unit": "ns/iter"
          },
          {
            "name": "queue_submit/128",
            "value": 23649038,
            "range": "± 163830",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}