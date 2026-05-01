window.BENCHMARK_DATA = {
  "lastUpdate": 1777665620262,
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
      }
    ]
  }
}