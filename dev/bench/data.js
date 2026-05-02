window.BENCHMARK_DATA = {
  "lastUpdate": 1777740675379,
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
      }
    ]
  }
}