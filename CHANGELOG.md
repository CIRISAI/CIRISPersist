# Changelog

All notable changes per release. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) +
[Semantic Versioning](https://semver.org/spec/v2.0.0.html), with mission /
threat-model citations because this crate's audit story is the point.

## [0.1.9] — 2026-05-01

Consume CIRISVerify v1.8.0's substrate primitives. Five interlocking
landings; all `BuildPrimitive::Persist` consumer work the upstream's
release notes named.

### Upstream dep bumps

- `ciris-keyring` v1.6.4 → **v1.8.0**.
- `ciris-verify-core` **v1.8.0** added (new direct dep).
- `rusqlite` 0.39 → **0.31** (Phase 2 stub; downgraded to match
  ciris-verify-core's `links = "sqlite3"` resolution).

### Drop the prediction shim — `storage_descriptor()` is authoritative

v0.1.7 introduced a vendored `predicted_software_seed_path` that
replicated ciris-keyring's private `default_key_dir()` logic, with
a documented "this is brittle" caveat. v0.1.8 ships
`HardwareSigner::storage_descriptor()` upstream — typed enum
returning `Hardware { hardware_type, blob_path }` /
`SoftwareFile { path }` / `SoftwareOsKeyring { backend, scope }` /
`InMemory`.

v0.1.9 swaps the shim for the real thing:

- `Engine.keyring_path()` is **authoritative**, not predicted. Returns
  `Some(path)` for `SoftwareFile` and `Hardware { blob_path: Some }`;
  `None` for HSM-only / OS-keyring / in-memory.
- New `Engine.keyring_storage_kind() -> str` returns one of seven
  stable tokens: `hardware_hsm_only`, `hardware_wrapped_blob`,
  `software_file`, `software_os_keyring_user`,
  `software_os_keyring_system`, `software_os_keyring_unknown`,
  `in_memory`. `/health` surfaces this without parsing the verbose
  descriptor.
- Boot-time warn dispatches typed cases: `SoftwareFile` keeps the
  ephemeral-path heuristic; `SoftwareOsKeyring{User}` warns
  separately (logout-bound); `InMemory` warns hard (key dies with
  process).
- `dirs` dep dropped (only used by the deleted prediction shim).
- 3 unit tests replaced with `storage_kind_token_dispatch`.

### `BuildPrimitive::Persist` — first-class manifest primitive

- New `src/manifest/mod.rs` defines `PersistExtras` (typed
  schema for the persist primitive's manifest extras blob)
  + `PersistExtrasValidator` (impl of upstream's `ExtrasValidator`
  trait) + `register()` public init function.
- Three persist-specific extras fields, all deterministic at build
  time:
  - `supported_schema_versions: Vec<String>` — wire-format versions
    this build accepts.
  - `migration_set_sha256: String` — sha256 of canonicalised
    `migrations/postgres/lens/V*.sql` concatenation (LF-normalised,
    file-separator-prefixed, lex-sorted).
  - `dep_tree_sha256: String` — sha256 of normalised `cargo tree`
    output (line-sorted, dedup-stripped).
- 6 unit tests cover happy path, malformed `sha256:` prefix, wrong
  hex length, empty schema versions, forward-compat tolerance,
  primitive discriminator.

### CI manifest signing via `ciris-build-sign`

- `.github/workflows/ci.yml::build-manifest` job rewritten to use
  upstream's CLI. `cargo install --git ...CIRISVerify --tag v1.8.0
  ciris-build-tool` pulls `ciris-build-sign` at the same tag we
  depend on.
- New CI step `emit PersistExtras JSON` runs
  `cargo run --release --bin emit_persist_extras` to produce the
  typed extras blob. Output is fed to `ciris-build-sign --extras`.
- Hybrid Ed25519 + ML-DSA-65 signing per PoB §1.4. Two new repo
  secrets required:
  - `CIRIS_BUILD_ED25519_SECRET` (base64-encoded 32-byte seed)
  - `CIRIS_BUILD_MLDSA_SECRET` (base64-encoded ~4 KB ML-DSA-65 secret)
- Bridge team uploads both per `docs/BUILD_SIGNING.md`. The
  workflow no longer falls back to unsigned mode — both signatures
  are required at v1.8.0+.
- New binary target `src/bin/emit_persist_extras.rs` produces the
  primitive-specific extras JSON. Reads source-tree migrations
  + `cargo tree` output; deterministic per checkout.

### Tooling — legacy python helper deprecated

- `tools/ciris_manifest.py` → `tools/legacy/ciris_manifest.py`.
  CI no longer calls it. Kept for one-release transition; deleted
  in v0.2.0.
- `tools/legacy/README.md` documents the upstream replacement
  path.

### deny.toml

- 5 transitive advisories accepted (all from ciris-verify-core's
  verification stack — DNS, HTTP, rustls, mobile attestation —
  none on persist's hot path):
  - RUSTSEC-2025-0134 — rustls-pemfile unmaintained
  - RUSTSEC-2026-0098 — rustls-webpki URI-name constraint
  - RUSTSEC-2026-0099 — rustls-webpki wildcard-DNS constraint
  - RUSTSEC-2026-0104 — rustls-webpki CRL parse panic
  - RUSTSEC-2026-0119 — hickory-proto DNS-encoding O(n²)
- License allow-list: **`CDLA-Permissive-2.0`** added (webpki-roots
  0.26+).

### Documentation

- **NEW**: `docs/BUILD_SIGNING.md` — bridge-team operator runbook
  for `ciris-build-sign generate-keys` + GitHub-secret upload +
  rotation.
- `docs/INTEGRATION_LENS.md` §11.5 — drop the predicted-vs-
  authoritative caveat; document the new typed dispatch + the
  `keyring_storage_kind()` method.
- `docs/THREAT_MODEL.md` — AV-27 promoted from "predicted" to
  "authoritative via upstream trait method"; mitigation matrix
  updated.

### Tests

- 109 lib + 5 AV-4 integration + 8 QA + 9 fixture =
  **131 tests, all green**.
- 6 new unit tests in `manifest::tests`.
- 1 new unit test (`storage_kind_token_dispatch`) replaces the
  3 deleted prediction-shim tests; net +3 over v0.1.8.
- clippy clean across postgres,pyo3,server,tls.

### Notes for consumers

- **Lens / agent / registry**: bump persist dep to v0.1.9 to pick
  up the upstream v1.8.0 substrate.
- **CIRISRegistry persist support** (`docs/TODO_REGISTRY.md`)
  remains the cross-repo follow-up. The registry-side `register`
  step in CI is still TODO; once registry accepts persist
  primitives, that one step lands trivially.
- **Operators on hardware-keyed deployments** see no behavior
  change — the warn paths only fire on software / in-memory
  signers, and only when the storage location is suspect.

## [0.1.8] — 2026-05-01

P0 production fix — closes THREAT_MODEL.md AV-4 (timestamp
canonicalization drift) that was rejecting every batch from
Python agents containing zero-microsecond timestamps.

### The bug

The lens production cutover hit `verify_invalid_signature` on
every batch. Root cause: persist's `verify::ed25519::format_iso8601`
helper re-formatted `DateTime<Utc>` via chrono's
`%Y-%m-%dT%H:%M:%S%.6f%:z` format string, which always emits six
microsecond digits. Python's `datetime.isoformat()` (the agent's
emitter, per TRACE_WIRE_FORMAT.md §8) drops the microsecond
fraction entirely when `microseconds == 0`. So an agent-signed
wire timestamp of `2026-04-30T00:15:53+00:00` became
`2026-04-30T00:15:53.000000+00:00` on the verify side, the
canonical bytes diverged, and `verify_strict` rejected.

The threat model had flagged this as the AV-4 residual since
v0.1.2 ("track in a Phase 1.x patch — preserve the on-the-wire
string"). Production confirmed it as P0.

### The fix — `schema::WireDateTime`

New wrapper type holding `(raw: String, parsed: DateTime<Utc>)`:

- `Deserialize` captures the wire string into `raw`, parses into
  `parsed` for typed access.
- `Serialize` emits `raw` verbatim — re-serialization is byte-equal.
- `wire()` accessor returns the raw bytes for canonicalization;
  `parsed()` returns the `DateTime<Utc>` for time arithmetic.
- Equality is *wire-byte equality*, not instant equality:
  `2026-04-30T00:15:53Z` and `2026-04-30T00:15:53+00:00` are the
  same instant but compare unequal because canonicalization
  treats them differently.

Replaces `DateTime<Utc>` in:

- `schema::CompleteTrace.{started_at, completed_at}`
- `schema::TraceComponent.timestamp`

`verify::ed25519::canonical_payload_value` now reads `.wire()`
instead of calling `format_iso8601`. The helper is removed.

`store::decompose` uses `.parsed()` to populate the `ts:
DateTime<Utc>` column on `TraceEventRow` / `TraceLlmCallRow` —
storage shape unchanged, only the verify path differs.

### Regression coverage

`tests/av4_timestamp_round_trip.rs` — 5 integration tests:

1. **Zero microseconds, no fraction** (the production-bug shape).
   `2026-04-30T00:15:53+00:00`. Pre-v0.1.8 this rejected; v0.1.8
   verifies clean.
2. Six-digit microseconds (Python isoformat with non-zero
   sub-second).
3. Z-suffix form.
4. Three-digit millisecond precision.
5. Tampered timestamp still rejected (verify gate didn't widen).

Plus 5 unit tests in `schema::wire_datetime` covering
deserialize/serialize byte-exact round-trips, equality semantics,
and parser rejection of invalid forms.

### Tests

- 103 lib + 5 AV-4 integration + 8 QA + 9 fixture =
  **125 tests, all green**.
- clippy clean across postgres,pyo3,server,tls feature combos.

### Notes for the lens team

- After deploying v0.1.8 + re-rolling the bridge, the existing
  `PERSIST_ROUTE` / `PERSIST_DELEGATE_RESULT` /
  `PERSIST_DELEGATE_REJECT` logs will confirm in seconds whether
  verify passes on real agent traffic.
- No API change; `Engine` ctor signature is unchanged. The shape
  change is internal to `CompleteTrace`.
- If you have any code that constructs `CompleteTrace` directly
  (vs. via wire-format deserialization), the timestamp fields are
  now `WireDateTime` instead of `DateTime<Utc>`. `"...".parse()`
  works (FromStr impl returns `WireDateTime`) — most call sites
  need no change.

### Float canonicalization residual

The other AV-4 sub-residual (Python `repr(float)` vs Rust `ryu`)
remains tracked but untriggered. No production divergence
observed; will close per-fixture-growth or when JCS becomes the
agent's canonicalizer.

## [0.1.7] — 2026-05-01

Three landings: bench harness + perf trend infrastructure, keyring
warn-on-ephemeral (production hot-fix), `Engine.keyring_path()`
observability surface.

### Added — bench harness + gh-pages perf trend

- **`benches/{ingest_pipeline,canonicalize,sign,dedup_key,queue}.rs`**.
  Five criterion-based benchmarks covering the hot paths:
  full pipeline against `MemoryBackend` (1 / 6 / 16 / 64 components),
  Python-compat canonicalization across payload sizes, Ed25519
  software-sign latency, decompose + dedup-key throughput, and
  bounded mpsc submit + drain. Local baseline:
  - sign 256/1024/16384 bytes: 13 / 15 / 56 µs
  - ingest_pipeline 1 / 6 / 16 / 64 components: 65 µs / 158 µs / 332 µs / 1.2 ms
- **`.github/workflows/bench.yml`**. Mirrors CIRISAgent's
  memory-benchmark trigger shape — Monday 7am UTC cron + manual
  dispatch + push-to-main + path-touched PR runs. Plus
  `benchmark-action/github-action-benchmark` publishing to
  `gh-pages` so the trend chart at
  `https://cirisai.github.io/CIRISPersist/` captures every release
  point. PR runs comment regression analysis at >10% threshold;
  no fail-on-alert until the runner's noise floor is established.
  90-day artifact retention on raw criterion JSON.

### Added — keyring warn-on-ephemeral (THREAT_MODEL.md AV-27)

The lens production cutover hit this:
[`get_platform_signer`](https://github.com/CIRISAI/CIRISVerify/) on a
container without TPM access falls back to `Ed25519SoftwareSigner`,
which writes the seed to a default path inside the container's
writable layer. Every `docker rm` + `docker run` bootstraps a fresh
keypair; the one-key-three-roles invariant (PoB §3.2) breaks
silently. Registry pubkey, scrub-envelope signer, and Phase 2.3
Reticulum address all churn together.

v0.1.7 catches it at boot:

- **At Engine construction**, when `is_hardware_available() == false`,
  predict the SoftwareSigner seed-storage path (replicating
  ciris-keyring v1.6.4's `default_key_dir()` logic) and check it
  against an ephemeral-path heuristic (`/home/`, `/root/`, `/tmp/`,
  `/var/cache/`, `/var/tmp/`). If matched, emit a loud
  `tracing::warn!` with the predicted path, the breakage mode, and
  the fix (`CIRIS_DATA_DIR=<persistent-volume>`).
- **Suppression**: `CIRIS_PERSIST_KEYRING_PATH_OK=1` after operators
  have audited that the path is on persistent storage (e.g. they
  mounted a volume at one of the heuristic-flagged prefixes).
- **`Engine.keyring_path() -> Optional[str]`** PyO3 method exposes
  the predicted path for `/health` surfacing — operators can
  confirm "this points at the persistent volume" without grepping
  logs. Returns `None` for hardware-backed deployments.

3 new unit tests cover the ephemeral / persistent / env-override
classification.

**Caveat — predicted vs. authoritative**: the path is predicted by
replicating ciris-keyring v1.6.4 private logic. A future
ciris-keyring tag bump may drift. We're tracking the upstream
`HardwareSigner::storage_descriptor()` trait method that would
make the path authoritative; v0.1.8+ swaps to that and the
prediction layer is removed. Suppression env var stays correct
either way.

### Documentation

- `docs/INTEGRATION_LENS.md` §11.5 — new "Keyring storage" section.
  docker-compose snippet for the fix (env + volume), how the warn
  reads in production logs, the suppression env var, the predicted-
  vs-authoritative caveat. **Required reading for any non-TPM
  deployment.**

### Tests

- 95 lib + 3 new pyo3 unit + 8 QA + 9 fixture = **115 tests**, all
  green.
- Bench harness compiles + smoke-runs cleanly across all five
  benches.

### Notes

- v0.1.7 ships the bench infrastructure first so the gh-pages
  baseline lands at a known-good commit before subsequent perf
  changes write to the trend chart.
- Two CIRISVerify issues queued (per design discussion):
  `HardwareSigner::storage_descriptor()` trait method (closes the
  prediction-drift caveat above) and generic `PoBManifest` +
  `verify_pob_manifest` (unblocks CIRISRegistry persist support).

## [0.1.6] — 2026-05-01

Hygiene batch from `docs/SECURITY_AUDIT_v0.1.4.md` §5. No
behavior changes; CI gates tightened.

### Added

- **`clippy.toml`** with `msrv = "1.75"` pin. Without this, a
  Rust toolchain bump on the CI runner can introduce new
  default-on lints that fail `-D warnings` for reasons unrelated
  to our code (we hit this once between Rust 1.93 and 1.95).
  Pinning to our declared MSRV applies the lint set as it was at
  that toolchain, even when the runner is newer.
- **Signer-variant log line** at PyO3 `Engine` construction.
  Emits a `tracing::info!` with `hardware_backed=true|false` and
  `variant=hardware|software` so ops can see in deployment logs
  whether the deployment is on the hardware path or the software
  fallback. Per-batch latency tax (~30 µs vs ~100 µs per sign)
  and security tier (UNLICENSED_COMMUNITY when software) both
  depend on this.
- **`#![deny(missing_docs)]`** at the lib root. Every public
  item now carries a doc comment; CI fails on any addition that
  ships without one. Pass over `src/store/types.rs`,
  `src/schema/{events,envelope,trace,mod}.rs`,
  `src/{ingest,journal,lib}.rs`,
  `src/store/{backend,decompose}.rs`, and `src/scrub/mod.rs` —
  ~160 doc additions, all on row-shaped types, error variants,
  and trait surfaces. Operator-readable: "what does this column
  mean" no longer requires reading the migration SQL alongside
  the source.

### Deferred to v0.1.7

- `Engine::with_software_fallback` env-flag opt-in
  (`SECURITY_AUDIT_v0.1.4.md` §3.1). `get_platform_signer`
  already auto-falls-back to software when no hardware is
  available — the env-flag pathway only matters when the OS
  keyring itself is unavailable (headless Linux without
  Secret Service / DBus). Narrower-than-thought; deferred until
  someone hits it.

## [0.1.5] — 2026-05-01

### Production hot-fix — multi-worker boot race (THREAT_MODEL.md AV-26)

The lens hit a race during a multi-worker production cutover:
several uvicorn workers calling `Engine(...)` concurrently against
the same DB raced on Postgres catalog inserts (hypertable type
registration in `pg_type`, `IF NOT EXISTS` checks across the
V001+V003 set, refinery's own schema_history bootstrap). Pre-v0.1.5
the second worker saw the unhelpful
`migrations: 'error asserting migrations table', 'db error'` —
no SQLSTATE handle, no way to distinguish "race" from
"unreachable" from "permission denied".

v0.1.5 closes the race with a session-scoped Postgres advisory
lock acquired on a dedicated single-use connection at the top of
`run_migrations()`. The lock id is `0x6369_7269_7370_7372`
(`"cirispsr"` in ASCII — greppable in `pg_locks`). Concurrent
workers serialize on the lock; the first worker through runs
migrations, subsequent workers block until the first's session
closes, then wake up, see "no migrations to apply", and proceed.
Lock auto-releases on connection close — including the
panic-mid-migration case (process dies → connection ends → lock
goes).

### Diagnostic improvement — SQLSTATE on migration errors

New `store::Error::Migration { sqlstate: Option<String>, detail }`
variant. The migration path walks the `tokio_postgres::Error`
source chain, extracts the SQLSTATE class+code, and surfaces it
in the Display format `migration: [42P07] ...`. The lens can now
distinguish:

- `42P07` "relation already exists" (pre-v0.1.5 race signature;
  shouldn't appear at v0.1.5+ unless schema is externally mutated
  mid-flight)
- `40P01` deadlock detected (caller should retry)
- `08006` connection terminated (transient; lens retries Engine
  construction)
- `42501` permission denied (DSN user lacks DDL rights — config
  bug, not transient)

`Error::kind()` returns the new stable token `store_migration` for
HTTP / PyO3 mapping.

### Tests

- 91 lib + 8 QA + 9 fixture = **108 tests, all green**.
- New QA scenario H — `av26_concurrent_boot_advisory_lock`: spawns
  10 concurrent `PostgresBackend::connect + run_migrations` calls
  against a freshly-truncated DB, asserts every one returns
  `Ok(())` and the migration history table has exactly one row
  per migration script (not N_WORKERS × migrations — that would
  mean the lock didn't hold). Gated on
  `CIRIS_PERSIST_TEST_PG_URL` like the other postgres integration
  tests; serialized via `serial_test::serial(postgres)`.

### Breaking change (small)

- `PostgresBackend::from_pool(pool: Pool)` →
  `PostgresBackend::from_pool(pool: Pool, dsn: impl Into<String>)`.
  The dsn is required for the migration phase to spin up a
  dedicated single-use lock-holder connection (the pool can't be
  used because session-scoped advisory locks would taint pooled
  connections). External callers were nil at the time of
  bump — no public-API users in the tree.

### Documentation

- `docs/INTEGRATION_LENS.md` §2 — new "Multi-worker boot contract
  (v0.1.5+)" subsection: serialization diagram, readiness-probe
  timeout guidance, SQLSTATE crib sheet.
- `docs/THREAT_MODEL.md` — AV-26 (Multi-worker migration race)
  added with the v0.1.5 mitigation prose.

### Notes

- The advisory lock takes ~negligible time on a warm lens
  deployment (migrations no-op after the first boot ever). On a
  fresh DB, ~50–200ms total.
- Best-effort `pg_advisory_unlock` is issued before the dedicated
  connection drops — shaves wait time off concurrent workers
  vs. relying on session close. Drop is the correctness guarantee;
  the unlock is the latency optimization.

## [0.1.4] — 2026-05-01

### QA harness landed as permanent CI gate

`tests/qa_harness.rs` (NEW) — seven-scenario stress suite that runs
post-tag against the v0.1.3 substrate. All seven passed first time:

```
A. high-volume concurrent agents     8 × 16 × 6 = 768 rows in 9 ms
B. AV-5 schema-version flood         10,000 rejections, no mem growth
C. AV-6 JSON-bomb depth               64-deep blob → typed rejection
D. AV-9 cross-agent dedup             both agents persist distinct rows
E. AV-24 sign-verify round-trip       256 rows, all ed25519_verified
F. AV-19 graceful shutdown drain      64 batches → all 256 rows drained
G. AV-17 attempt_index out-of-range   2^32 → typed rejection
```

The scenarios are now part of the test corpus. Run via
`cargo test --test qa_harness --release -- --test-threads=1
--nocapture`.

### Fixes from CI feedback at v0.1.3

- **cargo-deny wildcard** — added `version = "1.6"` alongside the
  `ciris-keyring` git+tag dep. cargo-deny no longer flags the
  unpinned semver requirement.
- **cargo-deny RUSTSEC-2024-0388 (derivative unmaintained)** —
  documented + ignored. Transitive via ciris-keyring's TPM/derive
  stack; proc-macro only, no runtime exposure.
- **cargo-deny RUSTSEC-2024-0384 (instant unmaintained)** —
  documented + ignored. Phase 2.3 Reticulum work likely replaces
  this branch entirely; tracking for upstream cleanup.

These were the three findings the v0.1.3 CI surfaced. The QA
harness ran clean against the substrate; only the dep-audit
gate needed reconciliation.

### Notes

- v0.1.3 release tag stays at the previous commit. v0.1.4 is the
  first version with all 8 CI jobs green simultaneously.
- No code-path changes in v0.1.4 — only `Cargo.toml` (version
  field) + `deny.toml` (ignored advisories) + the new test file.

## [0.1.3] — 2026-05-01

### ⚠ Breaking changes

- `Engine(...)` constructor in PyO3 now **requires** a
  `signing_key_id` parameter. v0.1.2's no-key path is gone. See
  `docs/INTEGRATION_LENS.md` §11 for the migration shape.

### Cryptographic provenance — scrub-signing pipeline (FSD §3.3 step 3.5)

- Every persisted row now carries a four-tuple scrub envelope:
  `original_content_hash`, `scrub_signature`, `scrub_key_id`,
  `scrub_timestamp`. **Always populated** — every component, every
  trace level. No "skip signing" code path; uniform contract.
- New direct dep on `ciris-keyring` (CIRISVerify's Rust crate, tag
  `v1.6.4`). Pipeline uses `&dyn HardwareSigner` directly — no
  wrapper trait. Hardware-backed where available (TPM / Secure
  Enclave / StrongBox / DPAPI); `Ed25519SoftwareSigner` for tests
  + dev / sovereign deployments.
- Pipeline gains step 3.5 between scrub and decompose:
  - `original_content_hash = sha256(canonical(component.data_pre_scrub))`
  - `scrub_signature = ed25519_sign(canonical(component.data_post_scrub))`
  - `scrub_key_id` + `scrub_timestamp` stamped per-row
- New `IngestError::Sign(String)` variant and `kind()` token
  `sign_keyring`. Maps to HTTP 5xx (operator-side fault, never
  agent-side).
- New `Engine.public_key_b64()` method exposes the deployment's
  public key for registry / lens-discovery layer publication.

### One key, three roles (PoB §3.2 — addressing IS identity)

The scrub-signing key is also the deployment's Reticulum
destination (`SHA256(public_key)[..16]`, when Phase 2.3 lands)
and the registry-published public key. One Ed25519 key, three
operational roles. No translation layer between cryptographic
provenance and federation transport. THREAT_MODEL.md AV-25
mitigation prose updated with the cost-asymmetry implication.

### Migrations

- **V003** (additive `ALTER TABLE`): adds the four envelope columns
  to `cirislens.trace_events`. No backfill — pre-v0.1.3 rows have
  NULLs (historical artifact bounded by 30-day retention). New
  partial index `trace_events_scrub_key` on
  `(scrub_key_id, ts DESC) WHERE scrub_signature IS NOT NULL` for
  per-deployment queries.

### Threat-model exposures closed

- **AV-17** (P0) — `attempt_index` integer truncation. Typed
  `MAX_ATTEMPT_INDEX = 1024` constant + new
  `Error::AttemptIndexOutOfRange { got, max }` variant; replace
  `as u32`/`as i32` casts with `try_into` throughout. Two regression
  tests: `2^32` rejected, `MAX+1` rejected, `MAX` accepted.
- **AV-18** (P1) — plaintext Postgres connection. New optional `tls`
  feature (default off) pulling in `tokio-postgres-rustls` +
  `rustls-native-certs`. Sovereign-mode deployments with remote DBs
  enable via `cargo build --features postgres,server,tls,...`.
- **AV-19** (P1) — graceful shutdown. `spawn_persister(...)` signature
  changes from `-> IngestHandle` to `-> (IngestHandle, PersisterHandle)`.
  Drop all `IngestHandle`s, `await persister.shutdown()` for clean
  drain. New `shutdown_signal()` async helper resolves on
  SIGTERM / SIGINT for the Phase 1.1 standalone server.
- **AV-24** (NEW v0.1.3) — Lens-scrub bypass / forgery. Mitigated by
  the always-on signed scrub envelope above.
- **AV-25** (NEW v0.1.3) — Scrub-key compromise. Mitigated by
  hardware-backed `ciris-keyring` (residual on `SoftwareSigner`
  fallback documented).

### General hardening (SECURITY_AUDIT_v0.1.2.md §4)

- `#![forbid(unsafe_code)]` at lib root (§4.1).
- `[profile.release] panic = "abort"` (§4.2): process dies fast on
  bug, supervisor restarts, journal-replay path runs.
- `[profile.release] overflow-checks = true` (§4.3): AV-17-class
  integer-truncation bugs panic in CI release builds.
- §4.12 PyO3 `catch_unwind` boundary — RESOLVED, subsumed by §4.2's
  panic-abort. With panic=abort there is no unwind to UB on across
  the FFI boundary; documented Option A vs B trade-off in the
  audit doc.

### CI / build manifest

- New `tools/ciris_manifest.py` (vendored from a planned shared
  refactor — tracking issue
  [CIRISAI/CIRISAgent#707](https://github.com/CIRISAI/CIRISAgent/issues/707)).
  Three subcommands (`generate` / `sign` / `register`); manifest
  schema matches CIRISVerify's signature shape.
- New CI job `build-manifest` after `pyo3-wheel`: generates +
  Ed25519-signs (via `CIRIS_BUILD_SIGN_KEY` secret) + uploads
  artifact. The `register` step is intentionally not yet wired;
  CIRISRegistry needs persist-side support first
  (`docs/TODO_REGISTRY.md`).

### Tests

- 95 lib + 9 fixture = 104 tests, all green.
- New regression coverage:
  - AV-17: `attempt_index` 2^32 → typed rejection
  - AV-19: graceful shutdown drains pending under load
  - AV-24: every row's `scrub_signature` round-trips through
    `ed25519_verify(scrub_signature, canonical(payload), public_key)`
  - PostgresBackend `as i32` paths use bounded `try_into`

### Documentation

- `FSD/CIRIS_PERSIST.md` updated with §3.3 step 3.5, §3.4
  robustness primitive #7, §3.7 schema additions. "One key, three
  roles" framing throughout.
- `docs/THREAT_MODEL.md` updated with AV-17..23 promoted from audit
  + AV-24/25 added; mitigation matrix and posture summary current.
- `docs/SECURITY_AUDIT_v0.1.2.md` updated with §4.12 resolution
  rationale.
- `docs/INTEGRATION_LENS.md` rewritten for v0.1.3 — §11 new
  scrub-signing pipeline section with migration path from v0.1.2.
- `docs/TODO_REGISTRY.md` (NEW) — tracks the cross-repo refactor
  ([CIRISAgent#707](https://github.com/CIRISAI/CIRISAgent/issues/707))
  and the registry-side persist-support work.

## [0.1.2] — 2026-05-01

### Security — threat-model hot-fixes

- **AV-5 fixed** — schema-version flood memory leak. The
  `parse_lenient` path no longer `Box::leak`s unrecognized version
  strings into `&'static str`. `SchemaVersion` now holds
  `Cow<'static, str>` — borrowed for [`SUPPORTED_VERSIONS`] entries,
  owned for unrecognized values which drop with the
  request. Earlier behavior was an exploitable DoS: an attacker
  flooding malformed bodies leaked unbounded memory.
- **AV-6 fixed** — JSON-bomb / deserialization amplification on
  per-component `data` blobs. New `MAX_DATA_DEPTH = 32` constant +
  `check_data_depth` walker invoked from
  `BatchEnvelope::from_json`. Deeper blobs reject with typed
  `Error::DataTooDeep`. Catches the
  `{"a":{"a":{"a":...}}}`-style bomb that the typed-envelope parse
  alone would have passed through into the `data` field.
- **AV-7 fixed** — body-size flood. Explicit `DefaultBodyLimit::max(8 MiB)`
  on the axum router. `MAX_INGEST_BODY_BYTES` is a public constant
  for operators to introspect. Bodies above 8 MiB hit
  `413 Payload Too Large` before reaching the queue or backend.
  Previously relied on deployment-edge proxy alone.
- **AV-9 fixed** — cross-agent dedup-key collision. The dedup tuple
  extends to include `agent_id_hash`. SQL UNIQUE index, in-memory
  backend `HashMap` key, `decompose::dedup_key()` function, and
  `ON CONFLICT` clause all updated together. A malicious agent
  reusing another agent's `trace_id` / `thought_id` shape can no
  longer DOS the victim's traces.
- **AV-15 mitigated** — error-display sanitization for HTTP / PyO3
  surfaces. Every typed error now exposes `kind()` returning a
  stable string token (`schema_unsupported_version`,
  `verify_signature_mismatch`, etc.). PyO3 raises the kind only;
  the verbose `Display` form (which can include attacker-supplied
  content) goes to `tracing::warn!` logs only. The lens HTTP
  layer maps token → status code.

### Schema reconciliation (Path B from integration-blocker call)

- `accord_public_keys` adopts the **lens-canonical schema** verbatim
  — `(key_id PK, public_key_base64, algorithm, description,
  created_at, expires_at, revoked_at, revoked_reason, added_by)`.
  Matches `CIRISLens/sql/011 + sql/022`. Earlier
  `(signature_key_id, public_key_b64, agent_id_hash, registered_at,
  revoked_at, metadata)` shape was the v0.1.x invention; the lens
  has 30 migrations of historical truth, so the crate adapts.
- `register_public_key()` Python signature gains optional
  parameters: `algorithm` (default `"Ed25519"`), `description`,
  `expires_at` (ISO-8601 string), `added_by`. Param `agent_id_hash`
  removed — it lives on the trace, not the key directory.
- `lookup_public_key()` filters on `revoked_at IS NULL AND
  (expires_at IS NULL OR expires_at > NOW())` — both gates the
  lens already had.
- **Migration impact:** `V001` becomes a no-op against the lens's
  already-extant table (every `CREATE TABLE IF NOT EXISTS`
  short-circuits). Sovereign-mode lens-less deployments get the
  same lens-canonical shape on a fresh DB. **No data migration
  needed for the lens.**
- V002 (audit anchor columns) folded into V001 — the audit anchor
  fields were appended to the `trace_events` shape, so v0.1.2's
  V001 includes them from the start. There is no V002 in the
  migration directory anymore.

### Tests

- Total: **92 lib + 9 fixture = 101 tests**, all green.
- New regression coverage:
  - AV-5: bound-check 1000 distinct unrecognized versions parse +
    drop without leaking.
  - AV-6: 64-deep JSON blob → `Error::DataTooDeep`. Shallow blobs
    pass.
  - AV-7: 9 MiB body → `413 Payload Too Large`.
  - AV-9: two distinct agents with same trace shape → both rows
    persist (no collision).

### Documentation

- `docs/THREAT_MODEL.md` — added; sixteen attack vectors with
  primary/secondary mitigations, cargo-audit findings, fail-secure
  degradation matrix, and v0.1.1 → v0.1.2 posture deltas.
- `docs/INTEGRATION_LENS.md` — updated for the column-name change
  in `register_public_key` + the new optional parameters.
- `THREAT_MODEL.md` posture summary at the bottom now reads:
  `AV-5/6/7/9/15 → ✓ Mitigated`.

### CI / build

- `cargo audit`: 0 vulnerabilities across 299 dependencies.
- `cargo deny`: license + advisory audit clean.
- All seven CI jobs green at the v0.1.2 tag.

### Known not-fixed-in-0.1.2 (tracked)

- **AV-2** (forged trace from compromised key) — Phase 2 closes via
  peer-replicate audit-chain validation.
- **AV-10** (audit anchor injection) — same Phase 2 dependency.
- **AV-11** (silent re-registration) — the lens-canonical schema's
  `revoked_at` + `revoked_reason` + `added_by` are the rotation-
  audit surface. Explicit rotation API (`rotate_public_key` with
  signed-by-old-key proof) is v0.2.x scope.
- **AV-16** (timing oracle on key directory) — low-impact (key ids
  are public-by-protocol); v0.2.x research.
- Float / timestamp canonicalization drift residual (AV-4 tail) —
  no production divergence detected; track per fixture growth.

## [0.1.1] — 2026-05-01

First fully-green CI run since 0.1.0. Infrastructure-level fixes;
substrate unchanged. See
[v0.1.1 release notes](https://github.com/CIRISAI/CIRISPersist/releases/tag/v0.1.1).

## [0.1.0] — 2026-05-01

Initial Phase 1 lens-ready release. See
[v0.1.0 release notes](https://github.com/CIRISAI/CIRISPersist/releases/tag/v0.1.0).
