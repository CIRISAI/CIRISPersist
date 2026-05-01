# Changelog

All notable changes per release. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) +
[Semantic Versioning](https://semver.org/spec/v2.0.0.html), with mission /
threat-model citations because this crate's audit story is the point.

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
