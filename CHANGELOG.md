# Changelog

All notable changes per release. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) +
[Semantic Versioning](https://semver.org/spec/v2.0.0.html), with mission /
threat-model citations because this crate's audit story is the point.

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
