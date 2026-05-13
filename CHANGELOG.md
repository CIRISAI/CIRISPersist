# Changelog

All notable changes per release. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) +
[Semantic Versioning](https://semver.org/spec/v2.0.0.html), with mission /
threat-model citations because this crate's audit story is the point.

## [0.8.1] — 2026-05-13

**Hash-chained audit log substrate (closes CIRISPersist#35).**
Absorbs CIRISAgent's GraphAuditService write path. Per-tenant
monotonic `sequence_number` + sha256 `prev_hash` chain enforces
entry ordering AND tamper-evidence. Step 1B continuation of the
4-step substrate-substitution migration.

### What landed

- **V014 migration** — `cirislens.audit_log` table with per-tenant
  monotonic `sequence_number` (UNIQUE constraint), 32-byte
  `prev_hash` / `entry_hash` BYTEA columns (sha256 of canonical
  bytes), action_type / subject_kind / subject_id correlation
  index path, standard audit-envelope columns. GIN-on-attributes
  not needed at audit-log layer (queries filter by tenant +
  action + actor, not by payload).
- **Wire types**:
  - `AuditEntry` — full row shape with hashes serialized as
    base64 strings on the JSON wire (BYTEA on disk).
  - `AuditFilter` (tenant-required), `AuditCursor` (v1 cursor on
    `(recorded_at, entry_id)`), `AuditListPage`.
  - `ChainVerification` + `ChainVerifyOutcome::{Ok, Break {
    at_sequence, reason, detail }}` with `ChainBreakReason` enum:
    `EntryHashMismatch | PrevHashMismatch | SequenceGap |
    SignatureFailure | GenesisPrevHashNotZero`.
- **`AuditService` trait** — 3 methods:
  - `record_entry` — re-derives `entry_hash`, verifies signature
    (self-signed against `actor_id` per v0.7.1 model), serializes
    writers within tenant via `SELECT … FOR UPDATE` on the tail,
    asserts `prev_hash` chain + sequence monotonicity, INSERTs.
  - `list_entries` — tenant-scoped cursor-paged listing (AV-51).
  - `verify_chain` — end-to-end chain walk with typed break
    diagnostic on first observed integrity violation.
- **Hash-chain verify helpers** (`audit::verify`):
  - `canonical_bytes_for_entry` — reuses the persist-wide
    canonicalizer.
  - `compute_entry_hash` — strips `signature` AND `entry_hash`
    (self-referential field) before sha256-ing.
  - `verify_entry_signature` — verify_hybrid against `actor_id`,
    HybridPolicy::Ed25519Fallback (per-actor ML-DSA-65 keys land
    with federation-wide PQC rollout).
  - `truncate_to_micros(DateTime<Utc>) -> DateTime<Utc>` —
    convenience for callers; Postgres TIMESTAMPTZ is
    microsecond-precision, so callers MUST truncate `recorded_at`
    before computing entry_hash + signing (else post-storage
    round-trip hash differs from pre-storage one). Documented.
- **PostgresBackend impl**: transactional INSERT-and-validate;
  reuses persist's existing `canonicalize_envelope_for_signing`
  + `verify_hybrid` primitives so the audit log inherits the
  v0.4.1+ verify stack.
- **PyO3 surface** — 3 `Engine.audit_*` methods. JSON-in /
  JSON-out; `catch_panic` discipline; `audit::Error → PyErr` via
  `audit_err_to_py` with stable kind() tokens.

### Threat-model anchors (THREAT_MODEL.md §4)

- **AV-49** — hash-chain integrity: re-derive + prev-hash match +
  sequence continuity + signature verify, all gated at
  `record_entry`. The `entry_hash` is bound by the signature (it's
  in the canonical bytes that get signed) so a downstream rewrite
  that tampers with one entry's `prev_hash` invalidates the
  upstream signature too.
- **AV-50** — chain fork detection: `verify_chain` walks
  end-to-end and surfaces typed breaks. Five distinct break
  categories let consumers route alerts appropriately.
- **AV-51** — tenant isolation: empty `tenant_id` filter rejects
  pre-SQL; every read pins `tenant_id` in WHERE. Federation-admin
  cross-tenant reads deferred to v0.9.x auth_tokens.

### Tests

- 12/12 audit tests pass against live `ciris-qa-postgres`:
  error-kind stability + genesis-sentinel lock + 4 type-level
  serde tests + 5 verify-helper unit tests + 1 full-lifecycle
  integration test covering: genesis insert → replay reject
  (ChainIntegrity OR Conflict) → sequence-gap reject → wrong-prev
  reject → 3-entry chain build → verify_chain Ok → list
  tenant-scoped → AV-51 cross-tenant returns empty (no leak) →
  AV-51 empty-tenant rejects → tamper detection via direct UPDATE
  surfaces `EntryHashMismatch` break at the right sequence.
- 315/315 full lib pass; clippy `-D warnings` clean across
  `cirisaudit cirisgraph postgres pyo3 cirisnode secrets extract
  classify scrub`.

### Unblocks (CIRISAgent migration)

- `AuditService` (GraphAuditService) — full write + verify parity
  via the trait.
- Distinct from cirisgraph: audit log is a separate hash-chained
  store, not graph rows. CIRISAgent's existing audit chain (the
  `audit_signing.py` path) maps directly onto this surface.

### References

CIRISPersist#35 (closes). Threat model: AV-49..AV-51.

## [0.8.0] — 2026-05-13

**Graph substrate — cirisgraph module (closes CIRISPersist#34).**
Absorbs CIRISAgent's `LocalGraphMemoryService` + `GraphConfigService`
off the agent's homegrown SQLite/Postgres + hand-rolled SQL. Step 1B
of the 4-step substrate-substitution migration trajectory (persist
→ edge → lens-core → node-core).

### Why Postgres + recursive CTEs (and not an embedded graph DB)

Verified via deepwiki against CIRISAgent's live code: the actual
graph workload is **point lookup by `(node_id, scope)`, time-window
scans on `updated_at`, predicate filters on JSONB attributes,
direct-edge retrieval per node, and bounded procedural k-hop
traversal** (`max_depth ∈ [1, 16]`). NO Cypher/Datalog requirement.
Postgres + recursive CTE on (node, edge) tables with a GIN index on
JSONB attributes handles every pattern at substrate-grade
reliability. Pulling in CozoDB / kuzu / indradb adds an embedded
engine + separate backup story + Rust dep weight for zero query
expressiveness gain. Decision documented in
`docs/THREAT_MODEL.md` AV-45..AV-48 + `migrations/postgres/lens/V013…sql`.

### What landed

- **V013 migration** — new `cirisgraph` schema:
  - `cirisgraph.nodes` (node_id, scope, node_type, attributes JSONB,
    version, updated_by, updated_at, created_at + audit envelope).
    PK is `(node_id, scope)` — same id may live in multiple scopes.
    Indexes: `(node_type, scope)`, `(updated_at)`, GIN on
    `attributes` for predicate push-down.
  - `cirisgraph.edges` (edge_id UUID PK, source/target node_id,
    scope, relationship, weight, attributes). NO FK on source/target
    so eventual-consistency writes work; k-hop CTE tolerates
    dangling edges.
- **Wire types** — `GraphNode`, `GraphEdge`, `GraphScope`
  (Local/Identity/Environment/Community per CIRISAgent's enum),
  `EdgeDirection`, `NodeFilter`, `NodeListPage`, `TraversalConfig`,
  `KhopEntry`, `ListCursor` (local v1 cursor matching v0.5.5 §I
  shape). Schema parity with CIRISAgent's `graph_nodes` /
  `graph_edges` (verified column-by-column via deepwiki).
- **`GraphService` trait** — 7 methods: `upsert_node` (AV-48
  optimistic-concurrency gate via `expected_version`), `upsert_edge`,
  `delete_node` (hard with edge cascade, or soft via `_deleted`
  JSONB marker), `get_node`, `get_edges_for_node` (directional +
  relationship-allow-list), `traverse_k_hop` (AV-46 bounded
  recursive CTE with BFS shortest-path semantics), `query_nodes`
  (cursor-paged newest-first, AV-47 scope-required).
- **PostgresBackend impl** — UNNEST'd UPDATE pattern matching
  v0.7.4's surface; recursive CTE for k-hop with per-level fan-out
  bound; dynamic filter composition for `query_nodes`; typed
  SqlState mapping (23505→Conflict, 23503→InvalidArgument FK,
  23514→InvalidArgument CHECK).
- **PyO3 surface** — 7 `Engine.cirisgraph_*` methods. JSON-in /
  JSON-out across FFI; `catch_panic` discipline; `cirisgraph::Error
  → PyErr` via `cirisgraph_err_to_py` with stable kind() tokens.

### Threat-model anchors (THREAT_MODEL.md §4)

- **AV-45** — attributes JSONB size cap (default 1 MiB; configurable
  via `CIRIS_PERSIST_GRAPH_MAX_ATTRIBUTES_BYTES`); enforced at the
  trait surface before binding to the SQL.
- **AV-46** — k-hop depth bound at `MAX_KHOP_DEPTH = 16` absolute
  cap; required non-empty `edge_relationships` allow-list (no
  wildcard traversal); per-level fan-out limit (default 1024) inside
  the CTE.
- **AV-47** — scope leakage prevention: every read takes
  `GraphScope` non-optionally at the type level; `query_nodes`
  refuses `NodeFilter` with `scope = None`.
- **AV-48** — UPSERT-by-version replay safety: `expected_version`
  must match current row's `version`; mismatch returns
  `Error::Conflict`; new rows pass `expected_version = 0`.

### Tests

- 9/9 cirisgraph tests pass against live `ciris-qa-postgres`:
  error-kind stability + MAX_KHOP_DEPTH lock + 7 type-level serde
  tests + 1 full-lifecycle integration test covering:
  - upsert × 3 → get round-trip
  - AV-48 version-conflict rejection (expected_version=0 for
    existing row → `Error::Conflict`)
  - successful update with correct expected_version
  - AV-45 oversized-attributes rejection (2 MiB > 1 MiB cap →
    `Error::InvalidArgument`)
  - 3-edge cycle (a→b→c→a) with mixed relationships (OWNS,
    SUMMARIZES)
  - get_edges_for_node directional (Outgoing / Incoming / Both)
  - relationship-allow-list filter
  - AV-46 traverse_k_hop bounds (depth > 16 rejects; empty
    relationships rejects)
  - 2-hop traverse (a→b→c) returns 3 entries with BFS depth tags
  - query_nodes with scope + type filter
  - AV-47 scope-required rejection
  - hard-delete cascade (node + edges)
- 303/303 full lib pass; clippy `-D warnings` clean across
  `cirisgraph postgres pyo3 cirisnode secrets extract classify scrub`.

### Unblocks (CIRISAgent migration Phase 1B)

- `MemoryService` (LocalGraphMemoryService) — full read/write parity
  via `GraphService` trait
- `ConfigService` (GraphConfigService) — config nodes use
  `node_type = 'config'` on the same tables
- Future v0.8.2: `TelemetryService` + `TSDBConsolidationService`
  write `TSDB_DATA` / `TSDB_SUMMARY` nodes here, with `SUMMARIZES`
  / `TEMPORAL_NEXT` edges in `cirisgraph.edges`

### References

CIRISPersist#34 (closes — substrate cut). Migration roadmap:
`memory/project_migration_roadmap.md`. Threat model:
`docs/THREAT_MODEL.md` AV-45..AV-48.

## [0.7.5] — 2026-05-13

**Pipeline orchestrator + PipelineEnvelope wire types** —
substrate foundation for CIRISEdge#3 / CIRISPersist#33 pieces 1+2.
v0.6.0 lifted the per-stage matcher / walker code from CIRISLens
under `classify` / `scrub` / `extract` features. v0.7.4 wired
`extract_features` inline into `IngestPipeline::receive_and_persist`.
v0.7.5 adds the orchestrator surface and the federation-internal
wire shapes that edge needs to compose `PipelineEnvelope`s.

### What landed

- **`Pipeline` orchestrator** in `src/pipeline/mod.rs`:
  composes registered `Stage` impls in declaration order; runs
  them sequentially via `Pipeline::run(&mut env, &mut state)`.
  `PipelineBuilder` validates declared `Stage::dependencies` at
  build time — a stage that names a dependency not added earlier
  fails with `Error::MissingDependency` (no runtime surprise).
  Stage failures short-circuit the run (FSD §3.3 step 3 — no
  partial-success path).
- **`ErasedStage` shim** — object-safe projection of the GAT-style
  `Stage` trait. Auto-impl'd for every `T: Stage`. Lets the
  builder hold `Vec<Box<dyn ErasedStage>>` without forcing
  `async_trait` onto the public trait.
- **`PipelineState` extended** per FSD §5.1: now carries
  `features: Option<Features>` (extract output),
  `encrypted_secrets: Vec<EncryptedSecretRecord>` (reserved for
  EncryptAndStoreStage), and a `pii_scrubbed` invariant flag.
  `stages_executed` changed from `Vec<&'static str>` to
  `Vec<String>` so wire-format `PipelineMetadata::stages_executed`
  can carry the same values without conversion.
- **`src/pipeline/types.rs`** — federation-internal wire shapes
  per FSD §4.3:
  - `PipelineEnvelope` — `pipeline_schema_version` (currently
    `"1.0"`), inner `BatchEnvelope`, `PipelineSidecar`,
    `edge_signature` (`HybridSignatureBlock`), `edge_key_id`,
    optional `edge_pqc_key_id`.
  - `PipelineSidecar` — `classifications`, `Option<Features>`,
    `encrypted_secrets`, `pipeline_metadata`. All fields
    feature-gated so sovereign-mode + scrub-only builds compose
    without dragging the secrets/classify deps.
  - `PipelineMetadata` — `stages_executed`, `fields_modified`,
    `pii_scrubbed`, `secrets_encrypted`, `pipeline_duration_ms`,
    `edge_build_id`.
  - `HybridSignatureBlock` — Ed25519 + optional ML-DSA-65
    base64 + `signed_at` timestamp; locally defined so the
    pipeline track stays decoupled from the federation-consensus
    `cirisnode::HybridSignature` track.
- **`ExtractStage`** concrete `Stage` impl wrapping
  v0.6.0 `extract_features`. Produces `state.features` from the
  first `CompleteTrace` in the envelope (matches FSD §5.1
  single-Option shape — multi-trace batches in the legacy
  inline path retain per-trace extract from v0.7.4).
- **`minimal_pipeline()`** factory — wires `ExtractStage` only.
  The full FSD §5.2 `default_pipeline(secrets)` wiring Classify
  → Scrub → EncryptAndStore → Extract is deferred (Classify
  matchers + EncryptAndStoreStage live in subsequent #33
  patches).

### Tests

- 7 pipeline orchestrator unit tests: error-kind stability,
  `PipelineState::default()` empties, `PipelineBuilder` rejects
  missing deps, `Pipeline::stage_names()` reports declaration
  order, `minimal_pipeline()` runs `ExtractStage` on an empty
  batch (records stage in `stages_executed`, no features
  populated since no traces).
- 4 wire-type serde tests in `pipeline::types`:
  schema-version constant locked, `PipelineMetadata::new` zeroed,
  `HybridSignatureBlock` round-trip + `None ml_dsa_65` correctly
  omitted, `PipelineMetadata` round-trip preserves fields.
- 294/294 full lib pass against live `ciris-qa-postgres`.
  Clippy `-D warnings` clean across `postgres extract classify
  pyo3 cirisnode secrets scrub`.

### Still deferred from CIRISPersist#33

- **Concrete `ClassifyStage`** — requires the matcher catalog
  (regex / NER) that ships types-only in v0.7.5. Tracked.
- **Concrete `ScrubStage`** — needs an adapter over the existing
  `crate::scrub::Scrubber` trait that the inline path uses; the
  pipeline wrapper is mechanical but bookkeeping-heavy.
- **`EncryptAndStoreStage`** — needs orphan-secret invariant glue
  + integration with `SecretsService` for the encrypt phase.
- **`Engine::receive_pipeline_envelope`** — verify-and-store
  HTTP handler accepting a `PipelineEnvelope`. Per FSD §4.3
  invariants 1–7.
- **`FederatedSecretsClient`** — HTTP client mirroring
  `SecretsService` for the agent's `SecretsServiceProtocol`
  cutover.
- **Role tag enforcement** — `cirislens_secrets_writer` /
  `_reader` / `_admin` on `federation_keys` + middleware.

### References

CIRISPersist#33 (this work — pieces 1+2 landed; 3+4+5 tracked
for subsequent v0.7.x patches). CIRISEdge#3 — substrate
prerequisite that drove the issue.

## [0.7.4] — 2026-05-13

**Pipeline orchestration — extract wired into receive_and_persist
(closes CIRISPersist#19).** v0.6.0 absorbed the scrub/extract/classify
substrate (modules + V009 migration + `get_features` /
`get_classifications` read API + scrub wired into ingest). v0.6.1
added SecretsService. The remaining gap from issue #19 was the
**extract orchestration**: extract was not actually called during
`receive_and_persist`, so V009's `extracted_features` column stayed
NULL in production and consumers' `get_features` calls always
returned `None`. v0.7.4 closes the gap.

### What landed

- **New `Backend::update_features_batch` trait method** — gated on
  the `extract` feature. Default impl returns 0 (no-op) so memory
  + sqlite backends silently skip; PostgreSQL backend overrides
  with a real `UPDATE ... FROM (SELECT UNNEST(...))` round-trip
  that touches every named `(trace_id, thought_id)` row.
- **Wire extract into `IngestPipeline::receive_and_persist`** —
  after the trace_events INSERT batch, iterate the verified
  `CompleteTrace` events, build `DeclaredCohortAxes` from each
  trace's `deployment_profile` block (V006 denormalized fields,
  required at trace_schema_version 2.7.9), call
  `pipeline::extract::extract_features(trace_json, declared)`,
  and batch-UPDATE all rows in one round-trip. Feature-gated on
  `extract`.
- **Non-fatal failure mode** — if the post-insert UPDATE fails
  (e.g. transient PG hiccup), persist logs a structured warn and
  returns the BatchSummary successfully. The trace_events rows
  already landed; an extract miss leaves `extracted_features`
  NULL, which matches the pre-v0.7.4 production state. Dropping
  verified agent testimony on the floor for a downstream-enrichment
  failure would be the wrong trade-off.
- **Trace-level serialize errors** are also non-fatal: skip that
  one trace's extract, log, continue with the rest of the batch.

### Tests

- New `update_features_batch_round_trip` integration test against
  live `ciris-qa-postgres`: insert 2 fixture traces with distinct
  cohort axes (moderation/production/US vs research/staging/EU),
  batch-update both with the corresponding `Features`, read back
  each via `read_features`, assert the cohort axes round-tripped.
  Covers the empty-fast-path (`update_features_batch(&[])` returns
  0 without hitting the DB).
- Existing happy-path ingest tests unchanged — the new code path
  is feature-gated on `extract`; memory-backend tests don't compile
  in the extract code (they use the no-op default).
- 268/268 lib pass; clippy `-D warnings` clean across
  `postgres extract classify pyo3 cirisnode`.

### What's still deferred from issue #19

- **Classify wiring** — the `pipeline::classify` module ships
  types (ContentClass / ContentClassMatch / etc.) but no matcher
  implementations yet. Wiring requires writing the regex/NER
  matcher catalog first. Tracked separately; consumers reading
  `classifications` via `read_classifications` still get empty
  vec.
- **`iter_features_by_cohort` streaming API** — RATCHET-side
  calibration consumers can read `extracted_features` directly
  via the `cirislens_reader` role for v0.7.4. A typed iterator
  remains a downstream nice-to-have.
- **Schema contract bump** to v0.3.3 — the `extracted_features`
  column shape is unchanged from v0.6.0's V009; no bump required
  for v0.7.4.

### Closes

CIRISPersist#19 — the post-ingest filter pipeline ask. v0.6.0
absorbed the substrate; v0.7.4 wires extract into the live
ingest path. Classify matchers + `iter_features_by_cohort` are
downstream follow-ups (not blocking the substrate ask).

## [0.7.3] — 2026-05-13

**CI hygiene — re-publish v0.7.2 features to PyPI.** v0.7.2 tag CI
failed on the `darwin-aarch64 (no postgres)` job: the macos-14
runner image ships a `rustup-init` stub at
`/Users/runner/.cargo/bin/cargo` that falls through to lazy
toolchain install. `Swatinem/rust-cache@v2` restored a cached
`~/.cargo/bin/` (created from an earlier run when the stub was the
only cargo), overwriting the dtolnay-installed real cargo. Result:
`cargo test` invoked the stub and exited 1 before the test even
loaded. The failing test gate blocked the `Publish wheel to PyPI`
step on the v0.7.2 tag CI; wheels built successfully (3 matrix
arches), but didn't upload.

v0.7.3 ships:

- `.github/workflows/ci.yml`: `cache-bin: false` on the
  `darwin-aarch64-test` and `ios-build` jobs. Disables the
  `~/.cargo/bin/` portion of the rust-cache so the dtolnay-installed
  cargo stays intact across cache restore. Build cache (registry +
  target) is unaffected — only the small fast-to-rebuild bin layer
  is excluded. Adds a `which cargo` diagnostic step before each
  build/test to surface this class of regression at the right place
  if it ever recurs.

Functionally identical to v0.7.2 — same code, same V012 migration,
same `put_promotion_attestation` trait method. Only the CI workflow
changed.

## [0.7.2] — 2026-05-13

**Canonical-promotion attestation (closes CIRISPersist#32).**
The v0.7.0 `is_canonical` column was readable via the
`ContributionsFilter`/`VotesFilter` `is_canonical` field but had no
typed-write to flip it. CIRISNodeCore's substrate-contract test
confirmed all 14 v0.7.1 methods sufficient for routine operations
EXCEPT canonical promotion (MISSION.md §3.4 truth-grounding loop).
v0.7.2 closes the gap with a signed-attestation envelope per
issue #32 Option B.

### What landed

- **V012 migration** — new `cirisnode.promotion_attestations`
  table with the standard CIRISPersist audit envelope columns
  (signature, signing_key_id, signature_verified, scrub_*, etc.),
  plus `target_kind` (CHECK against 5 enum variants), `target_ids
  UUID[]` (bulk-promote per attestation), `attested_by` (consensus
  crate identity), and `aggregate_evidence JSONB` (policy-shaped
  threshold-crossing details). GIN index on `target_ids` for
  "which attestations promoted this row?" reverse lookups during
  truth-grounding-loop audits.
- **New wire types** in `src/cirisnode/types.rs`:
  - `TargetRowKind` enum — 5 variants (`Contribution`, `Vote`,
    `ModerationEvent`, `SlashingAttestation`,
    `ReconsiderationAttestation`). `ReconsiderationRequest` is
    absent — request lifecycle is carried by the paired
    ReconsiderationAttestation, no separate promotion needed.
  - `PromotionAttestation` struct — `attestation_id`,
    `target_kind`, `target_ids`, `attested_by`,
    `aggregate_evidence`, `signature`, `attested_at`.
- **New trait method** — `NodeCoreService::put_promotion_attestation`,
  9th typed-write on the trait. Documents the transactional
  invariant: every named target_id must exist, or the whole
  transaction rolls back (no partial promotion).
- **PostgresBackend impl**:
  - Verify gate via v0.7.1 `verify_envelope_signed` (signer is
    `attested_by` — consensus crate identity, base64-encoded
    Ed25519 pubkey per SCHEMA.md §2.2).
  - Empty `target_ids` → `Error::InvalidArgument`.
  - BEGIN → INSERT promotion_attestations → UPDATE target rows
    (`is_canonical = TRUE`, `canonicalized_at = NOW()` via `WHERE
    id = ANY($1::uuid[])`) → assert affected-row count matches
    `target_ids.len()` (else rollback with InvalidArgument) → COMMIT.
  - Idempotency: targets already canonical still match the
    affected-row count (UPDATE no-ops on them).
  - Table + column names come from the typed `TargetRowKind` enum
    — no caller-controlled SQL injection surface.
- **PyO3 wrap** — `Engine.cirisnode_put_promotion_attestation(att_json)`,
  same `catch_panic` + JSON-in + `cirisnode_err_to_py` discipline
  as the v0.7.0-α5 surface.

### Tests

- New `promotion_attestation_round_trip` integration test against
  live `ciris-qa-postgres`: insert 2 pending contributions, bulk-
  promote both with one attestation, verify both flip to canonical
  via the existing `is_canonical=Some(true)` filter; assert
  duplicate `attestation_id` → Conflict, empty `target_ids` →
  InvalidArgument, phantom target → InvalidArgument **with proof
  of rollback** (re-using the same attestation_id with a valid
  target succeeds, confirming the prior INSERT did not persist).
- 14/14 cirisnode tests pass; 229/229 full lib suite pass; clippy
  `-D warnings` clean across `cirisnode postgres pyo3`.

### Closes

CIRISPersist#32 — NodeCoreService gap: no write method to promote
rows from pending to canonical.

## [0.7.1] — 2026-05-12

**Real envelope signature verification (closes the v0.7.0 caveat).**
v0.7.0-α4 shipped a structural stub: `verify_envelope_signature`
checked that the signature fields were base64-decodable and that
`signed_at` was non-zero, but did not actually verify the signature
against any pubkey. v0.7.1 makes verification real and gates
`signature_verified = TRUE` on a passing verify.

### Model

Per `CIRISNodeCore/SCHEMA.md` §2.2, every `ContributorId`
(`author_id`, `voter_id`, `accuser_id`, `adjudicator_id`,
`requester_id`) **IS** the Ed25519 public key — base64-encoded.
Federation-consensus envelopes are self-signed against the
identity-as-pubkey embedded in the envelope itself; persist does
not need a federation_keys directory lookup for cirisnode-track
verification (in contrast to the v0.4.1 outbound-envelope path
that uses `verify_hybrid_via_directory`).

This corrects the v0.7.0 CHANGELOG note about "threading
verify_hybrid_via_directory" — the schema's identity model is
self-signed, so the directory variant is not the right primitive
for this track. Persist still owns one canonicalization rule (via
`verify::canonical::canonicalize_envelope_for_signing`); only the
key-lookup path differs.

### What landed

- New `src/cirisnode/verify.rs` module with:
  - `canonical_bytes_for_envelope<T: Serialize>(envelope)` —
    serialize to JSON Value, strip the `signature` field, run the
    persist-owned Python-compatible canonicalizer. Same rule the
    agent / lens / edge envelopes use.
  - `verify_envelope_signed<T: Serialize>(envelope, sig, pubkey)` —
    canonicalize, then `verify_hybrid` with
    `HybridPolicy::Ed25519Fallback`. Hybrid envelopes (Ed25519 +
    ML-DSA-65) accepted via the upstream impl; classical-only
    accepted under fallback (per-contributor PQC key registration
    lands in a later release).
- `PostgresBackend::NodeCoreService` impl: all 6 typed-writes that
  carry signatures now call `verify_envelope_signed` before INSERT.
  `signature_verified = TRUE` is gated on the verify pass; persist
  refuses to insert on failure.
- Integration test now uses real `ed25519_dalek` signing keys; the
  test contributor + voter identities ARE base64-encoded Ed25519
  pubkeys (matches the schema). New tamper-rejection assertion:
  mutating the envelope payload after sign rejects with
  `Error::Signature`.

### Tests

- 13/13 cirisnode tests pass — 5 new verify-module tests
  (round-trip, tampered payload, wrong pubkey, empty signature,
  malformed base64) + 7 types tests + 1 error-kind + 1 full
  lifecycle integration test (real Ed25519 sign + tamper rejection)
  against live `ciris-qa-postgres`.
- Full lib test suite: 228/228 pass (was 223 in v0.7.0; +5 new
  verify tests). Clippy `-D warnings` clean across `cirisnode
  postgres pyo3` feature matrix.

### Still deferred

- ML-DSA-65 hybrid verification for contributor envelopes requires
  per-contributor PQC key registration (the cirisnode track does
  not yet have a PQC pubkey field on contributor identity).
  Classical Ed25519 verification is sufficient for v0.7.1.
- Tightening `HybridPolicy::Ed25519Fallback` → `HybridPolicy::Strict`
  is a CIRISNodeCore-track decision deferred until the PQC pubkey
  rollout completes federation-side.

## [0.7.0] — 2026-05-12

**CIRISNodeCore federation-consensus substrate (CIRISPersist#30).**
Clean-break release on a new track: persist becomes the federation-stable
host for the six federation-consensus row classes (Contribution, Vote,
Ledger, Moderation, Slashing, Reconsideration) that CIRISNodeCore
produces. Distinct from the v0.6.x lens/agent/bridge substrate —
different consumer ecosystem, different Cargo feature (`cirisnode`),
different PostgreSQL schema (`cirisnode.*`). Implementation of FSD
Appendix A.

### What landed (α1..α5)

- **α1 — Foundation** (commit `3df9618`): `cirisnode` Cargo feature.
  V011 migration with 8 tables under the `cirisnode` schema
  (contributions, votes, credits_ledger, expertise_ledger,
  moderation_events, slashing_attestations, reconsideration_requests,
  reconsideration_attestations). `IF NOT EXISTS` on every CREATE
  (v0.6.1-α3 idempotency discipline). Module skeleton + `Error` type
  with 8 stable `kind()` tokens (THREAT_MODEL.md AV-15).
- **α2 — Wire types** (commit `2cf5f90` + Cell-fix follow-up):
  24 federation-stable structs + 2 enums per
  `CIRISNodeCore/SCHEMA.md` §3–§10 — `ContributionEnvelope`,
  `VoteEnvelope`, `Cell`, `RoutableContributor`, `VoteWeight`,
  `CreditsUpdate`/`CreditsLedgerEntry`, `ExpertiseUpdate`/
  `ExpertiseLedgerEntry`, `ModerationEvent`, `SlashingAttestation`,
  `ReconsiderationRequest`/`ReconsiderationAttestation`,
  `HybridSignature`, `Witness`/`WitnessSet`, `DiversityProof`,
  `ListCursor`, plus list-page + filter shapes. NodeCore feedback:
  `Cell.subject` is `Option<String>` (Expertise paths use `None`).
- **α3 — Trait surface** (commit `5f884a4`): 13-method
  `NodeCoreService` trait — 8 typed-writes + 5 read clusters,
  `impl Future<...> + Send` GAT pattern (no `async_trait` dep).
  Audit-envelope invariant documented: every typed-write verifies
  hybrid signature before INSERT.
- **α4 — PostgresBackend impl**: `NodeCoreService for
  PostgresBackend`. 8 typed-writes (verify-then-INSERT, idempotent
  ledger UPSERT). 5 read clusters: `routable_contributors` (uses
  the partial index on `(domain, language, is_active)`),
  `read_vote_weight` (SCHEMA.md §5.2 — Credits ×
  expertise_multiplier × active_tier_multiplier),
  `list_contributions` / `list_votes` (cursor-paged newest-first
  per v0.5.5 §I shape with dynamic filter composition),
  `get_credits_ledger` / `get_expertise_ledger` point-lookups.
  Typed error mapping via `SqlState`: 23505 → Conflict, 23503 →
  InvalidArgument FK, 23514 → InvalidArgument CHECK. Full lifecycle
  integration test passes against live `ciris-qa-postgres`.
- **α5 — Engine PyO3 surface**: 14 PyO3 methods on `Engine`
  (`cirisnode_put_contribution`, `cirisnode_cast_vote`,
  `cirisnode_update_credits_ledger`, etc.). Each wrapped in
  `catch_panic` (v0.5.3 contract); JSON-encoded inputs + outputs;
  `cirisnode::Error` → `PyErr` via `cirisnode_err_to_py` with stable
  kind() tokens at the boundary.

### Signature verification — placeholder

The α4 `verify_envelope_signature` is a structural stub: it parses
the `HybridSignature` fields and rejects malformed inputs, but does
not yet thread `verify_hybrid_via_directory` (v0.4.1 surface). Full
canonicalization-aware verification lands in a v0.7.0.x patch once
the CIRISNodeCore canonical-bytes spec is locked. Rows currently
INSERT with `signature_verified = TRUE`; the patch will gate that
flag on the real directory check.

### Track distinction (v0.6.x vs v0.7.0)

v0.6.0 / v0.6.1 / v0.6.2 are the lens/agent/bridge track (pipeline
orchestration, federated secrets, taxonomy, scrub/extract lift from
CIRISLens). v0.7.0 is the **CIRISNodeCore track** — distinct
consumer, distinct schema, distinct feature gate. They ship from
the same crate but never share write paths. See
`FSD/CIRIS_PERSIST.md` Appendix A for the rationale and §A.5 for
sequencing.

### Tests

- 8/8 cirisnode tests pass — 1 error-kind-stability, 6 serde
  round-trip, 1 full-lifecycle integration test against live
  `ciris-qa-postgres` (`put_contribution` → `cast_vote` → ledger
  updates → `routable_contributors` → `read_vote_weight` →
  `list_*` → `get_*`).
- Conflict semantics verified (duplicate `contribution_id` →
  `Error::Conflict`).
- Full lib test suite green; clippy `-D warnings` clean across the
  `cirisnode postgres pyo3` feature matrix.

### Closes

- CIRISPersist#30 (FSD Appendix A spec + impl).
- CIRISPersist#31 (`deferral_*` → `agent_deferrals_*` rename
  landed in the v0.6.x track but referenced from Appendix A.1 for
  context).

## [0.6.1] — 2026-05-12

**Federated SecretsService — substrate cut (CIRISPersist#19).**
v0.6.0 landed the pipeline substrate; v0.6.1 lands the federated
`SecretsService` ("secrets are on us"). Five alpha checkpoints
(α1..α6, secrets-server α7 deferred to v0.6.1.x).

### What landed (α1..α6)

- **α1 — Foundation** (commit `5ff57a5`): `secrets` + `secrets-server`
  Cargo features. V010 migration with `cirislens_secrets` schema +
  `cirislens_pseudonyms` (5 tables). `SecretsError` with 8 stable
  `kind()` tokens. `src/secrets/crypto.rs` — the sole import site
  of `ciris_crypto::*` (FSD §7.5a invariant): AES-256-GCM encrypt /
  decrypt, PBKDF2-HMAC-SHA-256 derive (600k iters per OWASP 2023),
  HMAC-SHA-256, OS-RNG. Persist takes **zero direct primitive deps**.
- **α2 — Wire types** (commit `71c1a9c`): 13 federation-stable
  structs + 2 enums per FSD §7.2 — `SecretRecord`,
  `EncryptedSecretRecord`, `SecretReference`, `SecretRecallResult`,
  `DecapsulationContext`, `AccessLogEntry`, `AccessOp`,
  `SecretsListFilter`, `SecretsServiceStats`, `RotationResult`,
  `MasterKeyRef`, `FilterConfig` + `FilterUpdateRequest/Result`.
  All serde-stable across PyO3 / HTTP / postgres-JSONB boundaries.
- **α3 — Trait surface + V010 idempotency** (commit `b8e9c3a`): the
  18-method `SecretsService` trait per FSD §7.1 using `impl Future<...>
  + Send` GATs. Fix V010 migration to use `IF NOT EXISTS` everywhere
  (av26 concurrent-boot test caught the gap).
- **α4 — Crypto facade**: shipped as part of α1.
- **α5 — PostgresSecretsBackend** (commit `8d3d19f`): the 18-method
  impl. CRUD with per-secret salt+nonce + PBKDF2 derive; transactional
  `reencrypt_all` with master_key_meta lifecycle; access_log writes
  on every call (audit invariant). 2 methods (`process_incoming_text`,
  `decapsulate_secrets_in_parameters`) stub to `SecretsError::Internal`
  pending v0.6.2 pipeline orchestration; `migrate_to_hardware_key`
  returns `HardwareKeyUnavailable` (waits on `ciris-keyring/
  symmetric-derivation` upstream). Full-lifecycle smoke test passes
  against live ciris-qa-postgres.
- **α6 — Engine PyO3 surface**: 18 PyO3 methods on `Engine`
  (`secrets_store_secret`, `secrets_encrypt`, etc.). Each wrapped in
  `catch_panic` (v0.5.3 contract); JSON-encoded results;
  `SecretsError` → `PyErr` via `secrets_err_to_py`.

### What's deferred

- **α7 — HTTP API behind `secrets-server`**: federation-stable HTTP
  endpoints per FSD §8 (POST `/api/v1/secrets/store`, etc.). The
  PyO3 surface from α6 is sufficient for lens / agent / bridge
  consumers; HTTP comes in v0.6.1.x or v0.6.2 with the edge cutover.
- **`secrets-hw` Cargo feature + `migrate_to_hardware_key` impl**:
  waits on `ciris-keyring/symmetric-derivation` upstream in
  CIRISVerify. The trait method exists; v0.6.1 returns
  `HardwareKeyUnavailable`.
- **Pipeline-integrated `process_incoming_text` /
  `decapsulate_secrets_in_parameters`**: v0.6.2 alongside pipeline
  orchestration. Today's stubs return `SecretsError::Internal`.

### Feature gates

```toml
secrets        = ["postgres", "classify",
                  "ciris-crypto/aes-gcm", "ciris-crypto/kdf",
                  "ciris-crypto/hmac", "ciris-crypto/random"]
secrets-server = ["secrets", "server"]   # HTTP — α7 deferred
```

### Threat model

No new vectors. Every `SecretsService` operation appends one
`access_log` row before returning (FSD §7.1 audit invariant). The
crypto facade in `src/secrets/crypto.rs` is the **only** import
site of `ciris_crypto::*` in persist — auditable boundary. The
in-memory software-key store loses keys on process restart;
persistent storage via `ciris-keyring` is a v0.6.1.x follow-up.
`lib.rs` retains `#![deny(unsafe_code)]` (no new unsafe surface).

### Verification

- 17 secrets unit tests (10 crypto + 7 types).
- 1 PG-gated full-lifecycle smoke test: rotate → encrypt → store →
  retrieve → list → recall → forget → audit-log → stats → health.
- cargo-deny / clippy / fmt clean across all feature combos.
- 18 PyO3 wraps compile + catch_panic-wrapped.

### Upgrade

```toml
ciris-persist = "0.6.1"
```

Pipeline reads from v0.6.0 are unchanged. SecretsService activates
behind `secrets` feature. Lens / agent target this version for the
secrets-substrate adoption track.

### What's next

- **v0.6.1.x**: persistent software-key storage via `ciris-keyring`
  (HMAC + secret-derivation feature add upstream). HTTP API behind
  `secrets-server` once edge surface is defined.
- **v0.6.2**: pipeline orchestration — `Engine.receive_pipeline_envelope`,
  Stage runner, `process_incoming_text` + `decapsulate_*` real impls.

## [0.6.0] — 2026-05-12

**Post-ingest filter pipeline substrate — partial close of CIRISPersist#19.**
The pipeline track lands in five alpha checkpoints (α1..α5, all on
main pre-tag). Secrets module + edge cutover deferred to v0.6.1 +
v0.6.2 per the locked
[FSD POST_INGEST_FILTER_PIPELINE.md](FSD/POST_INGEST_FILTER_PIPELINE.md)
§12 migration plan.

### What landed (α1..α5)

- **α1 — Foundation:** `classify` taxonomy (36-variant `ContentClass`
  + `DetectionMethod` + `Sensitivity` + `Action` + `LearningState`
  + `ContentClassMatch`), `Stage` trait, `PipelineState`,
  `pipeline::Error` with stable `kind()` tokens. V009 migration adds
  `extracted_features` + `classifications` + `pipeline_metadata`
  JSONB columns to `cirislens.trace_events` — all nullable so
  pre-pipeline rows stay valid (FSD §12.7 rollback-safe).
- **α2 — Scrub lift:** verbatim port of CIRISLens
  `cirislens-core/src/scrubber/` (fields catalog, regex catalog with
  production-corpus false-positive guards, depth-limited JSON walker
  with two-phase NER batch shape, NER stub). ~1,200 LOC under the
  `scrub` feature gate. 33 lifted unit tests pass.
- **α3 — Extract lift:** verbatim port of CIRISLensCore
  `src/extract/` (typed `Features` struct with `DeclaredCohortAxes` +
  `StepTimestamps` + `ObservationWeights` + `ModelClass`,
  `extract_features` static walker, `resolve_json_path` utility).
  ~700 LOC under the `extract` feature gate. Serde-roundtrip stable
  for the V009 JSONB columns.
- **α4 — NER backends:** verbatim port of XLM-RoBERTa (candle) +
  DistilBERT-multilingual + ORT INT8 backends. ~1,550 LOC behind
  `scrub-ner` / `scrub-ort` feature gates. Cache-deduped batch
  inference (~98.8% dedup ratio on production HF corpus). `lib.rs`
  relaxed `forbid(unsafe_code)` → `deny(unsafe_code)` so the three
  safetensors-mmap loader files can scope-allow unsafe at the file
  level — non-NER code stays effectively unsafe-free. `deny.toml`
  ignores `RUSTSEC-2025-0119` (number_prefix unmaintained) +
  `RUSTSEC-2024-0436` (paste unmaintained), both transitive-only
  through the ML deps.
- **α5 — Engine read API:** `Engine.get_features(trace_id,
  thought_id)` + `Engine.get_classifications(trace_id, thought_id)`
  PyO3 methods + the inherent PG implementations behind them. Read
  the V009 JSONB columns; return `None` / empty when pipeline
  hasn't run on those rows. Pipeline ORCHESTRATION
  (`Engine.receive_pipeline_envelope`, the per-stage runner) lands
  with v0.6.1's edge cutover — v0.6.0 ships the read surface only.

### Cargo features (FSD §2.4 shape)

```toml
classify       = ["dep:regex"]                         # ContentClass + matchers
scrub          = ["classify"]                          # regex scrubber + walker
extract        = ["scrub"]                             # typed Features
scrub-ner      = ["scrub", "dep:anyhow", "dep:log",    # multilingual NER
                  "dep:candle-core", "dep:candle-nn",
                  "dep:candle-transformers",
                  "dep:tokenizers", "dep:hf-hub"]
scrub-ort      = ["scrub-ner", "dep:ort", "dep:ndarray"]  # ORT INT8 fast path

default-pipeline-ml     = ["scrub-ner", "extract"]     # production lens / edge
default-sovereign-light = ["scrub", "extract"]         # Pi-class / sovereign
```

### Threat model

No new vectors. The pipeline operates on already-verified
`BatchEnvelope`s (after `verify_hybrid`); its outputs are stored
under the same `cirislens.trace_events` AV-9 cross-agent dedup
discipline. The `deny.toml` advisory ignores are both
unmaintained-track (not exploitable), scoped to feature-gated ML
deps.

### Verification

- 53 pipeline tests pass under `scrub-ner` build, 52 under light
  build (one feature-gated NER test).
- 230+ lib tests total across all feature combinations.
- 38 PG-gated tests pass against live `ciris-qa-postgres` (pre-push
  hook gate).
- cargo-deny / clippy / fmt clean across all feature combos.

### Upgrade

```toml
ciris-persist = "0.6.0"
```

Pipeline reads activate when consumers enable the `extract` /
`classify` features. The pre-v0.6.0 ingest path is unchanged
(V009 columns are nullable; legacy rows have `extracted_features
IS NULL`). Lens / lens-core target this version for adoption
tracking; secrets module + edge cutover land in v0.6.1.

### What's next

- **v0.6.0.x patches:** α6 — proptests port from
  `cirislens-core/src/scrubber/proptests.rs` (~184 LOC) +
  `differential` tests vs `AdaptiveFilterService`.
- **v0.6.1:** `crate::secrets::SecretsService` (18-method trait +
  V010 migration, `cirislens_secrets` schema 4 tables + HTTP API +
  ciris-crypto facade). Per FSD §12.1 — prerequisite (ciris-crypto
  v2.0.2 `aes-gcm`/`kdf`/`hmac`/`random` features) already met.
- **v0.6.2:** Engine pipeline orchestration —
  `receive_pipeline_envelope`, `Stage` runner, edge call site.

## [0.5.8] — 2026-05-12

**Real production bug fix: `put_revocation` + `put_attestation`
String→UUID binding rejection.** Surfaced via the v0.5.5 §I round-
trip test. v0.5.6/v0.5.7's hotfixes only touched test fixtures and
missed the underlying issue — the existing impl is wrong, not the
tests.

### The bug

`put_revocation` and `put_attestation` both write to `UUID`-typed
columns via `$1::uuid` cast on a `&String` param:

```sql
INSERT INTO cirislens.federation_revocations (revocation_id, ...)
VALUES ($1::uuid, $2, ...)
```

```rust
&[&row.revocation_id /* String */, ...]
```

Some `tokio-postgres` / `postgres-types` version combinations refuse
to serialize `&String` against a `$1::uuid` cast param — the driver's
type-check sees the inferred `UUID` column type and rejects `String`
even though the explicit `::uuid` cast would have accepted `TEXT`.
Result: `Backend("insert revocation: error serializing parameter 0")`.

The bug was latent since v0.3.x — no prior PG test exercised
`put_revocation` or `put_attestation` end-to-end (only the read-side
`attach_*_pqc_signature` SELECT paths). The §I round-trip test added
in v0.5.5 was the first to exercise the put path under live Postgres.

### The fix

Parse `String → uuid::Uuid` at the persist boundary, bind the
`Uuid` value directly. The `with-uuid-1` feature on tokio-postgres
already provides the `ToSql` impl; we just stop relying on the
fragile `&String → $::uuid` cast path:

```rust
let revocation_uuid = uuid::Uuid::parse_str(&row.revocation_id)?;
client.execute(
    "... VALUES ($1, $2, ...)",   // no ::uuid cast needed now
    &[&revocation_uuid, ...]
)
```

Same fix applied to `put_attestation`. Other `$N::uuid` sites
(`attach_*_pqc_signature`, outbound queue ops) are unchanged for now
— they're SELECT-by-id paths where bind-as-Uuid hasn't been observed
to fail in production. Will revisit if test coverage surfaces them.

API-level surface: callers still pass `revocation_id: String` /
`attestation_id: String` on the public `Revocation` / `Attestation`
types — parsing is internal. Invalid UUIDs now surface as
`Error::InvalidArgument` (was: `Error::Backend` with opaque
serialization error message) — strictly better error class for
operators.

### Pre-push hardening

`scripts/hooks/pre-push` now auto-discovers a local Postgres
container (`ciris-qa-postgres` by name, the dev convention) and
runs the `read_section_*` PG-gated tests against it before pushing.
When no live PG is reachable, it warns but doesn't fail (preserving
the historical "integration in CI" contract). Two release versions
burned in 30min to fixture bugs that local `cargo test` silently
skipped — this stops that pattern.

### Verification

Locally: 38 / 38 `read_section_*` tests pass against the live
`ciris-qa-postgres` Docker container (`docker inspect`-discovered
DSN). Same matrix CI will exercise.

### Upgrade

```toml
ciris-persist = "0.5.8"
```

If you're a caller that ever called `put_revocation` or
`put_attestation` in postgres-backed deployments — you probably
wanted v0.5.8. v0.5.5/.6/.7's published tag exists but the
`put_revocation`/`put_attestation` paths were never working
end-to-end in those releases anyway.

Lens / lens-core teams: target `ciris-persist == 0.5.8` for adoption.

## [0.5.7] — 2026-05-12

**Second §I test fixture hotfix.** v0.5.6 fixed the cursor + hex
fixture bugs but missed one: `revocation_id` is `::uuid`-cast in
`put_revocation`'s INSERT SQL, so the test's `format!("rev-§i-{}",
uuid_like())` (a hex-timestamp token, not a UUID) fails parameter
serialization at the postgres driver. Fixed to use `uuid::Uuid::new_v4()`
which the rest of the test suite already uses for derived-schema
inserts.

Zero impl changes from v0.5.5 / v0.5.6 — same single-line test
fixture fix as v0.5.6 was. Manifest-integrity discipline applies
again (v0.5.6's build-manifest was registered with the registry
before publish-pypi was skipped), hence v0.5.7.

Lens / lens-core teams: target `ciris-persist == 0.5.7` for adoption.

### Upgrade

```toml
ciris-persist = "0.5.7"
```

## [0.5.6] — 2026-05-12

**Test fixture hotfix for v0.5.5 §I federation observability tests.**

v0.5.5's tag-push CI failed two §I tests under live Postgres
(unit-only `cargo test` had passed because PG-gated tests early-return
without `CIRIS_PERSIST_TEST_PG_URL`):

1. `read_section_i_list_federation_keys_cursor` asserted
   `next_cursor.is_none()` on an exact-fill page (4 keys, limit=2 →
   page 2 yields 2 items with no more remaining). The pagination
   contract (matching §A from v0.5.0) is "next_cursor is None **only**
   when items.len() < limit"; impl can't distinguish "exactly limit
   remaining" from "more remain" without fetching limit+1. Fixed the
   test: walk an extra empty page (page 3) and assert IT has no
   cursor and zero items.
2. `read_section_i_list_revocations_round_trip` set
   `original_content_hash: "abc"` — 3 hex chars, odd length. The
   federation persist layer rejects with
   `InvalidArgument("Odd number of digits")`. Fixed the fixture to
   use a 64-char sha256-shaped hex placeholder.

**Zero impl changes** — every §C/D/G/H/I primitive's Rust code is
the v0.5.5 code unchanged. The pagination contract was correct;
only the §I test assertion was wrong about it.

v0.5.5's PyPI publish was skipped because of the test failure (no
artifact ever reached PyPI); v0.5.5's git tag exists but doesn't
correspond to a shipped wheel. Build manifest WAS registered with
the registry for version=0.5.5, which is why we cut v0.5.6 rather
than force-moving the v0.5.5 tag — manifest integrity discipline.

Lens / lens-core teams: target `ciris-persist == 0.5.6` for adoption.

### Upgrade

```toml
ciris-persist = "0.5.6"
```

## [0.5.5] — 2026-05-11

**Federation read primitives §C/D/G/H/I — closes CIRISPersist#23.**
v0.5.0 shipped §A/B/F/E (validated in production via the v0.5.3
bridge sweep, 50× §E baseline calls, zero failures). v0.5.5 closes
the issue with the deferred batch — five additive primitives, no
schema changes, no breaking API edits.

### Section C — Task-grouped listing

```rust
pub fn list_tasks(filter: TaskFilter, cursor: Option<TaskCursor>, limit: i64)
    -> Result<TaskListPage, Error>
```

`TaskClass::from_task_id` is the canonical task-id → class mapping
(qa_eval / discord / real_user_* / wakeup_ritual / other) — every
federation peer sees the same class for the same `task_id`.
`initial_observation` extracts the earliest THOUGHT_START's
`task_description` payload field at SQL layer so it's a server-side
constant. Cursor: `(earliest_at, task_id)` tuple, newest-first.
Trace ordering within a task: `thought_depth ASC NULLS LAST` →
reasoning chain reads top-to-bottom.

PyO3: `Engine.list_tasks(filter_json, cursor_json, limit) -> str`.

### Section D — LLM call surface

```rust
pub fn list_llm_calls(filter: LlmCallFilter, cursor, limit) -> Result<LlmCallListPage, ...>;
pub fn aggregate_llm_costs(filter: LlmCallFilter) -> Result<LlmCostAggregate, ...>;
```

`list_llm_calls`: cursor-paged listing of `cirislens.trace_llm_calls`,
filterable by time / agent / model / status / trace / thought.
Cursor: `(ts, trace_id, attempt_index)` tuple. Agent-side filters
force a JOIN to `trace_events` on `(trace_id, parent_event_id)` so
`agent_id_hash` / `agent_name` / `deployment_domain` reach the
parent row.

`aggregate_llm_costs`: rollup by_model, by_agent, by_domain, plus
window-level totals. Four SQL passes share the same WHERE filter;
every `SUM` is `COALESCE`'d to 0 (CIRISPersist#24 hygiene applied
proactively — empty-window inputs return zeros, not NULL panics).

PyO3: `Engine.list_llm_calls`, `Engine.aggregate_llm_costs`.

### Section G — Corpus shape

```rust
pub fn corpus_shape(filter: CorpusShapeFilter) -> Result<CorpusShape, ...>;
```

Six breakdowns per window: by_task_class, by_qa_language,
by_qa_question_num, by_agent_name, by_agent_version (= agent_template),
by_primary_model, by_deployment_region. `primary_model` is the
per-trace most-frequent LLM call model (ties broken alphabetically).
QA breakdowns extract `qa_<lang>_<num>` via Postgres regex.
`stationarity_z_score` reserved for a future baseline-comparison
API extension — v0.5.5 returns `None` (lens can compute by calling
`corpus_shape` twice and comparing distributions).

PyO3: `Engine.corpus_shape(filter_json) -> str`.

### Section H — Privacy / scrub observability

```rust
pub fn aggregate_scrub_stats(window: TimeWindow) -> Result<ScrubAggregate, ...>;
```

`envelopes_scrubbed` (distinct traces with `pii_scrubbed = true`)
and `by_trace_level` populate from `cirislens.trace_events` today.
`fields_scrubbed_total` and `by_entity_type` are gated on v0.6.0's
post-ingest classification pipeline (CIRISPersist#19) — they
return `0` / empty until the pipeline lands the per-entity taxonomy.
The shape is locked now so consumers don't churn when the v0.6.0
pipeline arrives.

PyO3: `Engine.aggregate_scrub_stats(since_iso8601, until_iso8601) -> str`.

### Section I — Federation observability bulk

```rust
pub fn list_federation_keys(filter, cursor, limit) -> Result<FederationKeyListPage, ...>;
pub fn list_attestations    (filter, cursor, limit) -> Result<AttestationListPage, ...>;
pub fn list_revocations     (filter, cursor, limit) -> Result<RevocationListPage, ...>;
```

Bulk-list primitives over `cirislens.federation_{keys,attestations,
revocations}`. Filters compose AND-style:

- **Keys**: `agent_id_hash`, `algorithm`, `revoked`, `pqc_completed`.
  `revoked` is a `EXISTS` predicate against `federation_revocations`;
  `pqc_completed` checks `pqc_completed_at IS NOT NULL`.
- **Attestations**: `attesting_key_id`, `attested_key_id`,
  `attestation_type`, `pqc_completed`.
- **Revocations**: `revoked_key_id`, `revoking_key_id`,
  `pqc_completed`.

Each newest-first by its respective `(timestamp, id)` tuple cursor.
Item types reuse `crate::federation::{KeyRecord, Attestation,
Revocation}` — no duplicate schemas.

PyO3: `Engine.list_federation_keys`, `Engine.list_attestations`,
`Engine.list_revocations`.

### Test coverage

17 new integration tests across §C/D/G/H/I:

- §C: TaskClass derivation table (pure-Rust unit), list_tasks
  round-trip, cursor pagination across 5 tasks, task_class filter,
  limit validation. **5 tests.**
- §D: list_llm_calls round-trip, cursor pagination across 5 calls,
  aggregate_llm_costs by model/agent/domain/totals, empty-window
  aggregate returns all zeros. **4 tests.**
- §G: corpus_shape round-trip with mixed task classes + QA buckets,
  empty-window shape, primary_model derivation across multi-call
  traces. **3 tests.**
- §H: aggregate_scrub_stats round-trip with mixed trace levels,
  empty-window. **2 tests.**
- §I: list_federation_keys round-trip + cursor + pqc filter,
  list_revocations round-trip, limit validation. **3 tests.**

Total: 222 lib tests pass (was 205 in v0.5.4).

### What you get

- Lens / lens-core / sovereign agents: every dashboard primitive
  (`/repository/traces`, `/repository/tasks`, cost dashboards,
  corpus drift, privacy dashboards, federation directory monitoring)
  now has a typed persist-owned endpoint. The historical
  `cirislens_reader` direct-SQL carve-out can retire.
- Federation peers: task classification, QA language extraction,
  primary-model derivation are SQL-side and identical across every
  consumer. No drift between lens vs. partner site implementations.
- v0.6.0 unblocker: §H's shape is committed; once the post-ingest
  pipeline lands per-entity classification, consumers see real
  values without API changes.

### Upgrade

```toml
ciris-persist = "0.5.5"
```

Additive only. Zero breaking changes. Existing v0.5.0 primitives
unchanged.

## [0.5.4] — 2026-05-11

**Crate-wide panic-isolation sweep completion + Python regression test
gate.** v0.5.3 hardened the v0.5.0 ReadEngine surface (the realized
incident path from CIRISPersist#24); v0.5.4 finishes the work across
the rest of the postgres backend and the FFI surface, then adds a
Python regression test that asserts the catch_panic invariant
end-to-end through the wheel. Closes
[CIRISPersist#28](https://github.com/CIRISAI/CIRISPersist/issues/28)
+ [#29](https://github.com/CIRISAI/CIRISPersist/issues/29).

### Phase 1 — `PgRowExt::safe_get` extension + full postgres sweep (#28)

The `PgRowExt` trait introduced in v0.5.3 only handled column-name
lookups returning `crate::read::Error`. v0.5.4 generalises it to
support both column-name and positional indices, and adds a
generic `safe_get_with(idx, err_ctor)` variant so non-ReadEngine
layers (federation, outbound, derived) can route the NULL-on-decode
failure into their own `Error::Backend` variants:

```rust
trait PgRowExt {
    fn safe_get<'a, T, I>(&'a self, idx: I) -> Result<T, crate::read::Error>
    where T: FromSql<'a>, I: RowIndex + Display;

    fn safe_get_with<'a, T, I, E, F>(&'a self, idx: I, err: F) -> Result<T, E>
    where T: FromSql<'a>, I: RowIndex + Display,
          F: FnOnce(String) -> E;
}
```

Every remaining bare `Row::get` on a `tokio_postgres::Row` in
`src/store/postgres.rs` swept to `safe_get` / `safe_get_with`. ~75
additional sites across:

- `pg_row_to_event_row` (decompose, ~30 sites, `store::Error`)
- `pg_row_to_outbound_row` (~30 sites, `outbound::Error`)
- `pg_row_to_key_record`, `pg_row_to_attestation`,
  `pg_row_to_revocation` (federation directory decoders;
  signatures bumped from infallible to `Result<_, federation::Error>`;
  call sites collect via `::<Result<Vec<_>, _>>()`)
- `list_hybrid_pending_{keys,attestations,revocations}` (PQC sweep
  pending lists)
- `lookup_public_key` + `sample_public_keys` (federation directory
  scalar reads)
- `delete_traces_for_agent` (DSAR cascade scalar reads)
- `enqueue_outbound` + `mark_transport_failed` (outbound state
  machine reads)
- `count_traces`, `count_overrides`, `count_identity_changes`,
  `aggregate_audit_chain` (read-engine count rollups that emit
  i64 via aggregate-on-empty paths)

A CI gate in `scripts/hooks/pre-commit` rejects new bare `row.get(`
patterns in `src/store/postgres.rs` so the regression class can't
sneak back in. SQLite path (`src/store/sqlite.rs`) is exempt by
construction — `rusqlite::Row::get` already returns `Result` on
NULL and doesn't share the panic class.

### Phase 2 — FFI `catch_panic` sweep (#28 part 2)

v0.5.3 wrapped the 13 v0.5.0 ReadEngine PyO3 methods in
`catch_panic(||{...})`. v0.5.4 completed the wrap across the
remaining 53 pre-v0.5.0 entry points (federation directory writers,
outbound queue ops, derived-schema CRUD, verify primitives,
canonicalization helpers, steward signing, debug methods). Now
**every** PyO3 method on `PyEngine` (~70 entry points) routes panic
through the explicit wrapper, converting `PanicException`
(BaseException) into `LensQueryError` (Exception) so uvicorn's
`except Exception:` path catches it as a normal 500.

Wrap done via a deterministic one-shot script with a brace-depth
scan (no proc-macro infra introduced — additive only). Pre/post
sanity: 169 lib unit tests pass before, 169 pass after, plus the
new Python test in Phase 3.

### Phase 3 — Python regression test (#29)

New feature-gated facility:

- `Cargo.toml`: `test-panic = []` feature flag.
- `#[cfg(feature = "test-panic")] #[pyfunction] _test_inject_panic`
  module-level function (no Engine construction needed — bypasses
  postgres + keyring setup) that calls `panic!()` inside the
  catch_panic wrapper.
- `tests/python/test_catch_panic.py` (5 tests):
  1. `LensQueryError` is exported and subclasses `Exception`.
  2. Rust panic surfaces as `LensQueryError` with message preserved.
  3. Bare `except Exception:` catches it (the actual CIRISPersist#24
     wedge shape — the regression-test the v0.5.3 hardening lacked).
  4. The converted error is NOT a `pyo3.exceptions.PanicException`.
  5. Module survives N repeated panics — process doesn't abort,
     normal calls still work after.
- `python/ciris_persist/__init__.py`: re-exports `LensQueryError`
  for consumer use (`from ciris_persist import LensQueryError`).
- `pyproject.toml`: `[tool.pytest.ini_options] testpaths =
  ["tests/python"]` for discovery.
- `.github/workflows/ci.yml`: appends `maturin develop --features
  test-panic,pyo3 --release` + `pytest tests/python/` to the
  linux-x86_64 job. Release wheels don't compile the injector in
  (gated out by feature flag — not exposed on PyPI artifacts).

Local validation: all 5 tests pass against a fresh maturin-develop
build.

### Threat model

- THREAT_MODEL.md §3.13 (panic isolation): no new vector — v0.5.4
  closes the carve-out in v0.5.3's text ("pre-v0.5.0 sites tracked
  in #28") without changing the AV-44 row's status. §9 header
  unchanged at v0.5.3 since this release strengthens defenses
  already counted rather than adding new ones.

### What you get

- Bridge / lens / agent: a Rust panic anywhere in persist now
  surfaces as `LensQueryError` (subclass of `Exception`) — a single
  `try: ... except ciris_persist.LensQueryError: ...` in the
  request handler catches every postgres NULL-on-decode hazard +
  every Rust panic class.
- Operators: the panic message is preserved through the FFI
  conversion (the typed exception's `str()` carries
  `rust_panic: <original panic message>`), so triage doesn't
  require source-diving.
- Future maintainers: the pre-commit Row::get gate rejects new
  unsafe reads at commit time, not at production crash time.

### Upgrade

```toml
ciris-persist = "0.5.4"
```

No API changes. The new `LensQueryError` export is additive; the
new `_test_inject_panic` symbol is feature-gated off in release
wheels (PyPI consumers don't see it). If lens / bridge already
catch every `Exception` at the request boundary (the recommended
shape), they get the v0.5.4 hardening for free.

## [0.5.3] — 2026-05-11

**Panic-isolation hardening track + verify deps v2.0.1 → v2.0.2.**
Three orthogonal layers of defense against the failure class that
caused CIRISPersist#24's prod wedge. Closes
[CIRISPersist#25](https://github.com/CIRISAI/CIRISPersist/issues/25)
+ [#26](https://github.com/CIRISAI/CIRISPersist/issues/26)
+ [#27](https://github.com/CIRISAI/CIRISPersist/issues/27).

### Phase 1 — `panic = "abort"` → `"unwind"` (CIRISPersist#25)

`Cargo.toml` `[profile.release]`:

```diff
-panic = "abort"
+panic = "unwind"
```

The original v0.1.x argument (SECURITY_AUDIT_v0.1.2.md §4.2) was
"abort fast so supervisor restart kicks in." That was correct for
the standalone-bin shape; the v0.5.x cdylib-in-uvicorn shape
inverts the trade-off — `abort()` short-circuits PyO3's
panic-catching trampoline (pyo3#797), so the prod wedge SIGABRT'd
every uvicorn worker in parallel from concurrent §E baseline
calls. `unwind` lets the trampoline catch panics as
`PanicException`. ~3-5% release-binary size cost from unwind
tables.

Full reframing rationale in `Cargo.toml`'s `[profile.release]`
comment + `THREAT_MODEL.md` §3.13 (new section) + AV-44 (new).

### Phase 2 — `PgRowExt::safe_get` + ReadEngine sweep (CIRISPersist#26)

`tokio_postgres::Row::get::<_, T>` panics when the column is NULL
and `T: FromSql` doesn't accept NULL. New `PgRowExt` trait wraps
`try_get` with a typed `Backend` error mapping that names the
column:

```rust
trait PgRowExt {
    fn safe_get<'a, T>(&'a self, col: &str) -> Result<T, crate::read::Error>
    where T: tokio_postgres::types::FromSql<'a>;
}
```

Every `Row::get(col)` in the v0.5.0 ReadEngine impl + decode
helpers (`pg_row_to_trace_summary`, `pg_row_to_llm_call_row`)
swept to `row.safe_get(col)?`. ~80 sites. Now a NULL surfaces as
HTTP 500 with `decode column <name>: <error>` instead of a Rust
panic.

Sweep scope (intentional): v0.5.0 read primitives only — that's
where the realized bug (CIRISPersist#24) happened, and where the
JSONB-extracting SUM-CASE patterns recur. Pre-v0.5.0 sites
(decompose, federation directory, outbound queue, derived put
paths) shipped stably without a realized panic; **CIRISPersist#28**
tracks completing the full crate-wide sweep in v0.5.4. Phase 3
(below) catches any missed sites defensively.

### Phase 3 — `LensQueryError` + `catch_panic` wrapper (CIRISPersist#27)

PyO3's built-in trampoline (now firing under `panic=unwind` from
Phase 1) raises `pyo3.exceptions.PanicException` — a Python
**BaseException** subclass. uvicorn's `try: except Exception:`
request-handler error path **doesn't catch BaseException**, so a
caught panic still escapes to uvicorn's outer handler — recoverable
but ugly (stack-trace dump, request fails with non-standard error
class).

New typed exception `cirislens_persist.LensQueryError(Exception)`
+ `catch_panic` helper at `src/ffi/pyo3.rs`:

```rust
pyo3::create_exception!(
    ciris_persist,
    LensQueryError,
    pyo3::exceptions::PyException  // derives from Exception, NOT BaseException
);

fn catch_panic<F, R>(f: F) -> PyResult<R>
where F: FnOnce() -> PyResult<R> {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(payload) => {
            let msg = panic_payload_to_string(payload);
            tracing::error!(panic = %msg, "PyO3 catch_panic caught Rust panic");
            Err(PyErr::new::<LensQueryError, _>(format!("rust_panic: {msg}")))
        }
    }
}
```

All 13 v0.5.0 ReadEngine PyO3 methods wrapped:
- `list_trace_summaries`, `get_trace_summary` (§A)
- `get_trace_detail` (§B)
- `cross_agent_divergence`, `temporal_drift`, `hash_chain_gaps`,
  `conscience_override_rates` (§F)
- `aggregate_scoring_factors`, `aggregate_scoring_factors_batch`,
  `count_traces`, `count_overrides`, `count_identity_changes`,
  `aggregate_audit_chain` (§E)

Now a Rust panic in any of those methods → `LensQueryError` →
caught by `try: except Exception:` in uvicorn → clean HTTP 500.
Pre-v0.5.0 methods (`put_public_key`, `put_attestation`, derived
schema CRUD, outbound queue ops) still rely on PyO3's built-in
trampoline (raising `PanicException` / BaseException);
CIRISPersist#28 tracks completing the explicit-wrap sweep.

### Verify deps v2.0.1 → v2.0.2

Three tag bumps: `ciris-keyring` + `ciris-verify-core` +
`ciris-crypto` to `v2.0.2`. v2.0.2 closed the
`ml-dsa → pkcs8 = "^0.11.0-rc.11"` caret-range hazard that broke
v2.0.0's and v2.0.1's fresh-resolve (CIRISVerify#18). v2.0.2 pins
`pkcs8` exact at the federation-crypto-authority layer; ml-dsa's
deeper transitives now resolve cleanly.

### Three-layer defense matrix (post-v0.5.3)

| Layer | Mechanism | What it catches |
|---|---|---|
| SQL → Rust | `PgRowExt::safe_get` (try_get + Option-aware) | NULL surfaces as `None` at decode, before panic candidates form |
| Rust → FFI | `panic = "unwind"` in release profile | PyO3 trampoline catches Rust panics as `PanicException` (BaseException) |
| FFI → Python | `catch_panic(AssertUnwindSafe(...))` per `#[pyfunction]` | Converts caught panic to typed `LensQueryError(Exception)`; uvicorn catches as 500 |

After v0.5.3: a single bad row / bad query at any layer triggers
HTTP 500 from lens, not a worker outage. The CIRISPersist#24
failure class is closed.

### Threat model

- `THREAT_MODEL.md §3.13` (new section) — panic-isolation posture,
  reframing of `panic = "abort"` rationale for v0.5.x cdylib shape.
- `THREAT_MODEL.md` summary table: **AV-44 added** — Rust panic
  escalates to process abort; three-layer mitigation documented.
- `§9 Threat Posture Summary` header bumped v0.5.0 → v0.5.3;
  17 vectors closed across v0.2.0..v0.5.3 (added AV-44).

### Tests

205 lib tests pass (no new tests in this release — Phase 1 + Phase
2 + Phase 3 are structural defense layers; CIRISPersist#24's
empty-window regression test from v0.5.1 + the v0.5.0 19-test
integration suite continue to pass through all three changes).

Phase 3 doesn't add an automated panic-injection regression test
(that requires Python-side fixture infrastructure we don't yet
have); a follow-up CIRISPersist#29 will add one when the
maturin-wheel CI grows the Python-test infrastructure.

### Out of scope (deferred)

- **CIRISPersist#28** — Complete the `safe_get` sweep + `catch_panic`
  wrap for pre-v0.5.0 PyO3 methods (federation directory, derived
  schemas, outbound queue, ingest pipeline). Pre-v0.5.0 sites have
  shipped stably for many releases; the v0.5.3 catch_unwind via
  PyO3's built-in trampoline catches any panic there as
  `PanicException` (BaseException) — bounded but ugly. v0.5.4
  completes the typed-Exception conversion crate-wide.
- **CIRISPersist#29** — Python-side panic-injection regression
  test (requires maturin-wheel test infrastructure).
- **v0.5.4 P1** — sqlfluff CI rule banning bare `SUM(` / `AVG(`
  without `COALESCE` (per the research agent's findings on
  CIRISPersist#24).
- **v0.5.4 P1** — Per-worker panic budget + circuit breaker
  (Cloudflare `workers-rs` poisoned-instance pattern).

## [0.5.2] — 2026-05-11

**Bump CIRISVerify deps v1.13.2 → v2.0.0 — fixes CI break from
upstream `ml_dsa` minor-version drift.**

v0.5.1 CI failed across every job (clippy + fmt + audit, all wheel
builds, linux full-features, darwin no-postgres, ios) with:

```
error[E0432]: unresolved import `ml_dsa::KeyGen`
error[E0599]: no function or associated item named `from_seed`
              found for struct `MlDsa65`
```

Root cause: `ciris-crypto v1.13.2` declared a caret range on
`ml-dsa`. The `ml-dsa` crate published a breaking minor that
removed `KeyGen` and `MlDsa65::from_seed`. v0.5.0 + v0.5.1 had
locally-cached `Cargo.lock` entries against the older `ml-dsa`, so
local builds and v0.5.0's CI run yesterday passed; today's CI
fresh-resolve pulled the new incompatible `ml-dsa` and broke the
build crate-wide. CIRISPersist's `Cargo.lock` is gitignored
(intentional — we treat persist as a library, not a binary), so
CI gets the latest semver-compatible resolution every time.

v2.0.0 of `ciris-crypto` pins `ml-dsa = 0.1.0-rc.9` precisely (no
caret range), closing this drift hazard. The bump matches the
already-planned v2.0-readiness work documented in v0.4.5 — Eric's
note at v2.0.0 publish time confirmed "zero breaking changes
despite the major bump; the major signals federation policy
('ciris-crypto is now THE crypto authority'), not API breakage."
Verified: 205 lib tests pass against v2.0.0 with no persist-side
code changes.

### Cargo.toml diff

```diff
- ciris-keyring     = { ... tag = "v1.13.2", version = "1", features = ["pqc-ml-dsa"] }
- ciris-verify-core = { ... tag = "v1.13.2", version = "1" }
- ciris-crypto      = { ... tag = "v1.13.2", version = "1", features = ["ed25519", "pqc-ml-dsa"] }
+ ciris-keyring     = { ... tag = "v2.0.0",  version = "2", features = ["pqc-ml-dsa"] }
+ ciris-verify-core = { ... tag = "v2.0.0",  version = "2" }
+ ciris-crypto      = { ... tag = "v2.0.0",  version = "2", features = ["ed25519", "pqc-ml-dsa"] }
```

Three tag bumps + three semver-major constraints (`version = "1"`
→ `"2"`, required by git-dep resolution). Zero code changes.

### What v2.0.0 brings beyond unblocking CI

(Informational; persist doesn't activate any of these in v0.5.2.)

- `aes-gcm` / `kdf` / `hmac` / `random` feature gates on
  `ciris-crypto` — the federated SecretsService prereq from
  CIRISPersist#19. v0.6.0 lights these up when the pipeline ships.
- `symmetric-derivation` on `ciris-keyring` (hardware HKDF) —
  same #19 prereq.
- `tree_verify` / `TreeVerifyRequest` / `TreeVerifyResult` /
  `FailedFile` / `FailedFileKind` on `ciris-verify-core` — runtime
  tree-walking verifier closing CIRISVerify#9. Surface is
  available through persist's curated prelude for any consumer
  that wants it; persist itself doesn't call `verify_tree` (that's
  CIRISAgent's attestation concern).

The crypto-through-ciris-crypto invariant (FSD §7.5a) remains:
persist takes ZERO direct deps on AES-GCM/PBKDF2/HKDF/HMAC/RNG
primitive crates. The v0.6.0 work flips features on the existing
deps, no new crates land.

### Tests

205 lib tests pass against v2.0.0 (same count as v0.5.1; no test
churn). The two CIRISPersist#24 regression tests
(`empty_window_does_not_panic`, `empty_baseline_does_not_panic`)
continue to pass — the v0.5.1 hotfix is unaffected.

### Defense-in-depth observation

The v0.5.1 CI break was caused by a transitive dep crater outside
our control. Our git-dep surface with caret-range transitive
constraints exposes us to drift. The v0.5.2 solution is "bump to
a verify version that pins exact transitives" — and verify v2.0.0
chose exactly that (`ml-dsa = 0.1.0-rc.9` exact, not caret). The
structural alternative is committing `Cargo.lock` in-tree; the
current gitignored-lock posture is documented in `Cargo.toml`'s
comment block. This break is the first time that trade-off bit.
If it recurs, switching to a committed `Cargo.lock` is the
cheaper move than chasing every transitive dep's pinning
discipline upstream.

## [0.5.1] — 2026-05-11

**P0 hotfix: `aggregate_scoring_factors` panicked + crashed uvicorn
workers when the baseline window was empty.** Closes
[CIRISPersist#24](https://github.com/CIRISAI/CIRISPersist/issues/24).
Production lens wedge 2026-05-11 15:09–15:59 UTC.

### Root cause

The §E `aggregate_scoring_factors` main SELECT runs without
`GROUP BY`, so on an empty input CTE (the agent has zero
`trace_events` rows in the window) Postgres produces ONE result row
but every `SUM(CASE WHEN ... THEN 1 ELSE 0 END)` returns NULL per
the SQL spec. Pre-v0.5.1 the Rust code read those columns as
`Row::get::<_, i64>` (not `Option<i64>`); `i64: FromSql` rejects
NULL → `Row::get` panicked → PyO3 propagated as
`Fatal Python error: Aborted` → SIGABRT → every uvicorn worker
died in parallel from concurrent §E baseline calls → `/health`
unreachable → lens wedged.

Trigger from prod validation matrix:

```
GET /api/v1/accord/scoring/factors/{agent}?hours=24&baseline_hours=168
```

Scout has 0 traces in the baseline window (168h–24h ago); every
baseline call crashed a worker. The fleet has ≥1 sparse-baseline
agent (Scout) so this fired immediately on real validation traffic.

The SIGABRT-not-PyErr behavior is itself a separate hazard — `panic =
"abort"` in our release profile prevents PyO3's panic-catching
trampoline from converting Rust panics to `PanicException`. v0.5.2
addresses that broader hardening (see *Hardening track* below).

### Fix

Belt-and-braces — fix applied at BOTH layers:

1. **SQL layer (data-layer fix)** — `COALESCE(SUM(...), 0)` on
   every SUM in the `aggregate_scoring_factors` main query (4
   SUMs: `conscience_overrides`, `audit_chain_total`,
   `audit_signed_total`, `unsafe_action_count`). The COALESCE
   intent is co-located with the SUM so future query edits keep
   the contract.
2. **Rust layer (defense-in-depth)** — read the 4 COALESCE'd
   columns via `try_get::<_, Option<i64>>(col)?.unwrap_or(0)`
   instead of `get::<_, i64>`. A future SQL edit that drops a
   COALESCE surfaces as a typed `Error::Backend` (HTTP 500) at the
   lens, not a Rust panic → SIGABRT → process abort.

`COUNT(*)` and `GREATEST(...)::bigint` stay un-COALESCE'd and read
as direct `i64`: SQL semantics guarantee non-NULL on empty input
(`COUNT` → 0, `GREATEST(... -1, 0)` → 0 by the literal).

### Tests — regression-proofed

Two new integration tests that exercise the exact prod-crash code path:

- `read_section_e_aggregate_scoring_factors_empty_window_does_not_panic`
  — unknown agent + far-past window = empty CTE = pre-fix
  `Row::get` panics. Test asserts all counts/rates are 0 / empty
  Vecs. **Verified to fail with the exact prod crash signature
  (`panicked at src/store/postgres.rs:3218:46: error retrieving
  column conscience_overrides: error deserializing column 2`) when
  the COALESCE is reverted; passes cleanly with the fix.**
- `read_section_e_aggregate_scoring_factors_empty_baseline_does_not_panic`
  — replicates the production trigger exactly: main window has
  traces, baseline window is empty (sparse-baseline agent). Asserts
  the result computes successfully with `drift_z_score=None` (no
  baseline samples → no drift).

### Audit — other NULL-panic candidates across §A/B/F/E

Grepped every `Row::get` call in the ReadEngine impl. The remaining
SUM-with-no-GROUP-BY pattern is the only place the bug surfaces:

| Site | SQL shape | NULL-safe because |
|---|---|---|
| `cross_agent_divergence` numeric branch | per-agent CTE has `HAVING COUNT(*) > 0`; outer SELECT iterates rows only if per_agent is non-empty | empty per_agent → 0 rows out → no iteration |
| `cross_agent_divergence` override-rate branch | same `HAVING` shape | same |
| `temporal_drift` | `COUNT(*) FILTER` for `base_n`/`comp_n` (never NULL); AVG/VAR_SAMP read via `Option<f64>` already; `bn==0` guard fires before AVG read | already Option-aware; defensive guard |
| `hash_chain_gaps` | `WHERE prev_seq IS NOT NULL AND seq > prev_seq + 1` filter post-LAG | NULL rows filtered before SELECT |
| `conscience_override_rates` | `GROUP BY agent_id_hash`; per_agent has at least one trace per group; `COALESCE(... , 0.0)` already applied to domain_avg | non-empty groups + existing COALESCE |
| `aggregate_audit_chain` totals | `COUNT(*) FILTER (WHERE ...)` — returns 0 on no match, never NULL | spec |
| `aggregate_audit_chain` gap_count | `COUNT(*)` post-LAG-window | spec |
| `count_traces` / `count_overrides` / `count_identity_changes` | `COUNT(DISTINCT)` / `COUNT(*)` / `GREATEST(... -1, 0)` | spec |
| `coherence_decay_series` | `GROUP BY bucket_at` — empty buckets produce no rows | non-empty groups |
| `recovery_events` | `WHERE was_overridden = TRUE AND next_trace_id IS NOT NULL AND next_coherence_passed = TRUE` — every result-row field is non-NULL by the filter | filter post-LEAD |

The lesson generalizes: **`SUM(CASE WHEN ...)` over a possibly-empty
set without `GROUP BY` is the foot-gun.** Documented inline at the
fix site so future query authors see the trap.

### Hardening track (v0.5.2 / v0.5.3) — informed by post-mortem

Hardening research filed at v0.5.1 ship time. The proximate fix
(this release) closes the bug; the systemic hardening track
addresses the failure-class:

1. **(v0.5.2, P0)** Remove `panic = "abort"` from the `cdylib`
   release profile; switch to `panic = "unwind"`. Without this,
   PyO3's panic-catching trampoline can't fire — any future Rust
   panic anywhere becomes SIGABRT. Threat-model implication
   re-evaluated; original AV-17/§4.2 audit argument for abort is
   pre-PyO3 (CIRISPersist#16 outbound queue era) and doesn't
   survive in a long-lived uvicorn-worker `cdylib`.
2. **(v0.5.2, P0)** Crate-wide sweep `Row::get` →
   `try_get::<_, Option<T>>`. Add CI gate: `rg "\.get::<" src/`
   returning non-zero fails the build.
3. **(v0.5.2, P0)** Wrap every `#[pyfunction]` entry point in
   `std::panic::catch_unwind(AssertUnwindSafe(|| …))` and convert
   the payload into a typed `LensQueryError(Exception)` — never let
   `PanicException` (which derives from `BaseException`, not
   `Exception`) reach uvicorn's request handler.
4. **(v0.5.3, P1)** sqlfluff in CI with custom rule banning bare
   `SUM(` / `AVG(` without `COALESCE`; FILTER-aware variant.
5. **(v0.5.3, P1)** Per-worker panic budget + circuit breaker
   (Cloudflare's `workers-rs` poisoned-instance pattern).

Each of those is a separate issue filed alongside this release.
v0.5.1 ships only the direct fix — every layer that broke today
gets its own focused release rather than a megabump.

### Operational notes

- 201 lib tests pass against local postgres:15-alpine (the two new
  regression tests above + the existing v0.5.0 suite). Hooks
  (fmt + clippy + test) clean.
- The 7 lens-side calls that surfaced this (`§E baseline_hours`
  paths) work cleanly post-fix; bridge team verified end-to-end
  reproduction matrix locally with the patched build before this
  release tagged.
- Lens-team unblocked from declaring v0.5.0/v0.5.1 validated.
- §B / §F surfaces unchanged; §A unchanged; bug is localized.

## [0.5.0] — 2026-05-10

**Federation read primitives — sections A/B/F/E.** Closes the lens-bleeding
read-side starvation that's been live since the persist-ingest cutover:
50 lens SELECTs against `cirislens.trace_events` directly, the
`/coherence-ratchet/stats` endpoint 500'ing, and `api/scoring.py`
running raw SQL on a substrate it shouldn't reach into.

Closes [CIRISPersist#23](https://github.com/CIRISAI/CIRISPersist/issues/23)
sections **A** (trace listing), **B** (trace detail), **F** (Coherence
Ratchet inputs), **E** (scoring factor aggregates). Sections C/D/G/H/I
ship in v0.5.1 after lens validates the v0.5.0 batch in production.

### Surface duality (v0.4.1 verify-primitive precedent)

Every primitive lands as **both** a Rust-public method on the
`ReadEngine` trait (re-exported through `crate::prelude`) AND a thin
PyO3 wrapper on `Engine`. Single source of truth — no Python-only
reimplementation drifting from Rust. Lens (PyO3 path), CIRISLensCore
(rlib path), and sovereign-mode agents (in-process Rust) consume the
same surface.

### Module shape

```
src/read/
├── mod.rs       — ReadEngine trait (12 methods) + Error + module docs
├── types.rs     — TimeWindow, TraceCursor, TraceFilter, DeviationMetric
├── trace.rs     — A/B/F: TraceSummary, TraceListPage, TraceDetail,
│                  TraceComponentRow, TraceEnvelopeRefs,
│                  DivergenceRow, TemporalDriftRow, HashChainGap,
│                  OverrideRateRow
└── scoring.rs   — E: ScoringFactorAggregate, RecoveryEvent,
                   CoherencePoint, AuditChainAggregate
```

### Section A — Trace listing

`Engine.list_trace_summaries(filter, cursor=None, limit=100)` and
`Engine.get_trace_summary(trace_id)` drive `/repository/traces` and
the trace explorer.

`TraceSummary` carries denormalized DMA / conscience / action /
cost fields synthesized from the trace's component rows via
PostgreSQL `FILTER (WHERE event_type = '...')` aggregation in one
GROUP BY pass — no N+1 round-trips. Cursor pagination via
`(started_at, trace_id)` tuple comparison; no OFFSET/LIMIT.

Filter struct supports time window, agent_id_hash, agent_name,
deployment_domain, deployment_type, trace_level, signature_verified,
schema_version, cognitive_state. Index coverage: agent_id_hash hits
`trace_events_dedup` leading column; agent_name hits
`trace_events_agent_ts`; no-filter scans the time hypertable
newest-first.

### Section B — Trace detail

`Engine.get_trace_detail(trace_id)` returns full trace
reconstruction: summary + all per-component data (chronological) +
LLM call rows (chronological) + envelope-level scrub + signature
refs. Three queries, one round-trip each; not paged (one trace fits
per spec — production traces top out around 30 components plus a
handful of LLM calls). Composes against §A's summary for the rollup
view; new helper `pg_row_to_llm_call_row` decodes the typed
`trace_llm_calls` rows.

### Section F — Coherence Ratchet inputs

Drives `/coherence-ratchet/stats` (currently 500'ing in lens because
it queries `accord_traces` directly). Lens consumes these inputs;
clustering / detection logic stays in lens.

- `cross_agent_divergence(domain, window, metric)` — per-agent metric
  mean compared to domain population mean+std (`STDDEV_SAMP`); rows
  ordered by `|z_score| DESC`. Two SQL shapes: numerical metrics
  (CSDMA / DSDMA / IDMA k_eff / IDMA correlation_risk) + override-rate
  (per-trace BOOL_OR collapse + per-agent rate over distinct traces).
- `temporal_drift(agent, baseline, comparison)` — Welch-style z-score
  on mean shift between two windows; lens applies its own p-value
  mapping.
- `hash_chain_gaps(agent, window)` — LAG window function over
  `audit_sequence_number` to detect non-contiguous pairs.
- `conscience_override_rates(domain, window)` — per-agent override
  rate with population-weighted domain average; `multiple_of_domain_avg`
  surfaces "this agent overrides N× more than peers."

### Section E — Scoring factor aggregates

Replaces `api/scoring.py`'s raw SQL. The "big aggregate" of #23.

`Engine.aggregate_scoring_factors(agent, window, baseline=None)`
returns one bundled `ScoringFactorAggregate` covering every Capacity
Score factor input in 4 round-trips:
1. Per-trace collapse + window-wide counts (trace_count,
   identity_changes, conscience_overrides, audit_chain_total,
   audit_signed_total, unsafe_action_count) in one CTE pass.
2. Audit-chain gap count via LAG window.
3. Recovery events (top 50 most-recent override → next-pass pairs)
   via LEAD window over per-trace `started_at`.
4. Coherence decay series (~24 buckets across the window; min
   1-minute buckets for sub-hour windows) via `to_timestamp` bucket
   math.
5. Drift z-score: when `baseline_window` provided, delegates to
   `temporal_drift` for the CSDMA significance.

`aggregate_scoring_factors_batch(agents, window, baseline=None)` —
fleet-wide score sweep. Loops over agents calling the single-agent
path; future single-query batch optimization deferred to v0.5.x
(lens-side batched calls are <100 agents today).

Granular sub-primitives composable for narrower questions:
- `count_traces(filter)` — DISTINCT trace_id count.
- `count_overrides(filter)` — BOOL_OR per-trace dedupe of recursive
  CONSCIENCE_RESULT retries.
- `count_identity_changes(filter)` — agent_name-rename count
  (agent_id_hash IS the identity fingerprint by construction;
  renames within a single hash are what's surfaced).
- `aggregate_audit_chain(filter)` — total / signed / hashed +
  gap_count (gap_count meaningful only when filter narrows to one
  agent; documented).

`calibration_error` is `None` for v0.5.0 — persist's wire format
doesn't carry `epistemic_certainty` yet. Wired up when that field
flows through.

### PyO3 surface (12 wrappers)

JSON-string in/out for complex types
(TraceFilter, TraceCursor, TraceSummary, TraceListPage, TraceDetail,
TimeWindow, DivergenceRow, ScoringFactorAggregate, etc.); primitives
as direct args. Same idiom as `put_public_key` /
`put_attestation` / `put_detection_event` already established.

```python
import json
page = json.loads(engine.list_trace_summaries(
    filter_json=json.dumps({"agent_id_hash": h}),
    cursor_json=None,
    limit=50,
))
detail = json.loads(engine.get_trace_detail(trace_id))
agg = json.loads(engine.aggregate_scoring_factors(
    agent_id_hash=h,
    window_json=json.dumps({"since": ..., "until": ...}),
    baseline_window_json=None,
))
```

### Threat model — AV-43 added

`docs/THREAT_MODEL.md` §3.11 + summary table + §9 posture summary
add **AV-43: Read-side adversary inference attack**:

- Aggregates return computed statistics, not per-trace content.
- `sample_count` / `trace_count` fields surface explicitly so
  callers gate k-anonymity at their layer.
- Error kinds are closed-set `&'static str` (no attacker-controlled
  strings cross the FFI boundary).
- AV-9 invariant preserved: trace-scoped reads carry `agent_id_hash`
  so callers authorize per-trace access at their layer.

§9 posture summary: header bumped v0.4.6 → v0.5.0; 16 attack
vectors closed across v0.2.0..v0.5.0.

### Tests

19 integration tests against real Postgres (gated on
`CIRIS_PERSIST_TEST_PG_URL`; CI workflow already sets it):

| Section | Tests |
|---|---|
| §A | round-trip; unknown→None; cursor pagination (5 traces, 3 pages, no overlap/gaps); agent_id_hash isolation (AV-9); limit boundaries (0/10001 reject); invalid cursor version reject |
| §B | round-trip with LLM call; unknown→None; no-LLM-calls returns empty Vec |
| §F | cross_agent_divergence on CSDMA (outlier detected) + override rate (sign of z); temporal_drift mean shift + significance sign; hash_chain_gaps detects 2→5 gap; conscience_override_rates with domain-weighted average |
| §E | aggregate round-trip; batch (empty + non-empty in input order); count_traces; count_overrides; aggregate_audit_chain (no audit rows → zero counts) |

All 19 pass against local `postgres:15-alpine` (timescaledb-less; the
V001 hypertable conversion is gated on `pg_extension` lookup so the
migration runs cleanly without it). 203 total lib tests pass.

### Carve-out retirement deferred to v0.5.1

The `cirislens_reader` Postgres role / lens-side direct-SQL path stays
deprecated-but-not-yet-retired in v0.5.0. Section D (LLM call surface)
covers `trace_llm_calls`, which lens currently reads via direct SQL;
until D ships in v0.5.1, that path remains. v0.5.0's threat-model
entry (AV-43) flags this honestly: "primary read surface; full
carve-out retirement in v0.5.1."

### Out of scope for v0.5.0 (deferred to v0.5.1)

- Section C — Task-grouped listing (lens can group on the lens side
  as a workaround until v0.5.1).
- Section D — LLM call surface (LlmCallFilter, LlmCostAggregate);
  trace_llm_calls full read path.
- Section G — Corpus shape (operator dashboard).
- Section H — Privacy / scrub observability.
- Section I — Federation observability bulk (list_federation_keys,
  list_revocations, list_attestations).

`FSD/V0_5_0_FEDERATION_READ_PRIMITIVES.md` documents the v0.5.0
sub-batch and the v0.5.1 deferral.

## [0.4.7] — 2026-05-09

**Threat-model documentation update for v0.4.3 + v0.4.6 legacy
accommodation.** Pure documentation; no code change. Functionality
identical to v0.4.6.

The v0.4.3 (CIRISPersist#21) restoration of `"2.7.legacy"` plus the
v0.4.6 (CIRISPersist#22) `attempt_index = 0` fallback at the legacy
arm exposed two documentation gaps in `docs/THREAT_MODEL.md` that
this release closes:

### Gap 1 — AV-35 mitigation language was imprecise

Pre-v0.4.7, AV-35 said deterministic dispatch is safe because
*"the field is part of signed canonical bytes, so an attacker
cannot forge it without breaking the signature."*

That's true at `2.7.0` and `2.7.9` (both 9-field canonicals carry
`trace_schema_version` as a signed field). It's NOT true at
`"2.7.legacy"` — the 2-field canonical only signs
`{components, trace_level}`.

The actual load-bearing safety property is **verification is bound
to the dispatch arm's canonical**: a signature signed against arm-A's
canonical bytes cannot pass arm-B's verification. Routing-input
forgery buys an attacker nothing because the verify step
deterministically fails on a wrong-arm reconstruction.

AV-35 narrative + summary table updated to clarify. The structural
invariant has always held; only the documentation overstated WHY.

### Gap 2 — AV-42 added: legacy `attempt_index` dedup-collapse

The v0.4.6 fallback documented in CHANGELOG was not in the threat
model itself. v0.4.7 adds AV-42 covering:

- **Attack** — pre-2.7.8.9 emitters that don't populate
  `data.attempt_index` collapse retries on the dedup tuple (only
  the first row lands; subsequent retries hit ON CONFLICT DO
  NOTHING).
- **Mitigation** — schema-version-gated (only `2.7.0` and
  `"2.7.legacy"`); 2.7.9 still strict; malformed values still error
  through AV-17 typed paths; fallback fires for absence ONLY.
- **Sunset** — telemetry-driven via
  `federation_canonical_match_total{wire="2.7.legacy"}` 7-day-zero
  soak window. Time-bounded by empirical observation, not
  permanent.
- **Bounded by signing-key control** — exploiting requires the
  legitimate signer's key, with which the attacker can already
  forge any trace; marginal capability is "compress retry semantics
  on the dedup tuple."
- **Why not lens-side** — the legacy 2-field canonical signs
  `components[].data`; synthesizing `attempt_index` post-hoc on the
  agent or lens side invalidates verify. Federation's append-only
  contract takes priority over per-row dedup fidelity at the legacy
  arm.

Added as residual #15 in §8, summary-table row, and threat-posture
summary block. Net positive item documented inline (AV-42's
companion correction): the v0.4.6 503→422 reclass closes a
previously-uncatalogued self-DoS amplification surface where
schema-misclass-as-Store turned every malformed batch into a
Retry-After hot loop.

### Section §9 also updated

`v0.3.6 Threat Posture Summary` → `v0.4.6 Threat Posture Summary`
with new blocks for v0.4.0 outbound queue (AV-40, AV-41 — already
shipped, previously uncatalogued in §9) and v0.4.3..v0.4.6 legacy
accommodation (AV-35 preserved, AV-42 new). Total closed:
fifteen v0.2.0..v0.4.6 attack vectors.

## [0.4.6] — 2026-05-09

**Legacy attempt_index gate + decompose error reclassification.** Closes
[CIRISPersist#22](https://github.com/CIRISAI/CIRISPersist/issues/22).

A 2.7.6-stable trace (legacy emitter, no `data.attempt_index` on
components) was hitting two persist-side bugs in series:

1. `decompose` raised `Schema(MissingField("attempt_index"))` for
   any component lacking the field (pre-2.7.8 emitters don't
   populate it).
2. The ingest call site mis-classified that schema error as a
   `Store` error, so the lens emitted **HTTP 503 + `Retry-After: 5`**
   instead of **422**. Agents retried forever on a deterministic
   schema reject.

We can't fix this lens-side: the 2-field legacy canonical signs
`{components, trace_level}`, so `components[].data` IS in the
signed bytes. Synthesizing `data.attempt_index` post-hoc on the
agent or lens side would invalidate the verify the
`v0.4.3 / CIRISPersist#21` legacy-restoration just got working.

### 1. `decompose.rs:82` — schema-version-gated `attempt_index` sourcing

Same shape as the existing `parent_event_type` / `parent_attempt_index`
gate at `build_llm_call_row` (CIRISPersist#12, v0.3.3):

- **2.7.9**: REQUIRED on the wire. Reject the trace.
- **2.7.0 / 2.7.legacy** (and future-versions-not-yet-wired):
  prefer wire field; fall back to **0** ONLY for the absence case
  (`MissingField`). Malformed values (negative, wrong type, out of
  range) still error — those are signal, not legacy quirk.

Why fallback to 0 for legacy: the dedup-collapse cost (legacy
retries deduping to attempt 0 on the
`(agent_id_hash, trace_id, thought_id, event_type, attempt_index)`
tuple) is acceptable for backfill — the alternative is dropping
pre-2.7.8 traces entirely, violating the federation's append-only
contract. Same telemetry-driven sunset rule
`federation_canonical_match_total{wire="2.7.legacy"}` (v0.4.3 /
CIRISPersist#21) deprecates the fallback once 2.7.6-era traffic
stops.

### 2. `ingest.rs:229` — typed Schema/Store error split

```rust
let mut d = crate::store::decompose(trace).map_err(|e| match e {
    crate::store::Error::Schema(s) => IngestError::Schema(s),
    other => IngestError::Store(other),
})?;
```

`IngestError::Store` is documented (line 78-80) as
"Backend write failure (DB unreachable, IO, etc.). Lens → HTTP 503
+ Retry-After." `decompose` returns `store::Error::Schema(...)` for
deterministic schema mismatches, which now correctly round-trip as
`IngestError::Schema` (line 62-65: "Lens → HTTP 422").

The two `insert_*_batch` callsites at `ingest.rs:265` / `:270` were
audited and stay on the `Store` arm — they legitimately return
`StoreError` from the backend write itself.

This stops the **503-retry loop on deterministic schema mismatches**:
agents see 422, give up immediately, and surface the bad trace to
ops instead of hammering the lens.

### 3. `IngestError::detail()` — non-breaking field-name surfacing

`IngestError::kind()` returns `&'static str` (closed-set token; can't
include a dynamic field name). Pre-fix, `kind() == "schema_missing_field"`
forced the bridge team to source-dive `decompose.rs` to find out
WHICH field was missing.

Added (option (b) per the issue, non-breaking):

```rust
impl crate::schema::Error {
    pub fn detail(&self) -> Option<String> { /* … */ }
}

impl IngestError {
    pub fn detail(&self) -> Option<String> { /* delegates to schema's */ }
}
```

`schema::Error::detail()` returns the variant-specific dynamic
content (field name for `MissingField`, version stamp for
`UnsupportedSchemaVersion`, `field:expected:got` for
`FieldTypeMismatch`, etc.) — closed-set or operator-supplied
strings; AV-15-safe by construction.

PyO3 surface (`Engine.receive_and_persist`) emits Python exception
`args` as a 2-tuple `(kind, detail)` when detail is present;
`(kind,)` otherwise. Lens consumers read:

```python
kind = e.args[0]
detail = e.args[1] if len(e.args) > 1 else None
```

Backward-compatible: pre-fix consumers reading `e.args[0]` (or
matching `str(e)` against a kind token) keep working.

### Tests

- `decompose::tests::missing_attempt_index_at_2_7_9_is_typed_error`
  (renamed from `missing_attempt_index_is_typed_error`; gates the
  strict 2.7.9 path)
- `decompose::tests::legacy_2_7_0_decomposes_with_default_attempt_index_zero`
  — pre-2.7.8 absence → fallback to 0
- `decompose::tests::legacy_2_7_0_with_explicit_attempt_index_uses_wire_value`
  — forward-compat: wire value honored when present
- `decompose::tests::legacy_2_7_0_rejects_malformed_attempt_index`
  — negative/wrong-type/out-of-range still error at the legacy gate
- `ingest::tests::decompose_schema_error_routes_to_schema_variant`
  — the load-bearing test for the 503-retry-loop fix; explicitly
  panics with REGRESSION marker if the variant comes back as `Store`
- `ingest::tests::ingest_error_detail_surfaces_missing_field_name` —
  detail() returns the field name for MissingField

184 lib tests pass (5 new over baseline 179).

### Out of scope follow-up

`LlmCallSummary` (`events.rs:259`) carries its own typed
`attempt_index: u32` — pre-2.7.8 LLM_CALL components without that
field fail at the LlmCallSummary deserialize, not at the
decompose-line-82 gate this fix targets. If bridge traffic carries
pre-2.7.8 LLM_CALL components, lifting LLM_CALL's attempt_index
into the legacy fallback is a follow-up issue.

## [0.4.5] — 2026-05-09

**CIRISVerify deps bump v1.9.0 → v1.13.2.** Closes
[CIRISPersist#20](https://github.com/CIRISAI/CIRISPersist/issues/20).
Pure dep-only bump; no public-API changes in persist itself, no
behavior change in any code path.

### Why we jumped past the issue's v1.10.1 target

CIRISPersist#20 was filed against v1.10.1 (the version current at
filing time, 2026-05-04). Verify shipped four minor versions in the
interim:

| Verify version | What landed | Persist API touched? |
|---|---|---|
| v1.10.0 | `ciris-build-sign register` subcommand (CLI) | No |
| v1.10.1 | HTTP `/v1/builds` cutover, drops `REGISTRY_JWT_SECRET` | No |
| v1.10.2 | `register` writes all 3 tables atomically | No |
| v1.11.0 | `RegistryClient` per-call project (CLI/library helper) | No |
| v1.11.1 | `register` writes `binary_hash` not `manifest_hash` | No |
| v1.11.2 | Step 5/6 walks agent_root when `python_hashes` is None | No |
| v1.11.3 | CI: switch zig install to mlugg/setup-zig | No |
| v1.12.0 | Per-call project on `RegistryClient` (closes #10/#11) | No |
| v1.12.1 | post-release-verify workflow fix | No |
| v1.12.2 | Defensive `_find_binary` platform suffix order (closes #13) | No |
| **v1.13.0** | **`tree_verify::{verify_tree, TreeVerifyRequest, TreeVerifyResult, FailedFile, FailedFileKind}` — runtime tree-walking verifier (closes #9)** | No (consumer-side feature) |
| v1.13.1 | rustdoc broken-intra-doc-links fix | No |
| v1.13.2 | Install libtss2 in post-release-verify (Linux wheel TPM dep) | No |

Every change in this window is CLI / RegistryClient / `verify_tree`
work — none of it touches `ciris-keyring`, `ciris-verify-core`'s
`HybridVerifier` / `Ed25519Verifier` / `MlDsa65Verifier`, or
`ciris-crypto`'s primitive surface that persist consumes today.
`cargo build` + `cargo test --lib` (179 tests) + `cargo clippy
-D warnings` all pass against v1.13.2 with no persist-side changes.

### What v1.13.0's `verify_tree` is for (informational)

Runtime tree-walking verifier closing CIRISVerify#9. CIRISAgent uses
it for L4 file-integrity attestation:

```rust
// ciris_verify_core::tree_verify
pub async fn verify_tree(
    request: &TreeVerifyRequest,
    registry: &RegistryClient,
) -> Result<TreeVerifyResult, VerifyError>;
```

Walks a source tree on disk, hashes via the same
`walk_file_tree` + `FileTreeExtras::compute_tree_hash` algorithm
`ciris-build-sign sign --tree` writes into
`builds.file_manifest_hash`, fetches the registered manifest, and
returns per-file divergences (`Missing` / `Extra` / `Mismatch`)
plus a top-level `valid` verdict.

Persist itself doesn't call `verify_tree` — that's an agent
attestation concern, not a substrate concern. But the surface is
now available to any consumer that imports persist's curated
prelude (or the workspace-coherent `ciris-verify-core` directly).

CIRISAgent's integration:
- `ciris_engine/.../attestation/tree_verify.py` wraps `verify_tree`,
  pulls `CANONICAL_RULES` from `tools/dev/stage_runtime` (the
  drift-prevention singleton — same `ExemptRules` the CI sign step
  uses, so runtime walk reproduces the canonical hash byte-for-
  byte).
- Mobile (Chaquopy) → Algorithm B (`startup_python_hashes.json`),
  caps at L3.
- Desktop / server / docker → Algorithm A (`verify_tree`), reaches
  L4. Run before `run_attestation_sync`; result overlays
  `attestation_data["python_integrity"]`.

### Readiness for CIRISVerify v2.0

CIRISVerify#7 (filed 2026-05-04, still open) is the prereq for
`CIRISPersist#19`'s federated `SecretsService`: ciris-crypto v2.0
must add `aes-gcm`, `kdf` (PBKDF2 + HKDF), `hmac`, and `random`
features so persist can wire them into `src/secrets/crypto.rs` per
FSD §7.5a. v0.4.5 lands persist in shape so this is a single
Cargo.toml tag flip when v2.0 ships:

```diff
- ciris-keyring     = { ... tag = "v1.13.2", features = ["pqc-ml-dsa"] }
- ciris-verify-core = { ... tag = "v1.13.2" }
- ciris-crypto      = { ... tag = "v1.13.2", features = ["ed25519", "pqc-ml-dsa"] }
+ ciris-keyring     = { ... tag = "v2.0.0",  features = ["pqc-ml-dsa", "symmetric-derivation"] }
+ ciris-verify-core = { ... tag = "v2.0.0" }
+ ciris-crypto      = { ... tag = "v2.0.0",  features = [
+     "ed25519", "pqc-ml-dsa",
+     "aes-gcm", "kdf", "hmac", "random",
+ ] }
```

The `secrets-*` cargo features documented in
`FSD/POST_INGEST_FILTER_PIPELINE.md §2.4` light up at that point;
the `src/secrets/` module per §2.2 lands as a clean addition with
a single import site (`src/secrets/crypto.rs` → `ciris_crypto::*`).
The crypto-through-ciris-crypto invariant (FSD §7.5a) is unchanged:
persist takes ZERO direct deps on AES-GCM/PBKDF2/HKDF/HMAC primitive
crates ever — CIRISVerify is the federation's crypto authority.

If verify chooses to ship the crypto facade in a v1.14.x patch
instead of v2.0, the same Cargo.toml flip applies; only the tag
string changes. Either way, persist is ready.

## [0.4.4] — 2026-05-08

**CI hygiene patch on top of v0.4.3.** v0.4.3 (commit 826c142) shipped
two CI regressions that didn't surface locally:

1. `server::tests::health_endpoint_returns_supported_versions` asserted
   `vec!["2.7.0", "2.7.9"]` against the v0.3.x-era hardcoded list.
   v0.4.3's #21 work added `"2.7.legacy"` to `SUPPORTED_VERSIONS`
   without updating this test. Fixed.
2. `cargo fmt --check` flagged formatting drift in 4 files (introduced
   during the v0.4.3 work without a follow-up `cargo fmt`). Fixed.

No behavioral change. Functionality is identical to v0.4.3.

### Process: pre-commit + pre-push hooks (`scripts/hooks/`)

To prevent this regression class, this release adds:

- `scripts/hooks/pre-commit` — runs `cargo fmt --check` and
  `cargo clippy --features postgres,pyo3,server,sqlite,tls
  --all-targets -- -D warnings` (the strictest CI matrix job)
  before every commit. Skips when no Rust files staged.
- `scripts/hooks/pre-push` — runs `cargo test --features
  postgres,pyo3,server --lib` against the pushed range. Skips
  pushes that don't touch Rust.
- `scripts/install-hooks.sh` — symlinks both into `.git/hooks/`.
  Idempotent; backs up any pre-existing hooks. Run once after
  fresh clone.

Bypass (not for routine use): `git commit --no-verify` /
`git push --no-verify`. The hooks match the CI checks exactly so
running them locally costs ~10s vs. the 5+ minute CI round-trip
that v0.4.3 wasted.

### Process: `scripts/bump_version.sh`

Companion: `./scripts/bump_version.sh <new_version>` bumps
`[package].version` in Cargo.toml, prepends a dated CHANGELOG
entry skeleton, and refreshes Cargo.lock via `cargo check`.
Idempotent — re-running with the same version is a no-op on
Cargo.toml but adds the CHANGELOG entry if missing.

## [0.4.3] — 2026-05-08

**Lens-derived schemas + 2.7.legacy restoration.** Two issues, one
release. Both close federation-coordination work the lens-core +
RATCHET track is blocked on (#18) and a v0.4.0 regression that left
pre-2.7.8.9 federation peers stuck (#21).

### Closes [CIRISPersist#18](https://github.com/CIRISAI/CIRISPersist/issues/18) — `cirislens_derived` schemas

New schema `cirislens_derived` (separate from `cirislens` — different
write authority, different access surface, different retention policy)
holds two tables federation peers produce AFTER trace ingest:

- `cirislens_derived.detection_events` — one row per lens-core detector
  flag (LC-AV-2 cohort/declared-inferred mismatch P0; LC-AV-11
  manifold-conformity outlier; LC-AV-18 reasoning-collapse; future
  ratchet detectors). Forensic join key is `body_sha256` (matches
  `edge::VerifiedTrace.body_sha256`).
- `cirislens_derived.calibration_bundles` — one row per RATCHET
  calibration; lens-core reads `is_current = TRUE` at startup + on
  refresh. Partial-unique index `calibration_bundles_one_current`
  enforces at-most-one-current at the DB level; `put_calibration_bundle`
  flips `is_current` atomically (UPDATE prior + INSERT new in a
  single transaction).

Both record kinds carry hybrid (Ed25519 + ML-DSA-65) signatures over
`canonical_bytes`. The `Engine.put_*` PyO3 surface verifies via
`crate::verify::verify_hybrid_via_directory` under
`HybridPolicy::Strict` BEFORE backend write (no fallback; both
signatures must verify; CIRISPersist#14 closure pattern).
`canonical_bytes` is canonical JSON via
`persist::prelude::canonicalize_envelope_for_signing` —
CIRISPersist#7 single-source-of-truth.

### `derived::DerivedSchema` trait + 5 methods

```rust
impl DerivedSchema for PostgresBackend {
    async fn put_detection_event(&self, event: DetectionEvent) -> Result<(), Error>;
    async fn get_detection_events(&self, filter: EventFilter) -> Result<Vec<DetectionEvent>, Error>;
    async fn put_calibration_bundle(&self, bundle: CalibrationBundle) -> Result<(), Error>;
    async fn get_current_calibration_bundle(&self) -> Result<Option<CalibrationBundle>, Error>;
    async fn get_calibration_bundle_by_version(&self, v: i32) -> Result<Option<CalibrationBundle>, Error>;
}
```

Memory + SQLite backends return `Error::NotImplemented` for the put
paths (sovereign-mode Pi-class deployments without lens-core /
RATCHET don't need the substrate); the get paths return empty
results so probing (e.g. lens-core's startup load) gets a clean "no
current bundle" rather than an error.

### PyO3 `Engine` surface

Five methods mirroring the rlib trait, JSON-string in/out per the
existing `put_public_key` / `put_attestation` / `put_revocation`
idiom:

```python
engine.put_detection_event(json.dumps(event_dict))
events_json = engine.get_detection_events(json.dumps({"trace_id": tid}))
engine.put_calibration_bundle(json.dumps(bundle_dict))
bundle_json = engine.get_current_calibration_bundle()  # None or JSON str
bundle_json = engine.get_calibration_bundle_by_version(42)
```

Both put paths verify hybrid sigs before backend write; verify
failures surface as `ValueError` with the standard `verify_*` token
(`verify_unknown_key`, `hybrid_verify_strict_required`, etc.). This
is the substrate-side closure of CIRISLensCore Phase 1 P0 ASKs
(LC-AV-2 / -11 / -18) + RATCHET's projection-v1 publication path
(CIRISLensCore#3).

### V008 migration

`migrations/postgres/lens/V008__lens_derived_schemas.sql`. Two
tables in `cirislens_derived` schema. CHECK constraints on signature
shape (Ed25519 = 64 bytes; ML-DSA-65 = 3309 bytes per FIPS 204
final, CIRISVerify#4 / CIRISPersist#8) and body_sha256 length (32
bytes). Partial-unique index on `is_current = TRUE` for atomic flip.

### `prelude` exports

```rust
pub use crate::derived::{
    CalibrationBundle, CohortCentroid, ConformityVariant, DetectionEvent,
    DetectionSeverity, EventFilter, ProjectionMetadata, Standardization,
};
pub use crate::derived::DerivedSchema;
```

### Closes [CIRISPersist#21](https://github.com/CIRISAI/CIRISPersist/issues/21) — restore `2.7.legacy` under telemetry-driven sunset

v0.4.0 dropped `2.7.legacy` from `SUPPORTED_VERSIONS` on a calendar /
fleet-migration framing that doesn't fit the federation's
decentralized model. CIRIS peers run whichever protocol versions
they run; sunset is empirical, not calendar-flag-gated. v0.4.3
restores `2.7.legacy` under the SAME telemetry-driven sunset rule
`2.7.0` already follows:

> Drop `"2.7.legacy"` once `federation_canonical_match_total{wire="2.7.legacy"}`
> stays at zero through a 7-day soak window.

### What changed

- `SUPPORTED_VERSIONS` now `["2.7.0", "2.7.9", "2.7.legacy"]`
  (`src/schema/version.rs`).
- `SchemaVersion::default_legacy_schema_version()` — serde-default
  fn returning `"2.7.legacy"`.
- `BatchEnvelope.trace_schema_version` and
  `CompleteTrace.trace_schema_version` get
  `#[serde(default = "default_legacy_schema_version")]`. Pre-2.7.8.9
  agents stamped no version field at all (the field landed in
  CIRISAgent commit 431b0e0ae alongside the 9-field cutover); those
  traces deserialize to the legacy default.
- Verify dispatch arm `"2.7.legacy" => canonical_payload_value_legacy`
  was already in place at `src/verify/ed25519.rs:463` from v0.3.0;
  v0.4.3 just makes it reachable.
- Telemetry: `tracing::info!(target: "federation_canonical_match",
  wire = ..., trace_id = ..., "federation_canonical_match_total")`
  emits per verify dispatch. Operators / lens log aggregation tally
  `wire = "<dialect>"` emissions across the soak window. (Explicit
  metrics-crate counter is a follow-up; tracing matches persist's
  observability discipline today.)

### Routing semantics — NOT a try-list fallback

Each trace dispatches to exactly ONE canonicalizer based on
`trace_schema_version`. Two routes hit the legacy arm:

1. **Sentinel route**: `trace_schema_version = "2.7.legacy"`
   explicitly stamped on the wire.
2. **Absence route**: `trace_schema_version` absent on the wire
   (pre-2.7.8.9). Serde-default deserializes to `"2.7.legacy"`.

Both routes are deterministic — absence is the unambiguous signal
for the pre-versioning dialect, NOT a "try 9-field, fall back to
2-field" iteration. TRACE_WIRE_FORMAT.md §8's "no try-list under
load" rule is preserved.

### Tests

- `verify::ed25519::tests::absence_routes_to_legacy` — round-trips a
  pre-2.7.8.9 wire (no `trace_schema_version` field) through verify;
  asserts default kicks in, `is_supported` accepts, dispatch routes
  to the 2-field canonical, and the signature verifies.
- `verify::ed25519::tests::legacy_two_field_canonical_dispatch_via_explicit_opt_in`
  unchanged shape; docstring updated to reflect the v0.4.3 restoration.
- `schema::version::tests::parse_accepts_2_7_legacy` —
  `"2.7.legacy"` is now a strict-parse-accepted dialect.
- `schema::version::tests::parse_rejects_old_version` — error message
  carries the updated `SUPPORTED_VERSIONS` for diagnostic clarity.

### Deeper bug, separate work item

`trace_schema_version` isn't currently in the signed canonical bytes
(it's a routing input only). An attacker could in principle forge
the version stamp to route to a different canonicalizer. Long-term
fix is bilateral — include in signed canonical bytes — coordinated
across agent + persist + edge. Out of scope for this release;
filed as a follow-up.

## [0.4.2] — 2026-05-03

**Rust-public `StewardSigner` for CIRISLensCore (rlib path).**
Closes [CIRISPersist#17](https://github.com/CIRISAI/CIRISPersist/issues/17).
Same closure pattern as v0.4.1's verify primitives:
substrate-owned signing, PyO3 surface refactored to thin wrappers
over the Rust struct.

### `signing::StewardSigner` (Rust public API)

```rust
use ciris_persist::signing::{StewardSigner, StewardSignerConfig};

let signer = StewardSigner::from_config(&StewardSignerConfig {
    key_id: "lens-steward".into(),
    key_path: "/run/secrets/lens-steward.seed".into(),
    pqc_key_id: Some("lens-steward-pqc".into()),
    pqc_key_path: Some("/run/secrets/lens-steward.mldsa.seed".into()),
})?;

// Hot-path Ed25519 sign (synchronous; 64-byte signature).
let sig: [u8; 64] = signer.sign_ed25519(canonical_bytes)?;

// Cold-path ML-DSA-65 sign (async; 3309-byte signature, FIPS 204 final).
let pqc_sig: Vec<u8> = signer.sign_ml_dsa_65(canonical_bytes).await?;

// Hybrid (Ed25519 + ML-DSA-65 over `canonical || classical_sig`)
// returning ciris_crypto::HybridSignature shape.
let hybrid: HybridSignature = signer.sign_hybrid(canonical_bytes).await?;

// Accessors:
signer.key_id()                    // &str
signer.pqc_key_id()                // Option<&str>
signer.public_key_b64()            // String (44 chars, base64 standard)
signer.pqc_public_key_b64().await? // Option<String> (~2604 chars)
```

Construction mirrors the PyO3 Engine constructor exactly: 32-byte
raw Ed25519 seed at `key_path`; optional ML-DSA-65 via
`MlDsa65SoftwareSigner::from_seed_file` at `pqc_key_path`. Both-or-
neither PQC config validated at construction
(`StewardSignerError::PqcConfigInconsistent`). Same
`tracing::info` observability shape ("ciris-persist: steward
identity loaded").

CIRISLensCore (rlib path, never PyO3) now composes against
`signing::StewardSigner` for its detection-event signing. Mission
lock-in `MISSION.md:166` ("uses persist.steward_sign() exclusively")
is finally implementable from Rust.

### PyO3 Engine refactored to back onto StewardSigner

`PyEngine` previously held four steward fields directly
(`steward_signing_key`, `steward_key_id`, `steward_pqc_signer`,
`steward_pqc_key_id`). v0.4.2 collapses these to one
`Option<Arc<StewardSigner>>`, and the PyO3 methods become thin
wrappers:

- `engine.steward_sign(message)` → `signer.sign_ed25519(message)`
- `engine.steward_pqc_sign(message)` → `signer.sign_ml_dsa_65(message)`
- `engine.steward_public_key_b64()` → `signer.public_key_b64()`
- `engine.steward_pqc_public_key_b64()` → `signer.pqc_public_key_b64()`
- `engine.steward_key_id()` → `signer.key_id()`
- `engine.steward_pqc_key_id()` → `signer.pqc_key_id()`

One implementation, both surfaces — CIRISPersist#7 single-source-of-
truth pattern repeated for signing. Cold-path PQC fill-in spawns
(per-write tokio::spawn + sweep) capture
`signer.pqc_signer_arc()` instead of the old direct
`steward_pqc_signer.clone()`.

Python contract is unchanged — error tokens, return shapes, both-or-
neither validation all match v0.4.1 byte-for-byte. New error
variants for the StewardSigner construction path
(`StewardSignerError::SeedRead`, `SeedLength`, `PqcSeedLoad`)
surface as the same `ValueError` / `RuntimeError` shapes the
inline path used.

### Prelude

```rust
use ciris_persist::prelude::*;
// + StewardSigner, StewardSignerConfig, StewardSignerError
```

### Tests

183 lib (179 + 4 new) + 22 integration tests pass; clippy clean
across all features; cargo-deny clean. New tests:

- `from_config_loads_ed25519_seed`: round-trip seed file → signer
  → sign/verify
- `from_config_rejects_wrong_seed_length`: typed `SeedLength`
  error on 31-byte seed
- `from_config_rejects_pqc_config_inconsistent`: typed
  `PqcConfigInconsistent` on key_id-without-key_path
- `sign_ml_dsa_65_without_pqc_config_returns_typed_error`:
  `PqcNotConfigured` when PQC isn't wired

### Edge / lens-core action

```rust
[dependencies]
ciris-persist = "0.4.2"
```

CIRISLensCore Phase 1 detection-event signing (LC-AV-2, LC-AV-11,
LC-AV-18) can now compose against `StewardSigner` directly. PyO3
consumers continue to use `engine.steward_sign(...)` unchanged.

## [0.4.1] — 2026-05-03

**Rust-side verify primitives + curated prelude.** CIRISEdge ask
to eliminate cross-repo drift surfaces in edge's verify pipeline.
All non-breaking; new public Rust API surface only.

### `verify::verify_hybrid_via_directory` (Rust free function)

```rust
pub async fn verify_hybrid_via_directory<F: FederationDirectory>(
    directory: &F,
    canonical_bytes: &[u8],
    signing_key_id: &str,
    ed25519_sig_b64: &str,
    ml_dsa_65_sig_b64: Option<&str>,
    policy: HybridPolicy,
    row_age: Option<Duration>,
) -> Result<VerifyOutcome, VerifyError>;
```

The PyO3 `Engine.verify_hybrid_via_directory` already combined
lookup + verify + policy. v0.4.1 promotes that combination to a
first-class Rust function so edge calls one function instead of
re-implementing the lookup-and-verify dance. Generic over
`FederationDirectory` so callers compose against any backend.

The PyO3 wrapper now backs onto this Rust function — one
implementation, two surfaces (CIRISPersist#7 single-source-of-truth
pattern repeated for the verify path). The Python contract
(`verify_unknown_key` sentinel, error tokens, dict shape) is
unchanged.

### `verify::canonicalize_envelope_for_signing` (Rust free function)

```rust
pub fn canonicalize_envelope_for_signing(
    envelope: &serde_json::Value,
) -> Result<Vec<u8>, Error>;
```

Strips top-level `signature` and `signature_pqc` fields, then
applies `PythonJsonDumpsCanonicalizer`. Returns the bytes the
sender signed — what the verifier needs to reproduce. Closes the
AV-5-class drift surface (canonicalization mismatch between sender
and verifier) by giving the strip rule one home: persist owns it,
edge calls it.

PyO3: `engine.canonicalize_envelope_for_signing(envelope_json) -> bytes`.

### `verify::body_sha256` (Rust free function)

```rust
pub fn body_sha256(body: &serde_json::value::RawValue) -> [u8; 32];
```

SHA-256 of body verbatim wire bytes. Used by the
`body_sha256_prefix` forensic join key and `in_reply_to` content-
derived ACK matching (`OutboundQueue::match_ack_to_outbound`).
Takes `&RawValue` so callers hash the bytes they received, not a
re-serialized form.

PyO3: `engine.body_sha256(body_bytes) -> bytes`.

### `ciris_persist::prelude` module

Curated re-exports for federation peers integrating with persist
at the Rust API layer:

```rust
use ciris_persist::prelude::*;
// FederationDirectory, OutboundQueue, Backend traits
// verify_hybrid_via_directory, verify_trace_via_directory,
//   canonicalize_envelope_for_signing, body_sha256
// HybridPolicy, VerifyOutcome, HybridVerifyError, PublicKeyDirectory
// Canonicalizer, PythonJsonDumpsCanonicalizer, canonical_payload_value
// AbandonedReason, OutboundFailureOutcome, OutboundFilter, OutboundRow,
//   OutboundStatus, QueueId
// Attestation, HybridPendingRow, KeyRecord, Revocation, SignedAttestation,
//   SignedKeyRecord, SignedRevocation
```

Edge previously imported from 6+ sub-modules; one
`use ciris_persist::prelude::*` now covers the substrate surface.
Curated (not a `*` re-export of the world) — internal types
(`IngestPipeline`, `BatchSummary`, etc.) stay sub-module-imported
by the smaller set of consumers that need them.

### Tests

179 lib (177 + 2 new) + 22 integration tests pass; clippy clean
across all features; cargo-deny clean. New tests:

- `canonicalize_envelope_for_signing_strips_signature_fields`:
  signed and unsigned envelopes produce byte-identical canonical
  bytes
- `body_sha256_matches_sha256_of_input`: digest equals
  `sha256(body.get().as_bytes())` directly

### Deps

- `serde_json` feature `raw_value` enabled (was already
  `arbitrary_precision`); needed for `body_sha256` taking
  `&RawValue`. No version bump on serde_json itself.

### Bridge / edge action

```
ciris-persist = "0.4.1"  # or in pyproject.toml: ciris-persist==0.4.1
```

Edge's verify pipeline can now collapse `~150 lines of hand-rolled
lookup-and-canonicalize logic` to `~30 lines composing against
persist's prelude` (per the CIRISEdge ask).

## [0.4.0] — 2026-05-03

**Federation substrate cut.** Three architectural deliverables shipped
together: edge outbound queue (CIRISPersist#16), full verify surface
exposed for agent-cutover-via-lenscore, and `accord_public_keys`
dual-read fallback retired (lens#8 ASK 2). Closes CIRISEdge OQ-09.

This is the schema-stabilization release — federation_keys is now
the canonical pubkey directory, the outbound queue substrate exists,
and the verify surface is complete enough that agent + edge can
consume verify exclusively through `Engine`.

### Edge outbound queue (CIRISPersist#16)

Durable substrate for `CIRISEdge::send_durable()`. New
`cirislens.edge_outbound_queue` table (V007 migration on postgres +
sqlite). Five-state machine:

```text
enqueue → pending → sending ─┬─ delivered (no ACK required)
                             ├─ awaiting_ack → delivered (ACK received)
                             │                 ↓
                             │              abandoned (ACK timeout → max_attempts)
                             └─ pending (retry) | abandoned (max_attempts | ttl_expired)
```

Per-row policy (`max_attempts`, `ttl_seconds`, `ack_timeout_seconds`)
copied at enqueue — message-type policy changes don't retroactively
break in-flight rows. Optimistic claim
(`claimed_until` + `claimed_by`) for multi-instance dispatch
(CIRISEdge OQ-06) via `SELECT FOR UPDATE SKIP LOCKED` on postgres.

15 new `OutboundQueue` trait methods exposed via PyO3:

```python
queue_id = engine.enqueue_outbound(
    sender_key_id, destination_key_id, message_type, edge_schema_version,
    envelope_bytes, body_sha256, body_size_bytes,
    requires_ack, max_attempts, ttl_seconds,
    initial_next_attempt_after_rfc3339,
    ack_timeout_seconds=...,  # required when requires_ack=True
)

# Dispatch loop
rows = engine.claim_pending_outbound(batch_size, claim_duration_seconds, claimed_by)
engine.mark_transport_delivered(queue_id, transport)
result = engine.mark_transport_failed(queue_id, error_class, error_detail, transport, next_attempt_after_rfc3339)
# {"outcome": "retrying"|"abandoned", "attempt": int|None}
engine.mark_replay_resolved(queue_id)

# ACK matching (content-derived via body_sha256)
row = engine.match_ack_to_outbound(in_reply_to_sha256)  # 32 bytes
engine.mark_ack_received(queue_id, ack_envelope_bytes)

# Background sweeps (run periodically per-deployment)
engine.sweep_ack_timeouts() -> int
engine.sweep_ttl_expired() -> int
engine.sweep_expired_claims() -> int

# Inspection / operator surface
status = engine.outbound_status(queue_id)  # dict | None
rows = engine.list_outbound(limit=100, status=..., destination_key_id=..., ...)
engine.cancel_outbound(queue_id)
engine.replay_abandoned(queue_id)
```

Stable error tokens: `outbound_invalid_argument`, `outbound_not_found`,
`outbound_invalid_transition`, `outbound_backend`.

### Full verify surface exposed (lens#8 + agent cutover)

Five new `Engine` verify methods so the agent can cut over to
persist for runtime verify when it's brought in via lenscore:

```python
# Full CompleteTrace verify with internal directory lookup
result = engine.verify_trace(complete_trace_json)
# {"verified": True, "schema_version": "2.7.0"|"2.7.9"}

# Hybrid verify with internal lookup_public_key
result = engine.verify_hybrid_via_directory(
    canonical_bytes, signature_key_id,
    ed25519_sig_b64, ml_dsa_65_sig_b64,
    policy="strict|soft_freshness|ed25519_fallback",
    soft_freshness_window_seconds=..., row_age_seconds=...,
)

# Federation directory row verify (verify-without-store)
engine.verify_signed_key_record(json, policy, ...)
engine.verify_signed_attestation(json, policy, ...)
engine.verify_signed_revocation(json, policy, ...)
```

The agent's runtime verify needs (CompleteTrace, peer-message
envelopes, federation directory rows, ACK envelopes, arbitrary
canonical bytes) all map onto Engine methods. No federation peer
needs to call `ciris_crypto::HybridVerifier` directly — verify-via-
persist is the single-source-of-truth (CIRISPersist#7 architectural
closure repeated for the verify path).

### accord_public_keys dual-read fallback retired (lens#8 ASK 2)

`Backend::lookup_public_key` on postgres + memory + sqlite now reads
only from `federation_keys`. The dual-read fallback to
`accord_public_keys` was retired this release, coordinated with
lens dropping its direct INSERT into `accord_public_keys` the same
release.

The legacy table stays in the schema for historical reads via
`cirislens_reader` (V005 read-only role) but the verify path no
longer touches it. `sample_public_keys` diagnostic also reads
federation_keys so the verify-unknown-key breadcrumb sample matches
the actual lookup query.

### Threat model bumps

AV-40 (outbound queue disk exhaustion) and AV-41 (spoofed
in_reply_to ACK matching) added to `docs/THREAT_MODEL.md` §3.11.
Mitigation matrix updated.

### Tests

177 lib tests pass; clippy clean across all features; cargo-deny
clean. `lookup_public_key_round_trip` and (formerly) `revoked_keys
_filtered` rewritten to use federation_keys directly (the legacy
accord_public_keys round-trip tests retired with the fallback).
The `revoked_keys_filtered` test became `expired_keys_filtered`
(federation revocations are a separate concern in
`federation_revocations` post-v0.2.0).

### Bridge action

```
ciris-persist==0.3.6  →  ciris-persist==0.4.0
```

Lens drops its direct INSERT into `accord_public_keys` the same
release (the v0.3.x fallback path is gone). DSAR handler folds onto
`engine.delete_traces_for_agent(agent_id_hash, signature_key_id)`
per v0.3.6's per-key contract. Agent runtime verify can now cut over
to persist exclusively.

### Schema changes

- V007 (postgres + sqlite): `cirislens.edge_outbound_queue` table +
  6 partial indexes (pending dispatch, awaiting_ack sweep,
  body_sha256 lookup, destination_key_id, status_enqueued,
  claimed_until sweep)

`accord_public_keys` table is **not dropped** — historical reads
work; only the runtime fallback path is retired. v0.5.0 may drop
the table itself once historical-reads consumers migrate.

### Deps

No version changes (`ciris-keyring` / `ciris-verify-core` /
`ciris-crypto` v1.9.0).

## [0.3.6] — 2026-05-03

**`Engine.verify_hybrid` for arbitrary canonical bytes** + **per-key
DSAR scope** (BREAKING).

Closes [CIRISPersist#14](https://github.com/CIRISAI/CIRISPersist/issues/14)
(CIRISEdge OQ-11 day-1 hybrid posture) and
[CIRISPersist#15](https://github.com/CIRISAI/CIRISPersist/issues/15)
(per-key DSAR authorization scope).

### Engine.verify_hybrid (CIRISPersist#14)

```python
result = engine.verify_hybrid(
    canonical_bytes,
    ed25519_sig_b64,
    ml_dsa_65_sig_b64,           # None when row is hybrid-pending
    ed25519_pubkey_b64,
    ml_dsa_65_pubkey_b64,         # None when row is hybrid-pending
    policy="strict",              # | "ed25519_fallback" | "soft_freshness"
    soft_freshness_window_seconds=None,  # required for soft_freshness
    row_age_seconds=None,                # caller-provided row age (SoftFreshness)
)
# {"outcome": "hybrid_verified" | "ed25519_hybrid_pending" | "ed25519_fallback",
#  "row_age_seconds": float | None}
```

The cryptographic primitive lives in `ciris_crypto::HybridVerifier`;
v0.3.6 wraps it with persist's policy machinery + PyO3 surface so
verify-via-persist remains the federation's single-source-of-truth
(per CIRISPersist#7). Edge calling `ciris_crypto::HybridVerifier`
directly would fork canonicalization expectations + bypass policy.

`HybridPolicy::SoftFreshness { window }` accepts hybrid-pending rows
when `row_age < window` — matches V004's eventual-consistency
contract. The `row_age` is caller-supplied (lookup of the row's
`pqc_completed_at` or `created_at` happens at the caller layer; the
primitive itself is policy-aware but lookup-free).

On verify failure raises `ValueError` with a stable persist
error-token (`verify_hybrid_pending_rejected`,
`verify_hybrid_soft_freshness_expired`,
`verify_hybrid_pqc_fields_mismatch`, `verify_hybrid_base64`,
`verify_hybrid_invalid_length`, `verify_hybrid_crypto`). Same
discipline as the rest of persist's PyO3 surface — structured
detail in tracing logs, stable token for HTTP layer mapping.

### Per-key DSAR scope (CIRISPersist#15) — BREAKING

`Engine.delete_traces_for_agent` now requires `signature_key_id`
in addition to `agent_id_hash`:

```python
# v0.3.5 — REMOVED
engine.delete_traces_for_agent(agent_id_hash, include_federation_key=False)

# v0.3.6 — required
engine.delete_traces_for_agent(
    agent_id_hash,
    signature_key_id,                     # required
    include_federation_key=False,
)
```

`signature_key_id` is the **authorization scope** of the DSAR, not
just an identity filter. A request signed by key A is only
authorized to delete traces signed by key A. Without per-key scope,
any one valid key could file a DSAR deleting traces from other
agent instances claiming the same logical identity (separate
deployments of the same template with different signing keys).

The v0.3.5 `Option<&str>` shape was wrong — `None` would have been
a footgun for admin/forensic deletes, but those belong in standard
privileged CRUD, not this DSAR primitive. v0.3.6 makes per-key
scope absolute.

Cascade semantics (per-key throughout):
- `trace_events` rows: `WHERE agent_id_hash = $1 AND signing_key_id = $2`
- `trace_llm_calls` rows: joined by `trace_id` from the deleted set
- `federation_keys`: when `include_federation_key=true`, only the
  one row matching `(agent_id_hash, signature_key_id)`. Other
  registered keys for the same agent stay alive.
- FK-cascade: `federation_attestations` + `federation_revocations`
  referencing that one key, deleted before the federation_keys
  delete.

### Lens action

Lens reverted the v0.3.5 fold attempt (lens commits 99359e8 →
fbbd844) once the per-key contract surfaced. v0.3.6 unblocks the
fold cleanly:

```
ciris-persist==0.3.5  →  ciris-persist==0.3.6
```

Lens DSAR handler at `accord_api.py:dsar_delete_traces` folds onto:

```python
engine.delete_traces_for_agent(agent_id_hash, signature_key_id)
```

— preserving the per-(agent_id_hash, signature_key_id) scope the
lens-owned legacy tables already enforce.

### Deps

- **`ciris-crypto`** added as direct dep (git tag v1.9.0, features
  `ed25519` + `pqc-ml-dsa`). Version-coherent with the existing
  ciris-keyring + ciris-verify-core deps. Pulls in the
  `HybridVerifier` + `Ed25519Verifier` + `MlDsa65Verifier` types
  used by `verify_hybrid`.

### Tests

177 lib (+9 new) + 22 integration tests pass; clippy clean across
all features; cargo-deny clean.

New tests:

- `verify::hybrid` (8 tests) — strict rejects hybrid-pending,
  fallback accepts, soft_freshness within/past window/no-row-age,
  PQC sig without pubkey rejects, full hybrid round-trip,
  tampered canonical rejects
- `dsar_per_key_scopes_correctly` — only the targeted key's traces
  delete; cross-key + cross-agent rows survive
- `dsar_per_key_cascades_llm_calls` — LLM call cascade walks the
  same trace_id set, doesn't touch other-key LLM calls

The v0.3.5 per-agent test was removed (the API doesn't exist
anymore).

## [0.3.5] — 2026-05-03

**DSAR primitive + page-cursor read primitive for analytical streaming.**
Closes [CIRISLens#8](https://github.com/CIRISAI/CIRISLens/issues/8) ASKs
1 + 3. ASK 2 (v0.4.0 timing for `accord_public_keys` dual-read
retirement) answered via comment on lens#8.

### ASK 1 — `Engine.delete_traces_for_agent` (GDPR Article 17)

```python
summary = engine.delete_traces_for_agent(
    agent_id_hash,
    include_federation_key=False,  # default — only trace data
)
# {
#   "trace_events_deleted":           int,
#   "trace_llm_calls_deleted":        int,
#   "federation_keys_deleted":        int,  # 0 unless include_federation_key=True
#   "federation_attestations_deleted": int,  # 0 unless include_federation_key=True
#   "federation_revocations_deleted":  int,  # 0 unless include_federation_key=True
#   "deleted_at":                     str,  # ISO-8601 UTC
# }
```

Always deletes `cirislens.trace_events` rows where `agent_id_hash`
matches + `cirislens.trace_llm_calls` rows joined by `trace_id` from
the deleted set. All in a single transaction.

When `include_federation_key=True`, additionally deletes
`federation_keys` rows where `identity_type='agent'` AND
`identity_ref=agent_id_hash` (may be >1 if the agent rotated keys),
plus FK-cascade rows in `federation_attestations` +
`federation_revocations` referencing those key_ids. FK-cascade is
explicit because persist's federation FKs are not `ON DELETE
CASCADE` — deleting in dependency order is what makes the
operation safe.

Idempotent: re-invocation on an already-deleted agent returns
all-zero counts.

**Persist owns the substrate row delete; lens orchestrates the DSAR
audit + signature verification.** This method does NOT validate the
caller's authority to delete the agent's data — that's lens-side
policy, same separation as the rest of the federation directory's
write surface.

### ASK 3 — `Engine.fetch_trace_events_page` (page-cursor read)

```python
page = engine.fetch_trace_events_page(
    after_event_id=0,
    limit=1000,
    agent_id_hash=None,  # or "<hash>" to filter
)
# list of dicts; each dict carries trace_events column → value pairs
# plus an explicit "event_id" field for cursor extraction
```

Caller orchestrates the cursor: track the max returned `event_id`
between calls, pass it as `after_event_id` for the next page, stop
when the result set is empty.

Cleaner than a callback-style `iterate_trace_events(filter, cb)`
across PyO3: callers pull pages on their own pace, no FFI re-entry
per row, no shared-state synchronization. Same shape as
`Engine.run_pqc_sweep` (cursor at the trait boundary, caller drives).

Use this when:
- Lens wants typed Rust-shape rows rather than raw SQL
- The caller is out-of-process and can't take `cirislens_reader`
  role for direct SQL
- Streaming over a >>memory result set (cursor pattern handles
  arbitrary corpus size)

For ad-hoc analytical queries inside lens-core, the
`cirislens_reader` role + direct SQL is still the recommended shape
— this primitive is for cross-process consumers (per lens#8's
rationale).

### ASK 2 — v0.4.0 timing (`accord_public_keys` dual-read retirement)

Answered via comment on lens#8. Persist will drop the
`Backend::lookup_public_key` accord_public_keys fallback in v0.4.0;
lens-core can drop its direct INSERT into `accord_public_keys` the
same release. No change to v0.3.x.

### Backend trait additions

Two new methods on `Backend` (memory + postgres + sqlite impls):

```rust
fn delete_traces_for_agent(
    &self,
    agent_id_hash: &str,
    include_federation_key: bool,
) -> impl Future<Output = Result<DeleteSummary, Error>> + Send;

fn fetch_trace_events_page(
    &self,
    after_event_id: i64,
    limit: i64,
    agent_id_hash: Option<&str>,
) -> impl Future<Output = Result<Vec<(i64, TraceEventRow)>, Error>> + Send;
```

`DeleteSummary` lands in `src/store/types.rs`. New `from_wire_str`
inverse on `ReasoningEventType` for the postgres + sqlite
row-to-struct conversions (`pg_row_to_event_row` /
`sqlite_row_to_event_row`).

### Tests

168 lib (166 + 2 new memory-backend tests) + 22 integration tests
pass; clippy clean across all features; cargo-deny clean. New
tests:

- DSAR deletes target agent's trace_events + trace_llm_calls
  atomically; other agents' data untouched; idempotent on
  re-invocation
- fetch_trace_events_page returns rows in event_id order, respects
  cursor + limit, filters by agent_id_hash

### Bridge action

Bump `ciris-persist==0.3.4 → 0.3.5` in `api/requirements.txt`.

Lens DSAR handler at `accord_api.py:2880,2891` (per lens#8 inventory)
folds onto `engine.delete_traces_for_agent(agent_id_hash)` — drops
the direct DELETE on `accord_traces`. The `partner_access` /
`public_sample` UPDATE moves to a lens-derived schema (out of scope
for persist; tracked on lens#8).

### Deps

No version changes (`ciris-keyring` / `ciris-verify-core` v1.9.0).

## [0.3.4] — 2026-05-03

**Deployment-profile block at trace_schema_version 2.7.9 — cohort
identity on the wire.** Closes
[CIRISPersist#13](https://github.com/CIRISAI/CIRISPersist/issues/13).
Companion to CIRISAgent's
[`431b0e0ae`](https://github.com/CIRISAI/CIRISAgent/commit/431b0e0ae)
([CIRISAgent#718](https://github.com/CIRISAI/CIRISAgent/issues/718))
which added the 6-field block to every `CompleteTrace` envelope at
2.7.9.

### What ships

**`DeploymentProfile` struct on `CompleteTrace`** (`src/schema/trace.rs`):

```rust
pub struct DeploymentProfile {
    pub agent_role: String,            // "ally", "scout", "echo-core", ...
    pub agent_template: String,        // "ally-v3-default", ...
    pub deployment_domain: String,     // "general", "healthcare", "legal", ...
    pub deployment_type: String,       // "production", "staging", "development", ...
    pub deployment_region: Option<String>,  // "US", "GB", "global", null
    pub deployment_trust_mode: String, // "sovereign", "limited_trust", "federated_peer"
}

pub struct CompleteTrace {
    // ...existing fields...
    pub deployment_profile: Option<DeploymentProfile>,  // NEW
    // ...
}
```

`Option<>` so 2.7.0 traces continue to deserialize cleanly. The
2.7.9-strict requirement fires at parse, not in serde — see below.

Persist accepts the agent's declared values verbatim — closed-enum
constraints live in the agent-side spec; persist's role is
ingest + verify, not enum-value gatekeeping. New enum values land
via spec PR without persist version bumps.

### Strict-parse + cross-shape gates

**At 2.7.9** (in `BatchEnvelope::from_json`): `deployment_profile` is
REQUIRED on the wire per FSD §3.2; absence surfaces as
`Error::MissingField("deployment_profile")`. The "required at 2.7.9"
contract now enforces *semantic* requirement, not just *presence*
(same gate-style as v0.3.3's parent_event_type fix).

**At 2.7.0** (cross-shape rule): a 2.7.0 envelope carrying a
`deployment_profile` field parses cleanly — but the field does NOT
enter the 2.7.0 canonical bytes. Mirrors the per-component
`agent_id_hash` cross-shape rule. Two traces (with vs. without the
block) at 2.7.0 produce byte-identical canonical bytes; tested by
`v270_ignores_deployment_profile_injection`.

### Updated 2.7.9 canonical signed bytes

10-key outer canonical (was 9 pre-v0.3.4). `deployment_profile`
sorts between `components` and `started_at` alphabetically (`c` <
`d` < `s`). Inside the block, the 6 fields sort
alphabetically too (Python `json.dumps(sort_keys=True)`):

```text
{
  "agent_id_hash": ...,
  "completed_at": ...,
  "components": [...],
  "deployment_profile": {
    "agent_role": ...,
    "agent_template": ...,
    "deployment_domain": ...,
    "deployment_region": ...,
    "deployment_trust_mode": ...,
    "deployment_type": ...
  },
  "started_at": ...,
  "task_id": ...,
  "thought_id": ...,
  "trace_id": ...,
  "trace_level": ...,
  "trace_schema_version": "2.7.9"
}
```

Byte-identical to the agent-side fixture at
`tests/adapters/accord_metrics/test_trace_signature_canonical.py::test_deployment_profile_canonical_byte_for_byte_pinning`.

### Denormalization onto trace_events (Option B)

V006 migration (postgres + sqlite) adds 6 columns to
`cirislens.trace_events`:

```sql
ALTER TABLE cirislens.trace_events
    ADD COLUMN agent_role            TEXT,
    ADD COLUMN agent_template        TEXT,
    ADD COLUMN deployment_domain     TEXT,
    ADD COLUMN deployment_type       TEXT,
    ADD COLUMN deployment_region     TEXT,
    ADD COLUMN deployment_trust_mode TEXT;
```

Plus 4 partial indexes on the high-cardinality cohort axes
(`deployment_domain`, `deployment_type`, `agent_role`,
`deployment_trust_mode`) — each `WHERE <col> IS NOT NULL` so the
indexes only carry post-2.7.9 traffic, keeping size proportional to
the corpus that actually has the labels.

`decompose.rs` copies the 6 fields onto every event row of the
trace, same shape as `agent_name` / `agent_id_hash` /
`cognitive_state` already do. Lens analytical paths (Coherence
Ratchet, capacity scoring, manifold-conformity) group/filter
without JSONB extracts.

Architectural note: this is denormalization tech-debt — the same
labels live both in `trace_events.payload` JSONB and in 6 dedicated
columns. The alternative (lens-side `trace_context` table fed by a
separate write path) re-introduces the architectural problem
CIRISPersist#10 closed: one substrate, N consumers; reimplementation
drift is the failure mode. Persist owns the denormalization.

### Tests

166 lib (162 + 4 new) + 22 integration tests pass; clippy clean;
cargo-deny clean. New regression tests:

- 2.7.9 missing `deployment_profile` → `MissingField` rejection
- 2.7.9 with the block parses cleanly (including
  `deployment_region: null` as valid declaration)
- 2.7.0 with the block parses cleanly (cross-shape ignore)
- 2.7.9 canonical bytes carry `deployment_profile` in expected
  sorted position
- 2.7.0 canonical bytes byte-identical with vs. without injected
  block (cross-shape rule enforced)
- 2.7.9 trace decomposes to event rows carrying all 6 columns
- 2.7.0 trace decomposes to All-NULL across the 6 columns

### Bridge action

Bump `ciris-persist==0.3.3 → 0.3.4` in `api/requirements.txt` and
deploy alongside agent `431b0e0ae`. Both must be live for the
end-to-end linkage to work — agent emits the block, persist verifies
the 2.7.9 canonical including the block, denormalized columns
populate every event row.

Validation query post-deploy:

```sql
SELECT deployment_domain, deployment_type, deployment_trust_mode,
       COUNT(*)
FROM cirislens.trace_events
WHERE schema_version = '2.7.9'
  AND ts > '<deploy-time>'
GROUP BY 1, 2, 3
ORDER BY 4 DESC;
```

Pre-fix the columns would all be NULL. Post-fix the breakdown
matches the 2.7.9 fleet's deployment_profile distribution.

### Deps

No version changes (`ciris-keyring` / `ciris-verify-core` v1.9.0).

## [0.3.3] — 2026-05-03

**LLM_CALL parent linkage — wire-format compliance at 2.7.9.**
Closes [CIRISPersist#12](https://github.com/CIRISAI/CIRISPersist/issues/12).
Paired with CIRISAgent's e714ff3c4 fix that wires
`parent_event_type` + `parent_attempt_index` into the agent's LLM_CALL
emission. Together they close the regression that
[CIRISLens#5](https://github.com/CIRISAI/CIRISLens/issues/5) surfaced:
100% of `trace_llm_calls` rows in the first 2.7.9 corpus export carried
`parent_event_type='LLM_CALL'` instead of the spec-mandated upstream-
step taxonomy.

### Root cause (v0.3.0 → v0.3.2)

Two interlocking gaps:

1. **`LlmCallSummary` schema** didn't model `parent_event_type` /
   `parent_attempt_index`. Even after the agent fix landed at
   e714ff3c4, persist's serde would have dropped both fields on
   parse — they'd never have reached the column.
2. **`decompose.rs` substituted** `component.event_type` (always
   `LlmCall` for an LLM_CALL component) into `parent_event_type`. The
   v0.3.0 "required at 2.7.9" deploy validation reported
   `without_parent = 0` because every row had the field set — to
   `LLM_CALL`. The check was for *presence*, not *validity*.

### What ships

**`LlmCallSummary` adds two fields**:

```rust
#[serde(default, skip_serializing_if = "Option::is_none")]
pub parent_event_type: Option<ReasoningEventType>,
#[serde(default, skip_serializing_if = "Option::is_none")]
pub parent_attempt_index: Option<u32>,
```

`Option<>` so 2.7.0 traces continue to deserialize cleanly. The
2.7.9-strict requirement fires at decompose, not parse — see below.

**`decompose.rs` schema-version-aware sourcing** in
`build_llm_call_row`:

- **`trace_schema_version == "2.7.9"`**: BOTH fields REQUIRED. Missing
  → `Error::Schema(MissingField("data.parent_event_type"))` or
  `MissingField("data.parent_attempt_index")`. The v0.3.0 "required at
  2.7.9" claim now actually enforces semantic correctness.
- **`"2.7.0"` and other**: prefer wire-provided value when present
  (forward-compat); fall back to the historical
  `component.event_type` / `attempt_index` substitution otherwise.
  Existing 2.7.0 traffic continues to land. Pre-fix
  `trace_llm_calls.parent_event_type='LLM_CALL'` rows are
  unrecoverable from persist alone — RATCHET uses `handler_name` as
  the upstream-step linkage workaround per CIRISLens#5.

### Tests

159 lib (155 + 4 new) + 22 integration tests pass; clippy clean
across all features; cargo-deny clean. New tests cover:

- 2.7.9 trace with both fields → wire values land on row (not
  substitution)
- 2.7.9 missing `parent_event_type` → MissingField rejection
- 2.7.9 missing `parent_attempt_index` → MissingField rejection
- 2.7.0 trace with no parent fields → historical substitution preserved

### Cross-repo

- **CIRISAgent**: agent#715 fixed at e714ff3c4. Deploying agent +
  persist v0.3.3 together closes the linkage end-to-end.
- **CIRISLens**: lens#5 closes when v0.3.3 is on PyPI and bridge
  redeploys. Lens analytical paths can drop the `handler_name`
  workaround once enough 2.7.9 traffic with correctly-populated
  `parent_event_type` accumulates.

### Deps

No version changes (`ciris-keyring` / `ciris-verify-core` v1.9.0).

## [0.3.2] — 2026-05-02

**Cold-path PQC sweep + read-only role for analytical consumers.**
Closes [CIRISPersist#11](https://github.com/CIRISAI/CIRISPersist/issues/11)
(sweep) and [CIRISPersist#9](https://github.com/CIRISAI/CIRISPersist/issues/9)
(read-only role + public schema contract).

### Sweep — closes #11

v0.3.1 wired the per-write cold-path: `put_public_key` /
`put_attestation` / `put_revocation` spawn a tokio task that
canonicalizes the envelope, signs `(canonical || classical_sig)` with
ML-DSA-65, and calls `attach_*_pqc_signature`. That covered every
NEW row.

It did NOT cover:

1. **Historical hybrid-pending rows** authored before the per-write
   cold-path was wired (lens deployment had 654 such rows from the
   v0.3.0 → v0.3.1 transition window).
2. **Cold-path failure recovery.** Any transient ML-DSA sign error,
   runtime panic between hot-path commit and cold-path attach,
   network blip during attach, or persist process restart with
   cold-path tasks inflight left rows hybrid-pending forever.
3. **V004's Phase 2 transition** ("pre-flip rows that are still
   pending get walked through the upgrade pipeline") — the contract
   assumed the upgrade pipeline existed.

v0.3.2 ships that pipeline as `Engine.run_pqc_sweep()`.

**Three new `FederationDirectory` trait methods**:

```rust
fn list_hybrid_pending_keys(&self, limit: i64)
    -> impl Future<Output = Result<Vec<HybridPendingRow>, Error>> + Send;
fn list_hybrid_pending_attestations(&self, limit: i64)
    -> impl Future<Output = Result<Vec<HybridPendingRow>, Error>> + Send;
fn list_hybrid_pending_revocations(&self, limit: i64)
    -> impl Future<Output = Result<Vec<HybridPendingRow>, Error>> + Send;
```

Implemented across all three backends (memory, postgres, sqlite). Each
returns `(id, envelope, classical_sig_b64)` triples for `WHERE
pqc_completed_at IS NULL ORDER BY <natural-ts> ASC LIMIT $1` —
sufficient to recompute the cold-path bound-signature input identical
to the per-write flow.

**`Engine.run_pqc_sweep(batch_size=1000) -> dict`**:

```python
result = engine.run_pqc_sweep()
# {
#   "scanned": int,        # total rows examined across the three tables
#   "signed":  int,        # rows hybrid-completed by this call
#   "failed":  int,        # rows where sign or attach errored (still pending)
#   "by_table": {
#     "federation_keys":         {"scanned": ..., "signed": ..., "failed": ...},
#     "federation_attestations": {...},
#     "federation_revocations":  {...},
#   }
# }
```

Walks each table cursor-style, reuses the v0.3.1 `cold_path_pqc_sign`
helper, calls the matching `attach_*_pqc_signature`. Idempotent:
`attach_*_pqc_signature` already guards via `WHERE
pqc_completed_at IS NULL`, so multi-worker concurrent sweeps just
waste signs on losers — no incorrect rows are produced. The
silent-skip path on `Conflict` is not counted as `failed`.

Re-invoke until `scanned == 0` to drain backlogs > `batch_size`.

Raises `ValueError` if no PQC steward configured (matches
`steward_pqc_sign` v0.3.1 shape).

**`pqc_sweep_on_init=True` constructor param** — additive, default
`True` when `steward_pqc_*` is configured. Spawned as a background
tokio task at the tail of `Engine::new`; doesn't block construction
return. Logs a `tracing::info!` summary when the sweep completes.

The default-true matches the writer contract intent in V004's schema
header: rows hybrid-complete by default; operators don't have to opt
in to the contract being self-enforcing. Pass
`pqc_sweep_on_init=False` to suppress (e.g., for migration-time
table walks where boot-time PQC fill is undesirable).

**Bridge action for the 654 lens rows**: nothing required beyond
deploying v0.3.2. The next bridge redeploy auto-fires the sweep at
boot; the 654 rows hybrid-complete passively within seconds.

### Read-only role — closes #9

`migrations/postgres/lens/V005__readonly_role.sql` provisions
`cirislens_reader` (NOLOGIN, USAGE on `cirislens` schema, SELECT on
all existing + future tables).

Operators provision a login user out-of-band:

```sql
CREATE USER cirislens_analytics WITH PASSWORD '<vaulted>';
GRANT cirislens_reader TO cirislens_analytics;
```

Lens analytical paths connect with that DSN
(`CIRISLENS_READ_DSN=...`). Write paths stay Engine-only on the
existing `DATABASE_URL`.

`docs/PUBLIC_SCHEMA_CONTRACT.md` documents the column-stability
contract:

- `stable` — semver-guaranteed; removal/type-change requires major
  bump + deprecation window
- `stable-ro` — server-computed, downstream may read but writes
  ignored (e.g. `persist_row_hash`)
- `internal` — may change at any minor without notice; downstream
  MUST NOT depend (e.g. `audit_*` forensic fields)

Includes the `accord_traces` → `trace_events` / `trace_llm_calls`
column mapping for lens science scripts migrating off the legacy
denormalized table.

### Tests

155 lib + 22 integration tests pass; clippy clean across all
features; cargo-deny clean. Two new memory-backend tests
(`list_hybrid_pending_filters_completed_rows`,
`list_hybrid_pending_limit_and_payload`) cover the sweep substrate.

### Deps

No version changes (`ciris-keyring` / `ciris-verify-core` v1.9.0 from
v0.3.1).

## [0.3.1] — 2026-05-02

**Persist-owned cold-path PQC fill-in.** Closes
[CIRISPersist#10](https://github.com/CIRISAI/CIRISPersist/issues/10).
Built on top of CIRISVerify v1.9.0's new `PqcSigner` trait +
`MlDsa65SoftwareSigner` (CIRISVerify#5).

### What ships

**Two new constructor params on `Engine`** (both optional, both-or-neither):

```python
engine = Engine(
    dsn=...,
    signing_key_id="lens-scrub-v1",          # P-256 scrub envelopes
    scrubber=...,
    steward_key_id="lens-steward",            # Ed25519 federation steward
    steward_key_path="/app/keys/lens-steward.seed",
    steward_pqc_key_id="lens-steward-pqc",    # NEW — ML-DSA-65 federation steward
    steward_pqc_key_path="/app/keys/lens-steward.mldsa.seed",  # NEW — 32B raw seed
)
```

The 32-byte seed is loaded via `ciris_keyring::MlDsa65SoftwareSigner::from_seed_file`
at constructor time. Seed bytes never enter the Python process —
same FFI-boundary discipline as Ed25519. HW acceleration when
post-quantum HSMs land is verify's responsibility (PqcSigner trait
is the dispatch surface).

**Three new `Engine` methods**:

```python
engine.steward_pqc_public_key_b64() -> str   # 1952B raw → ~2604 chars
engine.steward_pqc_key_id() -> str            # the configured identifier
engine.steward_pqc_sign(message: bytes) -> bytes   # 3309-byte raw sig (FIPS 204 final)
```

All three raise `ValueError` if no PQC steward identity configured —
unchanged behavior for v0.3.0 callers, fully backwards-compatible.

**Auto-fire after federation writes**. When `steward_pqc_*` is
configured, persist automatically:

1. Captures the row's `registration_envelope` (or attestation /
   revocation envelope) + `scrub_signature_classical` BEFORE the
   synchronous put consumes the record.
2. Awaits the synchronous put — Python returns once the row lands
   hybrid-pending.
3. `tokio::spawn`s a fire-and-forget cold-path task that:
   - Canonicalizes the envelope via `PythonJsonDumpsCanonicalizer`
   - Decodes `classical_sig` from base64
   - Concatenates `(canonical || classical_sig)` — bound signature
     pattern matching CIRISVerify's `HybridSignature` spec
   - Signs with ML-DSA-65 via `PqcSigner::sign`
   - Calls `attach_*_pqc_signature` to populate the PQC fields and
     timestamp `pqc_completed_at`

Per the writer contract in `migrations/postgres/lens/V004__federation_directory.sql`:
"kick off IMMEDIATELY after Ed25519 sign, not delayed/batched/scheduled,
just off the synchronous request path." The `tokio::spawn` post-put
matches that exactly — synchronous Python returns once the row
commits; PQC catches up within seconds.

Failure mode: if cold-path sign or attach fails, the row stays
hybrid-pending. `tracing::warn!` surfaces the failure in operator
logs; consumers can fill in via the v0.2.0 `attach_*_pqc_signature`
escape hatch on their own schedule.

### Why persist owns the cold-path

Per CIRISPersist#10:

1. The writer contract LIVES in persist's V004 schema header. Persist
   owns the schema and the contract; persist owns making the contract
   happen.
2. "One substrate, N consumers" — each consumer reimplementing cold-
   path drifts (Python ML-DSA library choice, retry policy, byte
   concat handling, failure semantics). Same drift surface
   CIRISPersist#7 burned us with on canonicalization; same mitigation
   pattern (`engine.canonicalize_envelope`, `engine.steward_sign`,
   now `engine` auto-fires the cold-path).
3. The cryptographic primitive is in `ciris-keyring v1.9.0+` — the
   right architectural home (HW acceleration, storage descriptor,
   lifecycle), not raw `ml-dsa` direct dep.
4. The seed-management pattern already exists for Ed25519
   (`steward_key_path`); ML-DSA counterpart is the same shape, second
   algorithm.

### Bridge action

Bridge mounts the ML-DSA-65 seed file alongside the existing
Ed25519 seed:

```yaml
# production.yml
volumes:
  - /opt/ciris/keys/lens-steward.seed:/app/keys/lens-steward.seed:ro
  - /opt/ciris/keys/lens-steward.mldsa.seed:/app/keys/lens-steward.mldsa.seed:ro  # NEW
```

Lens `Engine(...)` constructor adds the two new params. From that
point forward, every `engine.put_public_key`/`put_attestation`/`put_revocation`
auto-fires cold-path PQC; pqc_completed_at populates within seconds
of the hot-path write.

### Bridge's 648 hybrid-pending rows

Run the existing migrator script (or any read-and-republish loop
that calls `engine.put_public_key` for each pending row) — auto-
fire kicks in for each, draining the queue. Or call
`engine.attach_key_pqc_signature` manually with bridge-side
ML-DSA signatures for the one-shot backfill. Same effect; same
schema state at the end.

### Tests

157 lib + 22 integration tests green; clippy clean across all
features; cargo-deny clean. New tests covering auto-fire end-to-end
land in v0.3.x as production traffic patterns surface.

### Deps

- `ciris-keyring v1.8.6 → v1.9.0` (adds `pqc-ml-dsa` feature →
  `MlDsa65SoftwareSigner`, `PqcSigner` trait, `get_platform_pqc_signer`
  factory; closes CIRISVerify#5)
- `ciris-verify-core v1.8.6 → v1.9.0` (no behavior change for persist
  beyond pulling the same workspace's ml-dsa-rc.3)

## [0.3.0] — 2026-05-02

**Wire format 2.7.9 — locked against `CIRISAgent/FSD/TRACE_WIRE_FORMAT.md @ cc41f315f`** (release/2.7.9 HEAD; byte-identical at v2.7.9-stable). QA runner cuts a `release/2.7.9` signed build today; persist v0.3.0 must be on PyPI before that build deploys, or persist v0.2.x will fail to verify the new shape.

### What changed

| Surface | v0.2.x | v0.3.0 |
|---|---|---|
| `SUPPORTED_VERSIONS` | `["2.7.0"]` | `["2.7.0", "2.7.9"]` |
| `TraceComponent` fields | 4 (component_type, event_type, timestamp, data) | 5 (above + `agent_id_hash`) — `Option<String>`; `None` at 2.7.0 (cross-shape injection defense), `Some(envelope_hash)` at 2.7.9 |
| Canonical-shape dispatch | try-9-field-then-2-field (silent fallback) | **deterministic by `trace_schema_version`** — NOT iterative. Per spec §8 |
| Per-component canonical | always 4 fields | 4 at "2.7.0", 5 at "2.7.9" (adds `agent_id_hash`) |
| Legacy 2-field canonical | silent fallback on mismatch | reserved behind explicit `"2.7.legacy"` opt-in (not in `SUPPORTED_VERSIONS` by default) |
| `verify::Error` variants | 5 (Mismatch / Canonicalization / UnknownKey / InvalidSignature / Internal) | 6 (above + `UnsupportedSchemaVersion` for the dispatch-table miss) |

### Why deterministic dispatch (not try-three)

The pre-v0.3.0 try-9-field-then-2-field-on-mismatch fallback worked but had three structural problems:

1. **Shape-shopping attack surface**. An attacker who could craft canonical-bytes collisions on one shape might escape rejection on the other.
2. **Spurious-sig-fail latency multiplier**. Under load, every successful verify for the second shape paid one wasted SHA-256 + Ed25519 verify.
3. **Telemetry noise**. "Verified on second try" doesn't tell you which shape the agent fleet is actually on.

`trace_schema_version` is part of the signed canonical bytes — self-authenticating. An attacker cannot forge the dispatch key without breaking the signature. Each trace contributes to exactly one canonical shape's verify path. Per cc41f315f hand-off note.

### Cross-shape field injection defense (§3.1)

At `trace_schema_version "2.7.0"`, canonical reconstruction MUST IGNORE per-component `agent_id_hash` even if present on the wire. Only the envelope value is authoritative. An attacker stuffing per-component `agent_id_hash` into a 2.7.0 trace cannot influence dedup or signing.

Test: `v270_ignores_per_component_agent_id_hash_injection` — builds the same trace with `agent_id_hash: None` vs `agent_id_hash: Some("attacker_smuggled_hash")`; the canonical bytes are byte-identical.

### `context/TRACE_WIRE_FORMAT.md` is now a pointer

Replaces the vendored copy with a single-line pointer to `CIRISAgent/FSD/TRACE_WIRE_FORMAT.md @ cc41f315f`. Eliminates the spec-vendor-drift class that produced the v0.1.18 → v0.1.20 float-canonicalization break.

When the agent introduces a future schema version (`2.8.0`, etc.), the pointer's pinned commit reference updates paired with a persist version bump — consumers always have a coherent (spec, persist code) pair.

### Sunset markers (telemetry-driven, not date-committed)

- Drop "2.7.0" once `federation_canonical_match_total{wire="2.7.0"}` stays at zero through a soak window.
- "2.7.legacy" — reserved sentinel for the pre-2.7.8.9 2-field shape; deployments opt-in by adding to `SUPPORTED_VERSIONS`. Never silent fallback for unrecognized versions.

### Threat-model closures (per cc41f315f hand-off note)

| Concern | Mechanism | Spec ref |
|---|---|---|
| AV-9 cross-agent pre-claim | `agent_id_hash` binds dedup tuple, denormalized per-component on the wire | §3.1, §4, §9.1 |
| LLM_CALL parent forgeability | `parent_event_type` + `parent_attempt_index` in signed canonical | §5.10 |
| VERB_SECOND_PASS dispatch ambiguity | Closed enum `{"tool", "defer"}` + extension policy | §5.7 |
| Cross-shape field injection at 2.7.0 | Canonical-reconstruction ignore-rule + test | §3.1 |
| Verifier dispatch ambiguity | Deterministic by `trace_schema_version`, NOT iterative | §8 |

Residual: `agent_id_hash` is 64-bit (8 bytes) — anti-DOS at federation scale, not a confidentiality boundary. Same trade-off PoB §3.2 made for Reticulum addressing.

### Tests

157 lib tests green (+2 new: `v279_signed_trace_verifies_via_deterministic_dispatch` and `v270_ignores_per_component_agent_id_hash_injection`); the v0.1.16 try-both fallback test renamed/refactored to `legacy_two_field_canonical_dispatch_via_explicit_opt_in` (now tests the explicit `"2.7.legacy"` opt-in path, not silent fallback). Clippy clean across all features. cargo-deny clean.

### Lens action

`pip install --upgrade ciris-persist==0.3.0`. The trace-verify path now dispatches by `trace_schema_version` automatically — no lens-side changes required for the wire-format bump itself. Lens's existing engine.receive_and_persist() flow handles 2.7.0 and 2.7.9 traces transparently.

### Deferred to v0.3.x

- Telemetry counters: `federation_canonical_attempts_total{shape, wire}` + `federation_canonical_match_total{shape, wire}` (each trace contributes to exactly one bucket given deterministic dispatch).
- LLMCallEvent required-field enforcement at parse layer for 2.7.9 (parent_event_type + parent_attempt_index). The fields land in `trace_llm_calls` correctly via the existing decompose path; what's deferred is the explicit parse-time rejection if absent at 2.7.9. Until v0.3.x, missing fields are caught downstream at trace_llm_calls insert NOT NULL constraint or at verify-canonical-mismatch.
- VERB_SECOND_PASS_RESULT closed verb enum validation at parse (current shape: parses any string in `verb_second_pass_data.verb`; spec requires `{"tool", "defer"}`). Caught at verify-canonical-mismatch indirectly today.
- Threat model refresh in `FEDERATION_THREAT_MODELS/CIRISPersist_THREAT_MODEL.md` per the hand-off note.
- Fixture regen for "2.7.9" — current fixtures cover 2.7.0; 2.7.9 fixtures land in v0.3.x once we have a real signed-by-agent fixture from the QA runner.

## [0.2.4] — 2026-05-02

First piece of verify subsumption (CIRISPersist#4) — **pip-install-time
subsumption**. `pip install ciris-persist==0.2.4` now also installs
`ciris-verify>=1.8.6,<2` transitively, which puts
`ciris-build-sign` and `ciris-build-verify` CLIs on PATH alongside
persist's existing entry points.

### What this unlocks

CIRISAgent / CIRISLens / CIRISBridge release workflows can drop
the `cargo install --git CIRISVerify` and curl-from-tarball
workarounds for the build-manifest signing CLIs and use a clean
`pip install ciris-persist==0.2.4` instead. Single install command
for the whole verify+persist stack.

CIRISVerify v1.8.6's wheels (linux x86_64/aarch64, macos
x86_64/arm64, windows x86_64) bring the binary entry points to all
5 platforms. v1.8.6 is the first version with that coverage —
hence the `>=1.8.6` floor. Pin upper bound `<2` so a hypothetical
v2.x verify breaking change doesn't silently propagate.

### What this does NOT do (yet)

The Python *import* surface is unchanged from v0.2.3:
`ciris-verify` is still a separate import path
(`from ciris_verify.exceptions import VerificationFailedError`)
rather than being re-exported through `ciris_persist`. The
verify-shaped `Engine` proxy methods (`Engine.sign`,
`Engine.public_key`, `Engine.verify_build_manifest`,
`Engine.attestation_export`, etc. — see
`docs/V0.2.0_VERIFY_SUBSUMPTION.md`) land in a follow-on v0.2.x
release once the engine-side wiring catches up. v0.2.4 is the
install-shape piece; the import-shape piece is task #82.

`Engine.sign()` and `Engine.steward_sign()` already exist
(v0.2.1 + v0.2.2) for the federation-keys signing path. The
build-manifest signing surface is what's queued.

### Tests + features

154 lib + 22 integration tests green; clippy clean across all
features; cargo-deny clean. PyPI wheel metadata gains a
`Requires-Dist: ciris-verify>=1.8.6,<2` line; wheel itself is
unchanged otherwise.

### Consumer action

`pip install --upgrade ciris-persist==0.2.4` — if `ciris-verify`
isn't already installed in the environment, pip fetches it.
Existing environments with `ciris-verify==1.8.6` see no behavior
change beyond the dependency constraint being formally declared.

## [0.2.3] — 2026-05-02

Patch release. Two doc-only / dep-hygiene fixes off CIRISBridge's
lens-steward bootstrap finding.

### CIRISPersist#8 — ML-DSA-65 signature size doc

`src/federation/types.rs:166` doc said "~4396 chars for 3293-byte
sig". The 3293 figure was round-3 era; FIPS 204 final (the version
the live `ml-dsa = 0.1.0-rc.3` and `dilithium-py` both emit) is
3309 bytes / 4412 base64 chars. Empirically confirmed by
CIRISBridge's bootstrap: `length(scrub_signature_pqc) = 4412` for
the persisted lens-steward row. Pure docstring fix; persist v0.2.x
has no ML-DSA verifier and no schema capacity check (column type
is `TEXT`), so no behavior change.

### CIRISVerify pin: v1.8.0 → v1.8.5

Hygiene bump. CIRISVerify v1.8.5 fixed the same FIPS 204 final
size constant in `ciris-crypto/src/types.rs:86`
(`PqcAlgorithm::MlDsa65.signature_size()`). Persist v0.2.x doesn't
use that constant directly — we use `VerifyError`,
`BuildPrimitive`, `ExtrasValidator`, and `register_extras_validator`
from ciris-verify-core, plus `HardwareSigner` /
`Ed25519SoftwareSigner` / `HardwareType` from ciris-keyring — but
keeping the pin current means when verify subsumption lands
(CIRISPersist#4 / task #82) we're already on the FIPS-correct line.

### CIRISPersist#6 — verify_unknown_key (closed pending confirmation)

The v0.1.16 universal `verify_unknown_key` issue. Resolution
trajectory:

| Version | What landed |
|---|---|
| v0.1.17 | `sample_public_keys` breadcrumb on the `lookup_public_key` Ok(None) path (the diagnostic CIRISBridge requested) |
| v0.1.18 | SignatureMismatch breadcrumb + `Engine.debug_canonicalize` |
| v0.1.19 | (lexical-core float fix attempt — superseded) |
| v0.1.20 | `arbitrary_precision` wire-token preservation — closed CIRISPersist#7 (the underlying canonical-bytes drift the verify-mismatch path was actually surfacing) |

Reading the issue body in retrospect: the v0.1.16 era was a window
where MULTIPLE verify-mismatch paths were misclassified as
`verify_unknown_key`. The breadcrumb (v0.1.17) gave us the
diagnostic surface to distinguish; v0.1.18-v0.1.20 closed the
underlying drift sources (base64 alphabet, canonical shape, float
formatting). With v0.2.x federation directory + dual-read, the
lookup path is fundamentally different.

Will close after CIRISBridge confirms no v0.2.x reproduction. If
they see `Ok(None) for rows that exist` in v0.2.x, the issue
re-opens with current-version evidence.

### Tests

154 lib + 22 integration tests green; clippy clean across all
features; cargo-deny clean.

## [0.2.2] — 2026-05-02

Lens v0.2.x ask round 2. v0.2.1 landed `Engine.sign()` keyed to
the scrub-envelope identity (`signing_key_id`, P-256 via
ciris-keyring). Bridge correctly identified that `lens-scrub-v1 ≠
lens-steward` — the steward identity is Ed25519, separate keypair
generated externally (by bridge). v0.2.2 adds the steward signing
surface as a separate FFI-boundary-clean primitive.

### What ships

**Constructor params** (both optional, both-or-neither):

```python
engine = Engine(
    dsn=...,
    signing_key_id="lens-scrub-v1",          # P-256 — scrub envelopes (existing)
    scrubber=...,
    steward_key_id="lens-steward",            # NEW — Ed25519 federation steward
    steward_key_path="/etc/ciris/lens-steward.seed",  # 32-byte raw seed file
)
```

The lens-steward keypair is generated externally (CIRIS bridge in
the lens deployment story); the 32-byte raw Ed25519 seed lives at
`steward_key_path` (chmod 600 expected). Persist reads the seed at
constructor time and holds the `SigningKey` privately. The lens
process never sees the seed bytes after construction.

**Three new methods** on `Engine`:

```python
engine.steward_public_key_b64() -> str   # 44-char Ed25519 pubkey base64
engine.steward_key_id() -> str           # the configured "lens-steward" identifier
engine.steward_sign(message: bytes) -> bytes   # 64-byte raw Ed25519 signature
```

Same FFI-boundary discipline as v0.2.1's `Engine.sign()`: bytes
in, bytes out, no key material crossing the boundary. All three
raise `ValueError` if the Engine wasn't constructed with both
`steward_key_id` and `steward_key_path`.

### Why a second identity, not just one signing key

Two roles, two algorithm requirements:

| Role | Identity | Algorithm | Used for |
|---|---|---|---|
| Scrub envelope | `signing_key_id` (e.g. `lens-scrub-v1`) | P-256 via ciris-keyring (hardware-backed where available) | Per-row scrub_signature on `trace_events`, AV-24 cryptographic provenance |
| Federation steward | `steward_key_id` (e.g. `lens-steward`) | Ed25519 (file-backed seed) | `federation_keys` rows the lens publishes — schema requires Ed25519 |

The federation_keys schema is Ed25519+ML-DSA-65 hybrid. The
existing scrub-signing identity is P-256 — wrong shape for
federation. Conflating them ("one key, three roles") was the
v0.2.1 framing error. v0.2.2 separates them explicitly.

The cold-path ML-DSA-65 sign for federation rows still happens
externally (lens runs ML-DSA-65 sign over `(canonical ||
classical_sig)` via its own pipeline) and lands via
`attach_key_pqc_signature()`. v0.2.2 covers the hot Ed25519 path;
ML-DSA-65 cold path may land as a steward_pqc_sign() in v0.2.x if
operationally justified.

### Lens cutover flow (end-to-end with v0.2.2)

```python
import json
import os

engine = Engine(
    dsn=DSN,
    signing_key_id="lens-scrub-v1",
    scrubber=lens_scrubber,
    steward_key_id="lens-steward",
    steward_key_path=os.environ["CIRISLENS_STEWARD_KEY_PATH"],
)

# Bootstrap: bridge ran the offline bootstrap script once,
# inserting the lens-steward self-signed federation_keys row.
# Verify it's there:
assert engine.lookup_public_key("lens-steward") is not None

# Per-agent register_public_key handler (the lens fleet hot path):
def register_public_key_federation_mirror(agent_key_id, agent_pubkey_b64):
    envelope = {
        "key_id": agent_key_id,
        "identity_type": "agent",
        "identity_ref": agent_key_id,
        # ... whatever the lens normally records about an agent key
    }
    canonical = engine.canonicalize_envelope(json.dumps(envelope))
    classical_sig = engine.steward_sign(canonical)
    record = {
        "key_id": agent_key_id,
        "pubkey_ed25519_base64": agent_pubkey_b64,
        "pubkey_ml_dsa_65_base64": None,  # cold-path attaches later
        "algorithm": "hybrid",
        "identity_type": "agent",
        "identity_ref": agent_key_id,
        "valid_from": now_iso(),
        "valid_until": None,
        "registration_envelope": envelope,
        "original_content_hash": sha256_hex(canonical),
        "scrub_signature_classical": base64.b64encode(classical_sig).decode(),
        "scrub_signature_pqc": None,
        "scrub_key_id": engine.steward_key_id(),  # "lens-steward"
        "scrub_timestamp": now_iso(),
        "pqc_completed_at": None,
        "persist_row_hash": "",  # server-computed
    }
    engine.put_public_key(json.dumps({"record": record}))
    # Cold path (lens's own pipeline) runs ML-DSA-65 sign over
    # canonical || classical_sig and calls
    # engine.attach_key_pqc_signature(...) when it lands.
```

### Tests + features

154 lib + 22 integration tests green; clippy clean across
`postgres,sqlite,server,pyo3,tls`; cargo-deny clean. The v0.2.2
adds are PyO3-surface only — no schema changes, no Backend trait
changes, fully backwards-compatible (unchanged behavior when
`steward_key_id`/`steward_key_path` are unset).

### Lens action

`pip install --upgrade ciris-persist==0.2.2`. Update the Engine
constructor call to pass the two new optional params; the rest of
the v0.2.1 surface stays as-is. Full federation cutover flow now
end-to-end without the lens-steward seed crossing the FFI.

## [0.2.1] — 2026-05-02

Lens-team v0.2.x asks. Three small additions completing the
federation-cutover surface so lens can actually wire writes
through persist without the keyring seed crossing the FFI.

### `Engine.sign(message: bytes) -> bytes`

Hot-path Ed25519 sign exposed on the PyO3 surface. Same shape as
the existing `public_key_b64()`: bytes in, bytes out, no key
material crossing the boundary. Lens builds a federation envelope,
hands canonical bytes to persist, gets the 64-byte raw Ed25519
signature back, embeds in the SignedKeyRecord, submits via
`put_public_key`.

The cold-path ML-DSA-65 sign happens elsewhere — writer's
responsibility per the writer contract
(`docs/FEDERATION_DIRECTORY.md` §"Trust contract"). This method
returns when Ed25519 sign completes; the writer kicks off the
cold-path ML-DSA-65 sign immediately afterward (no delay, no
batching) and calls `attach_key_pqc_signature` once it lands.

### `Engine.canonicalize_envelope(envelope_json: str) -> bytes`

Persist's canonicalizer surface as the lens-team-preferred
"hide the rules inside persist" shape. Takes a JSON object as a
string, runs through `PythonJsonDumpsCanonicalizer` (sorted keys,
no whitespace, `ensure_ascii=True`), returns the exact byte
sequence that should be signed. Hides the canonicalization rules
where they live anyway (persist's own scrub-signing already uses
them) — no drift risk between lens and persist if either side
touches the rules later.

Workflow:
```python
envelope = {"role": "lens-steward", "scope": "..."}
canonical = engine.canonicalize_envelope(json.dumps(envelope))
classical_sig = engine.sign(canonical)
# Cold path: ML-DSA-65 sign over (canonical || classical_sig)
# happens via the writer's own pipeline; result lands via
# attach_key_pqc_signature.
```

### `Backend::lookup_public_key` dual-read migration

The existing trait method (used by trace verify) now reads from
`federation_keys` first, falls back to `accord_public_keys`
(legacy) on miss. Lens can now write to the federation surface
and have the existing trace-verify path find the key
automatically — no big-bang switchover, no separate cutover
window for ingest.

Same dual-read in all three backends (memory, postgres, sqlite).

Filter on `federation_keys`: `valid_until IS NULL OR valid_until
> NOW()`. Filter on `accord_public_keys` retained:
`revoked_at IS NULL AND (expires_at IS NULL OR expires_at >
NOW())`. Strict consumers can layer the federation revocation
check via `revocations_for()` in addition.

The legacy fallback retires at v0.4.0 per the roadmap
(`docs/ROADMAP.md`). Until then, both tables are load-bearing
during the migration window.

### Tests + features

154 lib tests green (+2 dual-read parity tests on memory backend);
clippy clean across `postgres,sqlite,server,pyo3,tls`; cargo-deny
clean.

### Lens action

`pip install --upgrade ciris-persist==0.2.1`. Federation cutover
flow now end-to-end without exposing the keyring seed:

```python
import json
envelope = {"role": "lens-steward", ...}
canonical = engine.canonicalize_envelope(json.dumps(envelope))
classical_sig = engine.sign(canonical)
# build SignedKeyRecord with classical_sig in
# scrub_signature_classical, scrub_signature_pqc=None initially
engine.put_public_key(json.dumps({...record...}))
# cold path produces ML-DSA-65 sig
engine.attach_key_pqc_signature(key_id, mldsa_pubkey_b64, mldsa_sig_b64)
# trace verify (Backend::lookup_public_key in the ingest path) now
# finds the key in federation_keys without any cutover step
```

## [0.2.0] — 2026-05-02

**Federation Directory** (registry-aligned per
`CIRISRegistry/docs/FEDERATION_CLIENT.md`). Lens-team-ready wheel
for cutting public key storage over to persist's federation
substrate. PoB §3.1 federation primitives land as the v0.2.x track.

### What ships

**Schema** — three tables with cryptographic provenance on every
row:

- `federation_keys` — pubkey rows (agent, primitive, steward,
  partner). Hybrid Ed25519 + ML-DSA-65 only;
  `algorithm = 'hybrid'` CHECK-enforced.
- `federation_attestations` — many-to-many "key A vouches for /
  witnesses / referred / delegated_to key B". Append-only.
- `federation_revocations` — append-only revocation log. Consumers
  compute "is K revoked?" by their own policy.

Every row carries the v0.1.3 four-tuple
(`original_content_hash`, `scrub_signature_classical`,
`scrub_key_id`, `scrub_timestamp`) plus PQC components
(`scrub_signature_pqc`) and `pqc_completed_at`. FK chain
terminates at out-of-band-anchored stewards.

**Trait** — `FederationDirectory` (8 base methods + 3 cold-path
attach methods, 11 total):

```rust
trait FederationDirectory {
    // Public keys
    fn put_public_key(&self, record: SignedKeyRecord) -> Result<()>;
    fn lookup_public_key(&self, key_id: &str) -> Result<Option<KeyRecord>>;
    fn lookup_keys_for_identity(&self, identity_ref: &str) -> Result<Vec<KeyRecord>>;
    // Attestations
    fn put_attestation(&self, attestation: SignedAttestation) -> Result<()>;
    fn list_attestations_for(&self, attested_key_id: &str) -> Result<Vec<Attestation>>;
    fn list_attestations_by(&self, attesting_key_id: &str) -> Result<Vec<Attestation>>;
    // Revocations
    fn put_revocation(&self, revocation: SignedRevocation) -> Result<()>;
    fn revocations_for(&self, revoked_key_id: &str) -> Result<Vec<Revocation>>;
    // Cold-path PQC fill-in
    fn attach_key_pqc_signature(&self, key_id, mldsa_pubkey, mldsa_sig) -> Result<()>;
    fn attach_attestation_pqc_signature(&self, attestation_id, mldsa_sig) -> Result<()>;
    fn attach_revocation_pqc_signature(&self, revocation_id, mldsa_sig) -> Result<()>;
}
```

No `is_trusted()`, `trust_score()`, `trust_path()`, or any
policy-bearing method. Consumers compose policy by walking the
attestation graph.

**Backends** — all three implement `FederationDirectory`:
`MemoryBackend`, `PostgresBackend`, `SqliteBackend`. Same
contract; same conformance suite.

**PyO3 surface** — 11 `Engine` methods exposed to Python with
JSON-string payload shape (lens calls `json.dumps`/`json.loads`
once per call):

```python
engine.put_public_key(json.dumps({"record": {...}}))
record_json = engine.lookup_public_key("agent-key-id")
# Optional[str]; None when missing
record = json.loads(record_json) if record_json else None
```

Same shape for attestations, revocations, attach_*_pqc_signature.
Errors translate: caller-fault → `ValueError` (4xx),
server-fault → `RuntimeError` (5xx). `Conflict` (e.g. on
double-PQC-fill) → `ValueError`.

### PQC strategy: hot Ed25519, cold ML-DSA-65

**Hybrid Ed25519 + ML-DSA-65 is the only signing scheme across
the federation.** Per CIRISVerify `ManifestSignature` +
`HybridSignature` (`function_integrity.rs:149`,
`ciris-crypto/types.rs:156`). Bound signature pattern: PQC
covers `data || classical_sig` to prevent stripping.

But waiting until everything is fast PQC ships nothing. So:

| Step | Path |
|---|---|
| 1. Sign canonical with Ed25519 | hot, synchronous |
| 2. Write the row (PQC fields None) | hot |
| 3. **IMMEDIATELY** kick off ML-DSA-65 sign on cold path | cold, no delay, no batching |
| 4. Call `attach_*_pqc_signature` once cold path completes | cold |

Writers commit to the contract; persist tracks via
`pqc_completed_at`. Telemetry signal:
`pqc_completed_at IS NULL` rows are pending; alarm if pending
too long. When quantum threat materializes, runtime policy
flips (`require_pqc_on_write=true`), step 3 folds into the
synchronous path, and post-flip rows are hybrid from the start.
Pre-flip pending rows walk through the upgrade pipeline.

Net property: every row in the historical audit chain ends up
hybrid-signed (post-quantum safe). Federation speed at write
time is Ed25519 latency, not Ed25519+ML-DSA-65 latency.

### Trust contract — eventual consistency as a federation primitive

Persist's promise to consumers is a **layered set of
eventual-consistency commitments** (PQC completion, replication,
cache freshness, peer attestation, revocation propagation), each
with an observability signal. Consumers compose their own trust
verdict — strict-hybrid / soft-hybrid+freshness / pure-attestation-
graph / coherence-stake — using persist's signals. Persist
exposes substrate, never verdicts.

See `docs/FEDERATION_DIRECTORY.md` §"Trust contract — eventual
consistency as a federation primitive" for the full architectural
treatment.

### Registry coordination

CIRISRegistry's v1.4 scaffolding (vendored types,
FederationDirectory trait, migration 024 cache columns, dual-write
feature flag, telemetry counters, audit-log envelope_hash
metadata) is unblocked by this release. Their R_BACKFILL can
begin.

Their vendored types in
`rust-registry/src/federation/types.rs` will need a follow-up to
match v0.2.0's hybrid shape (split `pubkey_base64` →
`pubkey_ed25519_base64` + `pubkey_ml_dsa_65_base64` Optional;
split `scrub_signature` → `scrub_signature_classical` +
`scrub_signature_pqc` Optional; add `pqc_completed_at`
Optional). I'll flag in their FEDERATION_CLIENT.md once the
v0.2.0 wheel is on PyPI.

### Tests + features

154+ tests green (152 lib + ≥22 integration); clippy clean
across `postgres,sqlite,server,pyo3,tls`; cargo-deny clean.

### Lens action

`pip install --upgrade ciris-persist==0.2.0`. The wheel exposes
the 11 federation methods on the existing `Engine`. Cutover
suggestion:

1. Run `Engine.run_migrations()` — V004 applies, federation
   tables exist alongside the existing `accord_public_keys`.
2. Write a self-signed `lens-steward` row to bootstrap the trust
   chain.
3. Migrate existing pubkeys from `accord_public_keys` → call
   `put_public_key` for each (with `scrub_key_id = lens-steward`).
4. Validate parity by reading back via `lookup_public_key`.
5. Cut new pubkey writes over to the federation surface;
   `accord_public_keys` becomes legacy for the duration of the
   migration window.

PQC: lens may write Ed25519-only initially (PQC fields None),
then call `attach_key_pqc_signature` once cold path completes.
The contract is PQC kickoff is immediate-not-batched; persist
tracks but doesn't enforce. Stricter consumers that need
hybrid-complete-only refuse pending rows at read time per their
own policy.

### Deferred to v0.2.x

- `persist-steward` bootstrap row (V005 migration) — pending
  CIRISCore Ed25519 + ML-DSA-65 keypair handoff.
- Helper binary updates for hybrid handoff protocol
  (`derive_persist_steward_bootstrap.rs`).
- Fixture JSON for registry serde validation.
- Telemetry: `federation_pqc_pending_age_seconds_max`.
- Verify subsumption (CIRISPersist#4 — `Engine` grows
  `sign`/`public_key`/`verify_build_manifest`/etc. proxy methods
  so lens/agent/bridge drop direct `ciris-verify` imports).

## [0.1.21] — 2026-05-02

SQLite Backend Phase 1 parity. Sovereign-mode + Pi-class
deployments per FSD §7 #7. Lens team requested before v0.2.0.

Closes the long-standing gap between
"`Backend` trait sealed Phase 1 to support every substrate" and
"only postgres + memory implementations exist". With v0.1.21 the
substrate matrix matches the trait surface — same lens ingest
path runs against postgres in datacenter deployments and SQLite
on a Pi-class node, no rewrites in between.

### What ships

**Migrations** (`migrations/sqlite/lens/`):
- `V001__trace_events.sql` — translates the postgres V001 schema
  to SQLite types: `BIGSERIAL` → `INTEGER PRIMARY KEY
  AUTOINCREMENT`, `TIMESTAMPTZ` → `TEXT` (RFC 3339), `JSONB` →
  `TEXT`, `BOOLEAN` → `INTEGER`, `DOUBLE PRECISION` → `REAL`. Drops
  postgres-isms not portable to SQLite: `CREATE SCHEMA cirislens`,
  the `cirislens.` namespace prefix, TimescaleDB hypertable
  creation, `IS DISTINCT FROM` (replaced with `IS NOT`). Same
  dedup index shape (`agent_id_hash, trace_id, thought_id,
  event_type, attempt_index, ts`) — THREAT_MODEL.md AV-9 protection
  is identical.
- `V003__scrub_envelope.sql` — translates the v0.1.3 ALTER TABLE
  ADD COLUMN. SQLite 3.2+ supports the ADD COLUMN form natively.

**SqliteBackend** (`src/store/sqlite.rs`, ~580 LoC):
- `Backend` trait Phase 1 surface implemented:
  `insert_trace_events_batch`, `insert_trace_llm_calls_batch`,
  `lookup_public_key`, `sample_public_keys`, `run_migrations`.
- Phase 2/3 inherit the trait `NotImplemented` defaults.
- Connection model: `Arc<Mutex<rusqlite::Connection>>`. Phase 1's
  single-ingest-writer-per-process shape (FSD §3.4 robustness
  primitive #1) means contention on the mutex is structurally
  negligible.
- Async adapter: every SQL call wrapped in
  `tokio::task::spawn_blocking`. rusqlite is sync; spawn_blocking
  moves the work to a tokio worker thread.
- File-backed and `:memory:` constructors:
  `SqliteBackend::open(path)` and `SqliteBackend::open_in_memory()`.
- Boot pragmas: `foreign_keys = ON`, `journal_mode = WAL`,
  `synchronous = NORMAL`. WAL gives concurrent readers without
  blocking the single writer; NORMAL durability is the right
  trade for the lens use case (durability via the v0.1.7 journal
  is the recovery primitive, not fsync-per-write).

**Cargo.toml** — `sqlite` feature is now real:
- `sqlite = ["dep:rusqlite", "dep:refinery", "refinery/rusqlite"]`
- `rusqlite` 0.31 (pinned since v0.1.9 to match
  `ciris-verify-core`'s transitive dep) with `bundled` + `chrono`
  + `serde_json` features.
- `refinery` already in postgres feature; `sqlite` adds the
  `rusqlite` feature on it for embedded-migration support.
- Cargo unifies cleanly when both `postgres` and `sqlite` are
  on (refinery built with both `tokio-postgres` and `rusqlite`
  features).

**Tests** — 7 new unit tests in `src/store/sqlite::tests`:
- `migrations_run_clean_in_memory` — refinery applies V001 + V003
  to a fresh DB; re-running is a no-op.
- `insert_idempotent` — second insert of the same row hits ON
  CONFLICT DO NOTHING (mirrors postgres test).
- `distinct_attempts_both_land` — different attempt_index → two
  rows (FSD §3.4 #4 per-attempt dedup).
- `llm_calls_batch_insert` — batch insert into trace_llm_calls.
- `empty_batches_are_noops` — zero-row batches return without
  touching the DB.
- `lookup_public_key_round_trip` — base64 → 32-byte VerifyingKey
  parsing matches postgres impl.
- `revoked_keys_filtered` — `revoked_at IS NOT NULL` filters out
  of both `lookup_public_key` and `sample_public_keys`.

### What this enables

- **Sovereign-mode lens** — single agent + lens on a Pi-class node
  lands traces directly into a SQLite file. No Postgres
  infrastructure needed.
- **Local dev** — tests can run against in-memory SQLite without
  Docker compose for postgres. Already shipped: 7 sqlite tests
  use `:memory:` and are part of the default test suite.
- **Pi-class deployments** — FSD §7 #7's "4GB-RAM solar-LoRa
  node" deployment shape becomes viable; the same crate API the
  multi-tenant lens uses serves the sovereign deployment.

### Substrate matrix after v0.1.21

| Backend | Use case | Status |
|---|---|---|
| `MemoryBackend` | Tests, parity-check fixtures | Phase 1 ✓ |
| `PostgresBackend` | Multi-tenant lens, datacenter | Phase 1 ✓ |
| `SqliteBackend` | Sovereign-mode, Pi-class | Phase 1 ✓ (NEW) |

All three implement the same `Backend` trait Phase 1 surface;
all three pass the same parity expectations. Phase 2/3 surfaces
land per the roadmap (`docs/ROADMAP.md`).

### Tests + features

150 tests green (128 lib + 22 integration; +7 sqlite). Clippy
clean across the full feature matrix
(postgres + sqlite + server + pyo3 + tls). cargo-deny clean.

### v0.2.0 unblocked

This was the gate the lens team requested before persist v0.2.0
(verify subsumption, CIRISPersist#4). With v0.1.21 in place, v0.2.0
ships next per `docs/V0.2.0_VERIFY_SUBSUMPTION.md`.

## [0.1.20] — 2026-05-02

P0 production fix #3, **second attempt** — v0.1.19 didn't close
the drift it claimed to.
Closes [`CIRISPersist#7`](https://github.com/CIRISAI/CIRISPersist/issues/7).

### Why v0.1.19 failed

Bridge re-ran `Engine.debug_canonicalize` against v0.1.19 with the
same `agent-62593bcd5a47__detailed__YO-REJECTED.json` body that
diagnosed the drift originally:

```
v0.1.19 emit: ..._usd":0.003199200000000001 ,"duration_ms":1433.2029819488523,...
python json:  ..._usd":0.0031992000000000006,"duration_ms":1433.2029819488525,...
sha256: e36f43dfba2bb1f6 (lens) vs af847a081ae634d1 (agent's signed)
```

Same drift, same fixtures. v0.1.19's plan was to *reproduce*
Python's `repr` from a Rust f64 via lexical-core's
`PYTHON_LITERAL` format with threshold tuning. That plan was
fundamentally wrong: lexical-core (like ryu, like every "shortest
round-trip" library that's not CPython itself) picks the same
shortest-form tie-break as ryu. **CPython's `Py_dg_dtoa` picks
differently** at representation boundaries — it adds one extra
digit (17-char form) where shortest would be 16 chars. Both
round-trip; both valid; different bytes.

More importantly: **the original token is not recoverable from a
Rust f64**. `0.003199200000000001` and `0.0031992000000000006`
parse to the same f64 bits. By the time we have a Rust `f64`,
the digits the agent originally wrote are gone.

### v0.1.20: preserve, don't reproduce

Enable `serde_json`'s `arbitrary_precision` feature. With it,
`serde_json::Number` is internally a `String` — the original
parsed wire token. `Number`'s `Display` impl emits that string
verbatim. Result:

| Path | Behavior |
|---|---|
| Wire bytes → parse → canonical bytes | byte-equal token preservation |
| `json!(42)` → canonical bytes | `"42"` (Rust integer Display, agrees with Python) |
| `json!(3.14)` → canonical bytes | Rust f64 Display (empirically agrees with Python on shortest-round-trip digits for production-range doubles, including the bridge's YO captures) |

For the verify path — the path that matters — we never construct
Numbers from Rust f64s. We always parse from agent wire bytes
and walk the parsed `Value` to canonicalize. With
`arbitrary_precision`, that walk preserves the agent's tokens
byte-exact.

### Empirical proof of the fix

Pre-feature-flag: parsing `0.0031992000000000006`, the f64 bits
get `Display`'d via ryu to `"0.003199200000000001"` — drift.

With `arbitrary_precision`:
```
in : {"x":0.0031992000000000006}
out: {"x":0.0031992000000000006}
in : {"x":1e-05}
out: {"x":1e-05}
in : {"x":1.7976931348623157e+308}
out: {"x":1.7976931348623157e+308}
```

All Python format variants (scientific threshold `1e-05` vs
`0.0001`, exponent padding `1e-06`, signed-positive exponent
`1e+16`) round-trip byte-identical because we never re-format —
we preserve the parsed token.

### What changed in code

`src/verify/canonical.rs`:

- `write_number` collapsed from 30 lines (i64/u64/f64 dispatch
  through `write_python_float`) to a single
  `write!(buf, "{n}")` call.
- `write_python_float` deleted (~80 lines).
- Module docstring updated to call out the v0.1.20 approach
  ("preserve, don't reproduce") and explicitly retire v0.1.19's
  reproduction plan.

`src/verify/canonical.rs` tests:

- `bridge_captured_divergent_floats_match_python` (v0.1.19) →
  removed; the test was constructed via `json!(0.003199...)`
  which goes through ryu before our writer ever sees it. With
  `arbitrary_precision`, Rust's std f64 Display happens to agree
  with Python on these specific values, but the test's
  *premise* (we can recover Python's bytes from a Rust f64) was
  false.
- `production_range_floats_match_python_repr` (v0.1.19) →
  removed; same premise problem.
- `wire_floats_preserved_through_canonicalization` (new) →
  parse the bridge's exact YO byte sequence; assert canonical
  bytes are byte-equal.
- `wire_python_format_variants_preserved` (new) → 14 Python
  format variants (scientific thresholds, exponent padding,
  signed-positive exponent, large/small extremes) — each parsed
  as wire bytes and asserted byte-equal through canonicalization.
- `llm_call_data_blob_wire_preserved` (new) → end-to-end
  parse-then-emit on the LLM-call dict shape from the bridge's
  capture.
- `wire_preservation_with_key_resorting` (new) → token
  preservation does not skip `sort_keys=True`; bodies arrive
  unsorted come out sorted with tokens preserved.

`Cargo.toml`:

- `serde_json` gets `arbitrary_precision` feature.
- `lexical-core` (added v0.1.19) removed.

### Trade-off: feature unification

`arbitrary_precision` is a serde_json feature flag. Cargo
unifies features across the dep tree, so any crate that pulls
ciris-persist transitively also gets `arbitrary_precision` on
its serde_json. Externally observable behavior under stable
serde_json APIs (`Number::as_f64`, `as_i64`, `as_u64`, Value
serialization, etc.) is unchanged. The only difference: code
that pattern-matched on `Number`'s private internal variants
(`Number::F64`, `Number::U64`) would break — but no stable code
does that. Safe.

### What this closes

| Layer | Closed by |
|---|---|
| Timestamp drift | v0.1.8 (`WireDateTime`) |
| Base64 alphabet | v0.1.15 (`decode_signature` URL-safe fallback) |
| Canonical-shape (9-field vs 2-field) | v0.1.16 (try-both) |
| Float formatting (preserve, not reproduce) | **v0.1.20** (`arbitrary_precision`) |

The v0.1.16 try-both-canonical now works as designed: both
9-field and 2-field shapes byte-match the agent because float
bytes finally match. Bridge's flag-on capture against v0.1.20
should show `signatures_verified == envelopes_processed` and
table rowcount growing.

### Tests

143 tests green (121 lib + 22 integration); clippy clean
across all feature combos; cargo-deny clean.

### Lens action

`pip install --upgrade ciris-persist==0.1.20`. v0.1.18's
diagnostic surfaces remain in place; v0.1.20 closes the
underlying canonical-byte drift end-to-end.

### What this did NOT close (but agent did)

CIRIS-Agent 2.7.8.12 (today) closes the **tee/wire byte-equality**
bug — agent's local-tee was writing
`json.dumps(..., ensure_ascii=False, separators=(",",":"))` while
aiohttp's `json=payload` path used Python's defaults
(`ensure_ascii=True`). Pre-2.7.8.12, lens-side
`body_sha256_prefix` from PERSIST_DELEGATE_REJECT couldn't match
any local-tee file. Separate fix; both must be true for clean
forensic correlation.

## [0.1.19] — 2026-05-02

P0 production fix #3 from the same diagnostic round (**superseded
by v0.1.20** — the lexical-core approach didn't actually close
the drift). Kept in this changelog for the diagnostic record.
Closes [`CIRISPersist#7`](https://github.com/CIRISAI/CIRISPersist/issues/7).
The bridge's v0.1.18 capture pinned the canonical-bytes drift to
**float formatting**: Rust's `ryu` (via `serde_json`'s default
`Display` impl on `Number`) and Python's `float.__repr__` (Gay's
`dtoa`) disagree on shortest-round-trip output for ambiguous
doubles.

### The bug

Concrete divergence from production traffic:

| f64 value | Rust ryu | Python repr |
|---|---|---|
| same double | `0.003199200000000001` | `0.0031992000000000006` |
| same double | `1433.2029819488523`   | `1433.2029819488525` |

Both strings round-trip to identical IEEE 754 doubles. Both are
valid "shortest round-trip" outputs. The algorithms (Adams 2018
ryu vs Steele-White / Gay's dtoa) differ on tie-breaking. Result:
universal `verify_signature_mismatch` on every YO-locale batch
across all three captured wire bodies, ~59-byte cumulative
divergence per trace.

### The fix

Route `Value::Number` through a Python-compatible writer.
`write_python_float` in `src/verify/canonical.rs`:

- **`lexical-core` PYTHON_LITERAL format**, with
  `negative_exponent_break(-4)` + `positive_exponent_break(15)`
  tuned to match Python's switch from decimal to scientific at
  `|f| < 1e-4` or `|f| >= 1e16`.
- **Scientific-form post-process** for the format-detail
  differences lexical leaves on the table:
  - Strip `.0` from `1.0eN` → `1eN` (Python doesn't write the
    `.0` for integer-valued mantissas in scientific form).
  - Add `+` sign for non-negative exponents → `1e+16` /
    `1.7976931348623157e+308`.
  - Pad single-digit exponent magnitude to ≥ 2 digits → `1e-05`
    / `1.5e-06`.
- **Integer fast-path** preserved: `Number::as_i64()` /
  `as_u64()` paths use bare `{}` Display (`42`, not `42.0`).

### Test coverage

4 new unit tests in `verify::canonical::tests`:

1. **`bridge_captured_divergent_floats_match_python`** — the two
   exact divergent values from the bridge's YO captures
   (`0.0031992000000000006`, `1433.2029819488525`). Pre-v0.1.19
   these round-tripped via ryu to the wrong shortest form.
2. **`production_range_floats_match_python_repr`** — 22
   `(input, python_reference)` pairs covering identity (0.0, 1.0,
   100.0), arithmetic edge cases (`0.1 + 0.2`, `1.0 / 3.0`),
   decimal/scientific threshold boundaries (`1e-4`, `1e-5`,
   `1e15`, `1e16`), and large/small extremes
   (`1e+100`, `1e-100`, `1.7976931348623157e+308`). Each pair
   was generated via `python3 -c "import json; print(json.dumps(<input>))"`
   ground truth.
3. **`integers_render_bare_no_decimal_point`** — `serde_json::Number`
   carrying integers must skip the float formatter (no `.0`
   suffix). Covers i64 + u64 ranges including `i64::MAX` and
   `u64::MAX`.
4. **`llm_call_data_blob_matches_python`** — end-to-end shape:
   the dict an LLM-call component carries (`cost_usd`,
   `duration_ms`, `prompt_tokens`, `score`) canonicalizes
   byte-identical to Python's `json.dumps(..., sort_keys=True,
   separators=(',', ':'))`.

### What this closes

Three independent layers now cover the verify-mismatch surface
on real agent traffic:

| Layer | Closed by |
|---|---|
| Timestamp drift | v0.1.8 (`WireDateTime` preserves wire bytes) |
| Base64 alphabet | v0.1.15 (`decode_signature` accepts STANDARD + URL_SAFE) |
| Canonical-shape (9-field vs 2-field) | v0.1.16 (try-both fallback) |
| **Float formatting** | **v0.1.19** (`write_python_float` matches Python's `repr`) |

The v0.1.16 try-both-canonical fallback now WORKS as designed:
both 9-field and 2-field shapes byte-match the agent because
their float representation matches. Bridge's flag-on capture
against v0.1.19 should show
`signatures_verified == envelopes_processed`, table rowcount
growing.

### Known limitation

Python's `Py_dg_dtoa` and lexical-core's underlying algorithm
CAN diverge on rare shortest-round-trip ties beyond what
threshold tuning + post-process fixes. The 22 production-range
test cases all match; if a future bridge capture surfaces a new
divergent f64, we ship a v0.1.x patch with a more exact
algorithm (vendored Gay's-dtoa Rust port, ~500 LoC, tracked on
the v0.2.x roadmap).

### Tests + deps

142 tests green (118 lib + 24 verify ed25519/canonical + 8 QA +
9 fixture); clippy clean across all feature combos; cargo-deny
clean.

New direct dep: **`lexical-core` 1.0.6** with `format` +
`write-floats` features. The Rust ecosystem's most flexible
number-formatter; specifically supports the cross-language
parity our use case demands.

### Lens action

`pip install --upgrade ciris-persist==0.1.19`. v0.1.18's wheels
have all the diagnostic surfaces in place; v0.1.19 closes the
underlying canonical-byte drift the diagnostics surfaced.
Bridge's flag-on capture should finally show clean verify
end-to-end.

## [0.1.18] — 2026-05-02

Diagnostic round 2 for [`CIRISPersist#6`](https://github.com/CIRISAI/CIRISPersist/issues/6) — extending v0.1.17's
unknown-key breadcrumb onto the `SignatureMismatch` path so the
bridge can pinpoint canonical-byte drift without source-level
instrumentation. Plus an optional `Engine.debug_canonicalize()`
PyO3 method for offline diff against a Python reference.

### What's new

- **`tracing::warn!` breadcrumb on the `SignatureMismatch` branch**
  in `IngestPipeline::verify_complete_trace`. Fires after
  `verify_trace` has tried both 9-field (spec) and 2-field
  (legacy) canonicals and neither verified. Surfaces:

  ```
  envelope_signer_id           agent-…
  wire_body_sha256             …                ← joins lens-side body_sha256_prefix
  canonical_9field_sha256      …                ← persist's 9-field canonical bytes
  canonical_2field_sha256      …                ← persist's 2-field canonical bytes
  canonical_9field_bytes_len   N
  canonical_2field_bytes_len   M
  signature_b64_prefix         first 16 chars   ← cross-check on which sig
  ```

  Three diagnostic outcomes the bridge can resolve offline:

  | Bridge's offline `json.dumps(canonical, sort_keys=True, separators=(",",":")).hash()` matches | Diagnosis | Fix |
  |---|---|---|
  | `canonical_9field_sha256` | Persist's 9-field canonicalizer is byte-correct; agent signed 2-field | Check why 2-field fallback didn't match — agent's `strip_empty` differs |
  | `canonical_2field_sha256` | Persist's 2-field canonicalizer is byte-correct; agent signed 9-field but persist's 9-field has subtle drift | Persist 9-field bytes diverge from spec |
  | Neither | Agent signs over a third shape we haven't enumerated | Agent-side investigation |

- **`Engine.debug_canonicalize(body: bytes) -> list[dict]`** — new
  PyO3 method. Runs body through schema parse + canonicalizer,
  returns BOTH canonical shapes (sha256 + base64-encoded full
  bytes + length) for each `CompleteTrace` in the body. Lets the
  bridge pipe any captured wire body through persist's
  canonicalizer offline:

  ```python
  result = engine.debug_canonicalize(body_bytes)
  # [
  #   {
  #     "trace_id": "trace-...",
  #     "signature_key_id": "agent-...",
  #     "signature": "<wire b64>",
  #     "canonical_9field_sha256": "...",
  #     "canonical_9field_b64": "...",       # full bytes, b64
  #     "canonical_9field_bytes_len": 16149,
  #     "canonical_2field_sha256": "...",
  #     "canonical_2field_b64": "...",
  #     "canonical_2field_bytes_len": 15827,
  #   }
  # ]
  ```

  Diagnostic-only. Doesn't verify, doesn't write, doesn't
  increment metrics. Future-proof for any future schema-version
  / canonicalization tweaks.

- **`pub(crate)` exposure of `canonical_payload_value_legacy`** so
  the breadcrumb + `debug_canonicalize` can re-canonicalize on
  the slow path without duplicating code.

- **`canonical_payload_sha256s(trace, canonicalizer)` helper** in
  `verify::ed25519` returning a `CanonicalDiagnostic` carrier
  (sha256s + raw bytes for both shapes). Used by both the
  breadcrumb and `debug_canonicalize`.

### Implementation notes

- v0.1.18 also adds **`wire_body_sha256`** to v0.1.17's
  `verify_unknown_key` breadcrumb so unknown-key + signature-
  mismatch logs share the same correlation field with the
  lens's POST-receipt log.
- Diagnostic computation is best-effort. If canonicalization
  itself fails (which can't happen if `verify_trace` just
  exercised the same code path and bubbled `SignatureMismatch`),
  the warn fires with `None` for the canonical fields and the
  typed error returns normally.
- Zero hot-path cost on happy-path verifies. Both breadcrumbs
  fire only in the slow paths (`Ok(None)` lookup or
  `SignatureMismatch`).

### Tests

138 tests green (116 lib + 5 AV-4 + 8 QA + 9 fixture); clippy
clean. No new test for the breadcrumb itself — its effect is
observable only against a real production rejection capture.

### What this doesn't fix yet

The actual canonical-bytes drift. v0.1.18 is purely diagnostic.
Once bridge captures the SignatureMismatch warn against a flag-
on run, the next patch closes whichever of the three diagnostic
outcomes lands.

## [0.1.17] — 2026-05-02

Diagnostic breadcrumb for [`CIRISPersist#6`](https://github.com/CIRISAI/CIRISPersist/issues/6) —
the bridge's flag-on capture against v0.1.16 surfaced a new
universal reject (`verify_unknown_key`) that doesn't fit any of
the four hypothesis classes a non-persist-side observer can
falsify. Source review confirms persist's `lookup_public_key` is
a direct SQL query (no internal cache, no input transform), so
the answer lives somewhere between persist's pool/connection
state and the actual SQL it's running.

This release adds **lookup-time observability** so the next
flag-on capture pinpoints which.

### What's new

- **`Backend::sample_public_keys(limit) -> PublicKeySample`** —
  new trait method returning total count of valid (unrevoked,
  unexpired) `accord_public_keys` rows + a stable-ordered sample
  of the first `limit` `key_id` values. Default impl is empty
  (memory backend); `PostgresBackend` runs `SELECT COUNT(*)` +
  `LIMIT N` against the same WHERE clause as
  `lookup_public_key` — so what the diagnostic sees is exactly
  what the runtime lookup is querying against.
- **`PublicKeySample`** struct re-exported from `crate::store`
  for diagnostic use. Not part of the production ingest contract.
- **`tracing::warn!` breadcrumb in `IngestPipeline::verify_complete_trace`**
  fires when `lookup_public_key` returns `Ok(None)`. Surfaces:
  - `envelope_signer_id`: the agent's claimed `signature_key_id`
  - `looked_up_id_bytes_hex`: same value as raw bytes (catches
    invisible-char drift)
  - `looked_up_id_byte_len`: integer length, easy grep
  - `accord_public_keys_size`: total valid rows persist sees
  - `accord_public_keys_sample`: first 5 `key_id` values in
    backend order

### Three diagnostic outcomes the bridge will see

| Observation | Conclusion |
|---|---|
| `accord_public_keys_size` differs from external `SELECT COUNT(*)` | Persist queries a different scope than the external check |
| `accord_public_keys_size` matches AND sample includes the target id | Lookup path has a bug; the rows ARE visible to persist |
| Sample shape (length / chars) differs from `envelope_signer_id` | Id transform somewhere in the deserialization path |

### Implementation notes

- Sample query uses the exact same WHERE clause as
  `lookup_public_key` — same connection from the same deadpool,
  same MVCC view per `tokio-postgres` autocommit semantics. If
  there's a pool-state weirdness causing the lookup miss, the
  sample will reflect the same weirdness (which is actually what
  we want for diagnosis — same weirdness, same blind spot).
- Best-effort: if `sample_public_keys` itself errors, the warn
  still fires with `None` for the diagnostic fields, and the
  typed `UnknownKey` error returns normally.
- Zero hot-path cost for happy-path verifies: the breadcrumb only
  fires when lookup misses.

### Tests

136 tests green (no regression); clippy clean. No new test —
breadcrumb effect is observable only against a real Postgres
backend with rows the lookup misses, which is exactly the
scenario the bridge will capture.

### What this doesn't fix yet

The actual lookup miss. v0.1.17 is purely diagnostic — once
bridge captures the warn output against a flag-on run, the next
patch (v0.1.18 or v0.1.x.y depending on root cause) closes
whichever of the three diagnostic outcomes lands.

### Notes for the bridge team

Flip the persist flag on for one capture window with
`RUST_LOG=ciris_persist=warn` (or wider if useful). Capture the
single `verify_unknown_key` warn for any rejected batch and ship
it back. Three lines of structured fields will pinpoint the root
cause class.

## [0.1.16] — 2026-05-02

P0 production fix #2 from the same diagnostic round that produced
v0.1.15. Closes [`CIRISPersist#5`](https://github.com/CIRISAI/CIRISPersist/issues/5).

### The bug (next layer of AV-4)

v0.1.15 fixed the base64 alphabet mismatch — every batch's
signature decoded successfully (64 bytes via the alphabet-agnostic
decoder). But every YO-locale batch still rejected with
`verify_signature_mismatch`. The bridge's diagnostic capture pinned
the next layer:

- Decode succeeds (64 bytes)
- Pubkey lookup succeeds (`accord_public_keys` table populated)
- `verify_strict` returns false because **persist canonicalizes 9
  fields per `TRACE_WIRE_FORMAT.md` §8 spec, but the agent fleet
  signs only 2 fields** (`{components, trace_level}`,
  post-`strip_empty`).

The agent's signing code (`Ed25519TraceSigner.sign_trace` in
`CIRISAgent/ciris_adapters/ciris_accord_metrics/services.py`) and
the lens-legacy verifier (`CIRISLens/api/accord_api.py
::verify_trace_signature`) both use the 2-field shape. The 9-field
spec form is the eventual target; agent migration is a separate
coordinated change.

Bytes diff on a real captured YO-rejected trace:

| canonical | bytes | sha256 prefix |
|---|---|---|
| 2-field (agent + lens-legacy actually-signed) | 15,827 | `af847a081ae634d1` |
| 9-field (spec / persist v0.1.15) | 16,149 | `bd6b48689df8adca` |

Different bytes → different sha256 → `verify_strict` returns false
on every batch.

### The fix — try-both fallback

Same defensive shape as v0.1.15's base64 fallback, applied at the
canonical-bytes layer. New `verify_trace`:

```rust
// 1. Decode signature (alphabet-agnostic per v0.1.15)
// 2. Try 9-field canonical first (spec target)
// 3. Fall back to 2-field canonical (agent + lens-legacy)
// 4. SignatureMismatch only if BOTH fail
```

The 2-field path uses `canonical_payload_value_legacy(trace)` —
serializes each component via serde, applies `strip_empty`
recursion (drops `null`/`""`/`[]`/`{}` at every nesting level)
to match the agent's pre-signature shape, and wraps in
`{"components": [...], "trace_level": "..."}`.

### Migration path

The 9-field spec form gains more provenance binding into the
signed bytes (`trace_id`, `thought_id`, `task_id`, `agent_id_hash`,
`started_at`, `completed_at`, `trace_schema_version`). When the
agent migrates to it, persist's primary path verifies cleanly and
the fallback never fires. Tracking agent-side migration via
**CIRISAgent issue** (sibling filing alongside this one); persist's
try-both keeps verifying both shapes through the migration window.

`TRACE_WIRE_FORMAT.md` §8 should split into "current (deprecated,
accepted through migration window)" and "v2 (target)" sections so
the spec reflects fleet state, not just the target.

### Regression coverage

3 new unit tests in `src/verify/ed25519.rs::tests`:

- `legacy_two_field_signed_trace_verifies` — sign the 2-field
  form (production shape), persist verifies via fallback. Pre-
  v0.1.16 this rejected on every YO-locale batch.
- `legacy_two_field_tampered_rejected` — tamper after legacy
  signing, both 9-field AND 2-field verify fail, typed
  `SignatureMismatch`. Confirms the fallback doesn't widen the
  security surface.
- `strip_empty_drops_empties_recursively` — exhaustive coverage
  of the recursion: null/empty-string/empty-array/empty-object
  drop at every nesting level; numbers (incl. `0`) and booleans
  (incl. `false`) are NEVER dropped.

### Tests

11 verify-module tests (3 new); 113 lib total + 5 AV-4 + 8 QA +
9 fixture = **136 tests** all green.

### Lens action

`pip install --upgrade ciris-persist==0.1.16`. v0.1.15's wheels
have the base64 fix but reject every real production batch on
the canonical-shape mismatch. v0.1.16 closes the round-trip;
PERSIST_DELEGATE_RESULT lines should show
`signatures_verified == envelopes_processed`,
`trace_events_inserted > 0`,
`SELECT count(*) FROM cirislens.trace_events` growing on every
batch.

### Threat model

`THREAT_MODEL.md` AV-4 promoted from "tracked residual / partial
mitigation" to "fully closed". Three independent layers — base64
alphabet (v0.1.15), timestamp drift (v0.1.8), canonical-shape
fallback (v0.1.16) — together close the entire pre-v0.1.x verify-
mismatch surface area on real agent traffic.

## [0.1.15] — 2026-05-01

P0 production fix + cohabitation doctrine refinement.

### The P0 fix — base64 alphabet mismatch

Persist's `verify::ed25519::verify_trace` decoded incoming
signatures with `base64::STANDARD` (`+`, `/`, `=` alphabet). The
agent emits signatures via Python's `base64.urlsafe_b64encode`
per `TRACE_WIRE_FORMAT.md` §8 — URL-safe (`-`, `_`, no padding).
**Every production batch failed `verify_invalid_signature`**
because the decoder either errored on `_` / `-` chars or
produced wrong-length bytes that `Signature::from_bytes`
rejected.

Concretely, all 4 wire fixtures in
`tests/fixtures/wire/2.7.0/*.json` use URL-safe-no-pad
signatures (86 chars, contain `-` / `_`, no `=`). Pre-v0.1.15
these were unverifiable through persist; the fixture tests
silently passed because they stop at decompose without
attempting verify.

This is the **universal** verify failure mode — independent of
canonicalization, payload, trace level, timestamps. AV-4
timestamp drift (closed v0.1.8) was real but secondary; the
base64 alphabet was the load-bearing bug.

### The fix

New `decode_signature(s)` helper in `src/verify/ed25519.rs`
tries `STANDARD` first (cheap; matches admin tooling + tests),
falls back through `URL_SAFE_NO_PAD` then `URL_SAFE`. Same
defensive shape `accord_api.py:1903` uses on the legacy Python
verify path. No agent-side coordination needed; the agent can
emit either alphabet without persist breaking.

### Regression coverage

Two new unit tests in `src/verify/ed25519.rs::tests`:

- `decode_signature_accepts_all_alphabets` — round-trips a
  64-byte payload through all four base64 variants (STANDARD
  with/without padding, URL_SAFE with/without padding); decoder
  must produce identical bytes for all.
- `url_safe_signed_trace_verifies` — end-to-end verify against
  a trace signed with `URL_SAFE_NO_PAD` (the agent's production
  form). Pre-v0.1.15 this rejected; post-v0.1.15 verifies clean.

### Cohabitation doctrine — daemon framing dropped

`docs/COHABITATION.md` rewritten to reflect what's structurally
true: **persist is a Python wheel, not a daemon.** The
"persist owns the keyring because it runs as a process" framing
was wrong. The actual claim:

> Persist is the lowest stateful CIRIS substrate library above
> verify. Its `Engine::__init__` is the canonical entry point
> for keyring resolution on a host. Any consumer importing
> persist gets the serialized-bootstrap guarantee for free; the
> flock makes cold-start safe regardless of how many consumers
> race the import.

Practical changes in the doc:

- Drop `persist.service` / `Requires=After=` systemd examples.
- Drop the k8s init-container example (it implied persist runs
  as a separate process that exits before the workload).
- Replace with multi-worker examples — each worker imports
  persist, all workers race through the flock, all converge on
  the same identity by construction.
- Reframe rule 1 from "persist owns runtime keyring bootstrap"
  to "first `Engine::__init__` on the host bootstraps the
  keyring; subsequent calls see existing key."
- Doctrinal section explains why "lowest stateful library above
  verify" lands persist as the authority — not the process
  shape, but the position in the dependency stack.

Implementation (the v0.1.14 flock) is unchanged. Only the
operator-facing framing.

### Tests

133 lib + 5 AV-4 + 8 QA + 9 fixture = **155 tests** (109 prior
+ 2 new url-safe + 44 verify suite count includes existing).

### Notes

- Lens cutover unblocked. Real production traffic now verifies
  end-to-end through persist.
- v0.1.14's PyPI publish is unaffected — wheels for that version
  carry the bug. Lens should bump persist dep pin to
  `==0.1.15` immediately.

## [0.1.14] — 2026-05-01

Cohabitation doctrine formalized + multi-worker bootstrap race
closed. Persist is now the runtime keyring authority above
CIRISVerify on every host where it runs.

### The doctrine

Three rules governing CIRIS primitives sharing a host:

1. **Persist owns runtime keyring bootstrap.** Other primitives
   cede to persist for `get_platform_signer()`-class operations.
2. **One keyring bootstrap per host/container.** Multi-worker
   deployments serialize cold-start through a filesystem
   `flock`; first worker bootstraps, others see the existing key.
3. **Same-alias = same identity** per PoB §3.2 (one-key-three-
   roles).

Full operator guidance + threat-model angle in
[`docs/COHABITATION.md`](docs/COHABITATION.md). Companion to
CIRISVerify's `HOW_IT_WORKS.md` § "Cohabitation Contract" + AV-14
in their threat model.

### What's new

- **Filesystem flock around `Engine::__init__`'s
  `get_platform_signer()` call.** Lock path:
  `${CIRIS_DATA_DIR}/.persist-bootstrap.lock` (preferred) or
  `/tmp/ciris-persist-bootstrap.lock` (fallback). POSIX `flock`
  auto-releases on FD close (incl. panic) — stuck holders aren't
  a normal failure mode. Lock is held only for the duration of
  `get_platform_signer()` (~50ms warm, ~500ms cold-start), not
  for the lifetime of the Engine.
- **`fs4` crate** added as direct dep for cross-platform safe
  flock semantics. POSIX-style on Linux + macOS; same call shape
  as our existing `pg_advisory_lock` for AV-26.
- **Two new unit tests** in `src/ffi/pyo3.rs::tests`:
  - `bootstrap_lock_path_resolution` — `CIRIS_DATA_DIR` /
    `/tmp` priority.
  - `bootstrap_lock_acquire_and_release` — open+lock+drop
    smoke test against a tempdir.

### What's NOT in v0.1.14

- **Strict process singleton.** Multi-worker deployments are
  real and supported; the flock just serializes cold-start.
- **Public `Engine.sign(payload: bytes)` API.** Architecturally
  the next step (lets primitives consume persist's identity
  directly instead of just deploying after persist), but
  requires consumer-side adoption. Deferred to v0.2.x once a
  concrete asker materializes.
- **Replacement of verify's planned v1.9 keyring-side flock.**
  The two locks compose: persist's lock serializes persist
  consumers; verify's v1.9 will serialize verify-direct
  consumers. Same identity by PoB §3.2.

### Threat model

- **AV-14 (cross-instance keyring contention)** — closed for
  persist consumers. Verify's `THREAT_MODEL.md` AV-14 stays
  open until v1.9 lands their keyring-layer flock for
  non-persist consumers.

### Tests

- 109 lib + 5 AV-4 + 8 QA + 9 fixture = 131 passing
- 2 new pyo3 unit tests for the flock helpers
- clippy clean across all feature combos
- No Rust code changes outside `src/ffi/pyo3.rs`

### Documentation

- **NEW**: `docs/COHABITATION.md` — operator runbook +
  doctrine, with docker-compose, systemd, k8s init-container
  examples. Cross-links to verify's `HOW_IT_WORKS.md` and
  `THREAT_MODEL.md`.
- `docs/INTEGRATION_LENS.md` § 11 — new "Cohabitation: persist
  comes up first" subsection covering multi-worker semantics
  and combined-deployment ordering.

## [0.1.13] — 2026-05-01

Multi-arch PyPI publish across the agent's full Phase 1 PyO3
surface. Closes [`CIRISPersist#3`](https://github.com/CIRISAI/CIRISPersist/issues/3).

### Wheels published

| Target triple | Wheel tag | Runner |
|---|---|---|
| `x86_64-unknown-linux-gnu` | `manylinux_2_34_x86_64` | `ubuntu-latest` |
| `aarch64-unknown-linux-gnu` | `manylinux_2_34_aarch64` | `ubuntu-24.04-arm` |
| `aarch64-apple-darwin` | `macosx_11_0_arm64` | `macos-14` |

Each wheel is `cp311-abi3` so consumer Python ≥ 3.11 picks the
right `(os, arch)` automatically. The agent's matrix per
`FSD/PLATFORM_ARCHITECTURE.md` §3.5; iOS / Android out of scope
(xcframework / UniFFI native packaging, not PyPI).

`darwin-x86_64` intentionally omitted — GitHub Actions Intel
macOS runners (`macos-13`) have ongoing capacity issues that
queue jobs indefinitely. CIRISAgent's matrix dropped it for the
same reason ("macOS Intel: built and uploaded manually (GitHub
runner capacity issues)" in their `build.yml`).
`FSD/PLATFORM_ARCHITECTURE.md` §3.5 already classifies it as a
"sunset target — keep CI green only"; not load-bearing for the
lens cutover. Add back via manual upload if a concrete consumer
materializes.

### CI changes

- **`pyo3-wheel`** — matrix expansion to four entries. Each runs
  on a *native* runner for its target so we avoid cross-compile
  drama (sysroot, linkers, vendored openssl quirks). GitHub
  Actions Linux ARM64 runners (`ubuntu-24.04-arm`) have been
  GA + free for public repos since 2025-01.
- **Per-matrix-entry wheel-shape sanity check** — rejects
  non-`cp311-abi3` builds at build time, not just at publish
  time. Catches v0.1.10-class regressions before they propagate.
- **`build-manifest`** — POSTs all four target hashes in one
  binary-manifest with `binaries: { target: sha256, ... }`.
  Round-trip verify confirms every target's hash matches the
  GET response; any single-target mismatch fails the build.
- **`publish-pypi`** — downloads all four wheel artifacts via
  glob pattern, sanity-checks the count + tag shape, uploads
  all in one `pypa/gh-action-pypi-publish` action call. Single
  PEP 740 sigstore attestation covers the full upload set.

### Lens cold-build win extends to ARM64

Pre-v0.1.13: lens's multi-arch Docker build (`linux/amd64` +
`linux/arm64`) had no PyPI option for arm64 — would either
fall back to compiling persist from source on arm64 (~75min,
defeating the v0.1.12 win) or fail outright if no sdist.

v0.1.13: both arches `pip install ciris-persist==0.1.13` in
~10s. Lens cold-build matrix collapses uniformly across the
two production architectures.

### Provenance

The BuildManifest signing path stays single-target (linux x86_64
canonical reference; per-target signing is a v0.1.14+ deliverable
once a concrete consumer asks). The registry's binary-manifest
covers all four targets via the multi-target `binaries` map;
each target's hash is registry-signed server-side with the
hybrid Ed25519 + ML-DSA-65 steward key. PEP 740 sigstore
attestation on the PyPI upload covers all four wheels in one
attestation bundle.

### Tests

131 tests green (no Rust code changes); clippy clean across
all feature combos.

## [0.1.12] — 2026-05-01

PyPI publication via OIDC trusted publishing. Closes the lens
cold-build bottleneck (~75min Rust compile per cold cache → ~10s
`pip install`).

### What's new

- **`.github/workflows/ci.yml::publish-pypi`** — tag-gated job
  that downloads the abi3 wheel produced by `pyo3-wheel`,
  sanity-checks its shape (rejects non-`cp311-abi3` builds to
  prevent v0.1.10-class regressions silently shipping), and
  publishes to PyPI via `pypa/gh-action-pypi-publish@release/v1`.
- **OIDC trusted publishing** — no API token in CI secrets. PyPI
  validates the workflow's GitHub-issued JWT against a pre-
  configured trust policy. Standard pattern across the OSS
  ecosystem (sigstore cosign, npm provenance, PEP 740 attestations).
- **PEP 740 sigstore attestations** enabled by default
  (`attestations: true`). The PyPI artifact carries a verifiable
  link back to this exact GHA workflow identity, compounding with
  the existing CIRISRegistry BuildManifest signature.
- **Environment-gated** — the publish job runs in the `pypi`
  GitHub environment, allowing optional human-approval gates per
  release if the repo maintainer adds them.

### Operator setup (one-time, on PyPI side)

See `docs/PYPI_PUBLISH.md`. Summary:

1. Reserve `ciris-persist` on PyPI via "Pending Publisher"
   (https://pypi.org/manage/account/publishing/) with:
   - Owner: `CIRISAI`
   - Repository: `CIRISPersist`
   - Workflow: `ci.yml`
   - Environment: `pypi`
2. (Optional) Configure GitHub environment `pypi` with required
   reviewers for human-approval gates.
3. Push v0.1.12 tag → publish triggers automatically.

After v0.1.12 ships:

```bash
pip install ciris-persist==0.1.12
# from python:3.11-slim, ~10 seconds vs ~75min source build
```

### Trust posture

Three independent provenance layers now stack on every release:

| Layer | Proves | Stored at |
|---|---|---|
| git tag + commit hash | source-of-truth identity | GitHub |
| BuildManifest hybrid signature (Ed25519 + ML-DSA-65) | binary built from that commit by CIRISAI's signing key | CIRISRegistry |
| PEP 740 sigstore attestation | PyPI artifact was uploaded by CIRISAI's GHA on that commit | PyPI |

The cryptographic root remains the BuildManifest (hybrid hardware-
ready signature, registry round-trip verified per commit). PyPI is
the fast delivery channel; verifiable but not load-bearing on its
own.

### Notes

- Wheel platform: linux x86_64 only at v0.1.12. macOS / arm64
  wheels can be added later by extending the `pyo3-wheel` matrix;
  not load-bearing for the lens cold-build win that motivated this
  release.
- No code changes; CI workflow + docs only. 131 tests green.

## [0.1.11] — 2026-05-01

CI registration step end-to-end. Closes the implementation half of
[`#2`](https://github.com/CIRISAI/CIRISPersist/issues/2); the issue's
explicit close gate ("at least one persist build registered end-to-end
and round-tripped") now lives in CI.

### CI workflow — three new steps after sign-manifest

1. **Pre-flight steward-key check**. `GET ${REGISTRY_URL}/v1/steward-key`
   logs the registry's active hybrid signing key + `key_id` to the
   GH step summary. Surfaces ephemeral-mode registries
   (registry-side AV-28: when `ED25519_KEY_PATH` / `MLDSA_KEY_PATH`
   aren't configured, every restart cycles the steward pubkey). Does
   not hard-gate registration; visibility-only so operators can see
   the posture before downstream peers do.

2. **Register binary manifest**. `POST ${REGISTRY_URL}/v1/verify/binary-manifest`
   with `project=ciris-persist`, the wheel's sha256, version, target.
   Auth via `Bearer ${REGISTRY_ADMIN_TOKEN}` (registry team issues +
   uploads as a repo secret). Registry signs server-side with its
   steward key.

3. **Round-trip verify**. `GET ${REGISTRY_URL}/v1/verify/binary-manifest/<version>?project=ciris-persist`,
   diff the returned `binaries["x86_64-unknown-linux-gnu"]` sha256
   against what was POSTed. Hash mismatch fails the build with a
   typed error. **This is persist #2's explicit close gate** — a
   green CI run on v0.1.11+ is evidence-of-registration.

### Two new operational secrets / variables

| Name | Type | Provided by | Default |
|---|---|---|---|
| `REGISTRY_URL` | repo variable | persist team | `https://registry.ciris.ai` |
| `REGISTRY_ADMIN_TOKEN` | repo secret | registry team | (required) |

Until `REGISTRY_ADMIN_TOKEN` is set, the registration step fails
with a typed message pointing at `docs/BUILD_SIGNING.md`. Same
pattern as the v0.1.9 `CIRIS_BUILD_*_SECRET` gates: failure is
self-documenting; the operational dependency is visible in CI
output, not buried in code.

### Documentation

- `docs/BUILD_SIGNING.md` — new "Registry registration (v0.1.11+)"
  section: required secrets/vars, the four CI steps, round-trip
  verification semantics, rotation guidance.
- `docs/TODO_REGISTRY.md` — rewritten as a historical "what
  shipped" audit trail. The three TODOs the doc once tracked
  (registry persist support, manifest tool refactor,
  ciris-keyring-sign-cli) all landed upstream; the doc now points
  at the resolutions.

### Artifacts

The build-manifest CI artifact gains three new files alongside
the existing `persist-extras-*.json` + `ciris-persist-*.manifest.json`:

- `steward-key.json` — registry steward-key snapshot at registration time
- `registry-response.json` — raw response body of the binary-manifest POST
- `round-trip.json` — raw response body of the round-trip GET

90-day retention; same as the existing v0.1.9 artifacts.

### What still depends on bridge / ops action

Persist's CI is fully ungated code-side. The remaining gates are
operational:

- bridge uploads `CIRIS_BUILD_ED25519_SECRET` + `CIRIS_BUILD_MLDSA_SECRET` (per `docs/BUILD_SIGNING.md`)
- registry team issues + uploads `REGISTRY_ADMIN_TOKEN`

When both happen, CI flips green end-to-end. Persist #2 closes
on the round-trip evidence.

### Tests

131 tests green; clippy clean; cargo-deny clean. No code-side
changes outside the workflow YAML.

## [0.1.10] — 2026-05-01

P0 wheel-tagging regression fix from v0.1.9.

### The bug

v0.1.9's `maturin build` produced `ciris_persist-0.1.9-cp312-cp312-manylinux_2_39_x86_64.whl`
instead of the expected
`ciris_persist-0.1.9-cp311-abi3-manylinux_2_34_x86_64.whl`. Lens
runs on `python:3.11-slim` containers — a `cp312-cp312` wheel is
not installable there, so the v0.1.9 release was unconsumable for
lens.

### Root cause

v0.1.9 added `src/bin/emit_persist_extras.rs` (a build-time CI
helper that emits the typed `PersistExtras` JSON). With the
existing `python-source = "python"` mixed-mode layout in
`pyproject.toml` plus the new `[[bin]]` target, maturin 1.13
auto-detection switched to "binary project wheel" mode and
started building the binary as the wheel's content instead of the
PyO3 cdylib library. The `[lib]` block in `Cargo.toml` had no
explicit `crate-type`, so maturin couldn't disambiguate.

### The fix

One-line `Cargo.toml` change:

```toml
[lib]
name = "ciris_persist"
path = "src/lib.rs"
crate-type = ["cdylib", "rlib"]   # ← v0.1.10
```

`cdylib` is the Python module maturin packages; `rlib` keeps the
library importable from `src/bin/*` and integration tests. With
the explicit declaration, maturin 1.13's mixed-mode build
correctly picks the cdylib for the wheel and produces the
abi3 form.

### Verification

```text
maturin build --release --strip
  → 📦 Built wheel for abi3 Python ≥ 3.11 to
       target/wheels/ciris_persist-0.1.10-cp311-abi3-manylinux_2_34_x86_64.whl

cargo run --release --bin emit_persist_extras
  → {"supported_schema_versions":["2.7.0"],"migration_set_sha256":"sha256:...",
     "dep_tree_sha256":"sha256:..."}
```

Both build paths work; the binary still runs for CI's manifest
emission.

### What's NOT in v0.1.10

The CIRISRegistry `register` step (issue #2) ships in **v0.1.11**.
Splitting that out so this release is purely the wheel-tagging
fix that unblocks lens; the registration step lands once the
bridge team has uploaded the v1.8.0 hybrid signing secrets and we
have one valid signed manifest to register end-to-end.

### Notes for lens team

- Bump persist dep to v0.1.10. The wheel will install on
  `python:3.11-slim` cleanly. v0.1.9 is broken on PyPI; **don't
  use it.**
- All v0.1.9 features (storage_descriptor authoritative,
  PersistExtrasValidator, AV-4 closure) ship in v0.1.10
  unchanged. Only the wheel-packaging shape differs.

131 tests green; clippy clean; cargo-deny clean.

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
