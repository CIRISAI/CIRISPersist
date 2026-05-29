# Changelog

All notable changes per release. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) +
[Semantic Versioning](https://semver.org/spec/v2.0.0.html), with mission /
threat-model citations because this crate's audit story is the point.

## [3.3.1] — 2026-05-29

**CIRISPersist 3.3.1 — second calibration anchor for memory-bound bench families (#122 / closes the v3.3.0 false-positive alert pattern).**

Bench-infrastructure-only patch. No Rust code change, no schema, no API surface. Closes **#122**.

### Why

v3.3.0's bench run flagged 3 perf alerts on `read_engine_analytics/aggregate_llm_costs/{1000,10000,25000}` (1.28× / 1.48× / 1.10×) — same bench family, non-monotonic with input size, on a commit (`baad6bf`) that touched zero code in `src/read.rs` or any analytics aggregation path. 7 prior bench runs across v3.0 → v3.2 had 0 alerts.

Diagnosis: the v2.12.0 / #116 CPU-bound calibration anchor (`splitmix64_10m`) doesn't normalize the memory/cache axis. A runner where CPU is fast but neighbor-tenant memory bandwidth contention is high produces CPU-anchored normalized values that look like memory-bound bench regressions but aren't real code regressions. The single-anchor design assumed runner noise was uniform across workloads; it isn't.

### The fix — additive second anchor

New `bench_calibration_dram_walk` function in `benches/calibration.rs`:
- 64MB buffer of `u64` (exceeds L3 on every Actions runner image — largest observed is ~36MB on the AMD EPYC `ubuntu-24.04`).
- 500k random reads per iteration via an LCG-driven index sequence (Numerical Recipes constants) — defeats the hardware prefetcher.
- Each access misses cache → goes to DRAM → measures effective DRAM latency + bandwidth-under-contention.
- ~50ms per iteration → 20 Criterion samples fit the default 5s budget with margin.
- Deterministic across runs (same LCG seed, same buffer init).

The bench workflow now extracts both `CALIBRATION_CPU_NS` and `CALIBRATION_MEM_NS`, errors if either is empty/zero, and classifies each downstream bench by name prefix:

```bash
case "$bench_name" in
  read_engine_analytics/*|dedup_key/*|occurrence_registry/*)
    anchor_ns="$CALIBRATION_MEM_NS"
    ;;
  *)
    anchor_ns="$CALIBRATION_CPU_NS"
    ;;
esac
```

Three memory-bound families today: `read_engine_analytics/*` (large row aggregations — the family that alerted), `dedup_key/*` (hashmap operations), `occurrence_registry/*` (registry mutations over substantial in-memory state). Everything else stays on the CPU anchor — same normalization the v2.12.0 / #116 trend chart series has been using.

### Back-compat with the existing trend chart

The pre-#122 series was published under env `CALIBRATION_NS` mapped to the CPU anchor. v3.3.1 keeps the alias so:
- The historical `splitmix64_10m` trend line on gh-pages doesn't fork — same series name, same anchor source.
- Memory-bound bench history isn't retroactively renormalized — the v3.3.0 alert datapoints stay as recorded, and the new anchor starts being applied from v3.3.1 onward. Trend chart will show a one-time shift at v3.3.1 for the three reclassified families; that's expected and correct.

### Why this is a release, not a config tweak

The bench workflow runs against `main` on push. The classifier table lives in YAML; changing it requires a commit. Treating it as a release means the CHANGELOG documents which families got reclassified and why — anyone digging into a future alert can grep the CHANGELOG for "memory-bound" and find the policy.

### Mission citations

- §1.6 fail-honest — the CPU-only calibration was silently producing false-positive alerts for ~30% of the suite. Two anchors with explicit classification is honest about what's being measured.
- Threat-model AV-15-adjacent — alert noise is signal-degradation. A regression-alert pipeline that cries wolf gets ignored; one that fires only on real regressions gets acted on.

## [3.3.0] — 2026-05-29

**CIRISPersist 3.3 — `put_blob_signing` ergonomic ingest + canonicalizer authority (#121 / closes the JCS-vs-Python silent-correctness trap).**

Closes **#121**: a new `BlobStorage::put_blob_signing` trait method (and `Engine` facade + PyO3 mirror) that collapses the 7-step holds_bytes ingest sequence to one call AND makes persist the canonical owner of the holds_bytes envelope canonicalizer. The existing `put_blob(PutBlobAttestation)` stays for re-emit / HSM-batch / replay paths where the caller has a specific signed envelope already.

### The trap this closes — not just ergonomics

Persist's production canonicalizer is **`PythonJsonDumpsCanonicalizer`** (`src/verify/canonical.rs:73`), NOT JCS RFC 8785. `Rfc8785Canonicalizer` lives at the bottom of the same file as a `#[cfg(test)]` parity reference — it doesn't ship in production builds.

Downstream consumers (CIRISNodeCore, CIRISEdge, CIRISLensCore) writing their own holds_bytes ingest path would naturally reach for `serde_json_canonicalizer` (the obvious crate name, JCS implementation) and produce signatures that fail downstream verification — **silently wrong rows in `federation_attestations`**. The signature column would contain a valid Ed25519 signature over JCS-canonical bytes; the verifier would recompute Python-compat bytes; the comparison would fail; the holder would be filtered out at `list_holders` read time without any write-side error.

This isn't a "make it nicer" feature. It's persist taking ownership of a substrate-defined operation (holds_bytes per CEG §10.1.2 is persist's invention) and closing a silent-correctness error class for every present and future consumer.

### New surface

```rust
trait BlobStorage {
    fn put_blob_signing<'s>(
        &'s self,
        sha256: &'s [u8; 32],
        body: BlobBody,
        media_type: Option<&'s str>,
        attesting_key_id: &'s str,
        signer: &'s dyn ciris_keyring::HardwareSigner,
        now: chrono::DateTime<chrono::Utc>,
        attestation_id: uuid::Uuid,
    ) -> impl Future<Output = Result<(), BlobError>> + Send + 's
    where Self: Sync;
}
```

**Default implementation provided in terms of `put_blob`** — backends inherit automatically, no per-backend code, no `BlobStorage` re-implementation. The default impl is the entire point: persist owns the canonicalization, all backends get it for free, future backends inherit correctness.

`Engine::put_blob_signing` facade sources the signer internally from `Engine::signer()` (the `&Arc<dyn HardwareSigner>` shape locked in v1.13.0 / #92), so consumers using `current_rust_engine()` don't thread a signer through their call sites.

PyO3 mirror `put_blob_signing(sha256: bytes, body_bytes, external_ref, media_type, attesting_key_id, now_iso, attestation_id_uuid)` likewise sources the signer internally from the engine — matches the cohabitation pattern (#119 `local_signer_capsule`): cross-cdylib signer access lives via capsules, not as PyO3 method args.

### Design calls

- **`&dyn HardwareSigner` not `&Arc<LocalSigner>`** — sidesteps the cross-cdylib `PyTypeInfo` trap (#109 / #111); both `LocalSigner` (via `LocalSignerHardwareAdapter` at `src/signing/mod.rs:405`) and hardware-rooted signers (TPM / Secure Enclave / StrongBox) implement the trait.
- **Explicit `now: DateTime<Utc>`** — pinned-time tests + replay + backfill paths provide their own clock; the one extra parameter buys determinism.
- **Explicit `attestation_id: Uuid`** — replay / migration paths reproduce specific IDs; normal callers pass `Uuid::new_v4()`.
- **`scrub_signature_pqc` stays `None`** — the cold-path PQC sweep populates later, matching existing `PutBlobAttestation` semantics (see `src/federation/blobs.rs:298-300`).
- **`scrub_key_id` sourced via `signer.current_alias()`** — verified against `Engine::receive_and_persist_with` at `src/engine.rs:496` which does exactly this for the existing ingest path (`let key_id = self.signer.current_alias().to_owned();`). Same shape, same source-of-truth.
- **Method on the trait, not Engine-only** — `Arc<dyn BlobStorage>` consumers (which `current_rust_engine` returns) get the method directly without going through Engine facade. The Engine facade exists for API ergonomics, not as a gating layer.

### Test coverage — 9 new tests pinning the correctness fix

1. **`put_blob_signing_canonicalizer_identity_holds_bytes_envelope`** (trait-level) — pins the production canonicalizer's byte output for the holds_bytes envelope. The natural divergence test the issue sketched DOESN'T work for this envelope because the shape is ASCII-only (`{"kind": "holds_bytes", "evidence_refs": ["<64-hex>"]}`) — Python-compat and JCS produce byte-identical bytes here. So the regression gate is byte-exact identity instead: the test hashes `PythonJsonDumpsCanonicalizer.canonicalize_value(envelope)` and asserts the hex hash matches an anchored constant. Any future canonicalizer drift — whitespace, key reorder, ASCII-affecting bug — trips this.
2. **`put_blob_signing_canonicalizer_divergence_for_non_ascii_envelope`** (trait-level) — pins the broader Python-vs-JCS divergence assumption on a non-ASCII envelope so a future refactor that accidentally flips the two impls into agreement (canonicalizer choice silently becoming irrelevant) is caught and forces the regression test design to be updated explicitly.
3. **`put_blob_signing_uses_python_canonicalizer_not_jcs_sqlite`** + **`_postgres`** — write via `put_blob_signing`, read back the `federation_attestations.original_content_hash` column, assert it equals SHA-256 of the production canonicalizer's output. Also pins `scrub_key_id == signer.current_alias()` and `list_holders` returns the writer.
4. **`put_blob_signing_inline_round_trip_sqlite`** — content + sha + key, `get_blob` returns the bytes; `list_holders` returns `[attesting_key_id]`.
5. **`put_blob_signing_external_round_trip_sqlite`** — same shape with `BlobBody::External("url")`.
6. **`put_blob_signing_unknown_key_rejects_sqlite`** — `attesting_key_id` not in `federation_keys` → `BlobError::AttestationEmissionFailed`.
7. **`put_blob_signing_replay_same_attestation_id_conflicts_sqlite`** — same `attestation_id` twice → collides on the attestation_id PK → `BlobError::AttestationEmissionFailed("attestation_id collision: ...")`. The replay path documents that callers regenerating UUIDs across retries get clean idempotency; callers reusing UUIDs intentionally are signaling a different intent.
8. **`put_blob_signing_idempotent_distinct_attestation_ids_sqlite`** — same content + same key + different `attestation_id` → both succeed (blob row idempotent on sha256 PK; two holder rows written; `list_holders` deduplicates by `attesting_key_id`).

Full nextest: **895/895 pass** on fresh PG; no regressions in the existing 886 from 3.2.x.

### Mission citations

- §1.3 lowest-stateful-library-above-verify — persist owning the holds_bytes ingest sequence end-to-end matches this role. Making consumers reassemble a substrate-defined concept is the anti-pattern.
- §1.5 parity invariant — trait default impl means both backends + every future backend get the convenience method for free.
- §1.6 fail-honest — the canonicalizer choice is no longer a silent-correctness landmine for downstream; persist is the authority.

## [3.2.0] — 2026-05-29

**CIRISPersist 3.2 — `BlackholeRules` durable per-identity deny-list (#120 / unblocks CIRISEdge#33 v0.15.0 routing-table FFI).**

Closes **#120**: a new sibling trait `BlackholeRules` + V052 `cirislens.blackhole_rules` table giving CIRISEdge's `ReticulumTransport` a durable home for operator-configured deny-list rules. v0.15.0's in-memory `Arc<RwLock<HashMap<Vec<u8>, BlackholeRecord>>>` survives transport rebuilds inside a single Edge; this release lets rules survive *process* restarts, which the v0.15.0 acceptance criterion requires.

### New `BlackholeRules` trait (sibling, not folded into `FederationDirectory`)

Trait location is a deliberate call: federation directory is about **cryptographic identities + trust statements**; blackhole is about **transport-layer address denials**. Different concern, different lifetime (transport addresses exist independently of crypto identities). Sibling pattern matches #115's `BlobStorage`. Object-safe via `#[async_trait]` — `Arc<dyn BlackholeRules>` works through the CIRISEdge `current_rust_engine()` path.

```rust
#[async_trait]
pub trait BlackholeRules: Send + Sync {
    async fn blackhole_list(&self) -> Result<Vec<BlackholeRecord>, Error>;
    async fn blackhole_upsert(
        &self,
        identity_hash: &[u8],
        until: Option<DateTime<Utc>>,
        reason: Option<&str>,
    ) -> Result<(), Error>;
    async fn blackhole_remove(&self, identity_hash: &[u8]) -> Result<(), Error>;
    async fn blackhole_record_hit(&self, identity_hash: &[u8]) -> Result<(), Error>;
    async fn blackhole_prune_expired(&self, now: DateTime<Utc>) -> Result<u64, Error>;
}
```

Lives at `src/federation/blackhole.rs`; re-exported from `crate::federation`.

### Operator-semantics calls baked into the surface

- **`blackhole_upsert` preserves `hits` + `added_at` on re-upsert.** Operator changing `reason` or `until` on an existing rule is intent-change, not counter-reset. `added_at` survives so forensics-style "when did we first ban this peer?" queries work.
- **`blackhole_remove` is silent on unknown hash** (no `PeerNotFound`-style error). Matches POSIX `rm -f` ergonomics; operator scripts can call without first checking. Different semantic from #117's peer-mutation surface where `update_*` rightly errors on unknown peers because the operator is asserting state-change on what they think exists.
- **`blackhole_record_hit` is race-tolerant.** Silent no-op if the rule was removed between the send-path check and the increment. The send-path is hot; persist does not gate it behind a transaction.
- **`blackhole_prune_expired` treats `until IS NULL` as the operator's "permanent" signal.** Pruner deletes only `until IS NOT NULL AND until < now`. Permanent rules survive every prune call by design.

### Hot-path hit-recording — single round-trip, no batching in persist

`record_hit` is the send-path check that fires for every blackholed envelope. Implementation: single `UPDATE blackhole_rules SET hits = hits + 1 WHERE identity_hash = $1` — commutative increment, no transaction wrap, no `persist_row_hash` recomputation. Callers concerned about latency batch client-side (the docblock points at `HashMap<Vec<u8>, u64>` + periodic flush) — persist exposes the primitive, doesn't pre-optimize the caller's shape.

### `persist_row_hash` excludes `hits`

A design call beyond the issue spec: the canonical-bytes shape (`compute_blackhole_row_hash`) covers `identity_hash`, `until`, `reason`, `added_at` — but NOT `hits`. Hot-path increments don't force a re-canonicalize. Operator-intent fields participate in the hash; counter doesn't.

### V052 migration — sibling table, both dialects

```sql
CREATE TABLE IF NOT EXISTS cirislens.blackhole_rules (
    identity_hash    BYTEA PRIMARY KEY,
    until            TIMESTAMPTZ,
    reason           TEXT,
    added_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    hits             BIGINT NOT NULL DEFAULT 0,
    persist_row_hash TEXT NOT NULL
);
CREATE INDEX idx_blackhole_until ON cirislens.blackhole_rules (until)
    WHERE until IS NOT NULL;
```

Partial index `(until) WHERE until IS NOT NULL` lets `prune_expired` scan only rules with finite TTLs. SQLite parallel: `BLOB PRIMARY KEY`, TEXT RFC3339 timestamps, identical partial index. No SQL CHECK on `identity_hash` length — length validated at the API surface (`Error::InvalidArgument` when `!= 16` bytes) instead, so a hypothetical future Reticulum hash-width change won't force a schema rewrite. `tests/qa_harness.rs` migration bound 51 → 52.

### Engine facade

Five methods on `Engine` mirroring the trait surface, plus `blackhole_rules() -> Arc<dyn BlackholeRules>` for consumers that want trait access directly. All `#[cfg(any(feature = "postgres", feature = "sqlite"))]` — matches the dispatch pattern for the existing facade methods (`archive_audit_range`, `sign_hybrid`, etc.).

### PyO3 mirrors

Five methods on `PyEngine`: `blackhole_list_json`, `blackhole_upsert(identity_hash: bytes, until_iso, reason)`, `blackhole_remove(identity_hash: bytes)`, `blackhole_record_hit(identity_hash: bytes)`, `blackhole_prune_expired_iso(now_iso)`. `identity_hash` flows as Python `bytes`; timestamps as ISO strings (matching `attach_revocation_pqc_signature` and the broader textual-timestamp convention). Errors route through the existing `federation_err_to_py` — no new kind tokens needed.

### Test coverage — 33 new (memory + sqlite + postgres + 3 module-unit)

- 10 per backend: `blackhole_upsert_then_list_round_trip`, `blackhole_upsert_with_until_round_trip`, `blackhole_upsert_idempotent_preserves_hits`, `blackhole_upsert_invalid_hash_length_rejects`, `blackhole_remove_unknown_silent_ok`, `blackhole_remove_idempotent`, `blackhole_record_hit_increments`, `blackhole_record_hit_unknown_silent_ok`, `blackhole_prune_expired_drops_only_expired`, `blackhole_prune_expired_with_no_expired_returns_zero`.
- 3 module-unit: `validate_identity_hash_len_accepts_16`, `validate_identity_hash_len_rejects_other_lengths`, `compute_blackhole_row_hash_excludes_hits_field`.
- Full nextest: **886/886 pass** on fresh PG; no regressions in the existing 883 from 3.1.x.

### Mission citations

- §1.5 parity invariant — both backends + memory parity; SQLite Pi-class deployment carries the same durable deny-list as a datacenter PG instance.
- §1.6 fail-honest — typed `InvalidArgument` on length-mismatch instead of silent CHECK violation at the DB layer; `record_hit` race-tolerance is documented, not buried.
- Operator-autonomy framing (Accord §I) — the deny-list is the operator's tool for refusing federation neighbors; persist stores the decision, doesn't second-guess it.

## [3.1.1] — 2026-05-28

**CIRISPersist 3.1.1 — two thin admission accessors closing today's CIRISEdge cohabitation gaps (#118 + #119).**

A patch release bundling two sub-50-line pyo3.rs additions that unblock distinct CIRISEdge consumers. Each addition is consumer-facing only — no schema changes, no trait breakage, no migration. The pair ships together because both touch `src/ffi/pyo3.rs` and ship in the same window.

### #118 — `put_edge_detection_event` admission on `DerivedSchema`

Mirrors the existing `get_edge_detection_events` read accessor (#113, v2.13.0). Unblocks **CIRISEdge#39 ProbePatternObserver** — `emit_verdict` changes from `tracing::warn!` to one `await` call.

- New trait method `DerivedSchema::put_edge_detection_event(EdgeDetectionEvent) -> Result<(), derived::Error>` (RPITIT, mirrors existing put paths).
- Both backends + memory:
  - **Postgres** — `INSERT … ON CONFLICT (detection_id) DO NOTHING` with conflict-check fallback comparing `persist_row_hash`; idempotent on matching hash, `Conflict` on differing hash. `detection_id` parsed as UUID with typed `InvalidArgument` on parse failure; subject_key_id FK enforces referential integrity to `federation_keys`.
  - **SQLite** — same shape via `rusqlite::params!`; `detection_id` stored as TEXT-UUID; subject_key_id FK via PRAGMA `foreign_keys=ON` (set at backend boot).
  - **Memory** — `NotImplemented` per the existing put-path convention (sovereign-mode Pi-class deployments don't run lens-core).
- **Signature trust model** documented in the trait docblock: unlike `put_detection_event` (which carries separate `ed25519_sig` + `ml_dsa_65_sig` + `canonical_bytes` for hybrid verification at the PyO3 boundary), `EdgeDetectionEvent` carries a single opaque `signature` over the canonical row. Edge owns the verification policy at the transport observation site (RATCHET `Core/ConsentGate.lean` F-CR-3 + Counter-RII Edge-layer spec); persist stores `signature` + `signature_verified` verbatim; LensCore joint-correlation reads filter on `signature_verified` per CIRISLensCore#21 threat model.
- Docblock update on `get_edge_detection_events`: replaces "The write side (INSERT) lives at the LensCore detector call site" with "Edge emits via `put_edge_detection_event`; LensCore reads via `get_edge_detection_events`; joint correlation in LensCore."
- PyO3 method `put_edge_detection_event(event_json)` on `PyEngine` — decodes JSON, dispatches through `BackendDispatch`, routes errors through `derived_err_to_py`.
- 5 new tests: `put_edge_detection_event_idempotent_{pg,sqlite}` (same row hash → second put OK), `put_edge_detection_event_conflict_on_differing_row_hash_{pg,sqlite}` (differing row hash → `Conflict`), `put_edge_detection_event_bad_uuid_rejects_pg` (non-UUID `detection_id` → typed `InvalidArgument`).

### #119 — `local_signer_capsule()` (6th PyCapsule accessor)

Closes the cross-cdylib gap that blocks **CIRISEdge v0.13.1 `ReticulumTransport`** identity. The hardware-rooted hybrid 65-byte `keyring_signer` (v2.7.0 / #109) drives hot-path scrub envelopes, but Reticulum link establish + Curve25519-derived DH needs the 32-byte Ed25519 `LocalSigner` private key — pubkey-only is identity-hash only. Without this 6th capsule, edge can learn the agent's public key (`engine.local_public_key_b64()` at `src/signing/mod.rs:340`) but cannot drive Reticulum link signing.

- 6th `PyEngine` method `local_signer_capsule()` parallel to `keyring_signer_capsule()` (v2.7.0 / #109 design pattern). Wraps a clone of the `Arc<crate::signing::LocalSigner>` field already at `src/ffi/pyo3.rs:355`.
- Capsule type identifier `ciris_persist::local_signer` — matches the established `ciris_persist::{name}` naming for the family.
- Defensive error: `ValueError("local_signer_unavailable")` when the engine was constructed without `from_shared_with_local` (older cohabitation init paths predating 2.12.0 / #112 don't propagate `LocalSigner` across the cross-cdylib boundary).
- Each capsule one job — preserves the v2.7.0 #109 design intent. `keyring_signer` drives scrub envelopes; `local_signer` drives transport-link identity; no splitting of signing identity across two channels.

Both additions are zero-schema-change and zero-trait-breakage; ship as `3.1.1` patch per #118's acceptance criterion.

### Capsule family (6 accessors as of 3.1.1)

| Capsule | Type tag | Wrapped | Ships |
|---|---|---|---|
| `federation_directory_capsule` | `ciris_persist::federation_directory` | `Arc<dyn FederationDirectory>` | v2.7.0 / #109 |
| `outbound_queue_capsule` | `ciris_persist::outbound_queue` | `BackendDispatch` | v2.7.0 / #109 |
| `keyring_signer_capsule` | `ciris_persist::keyring_signer` | `KeyringSignerHandle` | v2.7.0 / #109 |
| `runtime_handle_capsule` | `ciris_persist::runtime_handle` | `tokio::runtime::Handle` | v2.8.0 / #111 |
| `blob_storage_capsule` | `ciris_persist::blob_storage` | `BackendDispatch` | v2.11.0 / #115 |
| **`local_signer_capsule`** | **`ciris_persist::local_signer`** | **`Arc<LocalSigner>`** | **v3.1.1 / #119** |

## [3.1.0] — 2026-05-28

**CIRISPersist 3.1 — peer-mutation surface on `FederationDirectory` (#117 / unblocks CIRISEdge v0.13.0 peer-mgmt UniFFI stubs).**

The release that closes **#117** in full: 6 new async mutation methods on `FederationDirectory` for operator-driven peer management, a new sibling table `federation_peer_metadata` (V051) carrying operator-local per-instance metadata, two new typed types (`TrustClass` enum + `PeerPolicyBlob` opaque newtype), two new typed errors with stable `AV-15` kind tokens, and PyO3 mirrors. Unblocks CIRISEdge v0.13.0's 7 UniFFI peer-mgmt stubs (the `PEER_MUTATION_FOLLOWUP` constant).

### Six new `FederationDirectory` methods (object-safe `#[async_trait]`)

- `add_peer_record(key_id, pubkey_ed25519_base64, identity_type, transport_identity)` — atomic insert of both the `federation_keys` identity row and the `federation_peer_metadata` row with default `trust = Untrusted`. Idempotent on matching pubkey; rejects with `Conflict` on differing pubkey.
- `remove_peer_record(key_id, hard: bool)` — soft (default) marks `removed_at = NOW()` and hides the row from reads while preserving the audit trail; hard cascades delete through the FK. Hard remove with active attestations rejects via the new `HardRemoveWithActiveAttestations` typed error — operator must soft-remove or revoke the key first.
- `update_peer_alias` / `update_peer_notes` — string field updates with `None`/`Some` semantics distinguished end-to-end.
- `update_peer_trust(key_id, TrustClass)` — typed-enum value-domain validation; no silent coercion.
- `update_peer_policy(key_id, PeerPolicyBlob)` — opaque JSON blob round-trip.

All return `Result<(), federation::Error>`; missing-row paths return the new `PeerNotFound` typed error.

### V051 migration — sibling `federation_peer_metadata` table

The design call: **operator-local per-instance metadata** lives outside `federation_keys` so the federation-shared identity row stays clean. One persist instance's view of a peer (`alias = "edge-east-1"`, `trust = Trusted`, operator notes, policy blob) differs from another's; the federation_keys row (pubkey + scrub envelope + identity_type) is the same across every member. Trust-boundary clarity per CIRIS Accord §I operator-autonomy framing.

```sql
key_id           TEXT NOT NULL PRIMARY KEY REFERENCES federation_keys(key_id) ON DELETE CASCADE,
alias            TEXT NULL,
trust            TEXT NOT NULL DEFAULT 'untrusted' CHECK (trust IN ('untrusted','trusted','restricted','blocked')),
notes            TEXT NULL,
policy_blob      JSONB NULL,
transport_identity TEXT NULL,
removed_at       TIMESTAMPTZ NULL,
inserted_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
persist_row_hash TEXT NOT NULL
```

Partial indexes: `(trust) WHERE removed_at IS NULL`, `(alias) WHERE alias IS NOT NULL`. SQLite dialect parity (TEXT timestamps + TEXT-as-JSON policy_blob); `tests/qa_harness.rs` migration bound 50 → 51.

### New typed surface

- **`TrustClass`** enum (`Untrusted` / `Trusted` / `Restricted` / `Blocked`) with `as_wire_str()` / `from_wire_str()` mirroring `VerificationSource` (#91). Wire mapping pinned by the SQL CHECK constraint — same closed set on both sides.
- **`PeerPolicyBlob`** — `#[serde(transparent)]` newtype around `serde_json::Value`. Opaque to persist; the operator-policy semantic lives at the CIRISEdge UniFFI layer.
- **`PeerMetadataRow`** — read shape carrying server-computed `persist_row_hash` via the same `compute_persist_row_hash` discipline as `KeyRecord` / `Attestation` / `Revocation`.

### Two new typed errors on `federation::Error`

- `PeerNotFound { key_id }` — stable kind token `federation_peer_not_found`. Returned by every `update_*` method when the peer doesn't exist.
- `HardRemoveWithActiveAttestations { key_id, attestation_count }` — stable kind token `federation_hard_remove_with_active_attestations`. Defensive: orphaning an attestation_envelope by hard-removing its issuer would break §6.1 chain-honesty; operator must soft-remove or revoke first.

Both route through `federation_err_to_py` as `PyValueError` per AV-15.

### PyO3 mirrors

Six new methods on `PyEngine` after `attach_revocation_pqc_signature`:
- `add_peer_record_json(payload_json)`
- `remove_peer_record(key_id, hard)`
- `update_peer_alias(key_id, alias_json)` — JSON-encoded `Option<String>` so `null` vs `""` is distinguishable
- `update_peer_trust(key_id, trust_wire)` — wire-string decode via `from_wire_str`; bad value raises `ValueError` with no silent coercion
- `update_peer_notes(key_id, notes_json)`
- `update_peer_policy(key_id, policy_json)`

### Test coverage — 32 new (both backends + memory parity)

- 10 memory-backend tests (atomic-insert / duplicate-rejects / soft-remove / hard-remove-with-attestations rejects / hard-remove-cascade / 4 round-trip update paths / unknown-key rejects).
- 11 SQLite + 11 Postgres mirrors (each adds the CHECK-bypass test catching direct-SQL trust-value bypass).
- Full feature-set nextest: **883/883 pass** on fresh PG container; no regressions in the existing 851 tests.

### Mission citations

- §1.5 parity invariant — both backends + memory, no PG-only declarations, no deferral.
- §1.6 fail-honest — typed errors, no silent coercion of TrustClass values, defensive `HardRemoveWithActiveAttestations` instead of orphaning attestations.
- §1.7 fractal-self — peer-management surface puts the **operator** at the centre of the trust-neighborhood decisions (CIRIS Accord §I autonomy); persist stores opinion, doesn't confer.

## [3.0.0] — 2026-05-28

**CIRISPersist 3.0 — Coherence Epistemic Graph 0.2 substrate conformance.**

The milestone release that closes persist's substrate-conformance against CIRISRegistry's Coherence Epistemic Graph 0.2 (commit [`4b27130`](https://github.com/CIRISAI/CIRISRegistry/commit/4b27130)). CEG 0.2 supersedes FSD-002 as the canonical federation spec; **3.0.0 is persist's conformant substrate adoption.**

The release closes **#116** in full (the persist-owned CEG slice), bumps the **CIRISVerify pin v3.9.0 → v4.0.0** (the federation-wide CEG 0.2 wire alignment), and brings forward the three earlier-shipped CEG-adjacent items:
- **#114** typed Goal primitive with M-1 alignment as construction-time invariant (shipped 2.10.0).
- **#110** occurrence_id / occurrence_count / occurrence_role envelope fields (shipped 2.9.0 via FSD-002 v1.4.2 §2.1 amendment).
- **#102** attestation_type vocabulary clean-break rename (shipped 2.4.0).

### CIRISVerify pin v3.9.0 → v4.0.0 (federation-wide CEG 0.2 wire alignment)

CIRISVerify v4.0.0 is the formal landing of the mechanism-prefix
wire shape (per CIRISVerify#38 / CEG §8.1.9 Policy I): the L1-L5
ladder is officially consumer-side composition, the wire carries
only mechanism strings (`attestation:self_verify`, etc.), and the
canonicalization tightening in §5.2.1 is locked. **3.0.0 is the
release that pairs persist's substrate-side CEG 0.2 conformance
with verify's wire-side conformance**, so consumers of persist's
wheel get the CEG 0.2 verify surface transitively.

- Cargo.toml: 6 `tag = "v3.9.0", version = "3"` sites → `"v4.0.0", "4"`
  (ciris-keyring / ciris-verify-core / ciris-crypto across base + the
  three per-target `[target.*]` tables for Linux TPM / iOS / Android).
- pyproject.toml `Requires-Dist`: `ciris-verify>=3.9.0,<4` →
  `>=4.0.0,<5` — Python wheel consumers now transitively pull the
  v4.x verify line.

Persist's consumed surface (`HardwareSigner`, hybrid signatures,
transparency-log machinery, `derive_symmetric_key`) is unchanged
across v3→v4 — the major break was wire-format-only. 851/851 nextest
tests pass identically on v4.0.0 and v3.9.0; no persist code change
needed beyond the pin sites.

### §6.1 — Concurrent-write precedence + dedup triple

Structural composers (`SUPERSEDES` / `WITHDRAWS` / `RECANTS`) are now idempotent on replay AND obey the precedence rule when concurrent writes target the same upstream attestation.

- **Dedup at write**: a second `put_attestation` with the same `(references_attestation_id, attestation_type, attesting_key_id)` triple is a silent `Ok(())` no-op (mirrors the V043 master-key idempotent contract). New `src/federation/precedence.rs` module (`is_dedup_match` / `is_structural_composer` helpers). Both backends + memory parity.
- **Precedence at read**: new `precedence_winner` helper over a slice of grouped attestations. Rank: `RECANTS=3 > WITHDRAWS=2 > SUPERSEDES=1`; tied rank → latest `asserted_at` wins; tied `asserted_at` → lex-smallest `attestation_id` wins. **Audit chain stores all composers honestly** (the write path is append-only); reads project the current effective state. Caller narrows the slice by `(attesting_key_id, references_attestation_id)` group per §6.1 rule 4.
- `delegates_to` excluded from precedence scope — it's forward-looking authorization with a different envelope shape (`delegated_scope[]`, no `references_attestation_id`); documented in the precedence module.

### §7.0 — Reserved-prefix admission rules + CEG 0.1→0.2 dual-acceptance

`DimensionAdmissionPolicy` (shipped 2.4.0) extended with two new rule families:

- **Reserved-prefix emitter rule**: `SCORES` attestations whose `dimension` matches a reserved prefix MUST be signed by a key with the matching `identity_type`. Defaults ship the CEG §5.3/§7.x base set — `system:` / `audit_chain:` / `corpus_health:` / `identity_continuity:` / `federation_directory:` → `substrate_persist`; `transparency_log:cosigned:` → `witness`. New typed `Error::ReservedPrefixEmitterMismatch { dimension, prefix, required, got_identity_type }` (stable `kind() = "federation_reserved_prefix_emitter_mismatch"`).
- **CEG 0.1 → 0.2 attestation-prefix transition**: CEG 0.2 renamed `attestation:l{N}:*` → mechanism-only (`attestation:self_verify` / `hardware_rooted` / `registry_consensus` / `license_validity` / `agent_integrity`). The L1-L5 ladder is now consumer-side composition per CEG §8.1.9 Policy I. Persist's policy: `AttestationLadderTransitionPolicy::DualAccept` (default for 3.0.0) admits BOTH the deprecated `attestation:l{N}:*` form AND the canonical mechanism form. Post-CEG-0.3 (separate future PR) the policy flips to `RejectDeprecated`. The transition target is documented + regression-tested at admission.

New `identity_type` constants: `SUBSTRATE_PERSIST`, `WITNESS`.

### §10.1.2 — `holds_bytes` 24-hour TTL + ContentMiss feedback

`DEFAULT_HOLDS_BYTES_TTL: Duration = 24h` constant on `crate::federation::blobs`. `BlobStorage::list_holders` now:
- Filters out rows whose `asserted_at + TTL < now` (stale holders no longer surfaced).
- Skips rows with a matching `WITHDRAWS` attestation from the same attester (the ContentMiss feedback loop — when a consumer can't fetch the bytes, they emit a `WITHDRAWS` against the stale `holds_bytes:sha256:{prefix}` row, which the §6.1 dedup + precedence machinery from §6.1 above accepts as a structural composer).

No migration required — the TTL is computed from `federation_attestations.asserted_at` (per CEG §10.1.2's "from `signed_at`" wording). PG impl uses a `NOT EXISTS` subquery for ContentMiss; SQLite uses a two-stage scan.

### §0.5 fractal-self framing — MISSION.md §1.7

New section documenting **persist is relational fabric, not a Cartesian gate**. Distinguishes wire-format gates that are Cartesian-OK (the `accord:*` constitutional asymmetry, §7.0 reserved-prefix, T1–T4 operational-language gate, attestation-ladder transition) from relational gates that would be Cartesian-misread (admission re-checks of self-attestation truth, N-cross-attestation requirements, gating writes on consumer composition outcomes). `DimensionAdmissionPolicy`'s doc-comment carries the same framing at the call site.

Cross-attestation already happened upstream (NodeCore / Verify / Registry); persist records the relational fabric, doesn't second-guess whether the self is "real."

### Verified

`cargo clippy --all-targets -- -D warnings` clean on default features AND `postgres server pyo3 sqlite cirisaudit secrets cirisnode cirisgraph telemetry`. **851/851 nextest tests pass** on both backends, fresh DB, `--test-threads=1`, full feature set. 39 new tests in the CEG bundle covering: structural-composer dedup, precedence rule + tie-break, reserved-prefix rejection + acceptance, dual-acceptance of both deprecated and canonical `attestation:*` forms, `holds_bytes` TTL filter, ContentMiss withdraw integration.

### Carry-forwards from earlier 2.x cuts that close the CEG conformance picture

| CEG ask | Closed by | Shipped |
|---|---|---|
| §6.1 dedup + precedence | **#116 (this release)** | 3.0.0 |
| §7.0 reserved-prefix + 0.1→0.2 dual | **#116 (this release)** | 3.0.0 |
| §10.1.2 holds_bytes TTL + ContentMiss | **#116 (this release)** | 3.0.0 |
| §0.5 fractal-self doc framing | **#116 (this release)** | 3.0.0 |
| occurrence_id / occurrence_count / occurrence_role envelope | #110 (opaque JSONB; spec ratified at FSD-002 v1.4.2 §2.1) | 2.9.0 |
| Typed Goal with M-1 alignment as construction-time invariant | #114 | 2.10.0 |
| `attestation_type` clean-break vocabulary rename | #102 Ask 2 | 2.4.0 |

### Judgement calls flagged (documented in code)

- **TTL anchor: `asserted_at`, not `first_seen_at`** — per CEG §10.1.2's "from `signed_at`" wording. The per-holder TTL has to anchor at the per-holder `asserted_at`; `first_seen_at` lives on `federation_blobs` (per-blob), not on the per-holder `federation_attestations` row.
- **Precedence at READ, not WRITE** — audit chain stores all composers honestly (append-only); reads project current effective state via `precedence_winner`. Trust-grant projection (chain-event-based, `federation_trust_grants`) is a separate read path and NOT wired into §6.1 precedence — that's a follow-up needing the projection's data model reconciled with composer rows.
- **`capacity:*` / `licensure:*` / `detection:*` admission carve-outs deliberately deferred** — those have rules at the envelope-shape layer (attester == attested for capacity; single-source confidence floor for licensure; primary-vs-cross-attestation distinction for detection) that don't fit the prefix-emitter-identity-type rule shape cleanly. Documented in `default_reserved_prefix_rules()` `What's deliberately NOT here`.
- **Version-segment exemption for attestation-ladder dimensions** — `attestation:self_verify` lacks `:v[0-9]+`; the T3 version-pinning rule would otherwise reject. Carve-out: version-pinning for these mechanisms lives in the attesting binary's SLSA stamp + calibration package, not the wire prefix.

## [2.13.0] — 2026-05-28

**`#113` — Detection-events Engine read + subscribe facade.** Unblocks
CIRISLensCore #15 (Node UX), #19 (scoring oracle), #20 (alert
subscriptions), #21 (Counter-RII / UnconsentedExternalProbe), #25
(ECF UI ProfileScorecard) — five lens issues converge here.

### Three new Engine methods

```rust
impl Engine {
    pub async fn get_detection_events(&self, filter: EventFilter)
        -> Result<Vec<DetectionEvent>, DerivedError>;
    pub async fn get_edge_detection_events(&self, filter: EdgeEventFilter)
        -> Result<Vec<EdgeDetectionEvent>, DerivedError>;
    pub fn subscribe_detection_events(&self, filter: EventFilter)
        -> impl Stream<Item = Result<DetectionEvent, DerivedError>> + Send;
}
```

- **`get_detection_events`** — thin facade over the existing
  `DerivedSchema::get_detection_events` per-backend impls; same
  closure pattern as `Engine::receive_and_persist` / `storage_summary`
  / `sign_hybrid`. Both backends.
- **`get_edge_detection_events`** — reads the V020
  `edge_detection_events` table (INSERT side existed; SELECT side
  added here). New `EdgeEventFilter` (`tenant_id` / `peer_key_id` /
  `event_type` / `recorded_after` / `limit`) and `EdgeDetectionEvent`
  types in `src/derived/types.rs`. Stable ORDER BY
  `(tenant_id, observed_at, detection_id)`. Both backends.
- **`subscribe_detection_events`** — v0.1 polling-based change feed.
  2s poll cadence; bounded `mpsc::channel` capacity 256 (coarse-but-
  honest backpressure: a full buffer makes the poll task `await` on
  `send` rather than drop events); cursor initialized to
  `Utc::now()` at subscribe time so subscribers see only new events,
  not historical replay; drop discipline via `ReceiverStream` closing
  the channel (poll task's `tx.is_closed()` + `send` error branches
  exit cleanly — no leak). DB errors forward as `Err(DerivedError)`
  on the stream without terminating the task — transient outages
  don't kill long-lived subscribers.

### v0.1 simplifications (documented in trait + here)

- **Polling, not WAL-hook / LISTEN-NOTIFY**: persist#84's broader
  substrate-wide change-feed is deferred to 3.0+; this is the
  LensCore-scoped slice that satisfies #20 today without blocking on
  the larger design.
- **Backpressure shape**: the bounded channel + blocking-send model
  is the right primitive; a v0.2 may add a `SubscriptionOptions`
  struct for configurable cadence + channel capacity + dropped-when-
  buffer-full policy. Doc-comments call it out.
- **No PyO3 subscribe surface**: a Python-callable polling
  subscription needs a queue across the FFI boundary; deferred. The
  Rust `subscribe_detection_events` is for co-resident Rust consumers
  (LensCore client-mode) until a Python-side design lands.

### PyO3 read additions

`get_detection_events_json` (existed since #18) is now the documented
facade for the JSON-in/JSON-out read path; new
`get_edge_detection_events_json` mirrors with the `EdgeEventFilter`
shape. Errors route through the existing `derived_err_to_py` taxonomy
(AV-15 stable kind tokens).

### Cargo additions

`futures-core = "0.3"` and `tokio-stream = "0.1"` declared directly
(both were transitive via `tokio-postgres`; declaring at the surface
so the public `Stream` signature doesn't lean on a transitive).

10 new tests covering all three accessors + the subscription's
yields-only-new + drop-terminates + filter-scoping invariants.
**812/812 nextest tests pass** on both backends, fresh DB, full
feature set. Clippy `--all-targets` clean on default AND full
feature sets.

## [2.12.0] — 2026-05-28

**`#112` — `Engine::sign_hybrid` facade + cohabitation propagation fix.**

The `Engine` struct gains a `local_signer: Option<Arc<LocalSigner>>`
field and a new `Engine::sign_hybrid(message) -> Result<HybridSignature, SignError>`
method. Same closure-pattern as `Engine::receive_and_persist` /
`Engine::storage_summary`: persist owns the underlying primitive
(`LocalSigner::sign_hybrid` — Ed25519 + ML-DSA-65 + hybrid binding);
persist exposes a clean Engine facade so co-resident Rust consumers
(CIRISLensCore client-mode trace signing on `ACTION_RESULT`, v0.4
EgressFilter re-signing of redacted envelopes) don't reach past the
`Arc<dyn HardwareSigner>` abstraction.

### The cohabitation propagation fix

Pre-v2.12, `Engine::from_shared` (which `current_rust_engine()` uses
to hand a co-resident Rust consumer an `Arc<Engine>` view onto the
process singleton) only carried `Arc<dyn HardwareSigner>` across —
the `LocalSigner` the singleton was constructed from was lost at the
boundary, so consumers could not reach the hybrid-signing path.

2.12 adds `Engine::from_shared_with_local(backend, signer,
local_signer)` and updates `current_rust_engine()` to call it,
propagating the `EngineCell`'s `local_signer` through. The singleton
already holds it; sharing across the cohabitation boundary doesn't
duplicate identity.

Hardware-rooted deployments (no LocalSigner present) keep using
`Engine::from_shared` and get `SignError::LocalSignerUnavailable`
from `sign_hybrid` — honest failure mode; rebuild a LocalSigner from
`PyEngine::keyring_signer()`'s `KeyringSignerHandle` if the
hardware-backed PqcSigner is accessible.

### Typed `SignError`

```rust
pub enum SignError {
    LocalSignerUnavailable,      // from_shared without local_signer propagation
    LocalSigner(LocalSignerError),  // underlying LocalSigner::sign_hybrid errors
}
```

`LocalSigner(LocalSignerError::PqcNotConfigured)` surfaces for
Ed25519-only deployments — the LocalSigner was reached but has no
PQC identity.

### Unblocks

- **CIRISLensCore#11** — v0.3 client-mode trace signing on `ACTION_RESULT`.
- **CIRISLensCore#14** — v0.4 EgressFilter re-signing when redaction
  has changed the canonical bytes.

Three new tests on the sign_hybrid path (`with_signer` route +
`from_shared` LocalSignerUnavailable + `from_shared_with_local`
propagation through to the LocalSigner). **803/803 nextest tests
pass** on both backends, clippy `--all-targets` clean on default AND
full feature sets.

## [2.11.0] — 2026-05-28

**`#115` `blob_storage_capsule` + CIRISVerify pin v3.7.0 → v3.9.0.**

### `#115` — fifth capsule on the cross-module cohabitation accessor family

`BlobStorage` is RPITIT (`impl Future + Send` returns) and therefore
NOT object-safe — `Arc<dyn BlobStorage>` won't compile. New
`blob_storage_capsule()` `#[pymethod]` wraps the engine's
`BackendDispatch` enum (same dispatch-enum pattern
`outbound_queue_capsule` uses from #109); consumer matches the variant
and calls `BlobStorage` trait methods on the concrete backend. Name
tag `ciris_persist::blob_storage`.

Unblocks **CIRISNodeCore#11** (`install_node_mode_serving`'s PyO3
wrapper) — same cross-module identity problem the rest of the
capsule family solves.

The cohabitation accessor surface on `PyEngine` is now:

| Capsule | Wraps | Issue |
|---|---|---|
| `federation_directory_capsule` | `Arc<dyn FederationDirectory>` | #109 |
| `outbound_queue_capsule` | `BackendDispatch` (OutboundQueue is RPITIT) | #109 |
| `keyring_signer_capsule` | `KeyringSignerHandle` | #109 |
| `runtime_handle_capsule` | `tokio::runtime::Handle` | #111 |
| `blob_storage_capsule` | `BackendDispatch` (BlobStorage is RPITIT) | #115 |

### CIRISVerify pin v3.7.0 → v3.9.0

CIRISVerify v3.8.0 added the Phase 1 `AttestBundle.provenance` carrier
for `skill_imports` / `build_manifest_per_locale`; v3.9.0 (Phase 2,
shipped today) added the verifiers: new `skill_import.rs` (with
`§3.2.1.1 SkillImportManifest::canonical_bytes`) and
`locale_merkle.rs` (with `§3.2.1.2 LocaleLeaf::leaf_hash` + RFC 6962
0x00/0x01 + padding). Persist doesn't directly consume these verifier
modules (they're Registry-facing), but the federation-wide consistency
matters — pinning persist's transitive `ciris-verify` to v3.9.0 means
consumers of persist's wheel get the new verifier surface for free.

- Cargo.toml: 6 `tag = "v3.7.0"` sites → `"v3.9.0"`
  (ciris-keyring/ciris-verify-core/ciris-crypto across base +
  per-target Linux/iOS/Android tables).
- pyproject.toml `Requires-Dist`: `ciris-verify>=3.7.0,<4` →
  `>=3.9.0,<4`.

## [2.10.0] — 2026-05-28

**`#114` — typed `Goal` primitive + storage + wire, with M-1 alignment as a structural construction-time invariant.**

The F-3 detector family (CIRISLensCore#23/#24/#26) operates on
"goals pursued by groups," but the substrate had no first-class
representation — just an untyped `serde_json::Value` named
`deferred_goals` and string-label detection axes like `goal:planet`.
That category gap closes here: every Goal in persist's wire +
storage MUST carry M-1 alignment, enforced at the type system the
same way `NonZeroU32` enforces non-zero. **A Goal cannot be
constructed without it.**

### The `Goal` type

```rust
pub struct Goal {
    pub goal_id: Uuid,                       // UUIDv7, creation-ordered
    pub declared_by_key_id: String,          // federation_keys.key_id FK
    pub declared_at: DateTime<Utc>,
    pub goal_text: String,
    pub scope: GoalScope,                    // SingleDeclarer | Cohort{id} | Federation
    pub meta_goal_alignment: MetaGoalAlignment,  // REQUIRED — by value, not Option
    pub retired_at: Option<DateTime<Utc>>,
}
```

`Goal::new(...)` takes `meta_goal_alignment: MetaGoalAlignment` by
value. There is no `Default` impl. The only constructor enforces the
invariant. M-1 isn't a validation rule — it's a type-system
construction precondition. A declarer cannot route around the
framework by simply "not setting it"; the compiler refuses.

### `MetaGoalAlignment` + `M1Dimension`

```rust
pub struct MetaGoalAlignment {
    pub dimension: M1Dimension,    // closed enum, #[non_exhaustive]
    pub rationale: String,          // free text, canonicalized into signed bytes
    pub deliberation_ref: Option<DeliberationRef>,  // pointer to PDMA/WBD/thread
}

#[non_exhaustive]
pub enum M1Dimension {
    Sustainability, Adaptivity, Coherence, Plurality,
    Flourishing, Justice, Wonder,
}
```

The seven dimensions cover the CIRIS Accord v1.2-Beta M-1 framing:
*"Promote sustainable adaptive coherence — the living conditions
under which diverse sentient beings may pursue their own flourishing
in justice and wonder."* The closed enum forces declarer engagement
(can't bypass with a free-text dimension); `#[non_exhaustive]` keeps
semver-minor extensibility.

### V050 migration (both dialects)

`goals` table: UUID PK, FK → `federation_keys(key_id) ON DELETE RESTRICT`,
`meta_dimension` CHECK in the 7 lex-sorted variants, `scope_kind`
CHECK in 3, JSONB `meta_deliberation` (TEXT-as-JSON on SQLite),
partial indexes on the F-3 hot path (live goals only). Cross-column
CHECK enforces `scope_kind = 'cohort' ⇔ scope_cohort_id IS NOT NULL`
— defense in depth, schema is the backstop for direct-SQL bypass.

qa_harness migration-count bound → `1..=50`.

### `FederationDirectory` trait surface

Four new `#[async_trait]` methods:

- `put_goal(goal)` — typed write; FK + CHECK enforced.
- `get_goal(goal_id)` — typed read; `Option` for not-found.
- `list_goals(filter)` — `GoalsFilter { declared_by_key_id?,
  m1_dimension?, scope_kind?, cohort_id?, include_retired: bool }`;
  stable lex order by `(declared_at, goal_id)`; `include_retired`
  defaults `false` so the F-3 hot path skips retired goals.
- `retire_goal(goal_id, retired_at)` — soft-idempotent (mirrors
  `revoke_trust`): second call against an already-retired goal
  returns `Ok(())` without changing `retired_at`; missing
  `goal_id` returns `Error::InvalidArgument`.

### PyO3 surface

`cirisnode_put_goal_json` / `cirisnode_get_goal_json` /
`cirisnode_list_goals_json` / `cirisnode_retire_goal_json` —
JSON in/out matching the existing `cirisnode_*_json` convention.
**M-1 enforcement reaches the FFI boundary**: a JSON payload
missing `meta_goal_alignment` raises `ValueError` before any DB
call — the Rust deserializer refuses to construct a Goal without
it.

### Judgement calls

- **`DeliberationRef` shape** — issue body cut off before defining;
  picked conservative `{artifact_type: String, artifact_id: String}`
  (vocabulary tokens like `"pdma"`, `"wbd"`, `"thread"`); persist
  stores opaque, leaves the WBD adjudication contract to canonicalize
  the vocabulary later.
- **`goal_text_canonical`** — issue mentioned the column but not the
  algorithm; implemented ASCII-whitespace trim + collapse runs to
  single space. The unchanged `goal_text` remains the signed form;
  `_canonical` is the lookup discriminant.
- **PG FK violation detection** — `tokio_postgres::Error`'s top-level
  `Display` is just `"db error"`; switched to
  `as_db_error().code()` SQLSTATE check (23503 for FK, 23514 for
  CHECK).

## [2.9.0] — 2026-05-28

**CIRISVerify pin v3.0.1 → v3.7.0 (L1-L5 → un-numbered wire shape) + closes #110.**

CIRISVerify v3.7.0 drops the L1-L5 attestation-ladder wire shape:
`attestation:l1:self_verify` → `attestation:self_verify` (and the four
others analogously); parameterized dimensions
(`provenance:slsa:{level}`, `cert_validity:{authority}`,
`hardware_custody:{platform}`, `transparency_log:*`) unchanged. The
ladder lives nowhere in verify's response now; "measurements, not
levels" is the standing principle.

Persist consumes verify's `ciris-crypto` / `ciris-keyring` /
`ciris-verify-core` APIs (signers, hybrid signatures, transparency-log
machinery) — not its dimension constants — so persist's code is
unaffected by the wire rename. **All 780/780 nextest tests pass on
v3.7.0** on both backends, identical to the 2.7.0 baseline.

- Cargo.toml: 6 `tag = "v3.0.1"` sites → `"v3.7.0"`
  (ciris-keyring/ciris-verify-core/ciris-crypto across base +
  per-target Linux/iOS/Android tables).
- pyproject.toml `Requires-Dist`: `ciris-verify>=3.0.1,<4` →
  `>=3.7.0,<4` — Python wheel consumers of persist now transitively
  pull the un-numbered verify wire shape.

### Closes `#110` (CIRIS 3.0 D09 per-occurrence mandate-fidelity)

`occurrence_id` / `occurrence_count` / `occurrence_role` envelope
fields landed at CIRISRegistry **FSD-002 v1.4.2 §2.1** (envelope-level,
relocated from the requested §3.1.5 since they apply across all
dimension families, not a per-component slice). All three are
**optional** with documented backward-compat defaults
(`occurrence_id → "occurrence-0"`, `occurrence_count → 1`,
`occurrence_role → "primary"`); single-occurrence agents leave them
null/absent.

**Persist needs zero code change.** The `attestation_envelope` JSONB
column on `federation_attestations` stores the envelope opaquely; the
new optional fields ride within automatically. Persist itself emits
no `system:*` attestations that would need to populate the fields
(verified via grep; the only persist reference to `system:*` is a
dimension-axis parsing test in `schema_resolver.rs`).

## [2.8.0] — 2026-05-28

**`#111` — `runtime_handle_capsule` cross-cdylib statics fix (extends #109).**

Persist#109 (v2.7.0) closed cross-cdylib **type identity** via the
`federation_directory_capsule` / `outbound_queue_capsule` /
`keyring_signer_capsule` PyCapsule accessors. #111 is the same
architectural class one layer deeper — **statics duplication**.

When persist is linked into BOTH `ciris_persist.abi3.so` AND a
consumer wheel (e.g. `ciris_edge.abi3.so`, which pulls persist as
a Cargo rlib via its `[dependencies]`), each `.so` gets its own
copy of persist's `static ENGINE_SINGLETON: OnceLock<...>` (and
every other persist `static`). The consumer's copy is never
populated by `ciris_persist.Engine(...)` in Python; that bootstrap
populates the persist `.so`'s copy. So
`ciris_persist::current_runtime_handle()` called from the
consumer's `.so` always returns `None` in production cross-wheel
deployments — the `'persist tokio runtime not yet installed'`
failure that CIRISConformance v0.10.0's cohabitation gate caught
on all 6 cells (3 platforms × 2 backends).

The fix mirrors #109's pattern: a new `#[pymethod]` on `PyEngine`
that wraps `tokio::runtime::Handle` in a `PyCapsule` with name
tag `ciris_persist::runtime_handle`. The handle is sourced from
`self.runtime.handle().clone()` — `self` already IS the singleton
holder in this extension module's view, so the static lookup is
sidestepped entirely. Consumer calls `engine.call_method0(
"runtime_handle_capsule")?` and extracts via
`unsafe { cap.pointer_checked(name)?.cast().as_ref() }`, then
`handle.enter()` to run any async substrate work under persist's
runtime regardless of which cdylib the calling code was linked
into.

The capsule pattern now generalizes to any persist `static`-rooted
accessor cross-wheel consumers might need; if more surface
duplicates this way in the future (a new singleton, a new
process-global), the recipe is the same.

## [2.7.0] — 2026-05-28

**`#104` UI aggregate queries + `#109` PyCapsule cross-module cohabitation accessors.**

Two parallel federation-unblockers — CIRISAgent 2.10.0's Epistemic
Commons Framework UI (#104) and CIRISEdge 0.9.2's cross-wheel
cohabitation init (#109). Shipping bundled because both touched
`src/ffi/pyo3.rs` and were ready together. 780/780 nextest tests pass
on both backends; clippy `--all-targets` clean on default AND full
feature sets.

### `#104` — Three PyO3 aggregate queries on `PyEngine`

Composes on top of the now-stable FederationDirectory + cirisnode +
audit-chain surfaces (the trait surface from 2.6.0). For
CIRISAgent#800's three UI surfaces — Trust Topology, Delegation
screen, The Commons audit-lineage.

- **`federation_directory_query(filter_json)` → `TrustTopology`** —
  feeds `TRUST_NODES + TRUST_EDGES` graph rendering. Walks
  `federation_attestations` rows of type `SCORES` matching the
  filter, partitions by `attestation_type` (`SCORES` /
  `WITHDRAWS` / `RECANTS` / `DELEGATES_TO`), classifies each edge
  as `Direct` / `Delegated` / `Adversarial`.
- **`delegates_to_graph(from_key, max_depth)` → `DelegationGraph`**
  — BFS over the `delegates_to:*` attestation graph from a root
  key, bounded by `MAX_DELEGATION_DEPTH = 16`. Cycle-safe (visited
  set keyed on granter `key_id`); annotates each edge with any
  `WithdrawalEntry` (`withdraws`/`recants`) cancellation.
- **`audit_chain_proof(trace_id)` → `AuditChainProof`** *(feature
  `cirisaudit`)* — walks `audit_log` from genesis to the row
  referencing `trace_id`; surfaces `head_signature` from the
  Merkle tree-head signer when one is installed.

New `src/federation/topology.rs` module + types
(`TrustTopology` / `TrustNode` / `TrustEdge` / `EdgeType` /
`DelegationGraph` / `DelegationEdge` / `WithdrawalEntry` /
`AuditChainProof` / `AuditChainEntry`).

### `#109` — Three PyCapsule cross-module accessors on `PyEngine`

`#[pyclass]` registration is per-extension-module. When
`ciris_persist.abi3.so` and a sibling consumer wheel (e.g.
`ciris_edge.abi3.so`) each statically compile persist's source,
each module registers its own `PyTypeInfo` for `PyEngine` and any
`#[pyclass]` handle struct — Python's type-identity check
(`isinstance(x, PyEngine)`) fails across modules even though both
Rust structs are bit-identical from the same git tag. That's the
production cohabitation init failure CIRISEdge#22 reported on
2.9.x.

The pure-Rust accessors (`pub fn federation_directory()` etc.
from #95) work for sibling cdylibs that share persist's
compiled-in type info; for Python-orchestrated cohabitation
across separately-built wheels, **`PyCapsule` is the right
primitive** — it's an opaque pointer with a name tag, no
`PyTypeInfo` check, and the consumer extracts the wrapped value
via `unsafe { capsule.pointer_checked(name)?.cast() }`.

- **`federation_directory_capsule()`** — wraps the shared
  `Arc<dyn FederationDirectory>` (object-safe after 2.6.0's
  async-trait refactor). Name tag
  `ciris_persist::federation_directory`.
- **`outbound_queue_capsule()`** — wraps the shared
  `BackendDispatch` enum. `OutboundQueue` is RPITIT
  (`impl Future + Send` returns) and therefore NOT object-safe;
  the dispatch-enum wrapping is the same pattern Option-B uses.
  Name tag `ciris_persist::outbound_queue`.
- **`keyring_signer_capsule()`** — wraps the
  `KeyringSignerHandle` (`Arc<dyn HardwareSigner>` +
  `Option<Arc<dyn PqcSigner>>` + `key_id`). Consumer reuses the
  host's already-loaded signer rather than re-bootstrapping the
  keyring (`docs/COHABITATION.md` rule 1). Name tag
  `ciris_persist::keyring_signer`.

The CIRISConformance suite captures `#109` as
`xfail(strict=True)` on `test_init_edge_runtime_succeeds`; the
moment 2.7.0 reaches PyPI and CIRISEdge picks up the capsule API,
that test flips PASSED → XPASS-strict → the cell turns red and the
xfail marker gets removed. That's the design working as intended —
the conformance suite becomes a strict regression gate the moment
the bridge is built.

The longer-term endpoint where Python disappears (the trajectory
endpoint #106 shipped in 2.6.0 unlocks) collapses these PyO3 layers
entirely; capsules are the bridge until then.

## [2.6.0] — 2026-05-28

**Federation-directory cohabitation unlock (#105 + #106 + #108) + retention primitives (#107).**

Bundled — both tracks landed together in the working tree (target-dir
recovery after a parallel-agent disk-fill mid-cut), all verified
together, shipping as one release. 761/761 nextest tests pass on both
backends; clippy `--all-targets -- -D warnings` clean.

### `#105` — `FederationDirectory::list_keys_by_identity_type`

New trait method enumerating `federation_keys` rows by `identity_type`,
stable `key_id` lex-sort order. Unblocks CIRISEdge#19 (2-of-3
accord-holder constitutional verification set) and CIRISEdge#20
(steward gossip topology — class-based recipient derivation +
dynamic rotation phasing).

### `#106` — `Engine::federation_directory() -> Arc<dyn FederationDirectory>`

The Rust-tier cohabitation accessor symmetric with
`node_core_service()`. **Prerequisite refactor:** `FederationDirectory`
was previously RPITIT (`impl Future + Send` returns) and therefore
not object-safe. Migrated to `async-trait` so the trait is now
object-safe and `Arc<dyn FederationDirectory>` compiles. Cost is one
heap allocation per call (the boxed future); negligible for the
directory's call frequency (admission paths, lookups). Documented in
the trait doc-comment.

Lets co-resident Rust crates (NodeCore, LensCore, registry-core) call
persist's federation-directory methods directly in Rust during
cohabitation, without PyO3 method dispatch. The PyO3 layer can shrink
to a one-line marshalling shim — deletable when the host process goes
Rust-native.

### `#108` — `persist_row_hash` surfaced on federation row reads

The `persist_row_hash` column already exists on `federation_keys` /
`federation_attestations` / `federation_revocations` (computed on
insert since V001+). 2.6.0 exposes it on the row types returned by
`FederationDirectory` reads. CIRISVerify v3.2.0's
`FederationProvenance::persist_row_hash: Option<String>` field now
populates from production reads (was always `None` before).

### `#107` — Engine retention primitives

Three Rust-public methods on `Engine` that CIRISLensCore#13 composes
against for v0.4 `RetentionPolicy` enforcement (CIRISLensCore owns
policy; persist owns the deletion primitives — the same split as the
#89 ingest facade):

- `storage_summary() -> StorageSummary` — read-only disk/row/age
  snapshot per table (`trace_events`, `trace_llm_calls`,
  `detection_events`, `audit_log`, `edge_outbound_queue`,
  `federation_keys`, total disk). Eviction-scheduler input.
- `delete_traces_older_than(ts, max_rows) -> usize` — batch-capped
  trace eviction (CTE-bounded DELETE on PG; `rowid IN (SELECT … LIMIT)`
  on SQLite). Bounded transaction size for Pi-class + Postgres-class
  alike.
- `archive_audit_range(from_ts, to_ts) -> ArchiveHandle` —
  **chain-preserving** audit archive. The audit hash chain
  (V014+: `UNIQUE(tenant_id, sequence_number)` + `prev_hash`) cannot
  tolerate a plain DELETE. Persist writes a chain-anchored archive
  blob (V049 `audit_archives` migration, both dialects) holding the
  canonical-bytes archive of the range; the live `audit_log` retains
  the row immediately after the archived range, whose `prev_hash`
  still points at the archived range's last row — verifiers walk the
  chain across the archive via the `chain_anchor` exposed on
  `ArchiveHandle`.

Public types: `StorageSummary`, `TableUsage`, `ArchiveHandle`. New
`src/retention/` module with `pub mod` re-export from `lib.rs`.

V049 (both dialects) — `audit_archives` table for the chain-anchored
blobs. qa_harness migration-count bound bumped to `1..=49`.

## [2.5.0] — 2026-05-27

**`#102` complete (final 2 of 8 asks) — envelope-schema validation hook (Ask 4) + hardware-attestation evidence (Ask 8).**

The two infrastructure-heavy asks that were deferred from 2.4.0. With
2.5.0 #102 is fully closed.

### Ask 4 — Envelope-schema validation hook (FSD-002 §4.9.1)

`SchemaResolver` trait + two impls + admission-hook integration. Lets
persist validate `scores` attestation envelopes at admission time
against per-axis JSON schemas.

- **`SchemaResolver`** — object-safe via boxed-future returns
  (`Pin<Box<dyn Future>>`), so backends store `Arc<dyn SchemaResolver>`.
  Default `NoOpSchemaResolver` returns `None` (fail-open; existing
  put_attestation callers don't break).
- **`BlobBackedSchemaResolver<B: BlobStorage>`** — generic over the
  concrete blob backend (BlobStorage isn't itself object-safe).
  Operator-supplied `axis_index: HashMap<String, [u8; 32]>` maps axis
  names to content SHAs; resolves schemas via `BlobStorage::get_blob`.
  Hash-keyed cache (`Arc<Mutex<HashMap<[u8;32], serde_json::Value>>>`)
  so axis-index churn doesn't invalidate cached bodies. Axis
  vocabulary is bounded (FSD-002 §4.9 — ~10s today, ~100s lifetime
  max even with §4.9.2 amendment churn), so plain HashMap beats LRU.
- **`axis_from_dimension(dimension) -> Option<&str>`** — pure helper
  that picks the last non-`:v[0-9]+` segment. FSD-002 §4.9.1 worked
  example: `detection:correlated_action:rights_asymmetry:v1` →
  `rights_asymmetry`.
- **Admission hook** — after `DimensionAdmissionPolicy::check`
  passes, if the engine has a resolver wired AND
  `attestation_type == "scores"`, validates the envelope JSON
  against the resolved schema via `jsonschema` 0.46
  (`default-features = false` — pure Rust, no file-fetch /
  network-fetch surfaces). On failure: typed
  `Error::EnvelopeSchemaViolation { dimension, axis, violations }`.
- Per-deployment `set_schema_resolver(Arc<...>)` on each backend.
  No Engine-level constructor variant; matches the `with_inline_bytes_cap`
  pattern from 2.3.0.

### Ask 8 — Hardware-attestation `attestation_evidence` (FSD-002 §7.3)

The data-model implementation of today's CIRISVerify
`docs/HARDWARE_ATTESTATION.md` answer: persist stores the evidence;
admission-hook policy decides acceptance.

- **V048 (both dialects)** — adds `attestation_evidence` column to
  `federation_keys`: `JSONB NULL` on PG, `TEXT NULL` on SQLite
  (JSON-as-text, mirrors persist's existing pattern). PG enforces
  via named `CHECK federation_keys_accord_holder_requires_attestation`
  (`identity_type <> 'accord_holder' OR attestation_evidence IS NOT NULL`);
  SQLite via `BEFORE INSERT` / `BEFORE UPDATE` trigger pair with
  `RAISE(ABORT, '<constraint name>')`. Partial index on accord-holder
  rows for the admission hot path.
- **`HardwareAttestationPolicy`** — `pub` fields
  (`accepted_hardware_types: HashSet<HardwareType>`, `max_nonce_age: Duration`).
  Default `accepted_hardware_types` lists the 11 non-`SoftwareOnly`
  variants **explicitly** — so a future ciris-keyring variant
  becomes a compile error here, forcing a policy decision rather
  than silent admission. Default nonce age 24h.
- **Admission hook** — on every `federation_keys` write with
  `identity_type = 'accord_holder'`:
  1. Parse `attestation_evidence` as
     `{platform_attestation, nonce_captured_at}`. Missing/malformed →
     `Error::AccordHolderRequiresAttestationEvidence`.
  2. Pick the finer-grained `HardwareType` from the variant body
     (`AndroidStrongbox` if `strongbox_backed`; `TpmDiscrete` if
     `discrete`; etc.). Reject with `HardwareTypeNotAccepted` if
     not in policy.
  3. Structural field-presence check per variant (Android: cert
     chain + Play Integrity token + StrongBox flag; iOS: SE flag +
     App Attest assertion + DeviceCheck token; TPM: TPMS_ATTEST
     quote + EK cert + AK pubkey + PCR values + manufacturer).
     Missing → `AttestationEvidenceIncomplete { hardware_type, missing_fields }`.
  4. Nonce-freshness vs `max_nonce_age`. Stale →
     `AttestationEvidenceStale`.
- **What persist does NOT do**: active chain validation (cert chain
  to Google root for Android, EK cert validation for TPM, etc.).
  Per CIRISVerify `docs/HARDWARE_ATTESTATION.md` §"Honest gap" —
  Verify#32 Ask 5 lands local chain validators. Until then,
  registry-side validates the chains; persist's storage of the
  evidence preserves the audit trail.

### Side-effect fix

Pre-existing `cirisnode::postgres::tests::list_contributions_filter_extension`
flake — hardcoded `[0xC4; 32]` author seed accumulated under the same
key across re-runs on the shared CI PG container. Per
`feedback_hundred_percent_green`, fixed (UUID-v4-derived seed) rather
than deferred.

V048 migration count bound: `1..=48`. PG `pg_row_to_key_record`
reads via `try_get::<_, Option<serde_json::Value>>` (absent column +
NULL both collapse to `None` — handles both pre- and post-V048
schemas via the same code path).

## [2.4.0] — 2026-05-27

**`#102` first cut (6 of 8 asks) — Registry directory contract: vocabularies + admission gate + operational docs.**

The Registry-side asks that don't need new substrate infrastructure
land in 2.4.0. The two infrastructure-heavy asks — envelope-schema
validation hook (Ask 4) and `attestation_evidence` column for
hardware-attested accord-holder rows (Ask 8) — are deferred to 2.5.0.

Per CIRISRegistry FSD-002 v1.4 + v1.2 deltas (`a46ff01`).

### Ask 1 — `identity_type` vocabulary extension

`federation_keys.identity_type` was already free-form `TEXT NOT NULL`
with no CHECK constraint, so no migration was needed. Added
`identity_type::ACCORD_HOLDER = "accord_holder"` constant + a
documented vocabulary table in `docs/FEDERATION_DIRECTORY.md` listing
all five values (`steward` / `agent` / `primitive` / `partner` /
`accord_holder`) with per-value rationale citing FSD-002 §7.2.

### Ask 2 — `attestation_type` vocabulary replacement (clean break)

Persist is the only consumer of `federation_attestations` and the
wire shape was not finalized. **Clean slate replacement** per
`feedback_clean_break_renames` — no deprecation aliases:

- `VOUCHES_FOR` / `WITNESSES` / `REFERRED` / `DELEGATED_TO`
  *(removed)*
- `SCORES` / `DELEGATES_TO` / `SUPERSEDES` / `WITHDRAWS` / `RECANTS`
  *(new)*

Per FSD-002 v1.2 Ask 2 delta + PRIOR_ART_SCAN Bucket 1: `recants` is
**wire-distinct** from `withdraws` — no prior (PGP/SPKI/VC) typed
epistemic-error-admission as a wire primitive. Consumer UIs may
collapse them; the wire keeps them distinct. Every old-constant
reference across `src/`, `docs/`, `THREAT_MODEL.md` updated.

### Ask 3 — Wire-enforced admission gate (FSD-002 §1.10.1)

`put_attestation` admission path gains a `DimensionAdmissionPolicy`
gate that fires only on `scores` attestations (the four structural
primitives — `delegates_to` / `supersedes` / `withdraws` / `recants`
— bypass; they carry structural metadata, not epistemic content).

**Layer 1 — the constitutional asymmetry** (FSD-002 §4.1 + §7): a
`dimension` starting with `accord:` is rejected when the attesting
key's `identity_type` is not `accord_holder`. Typed
`Error::AccordDimensionRequiresAccordHolder`. The schema CHECK can't
enforce this (the constraint crosses tables — attestations row vs.
keys row), so admission carries it.

**Layer 2 — the four-test operational-language gate** (FSD-002 v1.2
§1.10.1):

1. Rules/verdicts separation — reject morally-charged stems
   (`deception` / `harm` / `evil` / `bad_actor` /
   `trustworthiness` / `malicious` / `lies`). The v1.2 rename target
   `emergent_deception` → `correlated_action` is encoded by this
   deny-list.
2. Mechanism-descriptive-not-judgment-descriptive naming — same
   deny-list class as #1.
3. **Version-pinning** — every accepted `scores` dimension MUST
   carry a `:v[0-9]+` segment.
4. Adjudication separation — same deny-list as #1; verdicts/policy
   are downstream of measurement.

Default policy is deny-on-fail; the `DimensionAdmissionPolicy` struct
has `pub` fields so sovereign deployments can extend the stem list.
Empty dimension on a `scores` attestation is rejected (wire-format
floor, not a policy choice). 24 tests cover the gate on both backends
(12 unit + 6 sqlite-backend + 6 postgres-backend), including the
FSD v1.2 rename-chain delta (structural primitive
`delegates_to:correlated_action_v2:from:emergent_deception_v1` is
exempt — references a now-banned dimension but the primitive itself
isn't measuring, it's structural).

### Asks 5, 6, 7 — Operational documentation

Three new sections in `docs/FEDERATION_DIRECTORY.md`:

- **Cross-region replication** (Ask 5): `federation_keys` rows with
  `identity_type ∈ {steward, accord_holder}` replicate to all
  regions (US / EU / APAC); other keys + their attestations
  replicate per the publishing key's residency; Spock
  replication-group config is **deployment-side** (no canonical
  persist topology document to cite, flagged honestly).
- **Transport story** (Ask 6): in-process (shipping) + direct-DB
  (shipping); **gRPC deferred** — persist v2.4.0 has no gRPC
  server, interim Registry deployments use direct-DB. Registry's
  three requirements (transactional `put_attestation`, sub-100ms
  cache-miss latency, distinguishable `Conflict` vs
  `RateLimited` errors) audited against current persist; honest
  gap surfaced: `Error::Conflict(String)` doesn't carry a
  structured `existing` payload.
- **PQC cold-path cadence** (Ask 7): persist exposes the
  `attach_*_pqc_signature` API; the cadence is
  **deployer-driven** (typical 5 min, worst-case
  deployer-configured). Registry's cache-TTL discipline reads this
  to size the hybrid-pending window.

### Hotfix carried in 2.4.0

2.3.0 (federation_blobs) committed to main but never tagged — its
default-features build failed clippy under `-D warnings` because two
`pub(crate)` helpers (`BlobBody::storage_kind` and
`verify_inline_hash`) were dead under no-backend builds. Cfg-gated to
`#[cfg(any(feature = "postgres", feature = "sqlite"))]`. 2.4.0
publishes 2.3.0's federation_blobs work + 2.4.0's directory-contract
work in a single PyPI release.

### Side-effect fix

Pre-existing PG `put_attestation`'s `weight` bind never actually
worked (`Option<f64>` against `NUMERIC` has no built-in
`tokio-postgres` serializer; no test had ever exercised the path).
Fixed via `$N::float8::numeric` write-side cast + `weight::float8`
read-side cast in the four affected SELECTs.

## [2.3.0] — 2026-05-27

**`#103` — content-addressable `federation_blobs` storage substrate.**

Where the SHA-256 hashes in `federation_attestations.evidence_refs`
actually resolve to bytes. The federation directory names what
exists; v2.3.0 adds the storage layer those SHAs point at — the
companion to CIRISEdge#21 (ContentFetch transport) and the planned
NodeCore node-mode serving.

### `federation_blobs` table (V047, both dialects)

- `sha256 BYTEA/BLOB PRIMARY KEY` (32-byte content hash); `storage_kind`
  CHECK `IN ('inline','s3','external_url')`; `bytes_inline` /
  `external_ref` columns with a named CHECK enforcing the inline ↔
  external split; `size_bytes`, `media_type`, `first_seen_at`,
  `regions_held TEXT[]` for per-region replication tracking.
- SQLite uses a table-level CHECK (no triggers needed at CREATE TABLE
  time) for cross-column constraint enforcement.

### `BlobStorage` trait — sibling, not a `FederationDirectory` extension

`put_blob` / `get_blob` / `has_blob` / `list_holders`. The federation
directory's surface is identity + trust statements; blobs are
content-addressable bytes — distinct concern, clean siblings, both
implemented by the same backends.

- `BlobBody { Inline(Vec<u8>) | External(ExternalRef) }` — the API
  takes whichever the caller supplies; persist stores the inline
  bytes or the external URI metadata. Persist never fetches from S3
  — that's the caller's responsibility.
- **Hash-on-write**: `put_blob(sha256, Inline(bytes), …)` hashes the
  bytes (via `sha2`) and rejects mismatch with typed
  `BlobError::HashMismatch { expected_hex, got_hex }`. External case
  trusts the caller-supplied SHA (documented invariant — same
  posture as the caller-supplied scrubber path).
- **Inline-size cap**: configurable per backend via
  `with_inline_bytes_cap(cap)` builder; default 1 MiB. Prevents a
  misbehaving caller from inlining a multi-GB blob; rejected with
  typed `BlobError::InlineSizeExceeded`.
- **Conflicting-storage_kind policy**: first-write-wins (silent
  accept). The blob is content-addressed; the SHA is the identity;
  `storage_kind` is a per-host hint, not a wire property. The SHA
  PK collapses replays via `INSERT … ON CONFLICT DO NOTHING`. The
  holder attestation lands per call regardless, so `list_holders`
  returns every writer.
- **Idempotent `put_blob`**: same SHA, same bytes — no error, no
  duplicate row.

### `holds_bytes:sha256:*` attestation auto-emission

Every successful `put_blob` writes an attestation into the existing
`federation_attestations` table with
`attestation_type = "holds_bytes:sha256:<first-8-hex-of-hash>"`. The
full 64-hex SHA lives in the attestation envelope's `evidence_refs`
array — collision resolution for the rare prefix collision. 8 hex
chars = 32 bits = birthday collision at ~65k blobs, well within
federation scale. `list_holders(sha256)` queries the prefix index
server-side then filters by `evidence_refs` client-side.

### PyO3 surface

`put_blob_json` / `get_blob_json` / `has_blob_json` /
`list_holders_json`. Inline bytes are base64-standard strings on the
JSON wire, raw bytes server-side — mirrors v2.2.0's
`delivery_attestation` PyO3 surface.

### Out of scope for v0.1 (deferred)

- **GC**. Blobs persist forever in v2.3.0; trait deliberately
  exposes no `delete_blob`. A future migration adds
  reference-counting + a `prune_blobs(min_age)` API.
- **Server-side `evidence_refs[]` containment lookup**. Today the
  full-SHA filter is client-side after the prefix query; a future
  migration could add an indexed `evidence_refs TEXT[]` projection
  column for server-side lookup.

V047 migration (both dialects, single). qa_harness migration-count
bound `1..=47`. Full nextest: **678 tests pass on both backends**
(`postgres,server,pyo3,sqlite,cirisaudit,secrets,cirisnode,cirisgraph,telemetry`).

## [2.2.0] — 2026-05-27

**`#101` — `federation_announcement` subject_kind + `federation_delivery_attestations` table.**

Persist now carries the federation-tier governance primitive — the
durable, tamper-evident record of multi-party bootstrap rotations,
threshold raises, key rotations, kill-switch invocations, and accord
carriers — that CIRISNodeCore emits and every peer must be able to
audit.

### `federation_announcement` subject_kind

- Rust types `FederationAnnouncementPayload`, `AnnouncementPriority`,
  `AnnouncementKind`, `AuthorityClass`, `AccordCarrier` mirror
  CIRISNodeCore `FSD/FEDERATION_ANNOUNCEMENT.md` §2.1 byte-exact (same
  field names, same serde rename rules, same enum variants — the
  cross-repo wire contract).
- Persist's canonical-chain row reused (the announcement is a
  Contribution; subject_kind is the new discriminator). Two indexed
  projection columns `announcement_priority` /
  `announcement_authority_class` so the constitutional CHECK and the
  filter API don't dig into JSONB per-row.
- **Constitutional asymmetry enforced at write admission** (per FSD
  §4.5 + Registry FSD-002 v1.4 §7.1): only
  `AuthorityClass::HumanityAccord` may sign a `priority == AccordCarrier`
  or `kind == AccordCarrier` announcement. Rejection is a typed
  `Error::FederationAnnouncementAuthorityMismatch`; the DB CHECK /
  SQLite trigger enforces the same rule independently — defense in
  depth. The first wire-format asymmetry that joins the existing
  trust-gate values (Open / Trust-gated / Witness-set-gated /
  Author-only) as **Authority-class-gated**.

### `federation_delivery_attestations` table (FSD §3.2.1 ratified)

The per-peer attestation that an announcement reached an edge's
application layer — the substrate observable RATCHET reads to detect
adversarial suppression. Wire contract was open question #3 of FSD
§7; ratified 2026-05-27 at FSD §3.2.1 by NodeCore (author),
CIRISEdge#18 (producer), and persist (this issue).

- One-to-one with the wire `DeliveryAttestation` struct:
  `announcement_id` (Contribution::id), `announcement_canonical_hash`
  (32-byte SHA-256 of canonicalized envelope including authority
  signature), `peer_key_id` + `peer_pubkey_ed25519_base64`,
  `received_at`, `transport_id` enum (`reticulum` / `tcp_tls` /
  `http_over_tls` / `other`), `signature_classical`,
  `signature_pqc` (optional ML-DSA-65).
- PK `(announcement_id, peer_key_id)` — idempotent on replay.
- Canonical-bytes encoder with domain string
  `ciris-edge-delivery-attestation-v1`, length-prefixed injective,
  mirrors CIRISEdge's `AttestationPayload::canonical_bytes` exactly
  (cross-repo wire contract — golden-vector test guards against
  drift). Hybrid signature follows persist's AV-33 bound-signature
  convention (PQC over `canonical_bytes || classical_sig`).
- Trait surface: `put_delivery_attestation`,
  `list_delivery_attestations(announcement_id)`,
  `count_delivery_attestations(announcement_id)`. Verifies the
  hybrid signature against `federation_keys[peer_key_id]` via
  persist's existing directory-lookup path; idempotent on duplicate
  `(announcement_id, peer_key_id)` (the FSD's replay-no-op contract).

### `list_contributions` filter extension

`ContributionsFilter` gains three optional fields — `priority`,
`authority_class`, `kind` — applied only when
`subject_kind == federation_announcement`. Backward-compatible
(serde defaults to `None`; existing call sites unchanged).
RATCHET + LensCore consume this for governance-history scans.

### PyO3 surface

`cirisnode_put_delivery_attestation` / `cirisnode_list_delivery_attestations`
/ `cirisnode_count_delivery_attestations`; existing
`cirisnode_list_contributions` routes the new filter fields through
serde defaults.

V046 migration (both dialects) is single — the announcement row
extensions + the delivery-attestations table ship atomically (the
FSD §3.2 substrate contract is atomic across them). qa_harness
## [2.0.2] — 2026-05-22

**Hotfix:** `pyproject.toml` `Requires-Dist` for the transitive
`ciris-verify` PyPI package was still pinned `>=2.1.5,<3` in 2.0.1
— even though the Rust-side `Cargo.toml` had moved to verify v3.0.1
in the 2.0-prep cut. Consumers running
`pip install ciris-persist>=2.0.1 ciris-verify>=3.0.1` hit an
irreconcilable resolver conflict; the install failed before any
code ran. 2.0.2 fixes the Python metadata to
`ciris-verify>=3.0.1,<4` so the Python wheel agrees with the Rust
crate about which verify major it's on. **Yank 2.0.1 from PyPI**
so new installs don't pick it up by default.

## [2.0.1] — 2026-05-22

**`#95` — Rust-level accessors for the cohabitation surface.**

Three plain `pub fn` accessors on `PyEngine` so a sibling cdylib
(CIRISEdge#16) can build a `ciris_edge::Edge` from the *shared*
engine, mirroring the Option-B pattern `node_core_service()` already
established:

- `federation_directory() -> BackendDispatch` — the federation
  directory substrate; the consumer matches the variant and calls
  `FederationDirectory` trait methods on the concrete backend.
- `outbound_queue() -> BackendDispatch` — the outbound-queue
  substrate; same shape, named distinctly so the call site documents
  which trait surface the consumer is using.
- `keyring_signer() -> KeyringSignerHandle` — the federation keyring
  signer parts (`Arc<dyn HardwareSigner>` + `Option<Arc<dyn PqcSigner>>`
  + `key_id`); Edge wraps these in its own `LocalSigner` without
  re-bootstrapping the keyring (`docs/COHABITATION.md` rule 1).

`LocalSigner::pqc_signer()` promoted from `pub(crate) pqc_signer_arc()`
— its doc-comment literally said "wired by the PyO3 Engine refactor in
a follow-up release"; this is that release. Unblocks CIRISEdge#16.

### `lookup_grant_id_by_chain_event` is now tenant-aware

The schema-API mismatch surfaced the moment cirisaudit tests finally
ran in CI (3 of the v2.0.1 matrix entries' first failures): the PG
impl queried `WHERE chain_event_id = $1` via `query_opt`, but
`audit_log.sequence_number` is `UNIQUE(tenant_id, sequence_number)`
— per-tenant — so two grants in different tenants share a
`chain_event_id` and the lookup blew up "unexpected number of rows."
Trait signature gains `tenant_id`, PG + SQLite SQL filters on
`(tenant_id, chain_event_id)`. **V045** adds the matching
`UNIQUE(tenant_id, chain_event_id)` index — the schema and the
query now agree (mirrors V021's `merkle_leaves` shape).

### Secrets PG tests are cross-process-safe under nextest

Nextest runs each test in its own process, so the pre-existing
`#[serial_test::serial(postgres)]` (in-process serialization) no
longer covers them. The PG secrets tests share
`cirislens_secrets.{master_key_meta,secrets,…}` plus a per-process
`SOFTWARE_KEYS` cache — two processes racing TRUNCATEs of the same
table left one process pointing at a master-key row whose bytes
lived in *another* process's cache → "active master key has no
in-memory bytes" panics, plus a deadpool-pool starvation that
nextest's 6-min terminate killed (the formerly-mystery timeout).
Switched the affected tests to a session-scoped PG advisory lock
(`PG_SECRETS_TEST_LOCK_ID = 'cirsscrt'` on a dedicated non-pooled
connection) — the same primitive `run_migrations` uses for its own
cross-process serialization. 5 PG secrets tests fixed; one was also
missing its `reset_secrets_state` call entirely.

### CI — nextest + bounded hang-detection

The 2.0 substrate-widening (every substrate's PG backend now tested
in CI) exposed a CI-specific hang in the secrets test suite that sat
silently for >1 hour twice before manual cancel — `cargo test` buffers
its output per-test, so a hung test prints nothing. Switching the
matrix test job to `cargo nextest run --no-fail-fast --all-targets`
gives per-test streaming PASS/FAIL/SLOW lines (you always know which
test is currently running) and the `.config/nextest.toml`
`slow-timeout = { period = "60s", terminate-after = 6 }` setting kills
any test that runs >6 minutes with its name in the log. Plus a
workflow-step `timeout-minutes: 25` as a backstop if nextest itself
stalls. Together: any future hang surfaces in <6 min with the test
name, and the step is bounded at 25 min regardless.

## [2.0.0] — 2026-05-22

**CIRISPersist 2.0 — Federation Ready.** The release that consolidates
persist onto the CIRIS 3.0 federation line: the federation surface
shipped and stable, every substrate concurrency-hardened and
CI-tested.

### CIRISVerify v3.0.1 — the federation major

`ciris-verify-core` / `ciris-keyring` / `ciris-crypto` pinned to the
CIRISVerify 3.0 line (v2.8.0 → v3.0.1; major `2` → `3`). Persist
tracks the federation-wide major; no breakage on persist's consumed
crypto / keyring / transparency surface.

### The federation surface (shipped v1.12–v1.13, stable at 2.0)

`root_binding` — cold-start binding rooting against `federation_keys`:
confirms a first-contact `key_id` by walking its recursive provenance
to a steward bootstrap, instead of trust-on-first-use.
`provenance_chain` — the verify-consumable recursive-provenance read.
`current_rust_engine()` — the co-resident `Arc<Engine>` bridge. The
persist side of the CIRIS 3.0 critical path (`CIRISVerify#28`).

### Concurrency hardening

- **Master-key bootstrap race** (production bug): `rotate_master_key`
  first-use activation was a check-then-act with no DB invariant —
  concurrent bootstraps on Postgres yielded multiple active master
  keys and `encrypt()` failed. **V043** adds a partial unique index
  DB-enforcing one active master key; `rotate_master_key` is now a
  single transaction with the index as backstop and a typed
  loser-converges path.
- **Telemetry rollup**: a flaky daily-tier test exposed a real bug —
  Postgres rounds a nanosecond timestamp on the `::timestamptz` cast
  while `tokio-postgres` truncates the bind parameter; at the day
  boundary the rollup silently dropped a window. Fixed (summary
  timestamps truncated to microseconds before serialization).
- Audit chain confirmed concurrency-safe (`SELECT … FOR UPDATE` +
  `UNIQUE(tenant_id, sequence_number)`).

### #91 — relay skip-verify

`IngestPipeline` gains an opt-in `VerifyMode` (`Full` default;
`TrustPreVerified`) so a relay ingesting already-Edge-verified batches
skips the redundant per-trace federation-directory lookup. A new
`verification_source` column (**V044** — `persist` / `edge`) records
*who* attested authenticity, so `signature_verified = true` stays
honest and a relay-ingested trace is distinguishable from a
persist-verified one rather than conflated. Reached via
`Engine::receive_and_persist_pre_verified`. The lens direct-ingest
path is unchanged.

### #93 — `audit_service()`

`Engine` / `PyEngine` gain `audit_service() -> AuditDispatch` — the
dispatch-enum accessor for the audit substrate, twin of
`node_core_service()`.

### Every substrate CI-tested

`cirisaudit`, `secrets`, `cirisnode`, `cirisgraph`, `telemetry` added
to the CI test + clippy matrix — those substrates' Postgres backends
were previously unexercised in CI. Full suite (566 lib + 22
integration) green on both backends.

## [1.13.0] — 2026-05-22

**`current_rust_engine()` — the process-singleton `Arc<Engine>` bridge
for co-resident Rust consumers (closes #92).**

The CIRIS 3.0 cohabitation model puts the agent + NodeCore + LensCore +
Edge in one process sharing one `Engine`. A co-resident Rust extension
(CIRISLensCore's `init_edge_runtime` relay path; CIRISEdge's resolver)
needs the Rust `Arc<Engine>` for the singleton the Python host built —
but `PyEngine` is a *sibling* of the Rust `Engine`, not a wrapper, with
no `Arc<Engine>` inside it.

### New surface

- `current_rust_engine() -> Option<Arc<Engine>>` — a free accessor over
  the process-singleton: builds (once, cached on the `EngineCell`) and
  returns the Rust `Arc<Engine>` view of the same engine `PyEngine`
  dispatches to — shared backend pool, shared signer, **no second
  `Engine` / runtime / connection pool**.
- `current_runtime_handle() -> Option<tokio::runtime::Handle>` — the
  singleton's long-lived runtime handle, so a co-resident consumer's
  `block_on` keeps the Postgres pool's connection-driver tasks on the
  process-lifetime runtime.
- `Engine::from_shared(backend, signer)` — construct an `Engine` from
  already-live parts; no new connection, no migration run.

### Breaking — `Engine::signer()` return type

`Engine` now holds `Arc<dyn ciris_keyring::HardwareSigner>` (was
`Arc<LocalSigner>`); `Engine::signer()` returns
`&Arc<dyn HardwareSigner>`. This makes `Engine` signer-compatible with
the process singleton and correct on hardware-attested deployments.
The constructors (`with_signer`, `with_signer_arcs`) are unchanged —
they still accept `Arc<LocalSigner>` and wrap it in the
`LocalSignerHardwareAdapter`. `Engine::signer()` had no known
consumers; flagged per the clean-break convention.

### Build — `extension-module` is now its own feature

`pyo3/extension-module` is split out of the always-on `pyo3` cargo
feature into a dedicated `extension-module` feature (maturin enables it
for the wheel via `pyproject.toml [tool.maturin] features`). The wheel
is unchanged; `cargo test --features pyo3` now links libpython the
normal way instead of failing on `undefined symbol: _Py_DecRef`.

## [1.12.0] — 2026-05-22

**Cold-start binding rooting — the CIRIS 3.0 critical-path node
(closes #94; CIRISVerify#28 Phase 2 / #29 WS-4).**

The 3.0 critical path is `CIRISVerify#27 → CIRISPersist rooting →
CIRISEdge resolver → fleet enforcement`. CIRISVerify#27 shipped at
v2.9.0; this release ships the next node — nothing downstream of
persist moved until it landed.

### `root_binding` — cold-start binding rooting

`federation::root_binding(directory, key_id, claimed_pubkey)` confirms
a first-contact federation `key_id` binding against the
`federation_keys` directory **instead of trust-on-first-use**: it
resolves the directory row, checks the claimed Ed25519 pubkey against
it, and walks the row's recursive provenance chain — each link's
scrub-signature verified through CIRISVerify — to a self-signed steward
bootstrap. Returns a typed `RootingVerdict`: `Confirmed { chain }` or
`Rejected { reason }` over eight typed rejection reasons (unknown key,
pubkey mismatch, broken / unsigned provenance link, not rooted at a
steward, cycle, over-depth, directory error). No third state; the walk
is depth-capped (64) and cycle-detected. CIRISEdge's `PeerResolver`
calls this on cold start.

### `provenance_chain` — verify-consumable read (WS-4)

`federation::provenance_chain(directory, key_id)` returns the
`federation_keys` row plus its full recursive-provenance four-tuple
(`original_content_hash` · `scrub_signature_classical`/`_pqc` ·
`scrub_key_id` parent pointer · `scrub_timestamp`), leaf→root, so
CIRISVerify can verify the chain verify-side and migrate off
registry-local `trusted_primitive_keys`.

Both surfaces are Rust-public and PyO3-exposed, work identically on
Postgres and SQLite (16-test conformance suite on both), and add **no
migration** — the four-tuple is the existing v0.1.3 scrub-signing
envelope on every directory row. Per finding G, transport identities
stay routing-only — never rooted, never in the provenance chain. A
hybrid-pending link (cold-path ML-DSA-65 not yet attached) is verified
on Ed25519 alone; a caller wanting PQC-strictness walks
`provenance_chain` and applies its own policy. The `RootingVerdict` /
`ProvenanceChain` types are the cross-repo contract for CIRISVerify
WS-4 and CIRISEdge #28 Phase 3 to ratify.

## [1.11.1] — 2026-05-22

**V042 — data-aware analytics indexes ("covering indexes as a
poor-man's column store").**

The `ReadEngine` scoring analytics scanned raw `trace_events` and
heap-fetched `payload` per row. V042 adds partial + expression +
composite indexes — one per (scored-scalar × event_type) — that turn
the scoring queries into **index-only scans**: column projection
(the index holds only the columns the query touches), row
elimination (the `WHERE event_type = '…'` partial predicate
physically excludes the ~2/3 of rows whose event-type doesn't carry
that scalar), and sorted runs (the composite key). Pure
`CREATE INDEX` — no schema change — and **both backends** (SQLite +
Postgres; backend parity preserved, no TimescaleDB-only path).

`EXPLAIN QUERY PLAN` confirms the structural change:
`cross_agent_divergence` goes from `SCAN trace_events` to
`SEARCH … USING INDEX trace_events_an_csdma` — index-only, no heap
fetch, no JSON re-parse. Controlled before/after on a realistic
federation corpus: `cross_agent_divergence` ~−42%,
`aggregate_llm_costs` ~−30%.

Two query families V042 deliberately leaves on the V041 range-scan —
honest data-shape limits: `conscience_override_rates` /
`aggregate_scoring_factors` test `event_type` *inside* a `MAX(CASE…)`
aggregate, not in `WHERE`, so they must scan every event-type of a
trace; and `list_trace_summaries`' multi-field FILTER aggregates
have no narrow covering index.

The `read_engine_analytics` bench seed was widened 2 → 24 agents —
the 2-agent corpus was degenerate (the SQLite planner chose a
skip-scan over the covering index, so the bench could not observe
the optimisation). The dashboard baseline resets to realistic-corpus
numbers from this release.

The residual gap to a true columnar engine after V042 — vectorized
SIMD execution + column compression, ~2–5× on the heaviest scans —
is the genuine architectural floor. The earlier "10–50× behind"
figure measured the *absence of targeted indexes*, not the
row-store architecture.

## [1.11.0] — 2026-05-22

**Consumer-facing facades — `Engine::receive_and_persist` (#89) and
`node_core_service()` (#90).**

Two Rust-public surfaces that close "compose around the substrate"
gaps for in-process consumers — CIRISLensCore relay mode and
CIRISNodeCore phases 2–3.

### `Engine::receive_and_persist` (CIRISPersist#89)

```rust
pub async fn Engine::receive_and_persist(
    &self, bytes: &[u8], scrubber: &dyn Scrubber,
) -> Result<BatchSummary, IngestError>
```

The Rust-side sibling of the PyO3 `receive_and_persist` — lens-core's
v0.2 relay handler is Rust and holds `Arc<Engine>`, so it needs a
Rust-public ingest facade rather than reaching into `Engine`'s parts
to reassemble `IngestPipeline` itself.

The scrubber is **caller-supplied** — not owned by `Engine`, not
baked into the facade. The privacy boundary is the originating node's
egress filter: federation-transit relay ingest passes `&NullScrubber`
(re-scrubbing at a relay would drift the stored bytes vs. what Edge
verified, and demand NER models relays aren't provisioned with),
while a first-hop deployment passes its real scrubber — the topology
decision lives at the call site. The canonicalizer is
facade-internal; the signer is the `Engine`'s existing `LocalSigner`,
adapted to `HardwareSigner` via a new `LocalSignerHardwareAdapter`.
Zero new `Engine` fields.

### `node_core_service()` (CIRISPersist#90)

`Engine::node_core_service()` / `PyEngine::node_core_service()` return
a `NodeCoreDispatch` enum (`Postgres` / `Sqlite` variants) — the
object-safe form of the issue's Option B. `NodeCoreService` is RPITIT
and cannot be `dyn`-ed, so this mirrors the existing
`Engine::maintenance() -> EngineMaintenance` dispatch-enum pattern.
CIRISNodeCore's PyO3 bindings match on it to drive their `NodeCore<E>`
logic through an injected persist engine.

Follow-up tracked: CIRISPersist#91 — a skip-verify path for relay
ingest of batches that arrived already Edge-verified.

## [1.10.3] — 2026-05-22

**CIRISVerify pin → v2.8.0 — ~9× faster secrets-at-rest crypto.**

v2.8.0 ships the AES-256-GCM AEAD optimisation that closes
CIRISVerify#26 — an issue filed straight off CIRISPersist's
`secrets_crypto` bench (v1.10.2 measured ~1 GiB/s, ~3–5× below the
ring/OpenSSL SOTA band). Re-running that same bench against v2.8.0:

| AES-256-GCM, 16 KiB | v2.7.0 | v2.8.0 |
|---|---|---|
| encrypt | 15.1 µs (~1.0 GiB/s) | 1.60 µs (~9.5 GiB/s) |
| decrypt | 15.4 µs (~1.0 GiB/s) | 1.51 µs (~10.1 GiB/s) |

A ~9.4× throughput gain on the secrets-at-rest crypto path
(`store_secret` / `recall_secret`, and `reencrypt_all` which runs it
per row), now ahead of the ring/OpenSSL band. `ciris-verify-core` /
`ciris-keyring` / `ciris-crypto` pins bumped v2.7.0 → v2.8.0; no API
breakage. The bench-coverage loop did its job end to end — measure,
file, fix upstream, confirm.

## [1.10.2] — 2026-05-21

**`reencrypt_all` chunked transaction (perf review H2), CIRISVerify
pin → v2.6.1, and the benchmark-coverage cut.**

### `reencrypt_all` — bounded-chunk re-encryption

`reencrypt_all` (the master-key rotation / `migrate_to_hardware_key`
re-encrypt pass) held one transaction across the *whole* secrets
table — with PBKDF2 at ~100 ms/secret that is a multi-minute write
lock on a large store. It now re-encrypts in 64-row chunks: the
CPU-bound decrypt/derive/encrypt runs with no transaction open
(SQLite: no connection lock held), and only each chunk's `UPDATE`
batch takes a short transaction, so the write lock is released
between chunks. The master-key activate/deactivate flip now happens
only on a fully-clean pass — a partial failure can no longer strand
secrets under a deactivated key (folds in #87-review H1 at the
source). Each secret row is self-describing (`encryption_key_ref`
per row), so a partially-migrated table stays fully decryptable.

### CIRISVerify pin → v2.7.0

`ciris-verify-core` / `ciris-keyring` / `ciris-crypto` bumped
v2.5.0 → v2.7.0 (just shipped). No API breakage.

### Benchmark-coverage cut

The v1.7.x–v1.10.1 surface had zero criterion coverage. Five new
benches: `sequence_contention` (fan-in on the atomic sequence
UPSERT), `engine_cold_start` (open + full migration run),
`read_engine_analytics` (the SQLite ReadEngine queries, size-swept
1k/10k/25k), `secrets_crypto` (AES-GCM facade), `occurrence_registry`
(register/heartbeat + size-swept `list_live_occurrences`). All
size-swept benches use `SamplingMode::Flat` so the scaling curves
are tight (±~1%) — a leak/regression baseline needs clean curves,
not noisy ones (an early linear-sampling run manufactured a spurious
"superlinear" reading that flat sampling showed was noise). Wired
into `bench.yml`. Dev-only — no change to the shipped crate.

## [1.10.1] — 2026-05-21

**`reset_engine()` — handle-free process-singleton reset
(CIRISPersist#88) — plus the v1.10.0 hardening-review follow-ups.**

### New: `ciris_persist.reset_engine()` — CIRISAgent 2.9.0 blocker

`Engine.close()` needs a live `Engine` handle. A consumer test
fixture that drops its Python reference without calling `close()`
leaves the Rust process-singleton pinned with nothing able to
reference it — the "orphan case" — and the next `Engine(...)`, even
with a correct different config, raises `EngineConfigMismatch`
forever. This made CIRISAgent's multi-fixture pytest suite
un-greenable against persist ≥1.6.8 (all 8 shards red).

`reset_engine()` is a module-level function — no `Engine` instance
required. It flips the current engine's `closed` flag, clears the
singleton slot **synchronously** (an immediately-following
`Engine(...)` with any config constructs cleanly), and drops the
engine cell (tearing down its runtime + pools) before returning. A
no-op when no engine is pinned; correct under repeated
reset/construct cycles. It also gives the in-process cohabitation
epic (#85) a deterministic teardown door.

### Hardening-review follow-ups (v1.10.0 secrets-hw)

- **Key-material zeroization** — the process-global software-key
  cache and the hardware seed are now `Zeroizing`, so freed master
  /seed bytes are scrubbed rather than left in the heap (swap /
  core-dump exposure).
- **`hardware_key_active` stat** — `get_service_stats` now derives
  it from the active master key's `key_kind` instead of a
  hard-coded `false`; ops can see whether `migrate_to_hardware_key`
  took effect.
- ⚠ **`migrate_to_hardware_key` now requires `CIRIS_DATA_DIR`** — it
  refuses (`HardwareKeyUnavailable`) rather than silently placing
  hardware-key storage under a world-writable, squattable `/tmp`
  path. A deployment that wants hardware-backed secrets must point
  `CIRIS_DATA_DIR` at a process-private directory.

### V041 migration — analytics indexes (both backends)

`trace_events (agent_id_hash, ts)` + `(deployment_domain, ts)`. The
ReadEngine analytics + `count_*` methods filter `<col> = ? AND ts
>= ? AND ts < ?`; no composite index covered the `(col, ts)` shape,
so those queries scanned every row for the agent/domain. Now
index-range scans.

## [1.10.0] — 2026-05-21

**Hardware-backed secrets-at-rest — `migrate_to_hardware_key` is now
real (CIRISPersist#87).**

`SecretsService::migrate_to_hardware_key` was an unconditional
`HardwareKeyUnavailable` stub. It now derives the secrets-store
master key from a **hardware-sealed seed** and re-encrypts every
secret under it — closing the last gap in a CIRISAgent's
crypto-at-rest story (identity key + wallet seed were already
TPM-sealed; the secrets master was software-only).

### Verify owns the crypto

The master key is derived via
`ciris_verify_core::derive_symmetric_key` (HKDF-SHA256 over a seed
loaded from a hardware-backed `SecureBlobStorage`). Persist calls
CIRISVerify for the derivation and never rolls its own KDF.

v2.4.0 trapped that function behind the C-ABI-only
`ciris-verify-ffi` crate (no `rlib` — not Rust-linkable);
**CIRISVerify#25 / v2.5.0** promoted it into the `ciris-verify-core`
rlib so persist can consume it. The CIRISVerify pins
(`ciris-verify-core` / `ciris-keyring` / `ciris-crypto`) move
v2.4.0 → v2.5.0.

### Hardware-capable on every platform, auto-detected

`ciris-keyring`'s hardware-storage backends are now enabled
per-target via `[target.*]` dependency tables: `tpm` on Linux,
`ios` on iOS, `android` on Android. `create_platform_storage`
runtime-detects the hardware and falls back to software storage
where there is none — so `migrate_to_hardware_key` does real
hardware migration on a TPM/Keystore/Secure-Enclave host and
returns `HardwareKeyUnavailable` (caller keeps the software master
key) on a host without. The Linux `tpm` feature builds `tss-esapi`;
the CI Linux jobs apt-install `libtss2-dev`.

### Build hygiene

`[profile.dev] debug = "line-tables-only"` — full debuginfo on this
crate's dep graph (pyo3 + the CIRISVerify stack + rusqlite +
timescale), compounded across every `--features` combination a
dev/CI session builds, had let `target/debug` reach 122 GiB.
`line-tables-only` keeps panic backtraces (file/line) while cutting
the per-build footprint several-fold.

No migration, no schema change — `migrate_to_hardware_key` records
its key as `master_key_meta.key_kind = 'hardware'` in the existing
V010 table.

### Pre-tag hardening (security review)

A security/performance review of the above caught two data-integrity
issues before v1.10.0 was tagged:

- **Durability across restart.** The derived master key lived only
  in the in-process key cache. After `migrate_to_hardware_key`
  flipped the active key to `hardware`, a process restart left every
  secret encrypted under a key whose bytes were gone — the store
  would be unrecoverable. Fixed: `active_master_key` now re-derives
  a `hardware` key from its TPM-sealed seed on a cache miss (the
  derivation is deterministic — that is the point of the sealed
  seed). A `software` key has no such recovery path and stays fatal.
- **Partial-migration honesty.** `reencrypt_all` reports per-secret
  failures via `RotationResult.success` rather than erroring;
  `migrate_to_hardware_key` ignored it and returned `Ok` even when
  secrets were stranded under the now-deactivated old key. It now
  returns an error naming the failed rows.

## [1.9.0] — 2026-05-21

**Change-feed / subscription API for cross-consumer notification
(CIRISPersist#84) — the last in-process-cohabitation enabler.**

Under the process-singleton engine, co-resident consumers (agent +
NodeCore + LensCore) previously had no way to react to each other's
writes except polling. v1.9.0 adds an in-process pub/sub bus keyed
by substrate family — the final enabler of the #85 cohabitation
EPIC.

### New `Engine` methods

- `subscribe(substrate, callback) -> id` — register a Python
  callable, invoked as `callback(substrate, event_json)`.
  `substrate` is validated against the five known substrate
  families (same namespace as `register_consumer`); unknown raises
  `ValueError`. Returns an opaque subscription id.
- `unsubscribe(id) -> bool` — idempotent removal.
- `publish_change(substrate, event_json) -> int` — deliver an event
  to every callback subscribed to `substrate`; returns the count
  delivered. `event_json` is opaque (producer/subscriber contract;
  persist does not parse it).
- `list_subscriptions() -> str` / `subscription_count` —
  diagnostics, parallel to the consumer registry.

### Delivery semantics (documented honestly)

Dispatch is **synchronous and in-process**: `publish_change`
invokes every matching callback, in subscription-id order, before
it returns. Each subscriber is invoked exactly once per event. A
callback that raises is caught and logged — it does not propagate
to the publisher or abort the other callbacks. Publishers are
GIL-serialized, so per-substrate event order is the order
`publish_change` was called. There is **no persistence and no
replay**: a subscriber that attaches after an event is published
does not see it — this is in-process notification, not a durable
log. (The issue floated "at-least-once"; the honest in-process
guarantee is the synchronous one above, and that is what the docs
state.)

The registry is bounded at 256 live subscriptions and is
re-entrancy-safe — a callback may `subscribe` / `unsubscribe` /
`publish_change` without deadlocking (the dispatch snapshots its
target list before invoking any Python).

No migration, no schema change. With #84 landed, every enabler in
the #85 in-process-cohabitation EPIC (#75–#84) is complete.

## [1.8.1] — 2026-05-21

**Fix: `audit_list_entries` rejected an empty-`last_id` cursor on
Postgres (CIRISPersist#86).**

An `AuditCursor` whose `last_id` is the empty string is the
documented "no cursor yet — return the first page" sentinel.
CIRISAgent's audit service builds exactly this on the first write
of a process to read the chain head. The Postgres `list_entries`
parsed `last_id` as a UUID unconditionally and raised
`invalid argument: entry_id parse: invalid length` — so on Postgres
deployments the agent's audit hash chain failed to initialize on
first write (non-fatal, but the chain did not start).

`task_list` and the SQLite arm already treated an empty `last_id`
as "first page", so this was both a SQLite-permissive /
Postgres-strict divergence and an internal inconsistency between
two substrates of the same engine.

Both backends now skip the keyset predicate entirely when `last_id`
is empty (Postgres parses it as a UUID only when non-empty; SQLite
no longer emits a degenerate `< (ts, '')` compare). Behaviour is
now identical across backends and consistent with `task_list`.

## [1.8.0] — 2026-05-21

**SQLite reaches full ReadEngine + DerivedSchema parity with Postgres.**

Until now the SQLite backend implemented every *substrate* (audit,
graph, telemetry, secrets, cirisnode, tasks, sequence, occurrence,
…) but two FFI-exposed trait surfaces still returned
`NotImplemented` on SQLite: the `ReadEngine` observability-analytics
API (~21 methods) and the `DerivedSchema` write paths. A
sovereign-mode deployment (Raspberry Pi / iOS, SQLite-backed) could
not use the trace/LLM/federation read API or store lens-derived
evidence at all. This release closes that gap — SQLite is now at
100% parity with Postgres across both traits.

### `ReadEngine` — 21 methods ported to SQLite

`list_trace_summaries`, `get_trace_summary`, `get_trace_detail`,
`list_tasks`, `list_llm_calls`, `aggregate_llm_costs`,
`corpus_shape`, `aggregate_scrub_stats`, `list_federation_keys`,
`list_attestations`, `list_revocations`, `cross_agent_divergence`,
`temporal_drift`, `hash_chain_gaps`, `conscience_override_rates`,
`aggregate_scoring_factors`, `aggregate_scoring_factors_batch`,
`count_traces`, `count_overrides`, `count_identity_changes`,
`aggregate_audit_chain` — every one now runs real SQL against the
SQLite tables, with identical pagination/cursor semantics and the
same `v1` cursor wire format as Postgres.

The analytics methods that Postgres backs with TimescaleDB
continuous aggregates are implemented as raw-window queries over
`trace_events`. SQLite has no `STDDEV`/`VAR_SAMP`, so per-group
means are computed in SQL and the variance / Welch-significance /
z-score math is finished in Rust — results match the Postgres
path.

### `DerivedSchema` — `cirislens_derived` substrate on SQLite

`put_detection_event`, `get_detection_events`,
`put_calibration_bundle`, `get_current_calibration_bundle`,
`get_calibration_bundle_by_version` now have real SQLite
implementations. Same idempotency + conflict semantics as Postgres
(PK collision is idempotent; collision with different
`canonical_bytes` raises `Conflict`); the `is_current` calibration
flip is a single transaction guarded by a partial-unique index.

### V040 migration (SQLite only)

`migrations/sqlite/lens/V040__cirislens_derived_tables.sql` adds
`cirislens_derived_detection_events` +
`cirislens_derived_calibration_bundles` — the SQLite-dialect
equivalents of the Postgres `cirislens_derived` schema (Postgres
already had these via V008). `TIMESTAMPTZ`→TEXT, `JSONB`→TEXT,
`BYTEA`→BLOB, `BOOLEAN`→INTEGER; all CHECK constraints preserved.

### Notes

No public API change — these FFI methods already existed; they
simply no longer fail on a SQLite engine. No Postgres-side change.
18 new SQLite round-trip tests (13 `re_*` for ReadEngine, 5 `de_*`
for DerivedSchema).

## [1.7.6] — 2026-05-21

**CI fix — `test_register_consumer_validation` skips on a
postgres-only wheel.**

The v1.7.5 review-hardening release added a python behavior test
that constructs an in-memory SQLite `Engine`. The CI `full
features` job builds the wheel **postgres-only** (per the
`pyproject.toml` note — release wheels carry sqlite, the CI test
wheel does not), so the test failed `ValueError: ... the sqlite
feature was not compiled in`, which skipped the tag-gated PyPI
publish. The test now `pytest.skip`s when the wheel lacks the
`sqlite` feature, matching the surface-only convention of the rest
of `tests/python/`.

No code change vs v1.7.5 — the v1.7.5 review fixes (error-kind
classification, close()/register_consumer race, registry bounds,
sequence overflow guard) are unchanged. v1.7.6 is the version that
actually publishes them.

## [1.7.5] — 2026-05-20

**Pre-pin review hardening — code-quality + security pass on the
v1.6.7..v1.7.4 in-process-cohabitation sprint.**

A three-reviewer audit ran before the federation pins a 3.0-ready
`ciris-persist`. v1.7.5 fixes the blockers it found; no API
additions, no migration, no schema change.

### Fixed — CRITICAL: sequence/occurrence errors mislabeled `Permanent`

`translate_error_kind` (the FFI error-classification table) had no
arms for the `sequence_*` / `occurrence_*` `kind()` tokens shipped
in v1.7.1 / v1.7.3, so **every** error from those two substrates
fell through to `Permanent`. A transient backend failure (pool
exhaustion, connection drop) surfaced as non-retryable, and a
`Conflict` never reached `except Conflict`. Now mapped correctly:
`*_not_found` → `NotFound`, `*_conflict` → `Conflict`, `*_backend`
→ `Transient`; `*_invalid_argument` / `*_internal` stay `Permanent`.

### Fixed — `close()` / `register_consumer` attach-during-close race

`close()` checked the consumer registry empty, released the lock,
then set the `closed` flag — a `register_consumer` could slip into
that window and attach to an engine that was about to tear down.
`close()` now holds the registry lock across the `closed` store,
and `register_consumer` re-checks `closed` under the same lock, so
attach and close are mutually exclusive.

### Fixed — consumer registry is now bounded

The process-global consumer registry had no size or name-length
cap: a co-resident consumer that re-registered under fresh names
without `deregister_consumer` could grow it without limit and OOM
every cohabiting consumer. Now capped at 64 entries and 256-byte
names; declared substrate lists are deduped. A new registration
past the cap raises `RuntimeError` (leak guard); re-registering an
existing name is always allowed.

### Fixed — sequence counter `i64`→`u64` decode guard

`next_value` is a signed DB column; a bare `as u64` cast on a
negative value (row tampering, or a silent SQLite `BIGINT`
overflow wrap) produced a huge non-monotonic number handed to a
consumer that relies on monotonic ordering. The decode now rejects
a negative counter with a loud `sequence_internal` error.

### Other

- `register_occurrence` gained an explicit `#[pyo3(signature=...)]`
  for consistency with every other multi-optional-arg method.
- `close()` doc now states plainly it is **not a quiescence
  barrier** — it does not drain in-flight operations on other
  threads; callers needing a hard drain quiesce their consumers
  first. (Review HIGH, documented as a deliberate boundary.)
- `docs/COHABITATION.md` substrate-ownership section unchanged;
  the advisory (non-enforced) nature of `substrate_owner` was a
  review finding and is already documented there.

## [1.7.4] — 2026-05-20

**Per-consumer substrate ownership declaration (CIRISPersist#82).**

Fourth and final CIRIS 3.0 in-process enabler cut. v1.7.0 added
`register_consumer(name, substrates=[...])` but recorded the
declared substrate list verbatim — a typo (`cirsnode`) declared a
consumer that owns nothing, silently. #82 closes that gap and gives
co-resident consumers a way to ask "who owns this substrate" before
writing under the shared singleton engine.

### `register_consumer` — substrate-name validation

Each name in `substrates` is now validated against persist's five
substrate families: `cirislens`, `cirislens_secrets`,
`cirislens_derived`, `cirisgraph`, `cirisnode`. An unknown name
raises `ValueError` at declaration time instead of becoming a
silent no-op.

### New `Engine.substrate_owner(substrate) -> str | None`

Returns the registered consumer that declared ownership of
`substrate`, or `None`. Cooperative, advisory check — an in-process
adapter calls it to confirm ownership before a write. If two
consumers declared the same family, the lexicographically-first
name is returned (stable). Behind the v1.6.8 `ensure_usable` guard.

### Scope — what this is NOT

Per-call write-rejection (the engine refusing a write to a
substrate the *calling* consumer didn't declare) is a deliberate
**non-goal** of the 1.7.x line, and this is stated plainly rather
than left as an implied capability. Under the process-singleton the
engine has no per-call consumer identity to enforce against:
whichever consumer constructs `Engine(...)` first migrates *all*
substrate schemas (V001–V039), and per-owner migration is therefore
moot. Hard enforcement needs consumer-scoped engine handles (each
adapter holding a handle that carries its own identity) — the
injected-engine-handle item still tracked in the #79–#84 set.
Until that lands, ownership is a cooperative contract: the
consumer→substrate ownership table now in `docs/COHABITATION.md`,
plus code review. No migration, no schema change, no new substrate.

### Docs

`docs/COHABITATION.md` gains a "Consumer → substrate ownership"
section: the ownership table (which consumer-class owns which
family) and an explicit statement of the singleton's
all-schemas-one-owner reality and the non-goal above.

## [1.7.3] — 2026-05-20

**First-class occurrence registration + liveness heartbeat
(CIRISPersist#81).**

Third CIRIS 3.0 enabler cut. CIRISAgent currently *infers* live
occurrences by scanning recent task-row activity and dedup'ing
`agent_occurrence_id` — an inference, not a registration: it can't
tell a clean shutdown from a crash and has no TTL. Under the
single-key model all occurrences of an agent share one Ed25519
identity, so occurrence churn is **endpoint liveness under a stable
identity**. The node layer needs an authoritative answer to "which
endpoints for identity X are reachable right now."

### New `occurrence` substrate — `OccurrenceService` (4 methods)

- `register_occurrence(occurrence_id, identity, ttl_seconds,
  metadata)` — register / re-register. `expires_at = now +
  ttl_seconds`. Idempotent on `occurrence_id`.
- `heartbeat_occurrence(occurrence_id, ttl_seconds) -> bool` —
  bump `last_heartbeat` + `expires_at`. Returns `false` for an
  unknown occurrence (heartbeat-before-register is a no-op, not an
  error).
- `deregister_occurrence(occurrence_id) -> bool` — clean shutdown,
  removes the row immediately. Idempotent.
- `list_live_occurrences(identity) -> Vec<OccurrenceRecord>` — rows
  whose `expires_at > now`. TTL-based: a crashed occurrence ages
  out without a clean deregister. Read-only — expired rows are
  filtered, not deleted.

### V039 migration (both backends)

`occurrence_registry(occurrence_id PK, identity, registered_at,
last_heartbeat, expires_at, metadata)` + an
`(identity, expires_at)` index for the live-listing hot path.
Feature flag `cirislens_occurrence`.

### PyO3 + .pyi

`Engine.register_occurrence` / `heartbeat_occurrence` /
`deregister_occurrence` / `list_live_occurrences`, gated on
`cirislens_occurrence`, all behind the v1.6.8 `ensure_usable`
guard.

### Tests

17 (PG + SQLite): register→list round-trip; re-register updates in
place (one row); heartbeat bumps `expires_at`, unknown→false;
deregister removes, absent→false; **TTL expiry — a row with a
past `expires_at` is filtered from `list_live_occurrences`**; two
identities are isolated; empty id / empty identity / `ttl <= 0` →
`InvalidArgument`.

CIRISAgent's inference-based `discover_active_occurrences` retires
in favor of this once the agent adopts v1.7.3.

## [1.7.2] — 2026-05-20

**Fix: the v1.6.8 engine-lifecycle exceptions weren't re-exported
from the Python package — publish-blocker for v1.6.8 / v1.7.0 /
v1.7.1.**

`python/ciris_persist/__init__.py` carries an **explicit**
`from .ciris_persist import (...)` list + `__all__` (not a
wildcard). v1.6.8 added `EngineConfigMismatch`, `EngineClosed`,
`EngineUsedAcrossFork` to the Rust extension module and registered
them via `m.add(...)` — but the package `__init__.py` re-export
list was not updated, so `import ciris_persist;
ciris_persist.EngineConfigMismatch` resolved through `__init__.py`
and raised `AttributeError`.

The v1.6.8 `test_engine_lifecycle_exceptions_exported` pytest case
caught it — CI's `pytest tests/python/` job failed, which gates the
`Publish wheel to PyPI` step. Result: **v1.6.8, v1.7.0, and v1.7.1
all built green but never published** (the same `__init__.py` gap
rode along in each). v1.7.2 is the fix.

Pure-Python one-liner: the three exception names added to the
`from .ciris_persist import (...)` block and `__all__`. The Rust
side was correct since v1.6.8 — only the wrapper package's
hand-maintained export list lagged.

Rust `cargo` builds + the pre-push hook never caught this: they
exercise the extension module directly, not the `__init__.py`
wrapper. Only `pytest tests/python/` (which does
`import ciris_persist`) goes through the wrapper.

No code/behavior change beyond the export list. v1.7.2 carries
everything in v1.6.8 + v1.7.0 + v1.7.1 (singleton lifecycle,
engine_handle, consumer registry, sequence primitive) — it is the
first **publishable** release of that line and the version the
federation should pin.

## [1.7.1] — 2026-05-20

**Atomic per-identity monotonic sequence primitive (CIRISPersist#83).**

Second CIRIS 3.0 enabler cut. A CIRIS runtime holds one Ed25519
identity (PoB §3.2 one-key-three-roles); every in-process consumer
(agent, NodeCore, LensCore) and every occurrence signs with it.
Anything emitting *ordered* signed output — NodeCore network-message
sequence numbers — needs a counter atomic across all of them, or
two occurrences both emit seq N and the signed stream forks.

### New `sequence` substrate

`SequenceService` — two methods:

- `next_sequence(identity, stream) -> u64` — atomically bump and
  return the next value for `(identity, stream)`. First call → 1,
  then 2, 3, … One `INSERT … ON CONFLICT (identity, stream) DO
  UPDATE SET next_value = next_value + 1 … RETURNING next_value` —
  a single atomic statement, correct under concurrent callers
  across occurrences + in-process consumers.
- `peek_sequence(identity, stream) -> u64` — read the last-issued
  value without bumping; 0 if the pair was never issued.

`(identity, stream)` keying: one identity runs many independent
ordered streams (one per message channel / signed-output kind);
the counters never interfere.

### V038 migration (both backends)

`identity_sequences(identity, stream, next_value, updated_at,
PRIMARY KEY(identity, stream))`. Feature flag `cirislens_sequence`.

### PyO3 + .pyi

`Engine.next_sequence(identity, stream) -> int` /
`Engine.peek_sequence(identity, stream) -> int`, gated on
`cirislens_sequence`, both behind the v1.6.8 `ensure_usable` guard.

### Tests

13 (PG + SQLite): increments 1→2→3; streams under one identity are
independent; identities are independent; `peek` returns 0 then the
last value without bumping; empty identity/stream → `InvalidArgument`;
**20-way concurrent `next_sequence` yields exactly the set {1..=20}
with no duplicates** — the atomicity proof.

## [1.7.0] — 2026-05-20

**In-process cohabitation foundation — `engine_handle()` + consumer
registry (CIRISPersist#79 / #80).**

First of the CIRIS 3.0 enabler cuts. v1.6.8 ended the
multi-consumer deadlock (the `Engine` process-singleton); v1.7.0
adds the surface in-process adapters (NodeCore, LensCore) use to
attach to and detach from that shared engine.

### #79 — `Engine.engine_handle()`

Returns a fresh handle to the process-singleton engine — a cheap
`Arc`-clone sharing the runtime, pool, signer, `closed` flag, and
consumer registry. The lifecycle owner (the CIRISAgent runtime)
uses it to inject the engine into an in-process adapter explicitly
— "injected engine, first parameter" (LensCore's existing pattern,
now the formal contract) — without the adapter needing the DSN /
signing key to re-call the constructor.

The COHABITATION.md in-process chapter landed in v1.6.8; v1.7.0
completes #79 with the accessor.

### #80 — consumer registry + lifecycle refcount

The engine now tracks who is attached:

- `register_consumer(name, substrates=None)` — an adapter calls
  this on bring-up. `substrates` declares the substrate families it
  owns (`["cirisnode"]` for NodeCore, etc.) — recorded for
  introspection; the per-owner-migration + write-rejection
  enforcement is the CIRISPersist#82 follow-on. Idempotent.
- `deregister_consumer(name) -> bool` — on the adapter's teardown.
  Idempotent.
- `list_consumers() -> str` — JSON snapshot
  `{name: {substrates, registered_at}}` for "who is using persist"
  diagnostics.
- `consumer_count` getter.

`close()` gains a `force` parameter and now **refuses while
consumers are still registered** — tearing the runtime out from
under an attached NodeCore/LensCore would deadlock them. The
well-behaved path: every adapter `deregister_consumer()` on its own
teardown, then the owner's `close()` finds the registry empty.
`close(force=True)` overrides — for a hard process shutdown.

The registry is in-memory on the singleton cell (an
`Arc<Mutex<HashMap>>` every handle shares); no DB, no migration.

### Tests

- Rust: the engine-config-fingerprint unit test (v1.6.8) covers the
  singleton config gate.
- Python: surface test pinning `engine_handle` + the four registry
  methods on the `Engine` class. Registry *behavior* is exercised
  by the downstream cohabitation suite.

### Compatibility

Purely additive — `close()`'s new `force` parameter defaults
`False`, so `engine.close()` is unchanged for a single-consumer
process (empty registry → closes cleanly). No SQL migration, no
wire-format change.

## [1.6.8] — 2026-05-20

**`Engine` is a process-singleton — ends the multi-consumer deadlock
(CIRISPersist#75 / #76 / #77 / #78). 2.9.0 ship gate.**

Pre-v1.6.8 every `Engine(...)` constructed its own multi-thread
tokio runtime. Two `Engine`s in one process → two runtimes
contending on the shared DB → the 39-minute hang CIRISAgent 2.9.0
auth-suite testing hit (#75). The CIRIS 3.0 in-process model (agent
+ NodeCore + LensCore each consuming persist) made this a hard
blocker.

### #75 — process-singleton runtime

The runtime + backend pool + signer state now live in one
process-global `EngineCell`, built exactly once, guarded by an
`OnceLock<Mutex<…>>`. The global lock is held for the **whole**
constructor — two threads cannot both run `Runtime::new()` (the #75
"no check-then-init race" requirement). A second `Engine(...)` with
the same config returns a cheap handle cloned from the singleton —
no second runtime, no second pool.

### #76 — config-mismatch raises, never silently rebinds

A second `Engine(...)` whose config fingerprint (DSN +
signing-key-id + local key ids) differs from the live engine's
raises the new typed `EngineConfigMismatch`. Silent rebind — caller
thinks it holds Postgres engine B, actually holds SQLite engine A —
would corrupt data, strictly worse than the deadlock. "Idempotent"
means *same-args → no-op*, never *always no-op*.

### #77 — `close()` teardown door

New `Engine.close()` flips the singleton's shared `closed` flag
(every handle sees it) and clears the global slot so a later
`Engine(...)` rebuilds. Idempotent. New `Engine.is_closed` getter.
Lifecycle rule: **one owner** constructs + closes; in-process
adapters attach and detach but never close. Use after `close()`
raises the typed `EngineClosed` instead of running against a
torn-down runtime.

### #78 — fork-safety guard

Every `Engine` method records the construction pid and compares it
to the calling pid; a mismatch (the process forked — uvicorn/gunicorn
preload, `multiprocessing` with the default `fork` start method)
raises the typed `EngineUsedAcrossFork` rather than deadlocking on a
runtime whose worker threads don't exist in the child. The contract
("construct after forking, or use the `spawn` start method") is
documented in `docs/COHABITATION.md`'s new in-process section.

### Per-method guard

`ensure_usable()` — the closed-check + fork-check — runs as the
first statement of all **214** `Engine` methods that touch the
runtime/pool. Pure local-read accessors (`keyring_path`,
`keyring_storage_kind`) are exempt — they can't deadlock and don't
return `PyResult`.

### Typed exceptions

`EngineConfigMismatch`, `EngineClosed`, `EngineUsedAcrossFork` —
new `create_exception!` classes, all deriving from `PersistError`
(so `except PersistError:` catches the umbrella), registered in the
module and exported. AV-15/AV-43 typed-error pattern.

### docs/COHABITATION.md

New "In-process cohabitation" section — the doc previously covered
only multi-*process* cohabitation (keyring flock). Now documents the
one-process-multiple-consumer model: one owner constructs, adapters
attach, one owner closes, construct-after-fork. Notes the #79–#84
enabler set (consumer registry, lifecycle refcount, injected-engine
handle) as the 3.0 follow-on this floor builds toward.

### Tests

- Rust unit test — `engine_config_fingerprint` distinguishes every
  config field, NUL-separated so field boundaries can't alias.
- Python tests — the three lifecycle exceptions are exported and
  derive from `PersistError`; `Engine` exposes `close` + `is_closed`.
- The singleton/close/fork *behavior* is exercised end-to-end by the
  CIRISAgent 2.9.0 suite (the suite that surfaced #75) — a Rust test
  can't cleanly exercise a process-global across cargo's
  shared-process test runner.

### Compatibility

The Python `Engine(...)` API is unchanged for the single-consumer
case — first construction behaves exactly as before. The new
behavior only triggers on a *second* construction in the same
process: same config → handle (was: second runtime); different
config → `EngineConfigMismatch` (was: second runtime). No SQL
migration. No wire-format change.

## [1.6.7] — 2026-05-20

**SQLite validates `incident_id` / `metric_id` as UUID — PG-parity,
no silent backend divergence (CIRISPersist#74).**

`incident_record` accepted any string for `incident_id` on SQLite
but rejected non-UUID values on Postgres: `cirislens.incident_records.incident_id`
is a PG `uuid` column, SQLite's is untyped TEXT. A caller passing a
prefixed id (the agent's `incident_<uuid>` shape) stored fine on
SQLite and then failed on **every** call once switched to Postgres
— a divergence invisible until a backend swap. In CIRISAgent this
amplified into a 12,000-error self-sustaining incident loop (an
ERROR-log handler re-capturing its own save failures; agent-side
loop-guard already fixed — persist's job is to make the trigger
impossible).

Same divergence class as #72 (naive timestamps) and #73 (text
edge_id vs uuid column): SQLite's permissive typing masks a
contract violation Postgres enforces.

### Fix — validate-on-both (option 1, the agent's preferred)

SQLite now rejects a non-UUID `incident_id` with the *same*
`InvalidArgument` Postgres raises, before any I/O — a malformed id
fails fast on the first call regardless of backend.

`incident` SQLite backend — new `validate_incident_id` guard wired
into:
- `record_incident` (`incident.incident_id`)
- `transition_state` (`transition.incident_id`)
- `list_incidents` (the cursor's `last_id` — PG already validated it)

### Audit of other caller-supplied uuid columns

Swept every PG `uuid`-typed column for the same asymmetry. Most
are persist-generated (`secret_uuid`, `entry_id`, `edge_id` post-#73,
the cirisnode ids) — no caller divergence. One real parallel:
**`telemetry` `metric_id`** — `cirisgraph.telemetry_metrics.metric_id`
is PG `uuid`; `MetricObservation.metric_id` is caller-supplied
`Option<String>`. SQLite's `resolve_metric_id` accepted any string;
PG's parsed it as UUID. Fixed — SQLite `resolve_metric_id` now
validates a caller-supplied `metric_id` identically.

### Tests

1 new SQLite test — `record_incident` + `transition_state` reject a
non-UUID `incident_id` with `InvalidArgument`; a well-formed UUID
still works (regression guard). The 20 existing incident tests +
68 SQLite telemetry/incident tests pass unchanged (they seed valid
UUIDs).

### Compatibility

Behavioral change on SQLite: a caller that previously stored a
non-UUID `incident_id` / `metric_id` on SQLite now gets
`InvalidArgument` — the same failure Postgres always gave. This is
the intended fail-fast. No SQL migration. No PyO3 signature change.

## [1.6.6] — 2026-05-20

**Legacy edge migration maps non-UUID `edge_id` to a deterministic
UUID (CIRISPersist#73).**

v1.6.4's A0a absorption errored on **every edge** when the legacy
`graph_edges.edge_id` is a plain string that isn't a valid UUID.
Against the scoutdb dump: nodes migrated 114,184/114,184 (the
v1.6.5 #72 timestamp fix works), but edges were 0/100, `errors:100`.

#73 was filed as a timestamp issue ("edge read still binds
created_at as timestamptz"). It wasn't — the v1.6.5 edge SELECT
already casts `created_at::text` and parses via
`parse_legacy_timestamp`. The actual root cause:

- `cirisgraph.edges.edge_id` is PG-typed **`uuid`** (V013 schema).
- The legacy 2.8.x `graph_edges.edge_id` is arbitrary **`text`**.
- `GraphService::upsert_edge` parses `edge.edge_id` into
  `uuid::Uuid` — a non-UUID legacy id (`'e1'`, scoutdb's
  `metric_*`-style ids) fails with `InvalidArgument`.

The v1.6.5 test masked it: `naive_timestamp_legacy_columns_migrate_ok`
seeded the edge with `Uuid::new_v4().to_string()` — an already-valid
UUID — so the upsert's parse never tripped.

### Fix — `canonical_edge_uuid`

New `legacy_migration::canonical_edge_uuid(legacy_id) -> String`:

- If `legacy_id` already parses as a UUID → returned verbatim.
- Otherwise → a deterministic **UUIDv5** under a fixed namespace
  (`Uuid::NAMESPACE_OID`, legacy id as the name). v5 is a pure
  hash of (namespace, name): re-running the migration derives the
  *same* UUID, so the `ON CONFLICT (edge_id) DO NOTHING`
  idempotency contract holds. Distinct legacy ids never collide.

Applied **identically on PG and SQLite**. SQLite's `edge_id`
column is untyped TEXT and would tolerate the raw legacy string —
but mapping it the same way means a legacy DB migrates to
byte-identical `edge_id`s regardless of target backend (closing the
silent cross-backend divergence #73 also flagged). The mapped id
is computed once, right after decode, and used for BOTH the
already-present check and the upsert so re-run detection stays
correct.

### `first_error_message` now populated on edge paths

#72's `LegacyMigrationStats.first_error_message` field existed but
wasn't being set on the edge error sites — #73 noted the field was
absent from the returned JSON. Now populated at every edge error
path (edge_id decode, scope normalize, attributes parse, created_at
parse, upsert failure) on both backends, alongside the existing
node-path coverage.

### Tests

4 new (2 PG + 2 SQLite):
- non-UUID legacy `edge_id` migrates with `errors == 0`; the edge
  is found in `cirisgraph.edges` under the canonical UUIDv5;
  re-run is idempotent (`edges_skipped_already_present`,
  `edges_written == 0`).
- `canonical_edge_uuid` unit coverage — valid UUID passes through,
  non-UUID derives a stable v5, distinct ids don't collide.

`uuid` crate gains the `v5` feature.

### Compatibility

The migrated `edge_id` for non-UUID legacy edges is the derived
UUIDv5, not the original text. The legacy `edge_id` is a
primary-key surrogate, not a federation-meaningful identifier — the
edge's `(source, target, relationship)` tuple carries the
semantics — so the remap is transparent. Re-running the migration
is safe. No SQL migration. PyO3 signature unchanged.

## [1.6.5] — 2026-05-20

**`run_legacy_graph_migration` handles `timestamp without time zone`
legacy columns (CIRISPersist#72).**

v1.6.4's A0a absorption errored on **every node** when the legacy
Postgres `public.graph_nodes` table declares `created_at` /
`updated_at` as `timestamp without time zone` — which the real
pre-v2.9.0 CIRISAgent schema does (confirmed against a pgEdge pg17
`ciris-scoutdb` production dump: 114k nodes, all naive-timestamp).
Every Postgres production upgrade copied 0 rows. SQLite was
unaffected (TEXT timestamps).

### Root cause

The PG reader bound `created_at` / `updated_at` as
`chrono::DateTime<Utc>` — i.e. it expected the column to be
`timestamptz`. tokio-postgres refuses to decode a
`timestamp without time zone` value into a TZ-aware type, so the
typed decode failed per row.

### Fix

The node + edge read SELECTs now cast both timestamp columns
`::text`. A new `parse_legacy_timestamp` helper accepts all three
shapes the cast can yield:

- **Naive** (`2026-01-21 20:07:17.391754` — `timestamp` column) —
  parsed as `NaiveDateTime`, **UTC assumed**, mirroring the
  pre-absorption `migrate_to_persist.py::normalize_datetime()`.
- **timestamptz `::text`** (`2026-01-21 20:07:17.391754+00` —
  2-digit offset) — RFC 3339 rejects the 2-digit offset, so the
  helper retries with `+00:00`.
- **Full RFC 3339** (`...T...+00:00`) — parsed directly.

`timestamptz` legacy columns (the v1.6.4 happy path) keep working.

### `first_error_message` field added to `LegacyMigrationStats`

Per #72's bonus ask — `LegacyMigrationStats` now carries
`first_error_message: Option<String>` alongside
`first_error_at_node_id`. Callers diagnose the first failure
without bisecting. Populated at every node/edge error site on both
backends (timestamp parse, scope normalize, attributes parse,
upsert failure).

### Tests

3 new:
- PG `naive_timestamp_legacy_columns_migrate_ok` — seeds a
  dedicated `legacy_naive_probe` schema with
  `timestamp without time zone` columns (also exercises the
  `legacy_schema` override), confirms 2 nodes + 1 edge migrate
  with `errors == 0` and the naive `created_at` lands as UTC.
- PG `parse_legacy_timestamp_accepts_naive_and_tz_forms` — unit
  coverage of all four accepted shapes + garbage rejection.
- The existing 22 legacy_migration tests still pass (the v1.6.4
  PG happy-path seed uses `timestamptz`, so it now exercises the
  offset-bearing parse arm).

### Compatibility

Wire-additive — `first_error_message` defaults to `None`, serde
skips it when absent. No migration. PyO3 signature unchanged.

## [1.6.4] — 2026-05-19

**Closes #70 — the LAST raw-SQL gap in CIRISAgent 2.9.0.**

Absorbs the agent's `tools/ops/migrate_to_persist.py` A0a graph
reader into a typed substrate method. With this method wired,
CIRISAgent 2.9.0 drops both `psycopg2` (PG path) and `sqlite3` (SQLite
path) from production `requirements.txt` and CIRISAgent#763 Phase 5
closes — no more direct DB driver imports in the agent.

### New substrate: `src/legacy_migration/`

Five files mirroring other v0.8.x / v1.x substrate layout:

- `mod.rs` — `Error` + stable `kind()` tokens
  (`legacy_migration_invalid_argument` /
  `legacy_migration_not_found` / `legacy_migration_conflict` /
  `legacy_migration_backend` / `legacy_migration_internal`) +
  re-exports.
- `types.rs` — `LegacyMigrationOptions` (4 optional fields, all
  with safe defaults) + `LegacyMigrationStats` (10 counters +
  `outcome` discriminator + `first_error_at_node_id` debug hint).
- `service.rs` — `LegacyMigrationService` trait (1 method).
- `postgres.rs` — `LegacyMigrationService for PostgresBackend` +
  identifier-validated `legacy_schema` interpolation (lowercase
  letters / digits / underscores, leading letter or underscore,
  ≤ 63 chars).
- `sqlite.rs` — `SqliteLegacyMigrationBackend` (shared
  `Arc<Mutex<Connection>>` with the rest of the SQLite stack);
  rejects non-`"public"` `legacy_schema` (SQLite has no schema
  namespace); probes `sqlite_master` for the legacy tables and
  returns zeroed `outcome="ok"` if absent (graceful no-op for
  fresh installs).

### Options shape

```python
{"dry_run": False,
 "attributes_cap_bytes": 1048576,   # None = 1 MiB default
 "legacy_schema": "public",          # PG only; SQLite enforces public
 "stop_after_errors": 100}           # None = unbounded
```

All fields optional; `{}` decodes to the documented defaults.

### Stats shape

```python
{"outcome": "ok" | "errors" | "partial",
 "nodes_read": int, "nodes_written": int,
 "nodes_skipped_already_present": int,
 "nodes_skipped_too_large": int,
 "edges_read": int, "edges_written": int,
 "edges_skipped_already_present": int,
 "edges_skipped_dangling_fk": int,
 "errors": int,
 "first_error_at_node_id": str | None}
```

`outcome` is the sentinel the agent's bootstrap layer reads to
decide whether to write the `.persist_migrated` flag — it writes
only on `"ok"`; `"partial"` / `"errors"` leaves the sentinel absent
so the next boot retries.

### Per-row decision tree

For each legacy node (in order):

1. Decode + normalize scope (`"local"` / `"identity"` /
   `"community"` / `"environment"` lowercase → UPPERCASE persist
   enum value; unrecognized scopes increment `errors`).
2. Re-serialize attributes once and check byte length against
   `options.attributes_cap_bytes` (defaults to
   `crate::graph::DEFAULT_MAX_ATTRIBUTES_BYTES`, 1 MiB). Over-cap
   rows increment `nodes_skipped_too_large` and DO NOT touch
   `upsert_node`.
3. If `dry_run`, increment `nodes_read` and continue (no write).
4. Call `upsert_node(node, expected_version = 0, bulk_import = true)`.
   `bulk_import=true` skips the graph layer's AV-45 cap — this
   substrate already enforced its own bound in step 2, so the
   re-check at the graph layer would double-count. On `Ok`
   increment `nodes_written`. On `Conflict` (version mismatch =
   "row already present") increment
   `nodes_skipped_already_present`. Other errors increment
   `errors` + record `first_error_at_node_id` (if unset); if
   `errors >= stop_after_errors.unwrap_or(100)`, break the loop.

For each legacy edge (in order):

1. If `dry_run`, increment `edges_read` and continue.
2. Pre-check source + target presence in `cirisgraph.nodes` /
   `cirisgraph_nodes`. V013 doesn't enforce the FK at the schema
   level by design (the substrate's k-hop CTE tolerates dangling
   edges), so the integrity check is at the substrate layer —
   absent source/target increments `edges_skipped_dangling_fk`.
3. Pre-check `edge_id` presence in the modern edges table.
   Already-present increments `edges_skipped_already_present`
   (`upsert_edge` swallows duplicates via `ON CONFLICT DO NOTHING`
   so the pre-check is the only way to count idempotent re-runs).
4. Call `upsert_edge(edge, bulk_import = true)`. `Ok` increments
   `edges_written`; `InvalidArgument` carrying `"FK"` substring
   maps to `edges_skipped_dangling_fk` (defensive — fires only if
   an operator added a schema-level FK); `Conflict` maps to
   `edges_skipped_already_present` (race winner); other errors
   increment `errors`.

### `bulk_import` cap bypass + re-check

`upsert_node` accepts `bulk_import: bool` (v1.3.2,
CIRISPersist#50). The flag was designed for exactly this case:
one-time historical migration where the operator wants to write
rows whose attributes payload might exceed the AV-45 1 MiB cap.
The legacy-migration substrate:

- Re-checks the cap itself against
  `options.attributes_cap_bytes.unwrap_or(DEFAULT_MAX_ATTRIBUTES_BYTES)`
  BEFORE the upsert call, so over-cap rows surface in the
  `nodes_skipped_too_large` counter (not silently written).
- Calls `upsert_node` with `bulk_import = true` so the graph
  layer's re-check doesn't double-fire on the rows that DID pass
  the operator-supplied bound.

An operator who raises the cap (e.g. `attributes_cap_bytes = 5 *
1024 * 1024`) gets exactly what they asked for — rows up to 5 MiB
land, rows over 5 MiB get counted as `nodes_skipped_too_large`.

### Cargo + maturin

- New feature `cirislens_legacy_migration = ["cirisgraph"]` —
  load-bearing dep on `cirisgraph` (the upsert path goes through
  it).
- Added to `pyproject.toml` `[tool.maturin] features` list so the
  release wheel ships the FFI method.

### PyO3 surface (one method)

`run_legacy_graph_migration(options_json: str) -> str`. Options +
stats round-trip as JSON strings (matching the rest of the v1.x
dispatch shape). Errors thread through `translate_error_kind`:
`legacy_migration_backend` → `Transient`,
`legacy_migration_invalid_argument` → `Permanent`.

### Tests

13 total covering all 6 SQLite scenarios from the spec +
2 PG validation tests + 5 PG behavior tests + the standard
mod-level `kind()` round trip:

- **Happy path** (both backends): seed 3 nodes + 2 edges → assert
  3/2 written + outcome `"ok"` + rows present via the
  `GraphService` reader.
- **Re-run idempotent** (both): 2x run; second yields
  `nodes_skipped_already_present == 3` + `edges_skipped_already_present == 2`.
- **Oversized attributes** (both): 1.5 MiB blob row → assert
  `nodes_skipped_too_large >= 1` and the over-cap row is NOT
  present in `cirisgraph.nodes` afterwards.
- **Dry run** (both): N seeded → `nodes_read == N` AND
  `nodes_written == 0` AND `cirisgraph.nodes` is empty.
- **Dangling edge FK** (both): edge → absent source/target →
  assert `edges_skipped_dangling_fk >= 1`, no `errors`.
- **SQLite legacy tables absent** (SQLite-only): fresh in-memory
  backend → `outcome == "ok"`, all counts zero.
- **SQLite non-`"public"` legacy_schema rejected** (SQLite-only):
  `legacy_schema = "other"` → `Err(InvalidArgument)`.
- **PG `validate_legacy_schema`** (PG-only): accepts `"public"` /
  `"_underscore"` / `"agent_v2"`; rejects empty, uppercase,
  injection-shaped (`"public; DROP"`), hyphenated, and over-63-char
  inputs.

PG tests use per-test UUID-prefixed rows + cleanup via per-prefix
`DELETE` (no `DROP TABLE` — the qa-postgres container is shared
with other serial tests).

### No `qa_harness` schema_history bump

No new migration. The substrate reads existing legacy tables and
writes via the already-shipped `cirisgraph_*` surface.

### Compatibility

Additive. Nothing existing changes shape; deployments that don't
turn on `cirislens_legacy_migration` see no change.

## [1.6.3] — 2026-05-19

**`task_upsert` + `thought_upsert` honor caller-supplied `created_at`
on UPDATE (CIRISPersist#71).**

Closes the inconsistency between cirisgraph_upsert_node (which has
honored supplied `created_at` since v1.3.1 / CIRISPersist#49) and
the tasks/thoughts substrates absorbed in v1.5.9 / v1.5.10 (which
were preserving the original `created_at` across re-upsert).

Unblocks CIRISAgent 2.9.0's test scaffolding for stale-task code
paths in `try_claim_shared_task` — the agent's
`_backdate_task_created_at` helper now works against persist as
expected. Three previously-skipped tests
(`test_get_shared_task_status_outside_window`,
`test_try_claim_shared_task_deletes_old_active_task`,
`test_try_claim_shared_task_datum_bug_scenario`) become unblocked.

### SQL changes

- `cirislens.tasks` ON CONFLICT(task_id) DO UPDATE — added
  `created_at = EXCLUDED.created_at` (PG) /
  `created_at = excluded.created_at` (SQLite).
- `cirislens.thoughts` ON CONFLICT(thought_id) DO UPDATE — same
  addition.

### Tests

4 new (2 SQLite + 2 PG-gated) — each backdates a row by 24h via
re-upsert and asserts `get` returns the backdated value within 1s
drift. The existing
`upsert_idempotent_same_payload_noop_diff_payload_overwrites`
tests still pass — they re-upsert with the SAME `created_at`, so
the assertion `got2.created_at == original_created` holds under
either preserve-or-honor semantics.

### Audit of other `*_upsert` surfaces

Reviewed `tickets_upsert`, `scheduled_task_upsert`, `wa_cert_upsert`
for the same gap. **Each has an explicit
`upsert_idempotent_preserves_created_at` test** asserting the
PRESERVE behavior as intentional (per the v1.5.13 / v1.5.12 /
v1.5.19 substrate-design specs respectively — those substrates
model domain entities whose `created` timestamp is genuinely
immutable). Leaving them unchanged. If a future agent path needs
backdating on one of those substrates we can extend with an opt-in
flag per substrate; today none requires it.

### Compatibility

Behavioral change on the UPDATE path: callers that **relied on** the
preserve semantics for tasks/thoughts (sending a stale `created_at`
inadvertently and expecting persist to ignore it) will see their
caller's value land. Audit your `*_upsert` callers if they
construct the payload from a partial source where `created_at` may
be wrong.

No SQL migration. PyO3 / `.pyi` signatures unchanged — wire shape
identical.

## [1.6.2] — 2026-05-19

**TSDB non-metric summary types — task / conversation / trace / audit
rollups (CIRISPersist#68). FINAL Phase 3b blocker for CIRISAgent
2.9.0.**

Persist's existing `telemetry_consolidate_period` covers the METRIC
summary type; the agent's TSDB pipeline produces FOUR additional
summary node types over non-metric source data, all of which were
still riding raw SQL against `cirislens.tasks` /
`cirislens.thoughts` / `cirislens.service_correlations` /
`cirislens.audit_log`. v1.6.2 closes the substrate gap with four
typed consolidate methods + a unified `query_summary_nodes` reader.

### Four new typed summary structs (`src/telemetry/types.rs`)

```rust
TaskSummary {
    tenant_id, period_start, period_end,
    total_tasks: i64,
    by_status: HashMap<String, i64>,
    mean_thought_depth: f64,
    consolidation_level,
}
ConversationSummary {
    tenant_id, period_start, period_end,
    total_messages: i64, unique_actors: i64,
    consolidation_level,
}
TraceSummary {
    tenant_id, period_start, period_end,
    total_traces: i64,
    by_action_type: HashMap<String, i64>,
    consolidation_level,
}
AuditSummary {
    tenant_id, period_start, period_end,
    total_events: i64,
    by_action_type: HashMap<String, i64>,
    unique_actors: i64,
    consolidation_level,
}

TypedConsolidationOutcome { summary_written: bool, source_rows: i64 }
```

Each summary serializes to the `attributes` JSON of a graph node
in `cirisgraph.nodes` (scope `ENVIRONMENT`) under the matching
`node_type` token — `task_summary`, `conversation_summary`,
`trace_summary`, `audit_summary`. Stable `node_id` shape:
`tsdb:{node_type}:{tenant_id}:{period_start_rfc3339}` (mirrors the
metric-summary key without the metric_name slot).

### Five new `TelemetryService` trait methods

```rust
fn consolidate_tasks(req: ConsolidationRequest)         -> TypedConsolidationOutcome
fn consolidate_conversations(req: ConsolidationRequest) -> TypedConsolidationOutcome
fn consolidate_traces(req: ConsolidationRequest)        -> TypedConsolidationOutcome
fn consolidate_audit(req: ConsolidationRequest)         -> TypedConsolidationOutcome
fn query_summary_nodes(
    node_type, level, tenant_id, from, to,
) -> Vec<serde_json::Value>
```

`query_summary_nodes` returns raw JSON `attributes` so callers
deserialize per summary type on their side. Lock acquisition is
skipped in v1.6.2 — the agent's non-metric consolidator is
single-threaded; lock arbitration parity with `consolidate_period`
is a v1.7.x extension if concurrent typed consolidations land.

### Aggregation SQL per type

**TaskSummary** — two queries against `cirislens.tasks` +
`cirislens.thoughts`:

```sql
-- Status histogram + total.
SELECT status, COUNT(*) FROM cirislens.tasks
 WHERE agent_occurrence_id = $tenant
   AND created_at >= $start AND created_at < $end
 GROUP BY status;

-- Mean thought_depth (COALESCE to 0.0 on empty).
SELECT AVG(thought_depth) FROM cirislens.thoughts
 WHERE agent_occurrence_id = $tenant
   AND created_at >= $start AND created_at < $end;
```

**ConversationSummary** — one query against
`cirislens.service_correlations`, filtered to the speak/observe
action shapes (case-insensitive):

```sql
SELECT COUNT(*), COUNT(DISTINCT request_data->>'actor_id')
  FROM cirislens.service_correlations
 WHERE agent_occurrence_id = $tenant
   AND timestamp >= $start AND timestamp < $end
   AND lower(action_type) IN
       ('speak', 'observe', 'speak_action', 'observe_action');
```

**TraceSummary** — `correlation_type = 'trace'` histogram:

```sql
SELECT action_type, COUNT(*) FROM cirislens.service_correlations
 WHERE agent_occurrence_id = $tenant
   AND correlation_type = 'trace'
   AND timestamp >= $start AND timestamp < $end
 GROUP BY action_type;
```

**AuditSummary** — `cirislens.audit_log` histogram + distinct
actor count. **Deviation from initial spec**: `audit_log` uses
`tenant_id` directly (NOT `agent_occurrence_id`) and `recorded_at`
(NOT `created_at`) per the V014 column shape — implementation
adjusted to match the actual schema. SQLite mirrors the same
column names.

### Unified `query_summary_nodes` read API

```sql
SELECT attributes FROM cirisgraph.nodes
 WHERE node_type = $1                             -- "task_summary" | etc.
   AND scope = 'ENVIRONMENT'
   AND consolidation_level = $2
   AND attributes->>'tenant_id' = $3
   AND ((attributes->>'period_start')::timestamptz) >= $4
   AND ((attributes->>'period_start')::timestamptz) <  $5
 ORDER BY (attributes->>'period_start')::timestamptz ASC;
```

SQLite uses `json_extract(attributes, '$.tenant_id')` /
`'$.period_start'` analogs and applies the v1.6.0
`truncate_to_micros` discipline on the period boundaries (mirrors
the metric `get_summary` write/read alignment).

`node_type` is validated against the four allowed tokens
up-front; unknown values yield `Error::InvalidArgument` (stable
`telemetry_invalid_argument` kind token, AV-15).

### PyO3 surface — 5 new `Engine` methods (`feature = "telemetry"`)

- `tsdb_consolidate_tasks(req_json) -> str`
- `tsdb_consolidate_conversations(req_json) -> str`
- `tsdb_consolidate_traces(req_json) -> str`
- `tsdb_consolidate_audit(req_json) -> str`
- `tsdb_query_summary_nodes(node_type, level, tenant_id, from_rfc3339, to_rfc3339) -> str`

Mirror the v1.6.0 `tsdb_*` shape — JSON wire for request +
response. Error kinds propagate through `translate_error_kind`
unchanged; no new error variants in `telemetry::Error`. `.pyi`
stubs document each summary type's JSON `attributes` shape so the
agent UI can shape per-period rollup cells without reading the
Rust source.

### Tests — 10 SQLite + 4 PG

SQLite: happy-path per summary type (with source-data seeded via
direct SQL into `cirislens_*` tables, so tests don't pull in the
substrate feature flags), `query_summary_nodes` validation
rejects (unknown `node_type` + inverted window), empty-window
sanity (summary node still written so the UI sees the bucket),
shared validation rejects across all four methods. PG: one
parity test per summary type, gated on `CIRIS_PERSIST_TEST_PG_URL`.

### Schema — no new migrations

v1.6.2 reads against existing `cirislens.*` substrates (V014,
V024, V025, V026) + writes against `cirisgraph.nodes` (V013 +
V019). `qa_harness` schema_history count unchanged.

## [1.6.1] — 2026-05-19

**cirisgraph `attribute_match` filter — JSON-path equality + array
containment (CIRISPersist#67).**

Phase 4 follow-up cut. CIRISAgent#763's `memory_query_helpers.py`
needs to enforce the OBSERVER user filter (Layer 1 access control:
"OBSERVER users see only graph nodes they created") via persist
instead of raw SQL. The substrate's `NodeFilter` had no JSON-
path-equality predicate, so the agent route either kept the raw
SQL or paginated the entire graph client-side. v1.6.1 closes the
gap.

### New `NodeFilter.attribute_match` field

```rust
NodeFilter {
    scope: GraphScope,
    node_type: Option<String>,
    attributes_contains: Option<Value>,
    updated_after / updated_before / created_after / created_before:
        Option<DateTime<Utc>>,
    exclude: Option<NodeExcludeRule>,
    attribute_match: Option<AttributeMatch>,          // ← NEW
}

AttributeMatch {
    path: String,                       // alphanumeric/underscore
    equals_any: Option<Vec<String>>,
    array_contains_any: Option<Vec<String>>,
}
```

- `equals_any`: row matches when `attributes->>path` ∈ values.
- `array_contains_any`: row matches when `attributes->path` is a
  JSON array containing any of the supplied values.
- Both clauses are independently optional; when both are set, they
  OR-combine (matches the agent's Layer 1 OBSERVER filter shape).

### PG dialect

- `equals_any` → `(attributes->>$path) = ANY($vals::text[])`
- `array_contains_any` → `(attributes->$path) ?| $vals::text[]`

Explicit `::text[]` casts on the right-hand side — tokio-postgres'
default bind for `Vec<String>` infers correctly with the cast,
without it the `?|` operator silently no-ops in some PG versions.

### SQLite dialect

- `equals_any` → `json_extract(attributes, '$.<path>') IN (...)`
- `array_contains_any` →
  `json_type(attributes, '$.<path>') = 'array' AND EXISTS (
    SELECT 1 FROM json_each(json_extract(attributes, '$.<path>'))
    WHERE value IN (...))`

The `json_type = 'array'` guard prevents `json_each` from raising
`malformed JSON` on rows whose `<path>` value is a scalar — common
when the same OR-combined filter targets both scalar (`created_by`)
and array-shaped rows in the same query.

### Security: SQL injection guard on `path`

`AttributeMatch.path` is interpolated directly into the SQL
fragment (not bound as a parameter — PG and SQLite both reject JSON
paths as bind values). Validated up-front to be alphanumeric +
underscore only. Hostile callers can't inject SQL via the path
slot.

### Honored in both `query_nodes` and `count_nodes`

Both endpoints emit the same WHERE-clause fragment via a shared
`push_attribute_match_clause` helper per backend.

### Tests

8 new (6 SQLite + 2 PG-gated):
- `equals_any` filters by `created_by` (scalar match)
- `array_contains_any` filters by `user_list` (array containment)
- OR-combine: scalar arm + array arm in the same query, neither-
  matches row excluded
- `count_nodes` honors the filter (parity with `query_nodes`)
- Empty `path` rejected as `InvalidArgument`
- Path with SQL-injection chars rejected as `InvalidArgument`
- PG: equals_any + array_contains_any with probe-scoped fixtures

PyO3 surface unchanged at the signature level —
`cirisgraph_query_nodes` and `cirisgraph_count_nodes` accept the
new `attribute_match` key inside `filter_json`. `.pyi` docstring
extended with the JSON shape + Layer 1 OBSERVER-filter rationale.

### Compatibility

Additive — existing `NodeFilter` payloads decode unchanged
(`attribute_match` defaults to `None` and serde skips the key when
absent).

## [1.6.0] — 2026-05-19

**TSDB consolidation substrate — period queries + prune + edge histograms (CIRISPersist#63).**

Final cut of the v1.5.19-follow-up wave. Unblocks CIRISAgent 2.9.0
Phase 3b: the agent's 6,680 LOC `services/graph/tsdb_consolidation/`
package (11 files of raw-SQL helpers) can now delegate query +
prune + edge-rollup to persist instead of owning the SQL builders.

Persist already shipped the consolidation engine in v0.8.2
(`consolidate_period` + multi-tier `Basic → Daily → Weekly →
Monthly` chain via `input_tier`). v1.6.0 adds the four primitives
needed to retire the agent's Python query/prune/edge layer:

### TelemetryService trait — 4 new methods

- `query_summaries(level, tenant_id, from, to) → Vec<MetricSummary>`
  Period-window query: every summary in `(level, tenant_id)` whose
  `period_start ∈ [from, to)`. Ordered by `(period_start ASC,
  metric_name ASC)`. Backs the agent's Basic (6h) / extensive
  (week) / profound (month) period queries — caller picks the
  window, persist emits a single indexed SELECT.

- `get_summary(level, tenant_id, metric_name, period_start) →
  Option<MetricSummary>`
  Point-lookup via the deterministic
  `tsdb:{level}:{tenant_id}:{metric_name}:{period_start_rfc3339}`
  node_id.

- `prune_summaries(level, tenant_id, before) → u64`
  Retention sweep. Deletes summary nodes whose `period_end <
  before` for the given (level, tenant) and cascades incident
  edges (TEMPORAL_NEXT chains). Returns the count of summary nodes
  removed. Used by Phase 3b's TSDB retention pass: once daily
  summaries roll up basic ones, the basic-tier rows are purged
  after a retention window.

- `count_edges_by_relationship_in_window(from, to) →
  HashMap<String, u64>`
  Group-by-relationship histogram of edges in `[from, to)`. Filter
  scope='ENVIRONMENT' (TSDB scope). Returns
  `{relationship: count}` for the agent's `edge_manager.py` daily
  rollup — agent reads this once per consolidation cycle and rolls
  the counts into the parent-tier summary's `attributes`.

### PyO3 surface — 4 new Engine methods

- `tsdb_query_summaries(level, tenant_id, from_rfc3339, to_rfc3339)
  -> str` (JSON `list[MetricSummary]`)
- `tsdb_get_summary(level, tenant_id, metric_name,
  period_start_rfc3339) -> str | None` (JSON `MetricSummary`)
- `tsdb_prune_summaries(level, tenant_id, before_rfc3339) -> int`
- `tsdb_count_edges_by_relationship_in_window(from_rfc3339,
  to_rfc3339) -> str` (JSON `dict[str, int]`)

All four gated on the `telemetry` feature. `level` is one of
`"basic" | "daily" | "weekly" | "monthly"` (matches
`ConsolidationLevel`'s wire shape). Timestamps are RFC 3339.

### Both backends

PG + SQLite parity (per `[[feedback-no-pg-only-no-deferral]]`). No
new migration — reads against the existing
`cirisgraph.{nodes,edges}` schema (V013) with
`consolidation_level` column (V019).

### SQLite micro-second truncation invariant

`get_summary`'s SQLite impl truncates the caller's `period_start`
to microseconds before composing the deterministic node_id —
mirrors the write path's existing `truncate_to_micros` invariant
(introduced for the same reason in the rollup path: nanosecond
precision in `chrono::Utc::now()` derivatives must round to micros
to match the stored format). PG TIMESTAMPTZ has native microsecond
precision so the PG path doesn't need explicit truncation.

### SQLite edge-timestamp lex-sort fix

`count_edges_by_relationship_in_window` wraps both sides of the
`created_at` range predicate in SQLite's `datetime()` function —
the edge table uses the schema-default
`datetime('now', 'subsec')` (space-separated form) which does NOT
RFC 3339 (T-separated). Lex compare on raw strings would miss
every row because ' ' < 'T'. `datetime()` normalizes both formats
for the compare. Defeats index use on the rarely-large edge
table; observability-tier cost.

### Tests

7 new (5 SQLite + 2 PG-gated):
- `query_summaries` returns consolidated rows ordered correctly
- `query_summaries` rejects empty/inverted window (InvalidArgument)
- `get_summary` round-trips one row; absent metric → None
- `prune_summaries` deletes only summaries with `period_end <
  before`; cascades incident edges
- `count_edges_by_relationship_in_window` groups TEMPORAL_NEXT
  edges from consecutive consolidations
- PG: full query → get → prune round-trip
- PG: TEMPORAL_NEXT edge histogram across periods

638/638 lib tests pass across `postgres + sqlite + all 12 cirislens
features + telemetry + cirisgraph` locally; CI matrix runs the same
sweep on a fresh PG container.

### Minor version bump rationale

This is the first minor since v1.5.0's federation Merkle layer.
The TSDB additions are additive (trait extension, not signature
change) but the agent-facing scope justifies the v1.6.0 marker —
all six v1.5.19 follow-ups (#60, #61, #62, #64, #65, #66) plus the
TSDB primitives complete the CIRISAgent 2.9.0 Phase-by-Phase
unblock chain.

### CI hardening (commit b2b0030)

Independent of the substrate work, this release ships an
infrastructure-resilience fix to the CI workflow: both
`actions/download-artifact@v4` invocations in `publish-pypi` and
`build-manifest` jobs are replaced with `gh run download` retry
loops (5 attempts, exponential backoff, fail-loud after exhaustion).
v1.5.24's tag CI failed at the sign step due to a transient `403
Forbidden: Error from intermediary` from GitHub's artifact-storage
backend — which was non-retryable in the action and cascaded into
"PyPI publish skipped." With this hardening, the next transient
failure absorbs into a warning and the publish completes.

Same retry pattern as the existing `gh release download` retry
block in the build-tool install step (v1.1.2 CIRISVerify v2.1.1 CI
hardening arc).

## [1.5.25] — 2026-05-19

**cirisgraph list/count/exclude gaps (CIRISPersist#65).**

Sixth of the v1.5.19 follow-ups. Closes the remaining cirisgraph
surface gap blocking CIRISAgent 2.9.0 Phase 4 (API memory routes
dropping raw `import sqlite3`). Three additions:

### Gap A — `NodeExcludeRule` on `NodeFilter`

New optional field `exclude: Option<NodeExcludeRule>` where
`NodeExcludeRule { node_type, node_id_pattern }`. Emits
`NOT (node_type = ? AND node_id LIKE ?)` server-side. Models the
agent's
`NOT (node_type = 'tsdb_data' AND node_id LIKE 'metric_%')`
memory-route exclusion verbatim. Honored by both `query_nodes` and
the v1.5.25 `count_nodes`.

PG: parameterized `LIKE` clause. SQLite: identical shape against
`json_extract`-friendly column types.

### Gap B — `count_nodes` + `count_edges`

- `count_nodes(NodeFilter) -> u64` — honors every `NodeFilter`
  key including the new `exclude` rule and existing
  `attributes_contains` / `updated_after` / `updated_before` /
  `node_type`. AV-47: scope is required.
- `count_edges(GraphScope) -> u64` — single
  `SELECT COUNT(*) FROM cirisgraph.edges WHERE scope = $1`.

### Gap C — `count_nodes_by_type`

- `count_nodes_by_type(GraphScope) -> HashMap<String, u64>` —
  `SELECT node_type, COUNT(*) FROM cirisgraph.nodes WHERE scope = $1
  GROUP BY node_type`. Replaces the agent's raw group-by-SQL on the
  dashboard "memory composition by type" tile.

### PyO3 + .pyi

3 new `Engine` methods gated on `cirisgraph` feature:
- `cirisgraph_count_nodes(filter_json) -> int`
- `cirisgraph_count_edges(scope: str) -> int`
- `cirisgraph_count_nodes_by_type(scope: str) -> str` (JSON dict)

`.pyi` stubs added with full docstrings. `cirisgraph_query_nodes`
unchanged at the signature level — the new `exclude` filter key is
additive inside `filter_json`.

### Tests

8 new (6 SQLite + 2 PG-gated):
- `count_nodes` returns total in scope
- `count_nodes` honors exclude rule (3-of-5 dropped)
- `count_edges` returns total in scope
- `count_nodes_by_type` group-by histogram
- Missing scope on `count_nodes` rejected (AV-47)
- `query_nodes` honors exclude rule in listing (drops matching rows
  from the page)
- PG: count_nodes_honors_exclude_rule + count_nodes_by_type_groups
  (with serial_test::serial(postgres))

### Compatibility

- `NodeFilter` wire shape additive — `exclude` field defaults to
  None and serde skips serialization when None. Existing JSON
  payloads decode unchanged.
- `query_nodes` / `count_nodes` / `count_edges` /
  `count_nodes_by_type` all on `GraphService` trait. PG + SQLite
  parity (no PG-only declarations per `[[feedback-no-pg-only-no-deferral]]`).

## [1.5.24] — 2026-05-19

**`secrets_store_detected_secret` + docstring fix (CIRISPersist#66).**

Fifth of six v1.5.19 follow-ups. Closes the secrets-substrate gap
that blocked CIRISAgent 2.9.0 Phase 2a. Two distinct fixes in one
cut:

### Gap A — `secrets_process_incoming_text` docstring was stale

The PyO3 wrapper's docstring still carried the v0.6.1 prose
`"Stub: v0.6.2 wires this with the pipeline classify stage. Until
then returns SecretsError::Internal."`. The body has been a fully
wired composition since v1.5.7 — `get_filter_config` +
`try_claim_secret` as a default trait impl shared by both
backends. The "empty `refs` array" the agent team observed is the
*correct* behavior of the wired code given an empty filter
catalog: no patterns configured → no detection. Docstring now
documents the catalog dependency, the JSON schema agents must seed
via `secrets_set_filter_config`, and points to
`secrets_store_detected_secret` as the agent-detection alternative.
Same docstring sweep for `secrets_decapsulate` (also pre-wired
since v0.6.1 but never relabeled).

### Gap B — `store_detected_secret` for agent-detection flow

New method on `SecretsService` accepting a **caller-supplied UUID**
plus the full `DetectedSecret` metadata bundle:
`description`, `sensitivity`, `detected_pattern`, `context_hint`,
`source_message_id`, `auto_decapsulate_for_actions`,
`manual_access_only`. Persist stores verbatim under the agent's UUID.

Distinct from existing paths:
- `store_secret(key, value)` — persist generates UUID; no detection
  metadata; `detected_pattern="manual"`.
- `try_claim_secret(plaintext, …)` — persist generates UUID;
  accepts a subset of metadata.
- `process_incoming_text(text, …)` — persist's regex catalog
  detects; agent has no UUID control.

### Semantics

- Returns `ClaimResult<SecretReference>` envelope:
  - `Stored(ref)` — clean insert under caller's UUID; reference
    carries the canonical row shape.
  - `AlreadyClaimed(ref)` — `content_hmac` collision (V017 unique
    index). Same plaintext exists from any caller path. The
    reference may carry a **different** UUID than the caller
    supplied — agent reconciles.
- Caller's UUID reused for a *different* plaintext →
  `InvalidArgument` (caller UUID-allocation bug).
- Audited via `access_log` with `operation = 'store'`, purpose
  carries outcome label.

### PyO3 + .pyi

`Engine.secrets_store_detected_secret(payload_json, accessor) -> str`.
Returns the JSON envelope
`{"outcome": "stored" | "already_claimed", "ref": <SecretReference>}`.
.pyi stub added with full docstring; PyO3 docstring fixes on
`secrets_process_incoming_text` + `secrets_decapsulate` deployed in
the same cut.

### Tests

9 new (6 SQLite + 3 PG-gated):
- Clean store with full metadata round-trips (caller UUID
  preserved, description / pattern / context_hint / sensitivity /
  auto_decapsulate all persisted).
- Same UUID + same plaintext → `AlreadyClaimed` (idempotent).
- Different UUID + same plaintext → `AlreadyClaimed` with
  *canonical* (first) UUID.
- Same UUID + different plaintext → `InvalidArgument`.
- Empty UUID / value / pattern / description / malformed UUID →
  `InvalidArgument`.
- Recall after store round-trips the value + metadata.

PG tests use a local `reset_secrets_state` helper that TRUNCATEs
the secrets-schema family before each test — addresses the
pre-existing test-pollution bug where rerunning master-key rotation
in a populated local DB tripped `active_master_key()`'s
"exactly 1 row" invariant. CI starts fresh so this is local-only
hygiene.

## [1.5.23] — 2026-05-19

**`service_token_revocation_*` substrate — last aiosqlite consumer absorbed (CIRISPersist#64).**

Fourth of six v1.5.19 follow-ups. New substrate replacing CIRISAgent's
standalone `revoked_service_tokens.db` SQLite file (the agent's
auth_service was the only remaining `aiosqlite` consumer in
`requirements.txt`). Lands the dependency-removal blocker for
CIRISAgent 2.9.0 Phase 2b.

### V037 schema (both backends)

```
revoked_service_tokens(
    token_hash  TEXT PRIMARY KEY,
    revoked_at  TIMESTAMPTZ NOT NULL,
    revoked_by  TEXT NOT NULL,
    reason      TEXT NOT NULL
)
```

`token_hash` is the SHA-based digest of a service token (NOT a
`wa_id` — service tokens don't map to WA certs; see #64 for the
two-table distinction with `wa_cert.active`).

### Trait — `ServiceTokenRevocationService` (3 methods)

- `record_revocation(revocation)` — idempotent on `token_hash` via
  `ON CONFLICT(token_hash) DO NOTHING`. First record wins;
  re-records are silent no-ops (timestamp + reason are stable once
  recorded — re-recording with different values does NOT overwrite,
  matching the agent's intent).
- `list_revocations()` — full table dump. Agent caches in memory at
  startup. Order unspecified. Empty Vec on cold table.
- `check_revocation(token_hash)` — point lookup. PK-indexed.

### Validation

`record_revocation` rejects empty `token_hash`, empty `revoked_by`,
empty `reason` with `InvalidArgument`.

### PyO3 surface + .pyi

3 new `Engine` methods gated on `cirislens_service_token_revocation`
feature:
- `service_token_revocation_record(revocation_json) -> None`
- `service_token_revocation_list() -> str` (JSON `list[...]`)
- `service_token_revocation_check(token_hash) -> str | None`

Stable AV-15 error kinds: `service_token_revocation_invalid_argument
| _not_found | _conflict | _backend | _internal`.

### Tests

15 new (6 PG-gated + 6 SQLite + 1 error-kind + 2 types serde):
- Record then check returns row.
- Idempotent same-hash no-op.
- `list` on populated table returns all rows.
- `list` on empty table returns empty Vec.
- `check` on unknown hash returns None.
- Empty token_hash → `InvalidArgument`.

596/596 pass across `postgres + sqlite + all 12 cirislens features`.

### Feature flag

`cirislens_service_token_revocation = []` in Cargo.toml +
pyproject.toml maturin features list. Independent of other
substrates — no transitive cirislens dep.

## [1.5.22] — 2026-05-19

**`correlation_id` uniqueness + `task_upsert` outcome envelope (CIRISPersist#61).**

Third of six v1.5.19 follow-ups. Restores the legacy CIRISAgent
migration-006 invariant that `add_task` won't duplicate when the
same upstream event (Reddit comment, Discord message, etc.) arrives
twice within the same `agent_occurrence_id`. Persist now enforces
this at the DB layer instead of relying on the agent's racey
client-side pre-check (paginates every task in the occurrence,
TOCTOU between get and upsert).

### V036 migration — partial UNIQUE index

- **Postgres:** `CREATE UNIQUE INDEX tasks_correlation_id_unique
  ON cirislens.tasks (agent_occurrence_id,
  (context_json->>'correlation_id')) WHERE context_json IS NOT NULL
  AND context_json->>'correlation_id' IS NOT NULL`.
- **SQLite:** same shape using `json_extract(context_json,
  '$.correlation_id')`. Partial expression index supported since
  SQLite 3.9.0.

Partial so correlation-less rows (most agent-internal tasks) skip
the index entirely. Index name `tasks_correlation_id_unique` is the
load-bearing identifier — the impl matches by constraint/index name
to distinguish from PK conflicts.

### `task_upsert` outcome envelope — breaking change

`TaskService::upsert_task` signature: `(Task) -> Result<(), Error>`
→ `(Task) -> Result<TaskUpsertOutcome, Error>`.

`TaskUpsertOutcome` is `Stored(Task) | AlreadyExists(Task)`:

- `Stored` — INSERT clean, or `ON CONFLICT(task_id) DO UPDATE`
  resolved to the caller's row. Canonical post-upsert shape
  returned (the impl re-reads to capture computed columns).
- `AlreadyExists` — V036 unique index tripped. A different `task_id`
  with the same `(agent_occurrence_id, correlation_id)` already
  exists. Returned `Task` carries the EXISTING row (its existing
  `task_id`, not the caller's). Mirrors `try_claim_shared_task`'s
  `ClaimResult` envelope shape.

The `AlreadyExists` outcome only fires when the caller's
`context.correlation_id` is set. Tasks without one insert normally
as `Stored`.

Per [[feedback-clean-break-renames]] / [[feedback-rename-consistency]]:
no deprecation alias, no second-method scaffold. Done in one cut
while CIRISAgent#763 is mid-absorption so callers reconcile against
the new shape directly.

### PyO3 + .pyi

- `Engine.task_upsert(task_json) -> str` (was `-> None`). Returns
  the JSON envelope `{"outcome": "stored" | "already_exists",
  "task": <Task>}`. Callers that previously discarded the return
  continue to work; callers that need dedup-detection unpack the
  envelope.
- `.pyi` docstring updated with the breaking-change note.

### Tests

9 new (5 SQLite + 4 PG-gated):
- Clean insert → `Stored` envelope, canonical row carries caller's
  task_id.
- Re-upsert same task_id with mutated payload → `Stored`
  (ON CONFLICT(task_id) UPDATE wins; correlation index does NOT
  trip).
- Different task_id, same (occurrence, correlation_id) → `AlreadyExists`
  carrying the first task_id.
- Same correlation_id under different occurrences → both `Stored`
  (index is per-occurrence).
- No correlation_id → many `Stored` inserts coexist.

585/585 pass across `postgres + sqlite + all 11 cirislens features`.

### Migration-rollout note

If the existing PG/SQLite data carries duplicate
`(agent_occurrence_id, correlation_id)` pairs (e.g. from CIRISAgent
v2.8.x pre-absorption), V036 will fail with a UNIQUE_VIOLATION at
index creation. Pre-existing data sets need a one-shot dedup pass
before this migration applies cleanly. The 11-substrate landings
(v1.5.9-v1.5.19) shipped before any agent traffic flowed through
them so there are no production duplicates today, but operators
running pre-1.5.x snapshots should validate before applying V036.

## [1.5.21] — 2026-05-19

**`created_before` / `created_after` filters on `task_list` + `thought_list` (CIRISPersist#62).**

Second of six v1.5.19 follow-ups. CIRISAgent#763's migrated cleanup
paths (`get_tasks_older_than`, `get_thoughts_older_than`,
`get_latest_shared_task`) needed `created_at < cutoff` queries.
v1.5.20 silently no-op'd unknown filter keys — the agent paginated
the whole occurrence and filtered in Python (O(N) per cleanup pass
on a long-running production agent). v1.5.21 emits the predicate
server-side.

### Filter additions

Two new optional keys on both `TaskFilter` and `ThoughtFilter`:

- `created_before` — RFC 3339 timestamp → SQL `created_at < ?`
  (strict inequality matches Python `task.created_at < cutoff`
  semantics; agent's `get_tasks_older_than` uses the same).
- `created_after` — RFC 3339 timestamp → SQL `created_at >= ?`
  (inclusive lower bound; symmetric with `updated_after`'s
  inclusive semantics).

Both keys compose with existing filter keys via AND. Both honored
on both backends (PG: `created_at` TIMESTAMPTZ comparison;
SQLite: `created_at` TEXT lexicographic, valid because we always
write RFC 3339 microseconds with TZ marker).

### No migration

These read against the existing `created_at` column (V024 + V025).
PG already has `created_at` as a sortable TIMESTAMPTZ; SQLite stores
RFC 3339 strings that lex-sort correctly. No index added — the
existing happy-path indexes (`tasks_status_occurrence`,
`thoughts_task_recency`, etc.) drive the WHERE clause down to a
small set that the date predicate filters in-memory, which is the
shape the agent's cleanup queries already assume.

### Tests

6 new (3 SQLite + 3 PG-gated):
- `created_before` excludes newer rows (2 rows, midpoint cutoff,
  only older survives).
- `created_after` excludes older rows.
- `created_after` + `created_before` window keeps middle row only
  (3 rows at -72h / -24h / now; window [-48h, -12h] keeps -24h).
- Thoughts: combined range filter on a thought tree with 3 thoughts
  at varied `created_at`.

### Compatibility

- Wire format additive — existing `TaskFilter` / `ThoughtFilter`
  decode unchanged (both new fields `Option<DateTime<Utc>>` with
  serde `default` + `skip_serializing_if = "Option::is_none"`).
- PyO3 surface (`task_list` / `thought_list`) accepts the keys
  inside `filter_json` — no method-signature change.
- .pyi docstrings extended to document the new keys.

## [1.5.20] — 2026-05-19

**`thought_delete` + `task_delete → thoughts` cascade (CIRISPersist#60).**

First of six follow-up cuts triggered by CIRISAgent#763's absorption
of the v1.5.19 substrate surface. Agent-side `delete_tasks_by_ids` /
`delete_thoughts_by_ids` semantics expected `task_delete` of a parent
with child thoughts to take the thoughts with it, and an explicit
`thought_delete` for direct row cleanup. v1.5.19 had neither — the
absorbed agent code fell back to a soft-cancel (status='failed') as
a workaround. v1.5.20 ships both, so the agent's hard-delete
semantics restore.

### V035 migration — `source_task_id` ON DELETE CASCADE

- **Postgres:** `ALTER TABLE cirislens.thoughts DROP CONSTRAINT
  thoughts_task_fk` + `ADD CONSTRAINT … ON DELETE CASCADE DEFERRABLE
  INITIALLY DEFERRED`. Two-statement migration; refinery wraps in
  its own tx.
- **SQLite:** 12-step rebuild dance (SQLite can't alter FK in place).
  `PRAGMA defer_foreign_keys=ON` → CREATE `cirislens_thoughts_new`
  with the new FK shape → `INSERT INTO new SELECT * FROM old` → DROP
  old → RENAME new → recreate the three indexes V025 declared.
  Data-preserving on existing rows (FK check fires at COMMIT).

The self-FK on `parent_thought_id` is **left strict** — symmetric
with `task_delete`'s parent-FK semantics. Callers walk
`thought_get_descendants` first or delete leaves-first. This matches
the explicit-subtree-management contract `delete_task` already
documents and keeps the two substrates consistent.

### `thought_delete(thought_id) → bool`

- Mirrors `task_delete` shape exactly: `bool` return (`true` on
  first delete, `false` on idempotent re-call).
- Empty id → `InvalidArgument`.
- Parent with children via self-FK → `Conflict` (PG
  FOREIGN_KEY_VIOLATION; SQLite extended code 787).
- Validated on both backends.

### Tests

8 new (4 PG-gated + 4 SQLite):
- `delete_thought` happy path → true then false (idempotent)
- empty id → InvalidArgument
- parent with children via self-FK → Conflict; leaves-first works
- `task_delete` of parent with multiple flat thoughts → cascades on
  both backends (thoughts gone)

### PyO3 + .pyi

- `Engine.thought_delete(thought_id) -> bool` — gated on
  `cirislens_thoughts` feature flag.
- Stable error kinds: `thought_invalid_argument | _not_found |
  _conflict | _backend | _internal` (unchanged from v1.5.10).

### Compatibility

- Existing `task_delete` callers: behavior changes on the failure
  path. Previously `task_delete` of a parent with thoughts returned
  `Conflict`. As of v1.5.20 it succeeds and cascades. Callers that
  relied on the conflict signal as a "do I have orphans" probe
  should use `thought_list(filter={source_task_id})` instead.
- `thought_get_descendants` semantics unchanged.

### Drive-by fix — `deferral_reports::record_deferral` commit error classification

The PG impl had a pre-existing miscategorization: the FKs on
`cirislens.deferral_reports` are `DEFERRABLE INITIALLY DEFERRED`, so
a dangling `task_id`/`thought_id` reference fires at `tx.commit()`,
not at INSERT. The commit error was wrapped as `Error::Backend("commit: …")`,
swallowing the FOREIGN_KEY_VIOLATION sqlstate that callers needed to
classify as `Conflict`. Routed the commit error through `map_pg_error`
so the pre-existing `deferral_pg_fk_rejects_nonexistent_task_or_thought`
test (added in v1.5.14) now passes — turned up by the full-features
lib sweep this cut requires.

Other modules with the same commit-error pattern (`tasks`, `audit`,
`creation_ceremonies`, `incident`, `cirisnode`, `store`) are left
unchanged for this cut — none of their FKs are DEFERRABLE today, so
the bug is latent. Will sweep if future DEFERRABLE additions surface
it.

## [1.5.19] — 2026-05-18

**`wa_cert` substrate — 11 of 11. CIRISPersist#59 CLOSES.**

Final substrate of the 11-cut absorption. With this release the
entire CIRISAgent `ciris_engine.db` is absorbed into persist; no
agent-side library opens the file directly anymore. The dual-WAL
corruption pattern from CIRISPersist#58 is structurally impossible
because persist is the only writer.

V034 migration on both backends. 24 columns — the Wise-Authority
cert directory. Lives in the engine DB (not a separate `auth.db`)
per the "persist is the only library that opens the file"
guarantee.

Per spec discussion in #59: the blast-radius argument for a separate
auth.db was valid but cuts against the WAL-corruption-end guarantee
that motivated #59 in the first place. Compromise-isolation can be
revisited as a v1.6.x track if needed without breaking the substrate
shape.

### Schema

- `wa_id` PK, `name`, `role` CHECK `root|authority|observer`
- `pubkey`, `jwt_kid` UNIQUE (JWT verification hot path)
- `password_hash`, `api_key_hash` — credential digests
- `oauth_provider`, `oauth_external_id`, `oauth_links` (JSONB/TEXT JSON)
- `veilid_id`
- `auto_minted` BOOLEAN
- `parent_wa_id` self-FK (DEFERRABLE on PG; immediate on SQLite),
  `parent_signature`
- `scopes` (JSONB/TEXT JSON; NOT NULL — every WA has a scope set)
- `custom_permissions` (JSONB/TEXT JSON)
- `adapter_id`, `adapter_name`, `adapter_metadata` (JSONB/TEXT JSON)
- `token_type` CHECK `standard|session|api_key|oauth|service`
- `created`, `last_login`, `active`

5 indexes:
- `wa_cert_jwt_kid` (UNIQUE) — JWT verify hot path
- `wa_cert_oauth (oauth_provider, oauth_external_id) WHERE NOT NULL` — OAuth login
- `wa_cert_role_active (role, active) WHERE active = TRUE` — role-based listing
- `wa_cert_adapter (adapter_id) WHERE NOT NULL` — adapter-bound enumeration
- `wa_cert_parent (parent_wa_id) WHERE NOT NULL` — tree walks

### WaCertService trait (7 methods)

- `upsert_wa_cert` — idempotent on wa_id; preserves `created`
- `get_wa_cert`
- `get_by_kid(jwt_kid)` — JWT verify hot path
- `get_by_oauth(provider, external_id)` — login path
- `list_by_role(role, limit)` — observer/authority enumeration
- `set_active(wa_id, active)` — activity toggle
- `update_last_login(wa_id, login_time)`

### PyO3 surface

7 new Engine methods gated on `cirislens_wa_cert` feature. Stable
error kinds: `wa_cert_invalid_argument | _not_found | _conflict |
_backend | _internal`.

### Tests

36 new (8 types + error_kind + 14 PG + 14 SQLite):
- All 24 columns round-trip
- Self-FK: nonexistent parent_wa_id rejects; NULL passes
- Idempotent upsert preserves `created`; differing data updates mutables
- `jwt_kid` UNIQUE: duplicate kid → Conflict (PG SqlState
  UNIQUE_VIOLATION; SQLite extended code 2067)
- `get_by_kid` hits unique index
- `get_by_oauth` hits partial index; missing oauth fields → None
- `list_by_role` filters by role + active=TRUE; insert mix
  (root/authority/observer/inactive) and verify
- `set_active` toggle; missing-row=false
- `update_last_login` success + missing-row=false
- Role CHECK + token_type CHECK reject unknown
- Parent tree: root + 2 children + 1 grandchild; chain holds

Lib suite: 312 pass with `postgres sqlite cirislens_wa_cert`.

### Token type vocabulary

`standard | session | api_key | oauth | service` — inferred from
agent's apparent TokenType taxonomy. Caller-validated either way
(WA mint happens agent-side). The DB CHECK keeps schema truthful
about what persist round-trips.

## CIRISPersist#59 — full absorption complete

11 substrates shipped across v1.5.9-v1.5.19:

| Substrate | Release | Schema | API methods |
|---|---|---|---|
| tasks | v1.5.9 | V024 / 17 cols | 6 |
| thoughts | v1.5.10 | V025 / 14 cols | 5 |
| service_correlations | v1.5.11 | V026 / 18 cols | 4 |
| scheduled_tasks | v1.5.12 | V027 / 15 cols | 3 |
| tickets | v1.5.13 | V028 / 17 cols | 5 |
| deferral_reports | v1.5.14 | V029 / 7 cols | 4 |
| maintenance_locks | v1.5.15 | V030 / 5 cols | 3 |
| creation_ceremonies | v1.5.16 | V031 / 14 cols | 4 |
| continuity_awareness | v1.5.17 | V032 / 14 cols + cross-FK to graph_nodes | 3 |
| feedback_mappings | v1.5.18 | V033 / 5 cols + FK to thoughts | 3 |
| wa_cert | v1.5.19 | V034 / 24 cols + self-FK | 7 |

Total: 11 migrations, 150 columns, 47 trait methods, ~250 tests across
both backends. No legacy direct-libsqlite access remains in
CIRISAgent's ciris_engine.db cutover surface.

The agent team can drop their raw-sqlite3 callers across all 11
substrates and adopt the persist API end-to-end. The dual-WAL
corruption surfaced in CIRISPersist#58 is structurally prevented.

## [1.5.18] — 2026-05-18

**`feedback_mappings` substrate — 10 of 11 (CIRISPersist#59 #10).**

V033 migration on both backends. 5 columns. Light shape. Design
decision: shipped as a **dedicated substrate**, NOT folded into
cirisgraph_edges. Rationale: `target_thought_id` references
cirislens_thoughts(thought_id), not graph_nodes; feedback rides on
Discord-message-to-thought-resolution pairs that don't fit the
node-to-node edge shape; folding would force representing thoughts as
graph_nodes and double the write surface.

Feature depends on `cirislens_thoughts` for the FK:

```toml
cirislens_feedback_mappings = ["cirislens_thoughts"]
```

3 partial indexes (all `WHERE column IS NOT NULL`):
- `(target_thought_id)` — feedback-for-thought hot path
- `(source_message_id)` — Discord-message lookups
- `(feedback_type, created_at DESC)` — typed-feedback timeline

### FeedbackMappingService trait (3 methods)

- `record_feedback` → ClaimResult (ON CONFLICT DO NOTHING)
- `list_feedback_for_thought(thought_id, limit)` — ORDER BY created_at DESC
- `list_feedback(filter, limit)` — filter by source_message_id /
  feedback_type / time window

### Nullable FK passthrough

Both backends handle NULL target_thought_id without firing the FK
constraint. Test `null_target_thought_passes_fk` verifies clean Stored
on PG (SQL standard) and SQLite (`PRAGMA foreign_keys=ON` doesn't fire
on NULL columns). Non-NULL dangling reference returns
`Error::Conflict` via extended-code 787 on SQLite, matching PG's
`SqlState::FOREIGN_KEY_VIOLATION` mapping.

### PyO3 surface

3 new Engine methods gated on `cirislens_feedback_mappings`. Stable
error kinds: `feedback_mappings_invalid_argument | _not_found |
_conflict | _backend | _internal`.

### Tests

18 new (3 types + 1 mod kind + 7 PG + 7 SQLite):
- All 5 columns round-trip
- `record_feedback` ClaimResult: clean Stored + duplicate AlreadyClaimed
- FK reject on non-NULL nonexistent target_thought_id (both backends)
- FK passthrough on NULL target_thought_id (both backends)
- `list_feedback_for_thought`: 3 rows pointing at one thought →
  returns 3 ordered DESC by created_at
- Filter by source_message_id / feedback_type / time window

Lib suite: 343 pass.

### Remaining 1 substrate

`wa_cert` (v1.5.19) — the Wise-Authority cert directory, last
substrate before #59 closes.

## [1.5.17] — 2026-05-18

**`continuity_awareness` substrate — 9 of 11 (CIRISPersist#59 #9).**

First substrate with a **cross-substrate composite-key FK** —
references `cirisgraph_nodes(node_id, scope)` shipped in v0.8.0
(PG: `cirisgraph.nodes`; SQLite: `cirisgraph_nodes`). Feature depends
on `cirisgraph` since the substrate genuinely can't function without
the graph migrations having run first:

```toml
cirislens_continuity_awareness = ["cirisgraph"]
```

V032 migration on both backends. 14 columns matching agent's
shutdown-awareness table. `preservation_scope` reuses
`crate::graph::types::GraphScope` (UPPERCASE `LOCAL|IDENTITY|
ENVIRONMENT|COMMUNITY`) — single source of truth across the cross-
substrate FK.

2 indexes:
- `(agent_id, shutdown_timestamp DESC)` — boot-time "where did I
  leave off"
- `(agent_id, shutdown_timestamp DESC) WHERE is_terminal = FALSE` —
  active-session reactivation hot path

### Composite-key FK semantics on both backends

- **PG**: `DEFERRABLE INITIALLY DEFERRED`. FK fires at commit time.
  PG test seeds graph_nodes row via `GraphService::upsert_node`;
  missing-row reject returns `Conflict` via
  `SqlState::FOREIGN_KEY_VIOLATION` mapping.
- **SQLite**: immediate enforcement (`PRAGMA foreign_keys=ON` set
  by SqliteBackend). SQLite error mapper distinguishes extended code
  787 (`SQLITE_CONSTRAINT_FOREIGNKEY`) → `Conflict` from other
  constraint violations → `InvalidArgument`, matching PG semantics.

### ContinuityAwarenessService trait (3 methods)

- `record_shutdown` → ClaimResult (write-once per shutdown event)
- `get_latest_shutdown(agent_id)` → boot-time query; ORDER BY
  shutdown_timestamp DESC LIMIT 1
- `record_reactivation(agent_id)` — increments `reactivation_count`
  on the most-recent non-terminal shutdown for the agent; returns
  false if no non-terminal shutdown exists

### PyO3 surface

3 new Engine methods gated on `cirislens_continuity_awareness`.
Stable error kinds: `continuity_awareness_invalid_argument |
_not_found | _conflict | _backend | _internal`.

### Tests

22 new (3 types + 1 mod kind + 9 PG + 9 SQLite):
- All 14 columns round-trip
- FK to graph_nodes rejects nonexistent (preservation_node_id,
  preservation_scope) — composite-key reject works on both backends
- `record_shutdown` ClaimResult: clean Stored; duplicate returns
  AlreadyClaimed
- `get_latest_shutdown`: 3 shutdowns with different timestamps;
  returns the most recent
- `record_reactivation` increments count (0 → 1 → 2)
- Reactivation returns false when only terminal shutdowns exist
- Scope CHECK rejects unknown values

Lib suite: 313 pass.

### Surprises

- Spec said PG parent was `cirislens.cirisgraph_nodes`; actual is
  `cirisgraph.nodes` (different schema; no `cirislens` prefix).
  Verified in V013 migration. Used correct names in V032.
- rusqlite's `ErrorCode::ConstraintViolation` collapses CHECK / NOT
  NULL / FK / UNIQUE under one variant. Reading extended code 787 is
  required to distinguish FK reject for PG parity. Earlier substrates
  with no FKs didn't need this; documented for future cross-substrate
  FK work.

### Remaining 2 substrates

`feedback_mappings` (v1.5.18), `wa_cert` (v1.5.19).

## [1.5.16] — 2026-05-18

**`creation_ceremonies` substrate — 8 of 11 (CIRISPersist#59 #8).**

V031 migration on both backends. 14 columns matching the agent's
identity-creation history table verbatim. Status CHECK:
`pending | in_progress | completed | failed | revoked`. No FKs
(agent_id references are free-form pointers across the federation).

`expected_capabilities` stays `Option<String>` rather than typed
JSON — the agent stores TEXT and we preserve the wire format
literally so callers ride the same payload across the absorb
boundary.

4 indexes: `(new_agent_id)`, `(creator_agent_id, timestamp DESC)`,
`(wise_authority_id, timestamp DESC)`, `(timestamp DESC)`.

### CreationCeremonyService trait (4 methods)

- `record_ceremony` → ClaimResult (write-once shape; ON CONFLICT DO
  NOTHING; AlreadyClaimed on duplicate)
- `get_ceremony`
- `list_ceremonies` — filter by creator/wa/new_agent/status/time
  window; ORDER BY timestamp DESC; LIMIT
- `update_ceremony_status` — atomic status advance; missing-row=false

### PyO3 surface

4 new Engine methods gated on `cirislens_creation_ceremonies`.
Stable error kinds: `creation_ceremonies_invalid_argument |
_not_found | _conflict | _backend | _internal`.

### Tests

22 new (6 types + 1 mod kind + 7 PG + 7 SQLite):
- All 14 columns round-trip
- AlreadyClaimed loser on duplicate ceremony_id
- List by creator / new_agent / WA + status + window
- Status CHECK rejects unknown
- `update_ceremony_status` success + missing-row=false
- Required columns validated

Lib suite: 298 pass.

### Remaining 3 substrates

`continuity_awareness` (v1.5.17), `feedback_mappings` (v1.5.18),
`wa_cert` (v1.5.19).

## [1.5.15] — 2026-05-18

**`maintenance_locks` substrate — 7 of 11 (CIRISPersist#59 #7).**

Generic `maintenance_locks` family — the agent's
`consolidation_locks` is the first user, but the substrate is
designed to subsume any future cross-occurrence coordination need
(per the spec). Renamed away from `consolidation_locks` to flag the
generality.

V030 migration on both backends. 5 columns: `lock_key` (PK),
`locked_by`, `locked_at`, `lock_timeout_seconds` (default 300, CHECK
> 0), `metadata` (JSONB/TEXT JSON — optional lock-holder context).

Partial index `(locked_at DESC) WHERE locked_by IS NOT NULL` for the
active-lock scan.

### MaintenanceLockService trait (3 methods)

- `try_acquire_lock(lock_key, locked_by, timeout_seconds, metadata?)`
  → `Option<MaintenanceLock>`. Race-safe via single-statement
  INSERT-OR-UPDATE with a WHERE clause that filters by
  lock-not-held OR lock-expired. Returns Some on win (clean acquire,
  re-acquire by same holder, or steal-from-stale); None when another
  active holder owns it.
- `release_lock(lock_key, locked_by)` → bool. Releases iff caller
  still holds it; mismatched caller is a no-op returning false.
- `get_lock(lock_key)` — read current state.

`MaintenanceLock::is_expired(now)` helper for client-side checks.

### Cross-backend expiry parity

Critical invariant verified: both backends evaluate expiry
server-side in the same statement that performs the acquire, using
the same server clock that stamped `locked_at`.

- PG: `WHERE locked_at + (lock_timeout_seconds * interval '1 second') < NOW()`
- SQLite: `WHERE julianday('now') > julianday(locked_at) + (lock_timeout_seconds / 86400.0)`

Test `expiry_semantics_match_client_helper` runs on both: acquire
with 1s timeout, wait 1.5s, assert client's `is_expired(Utc::now())`
agrees with `try_acquire_lock(...) → Some(_)` from a different
holder. Both pass; sub-millisecond clock skew tolerance.

### PyO3 surface

3 new Engine methods gated on `cirislens_maintenance_locks`:
- `lock_try_acquire(lock_key, locked_by, timeout_seconds, metadata_json?) → Option<json>`
- `lock_release(lock_key, locked_by) → bool`
- `lock_get(lock_key) → Option<json>`

Stable error kinds: `maintenance_locks_invalid_argument |
maintenance_locks_not_found | maintenance_locks_conflict |
maintenance_locks_backend | maintenance_locks_internal`.

### Tests

28 new (9 types + 1 mod kind + 9 PG + 9 SQLite):
- All 5 columns round-trip
- Clean acquire on empty key
- Same-holder refresh (re-acquire is idempotent)
- Contention: active holder → None
- Steal-from-stale: expired lock → Some
- Release-matches → true + cleared
- Release-mismatches → false + no-op
- `get_lock` returns current state
- `is_expired` matrix (None timestamps, exact-boundary, beyond-boundary)
- Cross-backend expiry parity test

Lib suite: 304 pass.

### Remaining 4 substrates

`creation_ceremonies` (v1.5.16), `continuity_awareness` (v1.5.17),
`feedback_mappings` (v1.5.18), `wa_cert` (v1.5.19).

## [1.5.14] — 2026-05-18

**`deferral_reports` substrate — 6 of 11 (CIRISPersist#59 #6).**

V029 migration on both backends. 7 columns: message_id (PK),
task_id (FK → cirislens_tasks), thought_id (FK → cirislens_thoughts),
package (JSONB on PG / TEXT JSON on SQLite), created_at, resolved_at,
resolution_notes.

Substrate adds `resolved_at` + `resolution_notes` columns beyond the
agent's bare 5-column schema. Necessary for the
`list_active_deferrals` query (WA deferrals awaiting resolution)
spec'd in CIRISPersist#59. Both nullable — back-compat with agent's
existing rows preserved.

3 indexes: `(task_id)`, `(thought_id)`, partial
`(created_at DESC) WHERE resolved_at IS NULL` for the active-only
hot path.

### DeferralReportService trait (4 methods)

- `record_deferral(report)` → `ClaimResult<DeferralReport>` —
  INSERT-OR-IGNORE on message_id; idempotent re-record returns the
  original row's payload
- `get_deferral(message_id)`
- `list_active_deferrals(filter, limit)` — only rows with
  `resolved_at IS NULL`; filter by task_id / thought_id / created
  window; ordered by created_at DESC
- `resolve_deferral(message_id, resolved_at, resolution_notes?)` →
  bool (false = didn't exist)

### PyO3 surface

4 new Engine methods gated on `cirislens_deferral_reports`. Stable
error kinds: `deferral_reports_invalid_argument |
deferral_reports_not_found | deferral_reports_conflict |
deferral_reports_backend | deferral_reports_internal`.

### Tests

18 new (3 types + 1 mod kind + 7 PG + 7 SQLite):
- All 7 columns round-trip including JSON package + nullable
  resolved_at/resolution_notes
- FK to tasks + thoughts: rejects nonexistent IDs on both backends
- `record_deferral` race semantics: clean Stored on first; duplicate
  message_id returns AlreadyClaimed carrying original row
- `list_active_deferrals`: 3 deferrals (2 resolved, 1 active) →
  returns 1 active; filter by task_id; filter by created_after window
- `resolve_deferral`: success + missing-row=false + readback reflects
  resolution

Lib suite: 18/18 deferral tests pass (and prior substrates unchanged).

### Notes on partial-then-finish work

Previous sub-agent timed out partway. Finish pass added: SQLite impl
(616 lines), Cargo.toml feature flag, pyproject.toml maturin entry,
lib.rs registration, all 4 PyO3 wrappers + error-kind tokens, .pyi
stubs, qa_harness count bump (1..=28 → 1..=29). No surprises in the
partial work — Postgres impl + service trait + types were all
correctly shaped.

### Remaining 5 substrates

`consolidation_locks` (v1.5.15), `creation_ceremonies` (v1.5.16),
`continuity_awareness` (v1.5.17), `feedback_mappings` (v1.5.18),
`wa_cert` (v1.5.19).

## [1.5.13] — 2026-05-18

**`tickets` substrate — 5 of 11 (CIRISPersist#59 #5).**

V028 migration on both backends. 17 columns. SOP/email-bound
substrate; lighter shape than tasks/thoughts (no FKs except a
free-form `correlation_id` pointer). Status vocabulary: 8-value
lowercase incl. `in_progress` (mixed snake_case;
`#[serde(rename_all = "snake_case")]` keeps JSON wire = SQL string).
Priority CHECK 1-10 with default 5.

`agent_occurrence_id` default is **`'__shared__'`** (sentinel for
cross-occurrence tickets; distinct from every prior substrate's
`'default'`).

4 indexes:
- `(agent_occurrence_id, sop, status, last_updated DESC)`
- `(email, last_updated DESC)`
- `(status, deadline ASC) WHERE status NOT IN ('completed','cancelled','failed')`
  — due-deadline scans
- `(correlation_id) WHERE NOT NULL`

### TicketService trait (5 methods)

- `upsert_ticket` — ON CONFLICT DO UPDATE; preserves `created_at` +
  `submitted_at`
- `get_ticket`
- `list_tickets` — filter by sop / type / status / email / occurrence
  / automated / deadline_before / last_updated window; cursor pagination
- `assign_ticket(id, user, new_status?)` — atomic assign + optional
  status flip; idempotent on re-assign to same user; missing-row=false
- `update_ticket_status(id, new_status, completed_at?, notes?)` —
  terminal states (`completed`/`cancelled`/`failed`) carry `completed_at`

### PyO3 surface

5 new Engine methods gated on `cirislens_tickets` feature.

### Tests

26 new (1 mod + 8 types + 8 PG live + 9 SQLite):
- All 17 columns round-trip
- Idempotent upsert preserves created_at + submitted_at
- Status CHECK rejects unknown values; priority CHECK rejects 0/11
- Filter by sop / status / email / automated / deadline_before
- Cursor pagination
- Assign success + missing + reassign no-op
- Status update success + missing + terminal-with-completed_at
- `in_progress` snake_case round-trips through both SQL and JSON

Lib suite: 302 pass with full substrate feature set.

### No Backend-trait collision

`upsert_ticket` / `get_ticket` / `list_tickets` / `assign_ticket` /
`update_ticket_status` are unique across the codebase. Method-call
dispatch suffices.

### Surprises

- **Nanosecond drift on PG TIMESTAMPTZ**: PG stores microsecond
  precision; `chrono::Utc::now()` produces nanoseconds. Fixed via
  same-second drift assertion (≤1s tolerance), matching how
  v1.5.12 scheduled_tasks tests handle this.
- **`'__shared__'` occurrence sentinel** is distinct from every
  prior substrate (`tasks`/`thoughts`/`correlations`/`scheduled_tasks`
  default to `'default'`). Codified in `default_occurrence()` helper
  and a regression test.
- **`TicketStatus::is_terminal()`** helper exposes the
  `{completed, cancelled, failed}` set for callers that need to
  branch on terminal state.

### Remaining 6 substrates

`deferral_reports` (v1.5.14), `consolidation_locks` (v1.5.15),
`creation_ceremonies` (v1.5.16), `continuity_awareness` (v1.5.17),
`feedback_mappings` (v1.5.18), `wa_cert` (v1.5.19).

## [1.5.12] — 2026-05-18

**`scheduled_tasks` substrate — 4 of 11 (CIRISPersist#59 #4).**

V027 migration. 15 columns. FK to `cirislens_thoughts(thought_id)` —
DEFERRABLE on PG, immediate on SQLite. Status CHECK uses **UPPERCASE**
vocabulary (`PENDING | ACTIVE | COMPLETE | FAILED`) per agent's
schema — distinct from tasks' lowercase 6-value set.

Three indexes:
- `(agent_occurrence_id, next_trigger_at) WHERE next_trigger_at IS
  NOT NULL AND status IN ('PENDING','ACTIVE')` — scheduler-tick hot path
- `(agent_occurrence_id, status, created_at DESC)` — list-by-status
- `(origin_thought_id)` — back-reference to triggering thought

### ScheduledTaskService trait (3 methods)

- `upsert_scheduled_task(task)` — ON CONFLICT (id) DO UPDATE on all
  non-monotonic columns; preserves `created_at` across re-upsert
- `list_due_scheduled_tasks(occurrence, now, limit)` — scheduler-tick
  query. WHERE next_trigger_at <= now AND status IN (PENDING,
  ACTIVE), ordered ASC by next_trigger_at. Hits the
  scheduled_tasks_due partial index.
- `update_after_trigger(task_id, last_triggered_at, next_trigger_at?,
  deferral_count, deferral_history?, new_status?)` — partial-update
  semantics; Some(...) writes, None preserves; returns false if task
  didn't exist

### Status vocabulary

`UPPERCASE`. Rust enum stays TitleCase (`Pending`/`Active`/`Complete`
/`Failed`); `as_sql_str` emits UPPERCASE; serde JSON wire format is
snake_case (per project convention); FFI uppercases caller input
before parse. CHECK rejects lowercase and tasks-vocab `COMPLETED`
(with the trailing D) — only exact `COMPLETE` is valid.

### PyO3 surface

3 new Engine methods gated on `cirislens_scheduled_tasks` feature.
Stable error kinds: `scheduled_tasks_invalid_argument |
scheduled_tasks_not_found | scheduled_tasks_conflict |
scheduled_tasks_backend | scheduled_tasks_internal`.

### Tests

22 new (1 mod kind + 6 types + 7 PG live + 8 SQLite):
- All 15 columns round-trip
- Upsert idempotency preserves `created_at`
- FK to thoughts rejects nonexistent origin_thought_id
- `list_due_scheduled_tasks`: 5 tasks with mixed past/future/NULL
  next_trigger_at; only past-due PENDING/ACTIVE return; ordered ASC
- `update_after_trigger` success + missing-row=false + partial-update
- CHECK guards: lowercase rejected, `COMPLETED` rejected, only
  `COMPLETE` valid

Lib suite: 347 pass with full substrate feature set
(`cirislens_tasks cirislens_thoughts cirislens_correlations
cirislens_scheduled_tasks`).

### No Backend-trait collision

The Phase-3 stub sweep didn't hit any `scheduled_task_*` method names.
UFCS dispatch used at PyO3 sites for consistency with prior substrate
pattern; harmless.

### Note on DEFERRABLE FK on PG

Even with `DEFERRABLE INITIALLY DEFERRED`, tokio-postgres's
auto-commit wraps each statement in its own implicit transaction.
Single-statement INSERTs against a dangling `origin_thought_id` fail
immediately at end-of-implicit-tx. The DEFERRABLE flag only matters
for callers that open a multi-statement transaction (which the agent
does for parent+child writes). Test
`scheduled_tasks_pg_fk_rejects_nonexistent_origin_thought` validates
the expected reject behavior.

### Remaining 7 substrates

`tickets` (v1.5.13), `deferral_reports` (v1.5.14),
`consolidation_locks` (v1.5.15), `creation_ceremonies` (v1.5.16),
`continuity_awareness` (v1.5.17), `feedback_mappings` (v1.5.18),
`wa_cert` (v1.5.19).

## [1.5.11] — 2026-05-18

**`service_correlations` substrate — 3 of 11 (CIRISPersist#59 #3).**

The hot-path substrate: 400+ rows on an active agent. Dual-purpose
schema absorbing service-interaction tracking + TSDB metrics +
distributed-trace spans + log correlations into one substrate.
Caller discriminates via `correlation_type`. Shipped as one substrate
per spec; may split later if access patterns diverge.

V026 migration on both backends with all 18 columns from
CIRISAgent v2.8.13:
- `correlation_id` PK, `service_type`, `handler_name`, `action_type`
- `request_data` / `response_data` / `tags` — JSONB on PG; TEXT JSON on SQLite
- `status`, `created_at`, `updated_at`, `correlation_type`,
  `retention_policy`
- `timestamp` — event time (distinct from row's `created_at`); used
  for metric/trace time-window scans
- `metric_name` / `metric_value` (REAL; PG f32 cast up to f64 at trait
  boundary to match SQLite's f64 REAL semantic)
- `log_level`, `trace_id`, `span_id`, `parent_span_id`, `tags`
- `agent_occurrence_id` (default `"default"`)

CHECKs:
- `status IN ('pending','active','completed','failed','cancelled')`
- `correlation_type IN ('service_interaction','metric','trace','log')`
- `retention_policy IN ('raw','aggregated','summary','retained_indefinitely')`

Indexes (5):
- `(agent_occurrence_id, service_type, updated_at DESC)` — list-by-service hot path
- `(correlation_type, timestamp DESC)` — metric/trace time-window scans
- `(trace_id) WHERE NOT NULL` — distributed-trace assembly
- `(parent_span_id) WHERE NOT NULL` — span tree walks
- `(metric_name, timestamp DESC) WHERE NOT NULL` — TSDB-style metric queries

### CorrelationService trait (4 methods)

- `record_correlation(correlation)` — INSERT-OR-IGNORE (`ON CONFLICT
  (correlation_id) DO NOTHING`); first writer wins; subsequent
  writers are no-ops; state advancement via `update_correlation_status`
- `get_correlation`
- `update_correlation_status(id, new_status, response_data_json?)` —
  response_data COALESCE merge; missing-row returns false
- `query_correlations(filter, cursor?, limit)` — filter by
  service_type / correlation_type / trace_id / metric_name /
  retention_policy / occurrence / event-timestamp window / row-update
  window; cursor pagination on `(updated_at, correlation_id)`

### PyO3 surface

4 new Engine methods gated on `cirislens_correlations` feature
(added to maturin wheel features). Stable error kinds added:
`correlations_invalid_argument | correlations_not_found |
correlations_conflict | correlations_backend | correlations_internal`.

### Tests

30 new (1 mod kind + 8 types unit + 9 PG live + 12 SQLite):
- All 18 columns round-trip
- `record_correlation` idempotency on conflict
- `update_correlation_status` success + missing-row=false + COALESCE merge
- `query_correlations` filtered by service_type / correlation_type +
  metric_name (TSDB hot path) / trace_id (distributed-trace assembly)
  / timestamp window
- Cursor pagination on `(updated_at, correlation_id)`
- Span tree: insert root + 2 children + 1 grandchild; parent_span_id
  query surfaces children
- 3 CHECK-constraint guards (status / correlation_type /
  retention_policy bogus values rejected)

Lib suite: 355 pass with `postgres sqlite cirislens_tasks
cirislens_thoughts cirislens_correlations`.

### Backend-trait collision (recurred)

`store/backend.rs` has a Phase-3 stub `Backend::record_correlation`
taking `&ServiceCorrelation` (legacy redb-era shape) that collides
with the new `CorrelationService::record_correlation(Correlation)`.
Resolved via UFCS at PG call sites (same shape as v1.5.9 tasks
collision). The legacy stub will be removed in a future cleanup once
no consumer references it.

### Vocabulary disclaimer

Status / correlation_type / retention_policy vocabularies came from
the v1.5.11 spec, not from `CIRISAgent v2.8.13` enum source. Sub-agent
flagged this — recommend a sanity grep against
`ciris_engine/schemas/runtime/enums.py` +
`ciris_engine/persistence/services/service_correlations.py` once the
agent integration PR is in flight. If the agent uses different status
strings (e.g., `processing` instead of `active`), a V027 will relax
the CHECK constraint. No persist-side shape change needed.

### `record_correlation` ON CONFLICT decision

Shipped as `DO NOTHING` (caller advances via `update_correlation_status`).
If agent retry path re-records with richer `request_data`, those writes
will be silently dropped. Two paths to fix if that turns out to matter:
- Switch to conditional upsert (DO UPDATE WHERE status='pending')
- Document the contract that callers must reuse original payload on retry

Decision deferred until agent integration PR lands and shows actual
call shapes.

### Remaining 8 substrates

`scheduled_tasks` (v1.5.12), `tickets` (v1.5.13), `deferral_reports`
(v1.5.14), `consolidation_locks` (v1.5.15), `creation_ceremonies`
(v1.5.16), `continuity_awareness` (v1.5.17), `feedback_mappings`
(v1.5.18), `wa_cert` (v1.5.19).

## [1.5.10] — 2026-05-18

**`thoughts` substrate — 2 of 11 (CIRISPersist#59 #2).**

Mirrors the v1.5.9 `tasks` shape with thought-specific lifecycle.
V025 migration on both backends, FK to `cirislens_tasks`, self-FK on
`parent_thought_id`. 14 columns. Status CHECK: `pending | processing
| completed | failed | deferred`.

### ThoughtType as transparent newtype

Spec hinted at `Standard | Reflection | Action | Observation` enum.
Inspection showed CIRISAgent's `ThoughtType` actually has 20+
values (STANDARD, FOLLOW_UP, ERROR, OBSERVATION, MEMORY, DEFERRED,
PONDER, FEEDBACK, GUIDANCE, IDENTITY_UPDATE, ETHICAL_REVIEW,
CONSENSUS, REFLECTION, SYNTHESIS, DELEGATION, CLARIFICATION,
SUMMARY, TOOL_RESULT, ACTION_REVIEW, URGENT, SCHEDULED, PATTERN,
ADAPTATION, …). A closed enum here would drift the moment the
agent adds a value. Shipped as a transparent `String` newtype with
`Default == "standard"` + convenience constructors for common
variants. SQL column is `TEXT NOT NULL DEFAULT 'standard'` with NO
CHECK — new agent variants flow through without persist schema
changes.

### ThoughtService trait (5 methods)

- `upsert_thought` — idempotent on `thought_id`; preserves
  `created_at` on re-upsert
- `get_thought`
- `list_thoughts` — filter by task / status / occurrence; cursor
  pagination on `(updated_at, thought_id)`
- `update_thought_status` — `final_action` JSON merge via COALESCE;
  missing-row returns `false`
- `get_descendants` — recursive CTE walking `parent_thought_id` chain
  from a root; ordered by `(thought_depth ASC, thought_id ASC)` for
  determinism. Same shape on both backends (SQLite 3.8.3+ supports
  WITH RECURSIVE; PG always has)

### PyO3 surface

5 new Engine methods gated on `cirislens_thoughts` feature (added to
maturin wheel features). Stable error kinds:
`thoughts_invalid_argument | thoughts_not_found | thoughts_conflict
| thoughts_backend | thoughts_internal`.

### Tests

27 new (1 mod kind + 6 types unit + 9 PG live + 11 SQLite):
- All 14 columns round-trip
- Idempotent upsert preserves `created_at`
- FK to tasks rejects nonexistent task on both backends
- Self-FK on parent_thought_id rejects nonexistent parent
- Filter by source_task_id / status / occurrence
- Cursor pagination
- `update_thought_status` success + missing-row=false + COALESCE merge
- 3-level descendant tree (root → 2 children → 1 grandchild each) →
  `get_descendants` from root returns 7 rows in deterministic order
- Single-leaf descendants (just the root)
- Unknown-root → empty Vec

Lib suite: 325 pass with `postgres sqlite cirislens_tasks
cirislens_thoughts` feature set.

### No Backend-trait collision this time

The Phase-3 stub sweep that hit `upsert_task` / `try_claim_shared_task`
in v1.5.9 didn't stub any `thought_*` methods. Plain trait dispatch
suffices; no UFCS needed.

### Schema notes

- `channel_id` column present per spec; nullable; no FK. Agent's own
  migration may differ but spec is authoritative for the substrate
  shape.
- FKs on PG are `DEFERRABLE INITIALLY DEFERRED` (matches V024 tasks
  pattern); SQLite uses plain `FOREIGN KEY` (immediate enforcement
  via `PRAGMA foreign_keys=ON`).

### Remaining 9 substrates

`service_correlations` (v1.5.11), `scheduled_tasks` (v1.5.12),
`tickets` (v1.5.13), `deferral_reports` (v1.5.14),
`consolidation_locks` (v1.5.15), `creation_ceremonies` (v1.5.16),
`continuity_awareness` (v1.5.17), `feedback_mappings` (v1.5.18),
`wa_cert` (v1.5.19).

## [1.5.9] — 2026-05-18

**`tasks` substrate — first of 11 absorptions ending dual-libsqlite WAL corruption ([#59](https://github.com/CIRISAI/CIRISPersist/issues/59) #1).**

CIRISAgent 2.9.0's full absorption commitment: persist becomes the
only library that ever opens the engine DB file. This ships the first
of 11 substrates absorbing the agent's `ciris_engine.db` legacy
tables. v1.5.10-v1.5.19 follow with the remaining 10.

### `tasks` substrate

V024 migration on both backends with all 17 columns from CIRISAgent
v2.8.13 `tasks` table:
- `task_id` PK, `channel_id`, `description`, `status`, `priority`
- `created_at`, `updated_at`, `parent_task_id` (self-FK, deferrable on PG)
- `context_json` / `outcome_json` / `images_json` (JSONB on PG; TEXT on SQLite)
- `retry_count`, `signed_by` / `signature` / `signed_at` (audit envelope)
- `updated_info_available` / `updated_info_content` (multi-occurrence sync)
- `agent_occurrence_id` (multi-occurrence partitioning; default `"default"`)

Indexes: `(agent_occurrence_id, status, updated_at DESC)` for the hot
list-by-status path; `(channel_id, updated_at DESC)`; `(parent_task_id)`
WHERE NOT NULL for tree walks.

Status vocabulary CHECK: `pending | active | completed | failed |
cancelled | deferred`.

### New `TaskService` trait + `Task` typed shape

`src/tasks/` module (gated on new `cirislens_tasks` feature, included
in the maturin wheel features):

- `Task` struct with all 17 columns typed (`context: Option<serde_json::Value>`
  etc.); `TaskStatus` enum with stable SQL strings; `TaskFilter` for
  bounded queries; `TaskCursor` for pagination; `TaskListPage`.
- `TaskService` trait, 6 methods:
  - `upsert_task(task)` — idempotent; same task_id with differing
    data overwrites non-monotonic columns
  - `get_task(task_id) -> Option<Task>`
  - `list_tasks(filter, cursor?, limit) -> TaskListPage` — cursor
    pagination on `(updated_at, task_id)`
  - `update_task_status(task_id, new_status, outcome_json?) -> bool` —
    false = task didn't exist
  - `try_claim_shared_task(task) -> ClaimResult<Task>` — atomic
    INSERT OR IGNORE for multi-occurrence coordination (race-safe on
    task_id PK; Stored on win, AlreadyClaimed on race)
  - `delete_task(task_id) -> bool` — true if a row was deleted; FK
    REJECT on children (caller deletes subtree explicitly)
- PG + SQLite impls (`src/tasks/postgres.rs` + `src/tasks/sqlite.rs`).

### PyO3 surface

6 new Engine methods, all JSON-in/JSON-out and dispatching to both
backends:
- `task_upsert(task_json)`
- `task_get(task_id) -> Option<json>`
- `task_list(filter_json, cursor_json?, limit) -> json`
- `task_update_status(task_id, new_status, outcome_json?) -> bool`
- `task_try_claim_shared(task_json) -> json` (ClaimResult)
- `task_delete(task_id) -> bool`

Stable error-kind tokens added to `translate_error_kind`:
`tasks_invalid_argument | tasks_not_found | tasks_conflict |
tasks_backend | tasks_internal`. Python wrapper `.pyi` extended with
all 6 signatures.

### Tests

22 new tests: 5 types unit tests + 1 mod error-kind test + 9 SQLite
integration + 7 PG integration. All 17 columns round-trip; idempotent
upsert; cursor pagination; concurrent try_claim race produces one
Stored + one AlreadyClaimed referencing the same row; FK parent
existence enforced on both backends (PG via DEFERRABLE constraint
checked at commit, SQLite via immediate FK).

Lib suite: 298 pass with `postgres sqlite cirislens_tasks` feature
set. `cargo fmt` + `cargo clippy ... -D warnings` clean.

### Method-name collision note

`PostgresBackend` already had `upsert_task` + `try_claim_shared_task`
placeholders on the `Backend` trait from a prior Phase 3 stub. The
new `TaskService` impl on the same type collides at method-resolution
time. Resolved via UFCS at every PG call site
(`TaskService::upsert_task(&backend, …)`). SQLite was clean —
`SqliteTaskBackend` is a separate wrapper. The Phase 3 `Backend` trait
placeholders can be removed in a future cleanup once we're sure no
other consumer references them.

### Remaining 10 substrates

| # | Substrate | Release |
|---|---|---|
| 2 | `thoughts` (FK to tasks) | v1.5.10 |
| 3 | `service_correlations` (hot) | v1.5.11 |
| 4 | `scheduled_tasks` | v1.5.12 |
| 5 | `tickets` | v1.5.13 |
| 6 | `deferral_reports` | v1.5.14 |
| 7 | `consolidation_locks` (generic maintenance_lock_*) | v1.5.15 |
| 8 | `creation_ceremonies` | v1.5.16 |
| 9 | `continuity_awareness` (FK to graph_nodes) | v1.5.17 |
| 10 | `feedback_mappings` | v1.5.18 |
| 11 | `wa_cert` | v1.5.19 |

## [1.5.8] — 2026-05-18

**SQLite parity for `get_classifications` + `get_features`. Plus write paths.**

v1.5.1's parity sweep made these two methods return a typed
`PyRuntimeError("pipeline-read primitives are Postgres-only")` on
SQLite. That framing was wrong — no PG-only declarations. This ships
the SQLite read path + adds explicit write methods on both backends
so the agent's AdaptiveFilter output round-trips through persist as
the storage substrate.

### V023 migration (SQLite only — PG already has these via V009)

```sql
ALTER TABLE trace_events ADD COLUMN extracted_features  TEXT;
ALTER TABLE trace_events ADD COLUMN classifications     TEXT;
ALTER TABLE trace_events ADD COLUMN pipeline_metadata   TEXT;
```

All three nullable; pre-V023 rows stay valid; pipeline-aware
consumers detect "no pipeline ran" via `extracted_features IS NULL`.

### New backend methods

- `read_features(trace_id, thought_id)` on `SqliteBackend` (mirrors
  the existing PG method)
- `read_classifications(trace_id, thought_id)` on `SqliteBackend`
  (mirrors PG)
- `write_features(trace_id, thought_id, features)` — NEW on both
  backends; updates the column when the row exists; no-op when it
  doesn't (caller's contract: "set this if present")
- `write_classifications(trace_id, thought_id, classifications)` —
  NEW on both backends; same shape

### New PyO3 methods

- `set_features(trace_id, thought_id, features_json)` — caller serializes
  on Python side; persist parses into typed `Features`, dispatches to
  backend write method
- `set_classifications(trace_id, thought_id, classifications_json)` —
  same shape; typed `Vec<Vec<ContentClassMatch>>`

### PyO3 dispatch updates

`get_features` and `get_classifications` SQLite arms now call into
`SqliteBackend::read_features` / `read_classifications` instead of
returning the PG-only error. Both methods work end-to-end on SQLite.

### Tests (8 new)

SQLite (6):
- `write_then_read_classifications_round_trip` — write + read returns
  equal Vec
- `read_classifications_returns_empty_when_null`
- `write_classifications_on_missing_row_is_noop`
- Same trio for `features`

PG (2):
- `pipeline_write_features_and_classifications_round_trip`
- `pipeline_write_classifications_missing_row_is_noop`

Lib suite: 349 pass with features `postgres sqlite classify extract`.

### What this enables

- **Agent migration path:** Python AdaptiveFilter produces
  classifications → agent calls `engine.set_classifications(...)` →
  reads back via `engine.get_classifications(...)`. Same shape on
  every backend.
- **Lens-tier observability** continues to work on PG via the existing
  pipeline-classify-stage write path (which still UPDATEs the column
  internally during ingest).
- **Sovereign-mode agents** (SQLite-first) now have first-class
  classifications + features storage that round-trips through persist
  without forcing a PG dependency.

### What's still deferred (out of scope)

- Wiring the pipeline classify stage to UPDATE classifications on
  SQLite during the ingest path itself — bigger pipeline substrate
  cut. The agent's path via explicit `set_classifications` covers the
  current use case.
- `pipeline_metadata` read/write PyO3 surface — column lands in V023
  for forward-compat; methods deferred until a real consumer asks.

## [1.5.7] — 2026-05-18

**`SecretsService::process_incoming_text` pipeline orchestration (closes [#57](https://github.com/CIRISAI/CIRISPersist/issues/57)).**

Ships the v0.6.2 stub that has been `Err("requires v0.6.2 pipeline
orchestration")` on both backends. Defaults the trait method to a
composition of existing primitives — `get_filter_config` +
`try_claim_secret` — so both PG and SQLite inherit it automatically
without per-backend SQL.

This is the pattern CIRISAgent Lane B's write-leg has been waiting
on. No more "do persist's job in Python" — the agent can drop its
regex+SecretReference implementation and call
`engine.secrets_process_incoming_text(text, source_message_id, accessor)`.

### Implementation

Default trait impl on `SecretsService::process_incoming_text` (composable
across every backend that supplies `get_filter_config` + `try_claim_secret`):

1. Load filter catalog via `get_filter_config()`.
2. Parse `config_value.patterns` as a typed `CatalogPattern[]` with
   fields `{ pattern_id?, regex, description, sensitivity?,
   auto_decapsulate_for_actions[] }`. Defaults: `sensitivity=High`,
   `auto_decapsulate_for_actions=[]`.
3. For each pattern, compile regex + scan filtered text for matches.
4. For each unique matched plaintext: `try_claim_secret(plaintext,
   description, sensitivity, auto_decapsulate_for_actions, accessor)`
   — race-safe HMAC dedup per v1.0.0 makes repeated calls idempotent.
5. Replace each matched plaintext in filtered text with
   `{SECRET:<uuid>:<description>}` placeholder.
6. Return `(filtered_text, Vec<SecretReference>)`.

### Filter catalog shape (locked)

```json
{
  "patterns": [
    {
      "pattern_id": "aws_access_key",
      "regex": "AKIA[0-9A-Z]{16}",
      "description": "AWS access key",
      "sensitivity": "high",
      "auto_decapsulate_for_actions": ["tool"]
    },
    {
      "pattern_id": "github_pat",
      "regex": "ghp_[A-Za-z0-9]{20,}",
      "description": "GitHub PAT",
      "sensitivity": "high",
      "auto_decapsulate_for_actions": []
    }
  ]
}
```

The catalog is operator-tunable via `update_filter_config`. Agents
seed it at deployment time with the pattern set they want;
`process_incoming_text` reads it on every call (no caching — operator
edits land immediately).

### Backends

- **Postgres**: existing `process_incoming_text` stub removed.
  Inherits the default trait impl which calls the PG-side
  `get_filter_config` + `try_claim_secret`.
- **SQLite**: same. Inherits the default; both primitives are
  SQLite-implemented per v1.5.1 parity sweep.

### Tests

- `process_incoming_text_detects_encrypts_and_replaces_via_default_impl`
  (SQLite): two patterns, two distinct plaintexts; verifies refs
  count, descriptions, no plaintext leaks, placeholder structure,
  and idempotent re-run yielding same UUIDs (HMAC dedup).
- `process_incoming_text_empty_catalog_passthrough` (SQLite): empty
  filter config returns text unchanged with no refs.

Lib suite: 436 pass (was 403 at v1.5.6 with the full feature set).

### Was deferred to v1.6.x — reversed

The v1.5.6 release notes said this method was "v1.6.x track" because
of "PG advisory-lock + RETURNING semantics." That framing was wrong —
the orchestration composes already-implemented primitives, no new
SQL surface. Shipping in v1.5.7 instead.

### Lane B status after this release

| Method | State |
|---|---|
| `secrets_process_incoming_text` | ✅ Both backends via default trait impl (this release) |
| `get_classifications` | SQLite parity is open work — separate cut. The v1.5.6 framing of "permanent PG-only" was wrong; the agent's classifier output should round-trip through persist on both backends. Tracked separately. |

CIRISAgent Lane B write-leg can adopt directly. SQLite parity for
`get_classifications` / `get_features` follows in a near-term cut —
substrate ask is small (V023 migration adding the columns to SQLite
trace_events + mirror PG's read path) but pairs naturally with a
`set_classifications` / `set_features` write API so the agent can
push their AdaptiveFilter output into persist as the storage
substrate.

## [1.5.6] — 2026-05-18

**Diagnostic for cirisgraph attributes UTF-8 decode failures (#58).**

CIRISAgent 2.9.0 staged-QA CI surfaced a hard-to-diagnose failure
where `cirisgraph_get_node` raises `Conversion error from type Text at
index: 3, invalid utf-8 sequence of 1 bytes from index 806` after a
seemingly-successful `cirisgraph_upsert_node`. The error tells the
caller nothing about which node, what surrounding bytes look like, or
how large the column is — making it impossible to trace upstream.

This release replaces rusqlite's default decode error with a detailed
diagnostic + adds defense-in-depth UTF-8 validation on the write side.
No persist-side root cause was identified (write path uses
`serde_json::to_string` which is UTF-8-safe by construction); the
diagnostic makes the actual bytes visible so the agent team can find
the upstream source of the bad data.

### What changed

`src/graph/sqlite.rs`:

1. **New `read_attributes_text`** helper used by `decode_node_row`:
   - Fast path: normal `row.get::<_, String>("attributes")`.
   - On UTF-8 failure: fall back to `Vec<u8>` get, run
     `std::str::from_utf8` to pinpoint the bad byte, return
     `Error::Backend` carrying:
     - The affected `node_id`
     - Position of the invalid byte
     - Length of the invalid UTF-8 sequence
     - Total bytes in the column
     - Hex dump of ±32 bytes around the failure, with `[...]`
       markers around the bad sequence
     - ASCII context (printable chars + • for non-printable)
     - Original `Utf8Error` for forensics

   Example error from the new path (vs the prior one-liner):

   ```
   decode attributes: node_id=ally/identity: invalid UTF-8 at byte 720
   (sequence length 1); attributes column is 730 bytes total. hex (±32
   around failure, [] = invalid bytes): 7b 22 70 ... [c0] 22 2c 22 6b...
   ascii context (• = non-printable): "...padding\":[•]\",\"k\"...".
   original error: invalid utf-8 sequence of 1 bytes from index 720
   ```

2. **`assert_valid_utf8_or_describe`** helper called from
   `encode_attributes` — belt-and-suspenders check that
   `serde_json::to_string`'s output is valid UTF-8 (it is, by
   construction). If a future regression somehow produces non-UTF-8
   bytes on the write path, the failure surfaces with caller context
   at write time rather than at the next read with no context.

### Tests

Two new regression tests in `src/graph/sqlite.rs`:

- `get_node_diagnostic_on_invalid_utf8_attributes` — injects a 0xC0
  byte (invalid UTF-8 start byte) directly via raw SQL `UPDATE`, then
  calls `get_node` and asserts the diagnostic includes node_id, byte
  position, hex dump marker, the invalid byte's hex form, and total
  length.
- `encode_attributes_always_produces_valid_utf8` — pins the write-path
  invariant across nested objects, unicode strings (日本語🎯), escape
  sequences, and large nested arrays.

Lib suite: 403 passed (up from 296 at v1.5.5 — full feature set: postgres,
sqlite, cirisgraph, cirisaudit, cirisincident).

### Impact

- **Diagnostic path activated automatically** — any future
  `cirisgraph_get_node` UTF-8 failure carries actionable info in the
  Python `Transient` exception's error message. Agent CI logs will
  now show the bytes the agent team needs.
- **No behavior change on the write path** — `encode_attributes` is
  UTF-8-safe today; the assertion is paranoid validation.
- **No schema change.** No migration. Zero risk to existing data.

### What this does NOT fix

The upstream root cause of the corruption isn't addressed — that
requires the agent team to see the actual bytes (which this release
enables) and trace where they're coming from. Hypotheses to test
once diagnostic output is available:

- Mojibake (double-encoded text)
- Binary data accidentally serialized as a string (hash bytes, pickle
  fragments, raw bytes from a TPM/keyring without base64 wrapping)
- Python `json.dumps` of a string containing lone surrogates after a
  json.loads → json.dumps round-trip
- An external writer (non-persist) writing to `cirisgraph_nodes`
  directly

The agent team will surface their CI log with the new diagnostic; if
the pattern points at persist, follow-up in v1.5.x or v1.6.x with the
root-cause fix.

### Cross-references

- [CIRISPersist#58](https://github.com/CIRISAI/CIRISPersist/issues/58)
- CIRISAgent#763 (Lane A1 — graph absorption)
- CIRISAgent staged-QA failure:
  https://github.com/CIRISAI/CIRISAgent/actions/runs/26008900813/job/76445550371

## [1.5.5] — 2026-05-17

**Cirisincident schema extension for CIRISAgent Lane D1-full (closes [#56](https://github.com/CIRISAI/CIRISPersist/issues/56)).**

Same shape as v1.5.3's `register_federation_key` and v1.5.4's audit
canonical helpers: when agent's needs reveal a substrate gap, persist
extends rather than asking agent to compromise. The agent's
`IncidentNode` captured 11 forensic fields (filename, line_number,
stack_trace, source_component, ...) that had no first-class home in
persist's `cirislens.incident_records`. Without them the absorption
either loses debug info or packs it into `description` as structured
prose, losing queryable access.

### Schema (V022 — additive, nullable, no breaking changes)

11 new nullable columns on `cirislens.incident_records`
(PG schema-qualified) / `cirislens_incident_records` (SQLite):

| Column | Purpose |
|---|---|
| `incident_type` | Free-form forensic type (`ERROR` / `WARNING` / `EXCEPTION`) |
| `source_component` | Component that raised the incident |
| `handler_name` | Handler that was executing |
| `exception_type` | Exception class name |
| `stack_trace` | Captured stack trace for EXCEPTION-type incidents |
| `filename` | Source file path |
| `line_number` | Source line number |
| `function_name` | Source function name |
| `impact` | Free-form impact statement |
| `urgency` | Free-form urgency statement |
| `detection_method` | How the incident was detected |

Forensic-query indexes added on both backends:
- `(filename, line_number)` WHERE `filename IS NOT NULL` — "all
  incidents from this file" oncall query
- `(source_component)` WHERE `source_component IS NOT NULL` — "all
  incidents from this component"

### Enum extensions

`IncidentSeverity` accepts the ITIL set as distinct variants alongside
the syslog set:
- syslog: `Info` / `Warning` / `Error` / `Critical` (V016 values)
- ITIL (new): `Low` / `Medium` / `High` (Critical maps across)

Both vocabularies are accepted in the SQL CHECK; the Rust enum
carries them as distinct variants so round-trip is lossless. Callers
that want "high-or-above" filtering should match on the enum, not
string-compare.

`IncidentState` gains `Recurring` — parallel to `Open` in rank (0),
representing "open + identified as part of a known problem pattern."

### AV-55 semantic update (recurring)

Per CIRISPersist#56: the agent's `_identify_problems` analysis
transitions OPEN incidents to RECURRING when they match a known
pattern. Since `Recurring` ranks with `Open` (both 0), `can_transition_to`
does NOT permit `Open → Recurring` (same-rank transitions still
rejected per AV-55 strict-forward). Caller signals "this is recurring"
by *initial-INSERT* with `state = 'recurring'`, not by transitioning
from `open`. To support this, `record_incident` now binds the
caller-supplied `state` (was hardcoded `'open'`) and rejects any
state outside `{Open, Recurring}` at the trait surface with
`Error::InvalidArgument`. Transitions still flow through
`transition_state` per AV-55. Locked by `incident_reject_non_initial_state_at_record`
test on both backends.

### Tests

`cargo test --features "postgres sqlite cirisincident" --lib` →
**296 passed, 0 failed** (live PG via `CIRIS_PERSIST_TEST_PG_URL`).
20 incident-namespace tests now: 3 new PG + 4 new SQLite + 5 new
types-module + 8 existing.

### Migration notes

- **V022 on PG**: `ALTER TABLE ADD COLUMN` for the 11 columns + DROP
  + ADD CONSTRAINT for relaxed severity / state CHECKs. Auto-named
  constraints (`incident_records_severity_check` /
  `incident_records_state_check`) confirmed live.
- **V022 on SQLite**: recreate-table dance (SQLite can't DROP
  CONSTRAINT). Preserves ALL V016 columns (including the
  signature/signing_key_id/signature_verified/persist_row_hash/created_at
  audit envelope), all V016 indexes, plus the 11 new columns +
  forensic indexes.
- **No explicit BEGIN/COMMIT** in either migration — Refinery wraps
  each migration in its own transaction; nesting fails with "cannot
  start a transaction within a transaction" (same fix shape as V019
  in commit `d8b467b`).

### Wire format compatibility

`Incident` struct extends with 11 fields marked
`#[serde(default, skip_serializing_if = "Option::is_none")]`. v1.5.4
callers that emit JSON without forensic fields deserialize cleanly
with all-None defaults. Pre-V022 rows SELECTed via the new decoders
yield NULL → `None` on every forensic field. Both directions clean.

### Unblocks

- **CIRISAgent D1-full** (IncidentManagementService absorption with
  full forensic fidelity)
- **Operator oncall queries** — "show me all incidents from this
  file" / "from this component" / "from this handler" now have
  indexed query paths

## [1.5.4] — 2026-05-17

**Audit-chain canonical-bytes helpers + bridge-entry permit (unblocks Lane A0b).**

Same pattern as v1.5.3's `register_federation_key` — agent shouldn't
reimplement persist's canonical-bytes rule in Python. Two PyO3 helpers
expose the canonicalization without forcing callers to choose between
a callback API (awkward over PyO3) and reimplementing the strip rule
in caller-language.

### New PyO3 methods

`engine.audit_canonicalize_for_hash(entry_json) -> bytes`
- Caller builds AuditEntry with `entry_hash=""` and `signature=""`.
- Method zeroes both fields (matching `compute_entry_hash`) and
  canonicalizes via `PythonJsonDumpsCanonicalizer`.
- Caller `sha256`'s the returned bytes to compute `entry_hash`.

`engine.audit_canonicalize_for_signing(entry_json) -> bytes`
- Caller has filled `entry_hash` and left `signature=""`.
- Method zeroes `signature` (matches `canonical_bytes_for_entry`)
  and canonicalizes. `entry_hash` stays in the signed body —
  binds signature to chain position so subsequent-entry rewrites
  invalidate this signature too.
- Caller signs with their own signer (CIRISVerify TPM, local Ed25519,
  KMS, whatever) and fills `signature`.

Both helpers parse the input JSON through the `AuditEntry` struct
before canonicalizing — guarantees byte-equality with persist's
internal computation. Raw-JSON canonicalization diverges on chrono
datetime + `Vec<u8>` field serialization; the struct-parse step
normalizes those.

### Bridge-entry permit (audit chain integrity)

`AuditService::record_entry` previously rejected non-zero `prev_hash`
on `sequence_number=1` with `Permanent: first entry must have
prev_hash = GENESIS_PREV_HASH (32 zero bytes)` — contradicting
`docs/AUDIT_CHAIN_BRIDGE.md §1` which explicitly supports bridge
entries (the verifier already signals them via
`ChainBreakReason::GenesisPrevHashNotZero` as informational, not a
break). Write-path now permits + logs the case for observability.

Impact: A0b (audit chain bridge entry on 2.9.0 first boot) can now
land. CIRISAgent's bridge from its pre-2.9.0 audit log into persist's
`cirisaudit` chain works as documented.

### Doc updates

`docs/AUDIT_CHAIN_BRIDGE.md` §1 expanded with the explicit caller
workflow (4-step Python recipe using the new helpers) and reference
to `crate::audit::verify::compute_entry_hash` as the canonical
implementation (rather than the prior `src/audit/postgres.rs`
reference which assumed downstream readers had source-tree access).

### Tests

`cargo test --features "postgres sqlite cirisaudit" --lib` — 368 pass
(unchanged; helpers compose existing tested primitives + bridge
permit only changes the rejection path that was always-erroring on a
documented-supported case).

Live smoke-tested with the agent's documented A0b flow against a
fresh SQLite DB:
- helpers produce canonical bytes that match persist's internal
  computation (no more `entry_hash mismatch` rejection)
- bridge entry with non-zero `prev_hash` on seq=1 lands successfully
- signature round-trips through the Ed25519 sign + persist verify path

### Unblocks

- **CIRISAgent A0b** (audit chain bridge entry on 2.9.0 first boot) —
  agent assembles bridge entry → `audit_canonicalize_for_hash` →
  sha256 → fill `entry_hash` → `audit_canonicalize_for_signing` →
  sign externally → fill `signature` → `audit_record_entry`. Done.
- **CIRISAgent A3** (GraphAudit cutover) — cascades behind A0b.
- Every other `audit_record_entry` caller — same pattern, no more
  canonical-bytes reimplementation in caller-language.

## [1.5.3] — 2026-05-17

**`register_federation_key` — one-call ergonomic helper that unblocks CIRISAgent Lane C federation directory registration.**

The federation-directory write path (`put_public_key`) requires a fully
assembled `SignedKeyRecord` — caller computes canonical bytes of the
registration envelope, signs Ed25519, attaches `scrub_signature_classical`,
builds the wrapper, then submits. CIRISAgent and other Python consumers
shouldn't re-implement persist's canonical-bytes rule in their own
language — that's exactly the "do persist's job upstream" anti-pattern
the substrate is designed to avoid.

New PyO3 method on `Engine`:

```python
key_id = engine.register_federation_key(
    identity_type="agent",
    identity_ref="agent-x-prod",
    valid_until="2027-12-31T00:00:00Z",     # optional
    registration_envelope_json='{"role":"agent","tenant":"t1"}',  # optional
    roles=["cirislens_pipeline_writer"],     # optional V020 role tags
)
# → returns the engine's local_key_id (which is what got registered).
# → row lands in federation_keys with full hybrid envelope.
# → cold-path ML-DSA-65 PQC sign fires automatically if Engine was
#   constructed with local_pqc_key_id + local_pqc_key_path.
```

Composes existing primitives — no semantic novelty:

1. Canonicalizes `registration_envelope_json` via `PythonJsonDumpsCanonicalizer`
   (same rule the documented manual workflow uses through
   `engine.canonicalize_envelope`)
2. Signs canonical bytes with `LocalSigner::sign_ed25519`
3. Computes `original_content_hash = hex(SHA-256(canonical_bytes))`
4. Builds a self-signed `KeyRecord` (`scrub_key_id = key_id`) with
   `algorithm = "hybrid"`, `pubkey_ml_dsa_65_base64 = None`,
   `scrub_signature_pqc = None`, `pqc_completed_at = None` (cold path
   fills)
5. Wraps in `SignedKeyRecord` + delegates to `put_public_key` — backend
   dispatch + cold-path PQC attach handled automatically

Idempotent on `key_id` PRIMARY KEY of `federation_keys` — same shape as
the underlying `put_public_key` contract.

Distinguishes the **federation directory** write path from
`register_public_key`, which writes to the **lens audit-chain pubkey
directory** (`accord_public_keys`) — two different tables, two different
purposes. Updated docstrings on both methods to make the distinction
explicit (closes the docs/clarity follow-up from CIRISPersist#54).

**Unblocks:** CIRISAgent 2.9.0 Lane C — federation_keys self-registration
without requiring the agent team to implement canonical-bytes in Python.
A0b (audit bridge entry) cascades behind this as separate agent-side
wiring; A3 cascades behind A0b.

Tests: 368 lib pass (unchanged; helper composes existing tested
primitives). The new path will smoke-test through downstream integration
once the wheel publishes.

## [1.5.2] — 2026-05-17

**Pin bump — ciris-keyring / ciris-verify-core / ciris-crypto v2.3.0 → v2.4.0.**

Workspace coherence with CIRISVerify v2.4.0's vocabulary-fix rename
(`load_steward_seed` → `load_local_seed`, `StewardSeedConfig` →
`LocalSeedConfig`). No code changes here — persist doesn't import the
renamed symbols (we use `Ed25519SoftwareSigner`, `MlDsa65SoftwareSigner`,
`PqcSigner`, `HardwareSigner`, none with "steward" in the name).

The Verify v2.4.0 vocabulary now matches what v1.4.0 (#51) +
v1.5.0 (Phase H) baked into persist's internals:

| Term | Meaning |
|---|---|
| **steward** | bootstrap-trusted root identity (Verify's `bootstrap_stewards.json` entries — the registry's anchor pubkeys that seed federation trust) |
| **local** | a deployment's own per-process signing identity (persist's `LocalSigner`, edge's signer, agent's signer) |

Tests: 368 lib pass (unchanged; pin-bump only).

## [1.5.1] — 2026-05-17

**SQLite parity sweep — 100% no-panic across the PyO3 surface.**

Completes the v1.0.0-scaffold port that v1.4.0 (#52) started for 9
federation methods. Every remaining `backend_postgres_unwrap()` call
site in `src/ffi/pyo3.rs` — 55 of them across attestation, revocation,
PQC-fill, outbound queue, detection events, calibration bundles, lens
reads, ratchet, scrub stats, scoring aggregates, audit chain, and trace
verification — now dispatches cleanly to `match &self.backend { Postgres
=> ..., Sqlite => ... }`. The helper itself is deleted.

This is the parity bar CIRISAgent's SQLite-first deployments need
before adopting v1.5.x. No more process panics on non-federation Engine
calls.

### What ported

53 methods to `SqliteBackend` trait dispatch (impls already existed in
`src/store/sqlite.rs`):
- Attestation / revocation surface: `put_attestation`, `list_attestations_for`,
  `list_attestations_by`, `put_revocation`, `revocations_for`, all three
  `attach_*_pqc_signature` variants, `list_attestations`, `list_revocations`,
  `run_pqc_sweep`
- Outbound queue: `enqueue_outbound`, `claim_pending_outbound`,
  `mark_transport_delivered`, `mark_transport_failed`, `mark_replay_resolved`,
  `match_ack_to_outbound`, `mark_ack_received`, `sweep_ack_timeouts`,
  `sweep_ttl_expired`, `sweep_expired_claims`, `outbound_status`,
  `list_outbound`, `cancel_outbound`, `replay_abandoned`
- Detection + calibration: `put_detection_event`, `get_detection_events`,
  `put_calibration_bundle`, `get_current_calibration_bundle`,
  `get_calibration_bundle_by_version`
- Lens reads + ratchet: `list_trace_summaries`, `get_trace_summary`,
  `get_trace_detail`, `list_tasks`, `list_llm_calls`, `aggregate_llm_costs`,
  `corpus_shape`, `aggregate_scrub_stats`, `cross_agent_divergence`,
  `temporal_drift`, `hash_chain_gaps`, `conscience_override_rates`,
  `aggregate_scoring_factors`, `aggregate_scoring_factors_batch`,
  `count_traces`, `count_overrides`, `count_identity_changes`,
  `aggregate_audit_chain`
- Trace verification + ingest: `receive_and_persist`,
  `delete_traces_for_agent`, `fetch_trace_events_page`, `verify_trace`,
  `verify_hybrid_via_directory`

These lens-read + ratchet methods were originally flagged as PG-only per
v0.5.0 FSD, but `SqliteBackend` already returns `Error::NotImplemented`
inside each trait impl — so dispatch through the trait surfaces the
right typed error via `read_err_to_py`. SQLite callers get a clean
4xx/5xx instead of a panic.

2 methods truly PG-only (inherent methods on PostgresBackend, no trait):
- `get_features` (extract pipeline read) — SQLite arm returns
  `PyRuntimeError("get_features: pipeline-read primitives are
  Postgres-only (v0.6.0 FSD); SQLite backends should query their PG
  counterpart for observability or wait for the sovereign-mode v0.6.x
  track")`
- `get_classifications` (classify pipeline read) — same shape

### Structural support

Two helpers refactored to take generic `Backend + Send + Sync + 'static`
trait bounds so a single primitive powers both arms:

- `run_pqc_sweep_inner` + its `sweep_keys` / `sweep_attestations` /
  `sweep_revocations` helpers (`src/ffi/pyo3.rs:~7990-8100`) — generic
  over `FederationDirectory`
- `TraceKeyDirectory` (`src/ffi/pyo3.rs:~8420`) — generic over
  `crate::store::Backend`; `verify_trace` constructs it per-arm

### What's gone

- `backend_postgres_unwrap()` helper itself (definition + doc comments)
- The `#[allow(dead_code)]` on `BackendDispatch::Sqlite` (every arm now read)
- The v1.0.0-scaffold module-header comment is rewritten to record the
  v1.5.1 completion

### Tests

`cargo test --features "postgres sqlite cirisaudit" --lib` — **368 pass**
(unchanged vs v1.5.0; the parity sweep is pure dispatch port, no
behavior change). Diff: `src/ffi/pyo3.rs` +1665 / −761 (one file).

### Impact

CIRISAgent's SQLite-first deployments can call any Engine PyO3 method
without process crashes. Where SQLite genuinely doesn't have an impl
(lens reads / ratchet / extract / classify pipeline), the caller gets a
typed Python error they can catch and handle. The substrate-level
"trust grant + Merkle transparency" surface from v1.5.0 was already
100% parity'd; this release closes the remaining surface.

## [1.5.0] — 2026-05-16

**The federation trust substrate — trust grants as signed events with per-tenant Merkle transparency.**

The substantive substrate cut spec'd in `FSD/FEDERATION_TRUST_INTERFACE.md`.
Trust grants become signed Contribution events that ride the audit chain;
every audit entry on every backend also appends a leaf to a per-tenant
Merkle tree and gets a freshly-signed STH (RFC 6962, Sigstore Rekor every-
append cadence). External verifiers can confirm any grant via inclusion
proof + STH signature without trusting the directory's projection.
Anchored on the SOTA upgrade in CIRISVerify v2.3.0
([CIRISVerify#23](https://github.com/CIRISAI/CIRISVerify/issues/23)).

### Architecture

- **Transparency primitives live in CIRISVerify** (`ciris-verify-core::transparency`).
  Persist consumes; edge consumes; no parallel Merkle implementations.
  `TransparencyLeaf` trait, `TransparencyStore<L>` trait, `SignedTreeHead`,
  `MerkleProof`, `ConsistencyProof`, `TransparencyLog<L>`, `verify_inclusion`,
  `verify_consistency` all imported. Persist contributes `AuditLeaf:
  TransparencyLeaf` + `PgMerkleStore` / `SqliteMerkleStore` adapters that
  expose the sync trait over async pools via `tokio` block_on +
  spawn_blocking.
- **Hash chain remains the source of truth** per FSD §4.4. Merkle tree
  is a projection over the existing per-tenant `cirislens.audit_log`;
  failures in the Merkle hook or trust-grant projection surface as
  typed errors (`Error::Merkle`, `Error::TrustGrant`) but the chain
  row stands. Phase I backfill reconciles orphans.
- **Per-tenant scoping** end-to-end. One Merkle tree per tenant
  (`log_id = "tenant:<id>"` per the Phase B prefix scheme).
  Cross-tenant correlation impossible at every layer.

### New schema (V021 — applied additively; V020 columns deprecated, dropped in v1.6.0)

- `cirislens.federation_trust_grants` — projection table for trust grant
  events. `UNIQUE (grantee_key, granter_key, purpose, scope)` global
  (federation_keys.key_id is globally unique; grant identity is the
  relationship + purpose + scope). UPSERT-on-conflict for re-issuance;
  revocation = re-issuance with `expires_at <= NOW()` sets `revoked_at` +
  `revoked_by`.
- `merkle_leaves(tenant_id, leaf_index, chain_event_id, leaf_hash,
  canonical_bytes, leaf_serialized, appended_at)` — one row per audit
  chain entry. Universal — applies to ALL audit entries, not just trust
  grants.
- `merkle_sth_log(tenant_id, tree_size, root_hash, signed_at,
  signer_key_id, signature_blob, witness_signatures)` — STH history,
  one row per leaf append per FSD §4.4 every-append cadence. Hybrid sig
  (Ed25519 + ML-DSA-65) stored as full tagged JSON blob (preserves
  algorithm/public_key/mode/crypto_kind fields). `witness_signatures`
  reserved for forthcoming witness-cosigning protocol.

### New Engine PyO3 surface (9 methods)

Emit:
- `grant_trust(tenant, grantee, purpose, scope, expires_at, rationale)`
  → JSON `TrustGrantReceipt` with canonical `grant_id` + post-emit STH
- `revoke_trust_grant(tenant, grantee, purpose, scope)` → same receipt
  shape (revocation = re-emit with `expires_at = now()`)

Read:
- `lookup_trust_grant(grantee, purpose, scope)` — exact + wildcard
  scope both surface (caller decides; FSD §3.3)
- `list_trust_grants(filter_json)` — dynamic filter
- `get_trust_grant(grant_id)` — by canonical PK
- `current_sth(tenant)` — latest signed tree head

Proof:
- `trust_grant_inclusion_proof(grant_id)` → `TrustGrantInclusionProof
  { sth, merkle_proof, leaf_canonical_bytes }`. External verifier:
  verify STH signature → check freshness → recompute leaf_hash via
  `sha256(0x00 || canonical)` (RFC 6962 byte prefix) → walk siblings →
  assert reconstructed root == STH root.
- `trust_grant_consistency_proof(tenant, old_size, new_size)` →
  RFC 6962 §2.1.2 ConsistencyProof. Verifier confirms STH(n) → STH(m)
  is a legal append.

Migration:
- `backfill_v020_trust_rows(tenant_id)` → JSON `BackfillReport`. One-shot
  V020 → V021 migration. Scope-limited to rows where `trusted_by`
  matches the local signer (only the granter can re-emit per FSD §3.1).
  Idempotent — re-running is a no-op for already-projected rows.

### TrustPurpose enum

`Technical | Deferral | Contribution | Service` (FSD §3.3 scope grammars).
The Service variant landed via the NodeCore MESSAGE_TAXONOMY 871ebab
coordination — gates access to advertised peer LLM/embedding/tool
services. Per-invocation RPC rides edge transport; chain records
service_announcement / service_deprecation / service_usage_summary.

### Breaking changes (clean break, no aliases)

**Internal type rename — finished the v1.4.0 (#51) deferred work:**
- `StewardSigner` → `LocalSigner`
- `StewardSignerConfig` → `LocalSignerConfig`
- `StewardSignerError` → `LocalSignerError`
- `steward_signer_err_to_py` → `local_signer_err_to_py`
- `EngineInner.steward_signer` field → `local_signer`

The public PyO3 surface was already renamed in v1.4.0. This finishes the
internals consistently, matching the [CIRISVerify v2.3.0 pattern]
(https://github.com/CIRISAI/CIRISVerify/commit/1a8110c) — rename
everywhere at once, no transitional aliases. Federation role-tag
concepts (the `STEWARD` const in `src/federation/types.rs`, the
`STEWARD_KEY_ID` in `src/server/secrets.rs`, RATCHET federation_keys
steward references) are UNCHANGED — they're semantically distinct from
the per-process signing identity.

### New trait surface

`AuditService` (the chain-write trait) grows 9 new methods (all default
to `Error::NotImplemented`; PG + SQLite override):
- `next_chain_position(tenant)` — probe-the-tail helper for emit-side
  callers (Phase E)
- `current_sth(tenant)` — read post-emit STH
- `lookup_grant_id_by_chain_event(chain_event_id)` — canonical PK
  lookup
- `get_trust_grant(grant_id)` / `lookup_trust_grant(...)` /
  `list_trust_grants(filter)`
- `leaf_canonical_bytes_for_chain_event(tenant, chain_event_id)` —
  inclusion-proof support
- `inclusion_proof_for_chain_event(tenant, chain_event_id)` —
  RFC 6962 §2.1.1
- `consistency_proof(tenant, old_size, new_size)` — RFC 6962 §2.1.2
- `read_v020_trust_rows_for_local(local_pubkey)` — backfill enumerator

`PostgresBackend` + `SqliteBackend` gain a `merkle_signer` slot
(`RwLock<Option<Arc<LocalSigner>>>`) and a `set_merkle_signer` setter.
Engine constructor auto-wires its `local_signer` into both arms — no
Python-side configuration; setting `local_key_id` + `local_key_path` is
sufficient to activate the Merkle hook.

### Threat model coverage (FSD §4.4)

| Threat | Mitigation |
|---|---|
| Log fork / split-view | STH + reserved witness cosigning |
| Retroactive insertion | ConsistencyProof per RFC 6962 |
| Selective omission | InclusionProof against signed root |
| Stale STH acceptance | STH timestamp; verifier-side freshness policy |
| Cross-tenant correlation breach | Per-tenant trees (no global root) |
| Cross-subsystem proof collision | RFC 6962 byte prefixes (0x00/0x01) |
| Quantum break on signing | Hybrid Ed25519 + ML-DSA-65 STH |
| Quantum break on tree | SHA-256 PQ-resistant |

### Atomicity

Order in `record_entry`: (1) chain commit with AV-49 integrity FIRST;
(2) Merkle hook (signer-gated) SECOND; (3) projection (subject_kind-
gated) THIRD. Merkle / projection failures surface as typed errors but
the chain row stands — the audit chain is the source of truth, Merkle
+ projection are downstream projections. Phase I backfill reconciles
orphans.

### Tests

`cargo test --features "postgres sqlite cirisaudit" --lib` —
**368 passed** (was 274 at v1.3.3). 2 pre-existing PG-gated audit
test failures unchanged (V020 `audit_log_action_type_check`).

### Implementation phases

| Phase | Commit | What |
|---|---|---|
| A | `bf075c2` | V021 migration + TrustPurpose + TrustGrantPayload + AuditLeaf |
| B | `35f3953` | PgMerkleStore + SqliteMerkleStore (TransparencyStore<AuditLeaf>) |
| C | `93841cc` | Audit-service Merkle hook (universal — every chain entry) |
| D | `cb93e00` | TrustGrant projection materialization |
| E | `7a2fbb1` | grant_trust / revoke_trust_grant emit API |
| F+G | `20b5071` | Read + proof retrieval APIs |
| H | `f41f191` | PyO3 wrappers + internal StewardSigner→LocalSigner rename |
| I | `fc50769` | V020 → V021 backfill |

### Cross-references

- **FSD:** [`FSD/FEDERATION_TRUST_INTERFACE.md`](FSD/FEDERATION_TRUST_INTERFACE.md)
- **Upstream:** CIRISVerify v2.3.0 (SOTA transparency upgrade);
  CIRISNodeCore 871ebab (15 new subject_kinds incl. trust_grant +
  MESSAGE_TAXONOMY)
- **Tracking:** [CIRISPersist#53](https://github.com/CIRISAI/CIRISPersist/issues/53)

## [1.4.0] — 2026-05-16

**Interim cut before v1.5.0 substrate work — SQLite federation parity + clean-break API rename + audit-bridge doc fix.**

This release closes the two open Lane C blockers downstream of v1.3.x
(CIRISPersist#52 SQLite federation panic, CIRISPersist#51 steward
naming leakage) and lands a small doc correction. v1.5.0 (the
purpose-scoped trust-grants-as-signed-events substrate per
`FSD/FEDERATION_TRUST_INTERFACE.md`) builds on this surface.

### Surface changes (breaking — see migration notes)

- **Engine PyO3 method rename (clean break, old names removed):**
  - `steward_sign` → `local_sign`
  - `steward_pqc_sign` → `local_pqc_sign`
  - `steward_key_id` → `local_key_id`
  - `steward_pqc_key_id` → `local_pqc_key_id`
  - `steward_public_key_b64` → `local_public_key_b64`
  - `steward_pqc_public_key_b64` → `local_pqc_public_key_b64`
- **Engine constructor kwarg rename (clean break, old kwargs removed):**
  - `steward_key_id` → `local_key_id`
  - `steward_key_path` → `local_key_path`
  - `steward_pqc_key_id` → `local_pqc_key_id`
  - `steward_pqc_key_path` → `local_pqc_key_path`

**Why:** "Steward" was a federation directory role tag (the registry
bootstrap anchor). The Engine's signing methods refer to *this
process's local signing key*, which is role-orthogonal — every CIRIS
agent (whether `client`, `proxy`, or `server` role) has a local
signer. The old names leaked the role concept into a process-local API
that doesn't need it. Clean break, no deprecation aliases — callers
update import names in lockstep.

**Migration:** sed-replace `steward_` → `local_` on Engine method
calls and constructor kwargs. Internal types (`StewardSigner` struct,
`steward_signer` field) are unchanged; renaming those is deferred to
2.0.0.

### SQLite parity for federation surface (closes #52)

The 9 federation-related PyO3 methods that previously panicked on
SQLite backends are now fully dispatched:

| Method | Backend trait used |
|---|---|
| `register_public_key` | Raw SQL (dialect-aware: `cirislens.accord_public_keys` on PG, unqualified on SQLite) |
| `put_public_key` | `FederationDirectory::put_public_key` |
| `lookup_public_key` | `FederationDirectory::lookup_public_key` |
| `lookup_keys_for_identity` | `FederationDirectory::lookup_keys_for_identity` |
| `federation_grant_trust` | `FederationDirectory::grant_trust` |
| `federation_revoke_trust` | `FederationDirectory::revoke_trust` |
| `federation_lookup_trust` | `FederationDirectory::lookup_trust` |
| `federation_list_trusted_keys` | `FederationDirectory::list_trusted_keys` |
| `list_federation_keys` | `ReadEngine::list_federation_keys` |

Each site now does `match &self.backend { Postgres(pg) => ..., Sqlite(sq) => ... }` dispatch (mirroring the v1.0.0 substrate-method port). All trait impls existed on `SqliteBackend` already; the gap was purely in the PyO3 wrapper's `backend_postgres_unwrap()` panic helper. Trait disambiguation (`Backend::lookup_public_key` vs `FederationDirectory::lookup_public_key`) handled via fully-qualified syntax.

**Impact on CIRISAgent 2.9.0:** unblocks Lane C (federation/auth absorption — CIRISAgent#765) in its entirety. SQLite-first deployments can now register agent pubkeys, look up federation peers, and use the trust hierarchy without panic-then-skip.

**Out of scope for this cut:** 65 remaining `backend_postgres_unwrap` call sites in non-federation surfaces (attestation, revocation, scrub, maintenance, etc.) — those land in subsequent SQLite parity sweeps.

### Doc fixes

- `docs/AUDIT_CHAIN_BRIDGE.md` — `engine.federation_put_public_key` → `engine.put_public_key` (the method has always been `put_public_key`; the doc string was wrong).

### Tests

`cargo test --features "postgres sqlite" --lib` — 274 passed, 0 failed. SQLite-only and Postgres-only feature combos both clean.

## [1.3.3] — 2026-05-16

**v1.3.2 CI fixup.** v1.3.2 tag build failed in the wheel jobs at
the FFI layer — `cirisgraph_err_to_py` legacy bridge function (used
by pre-v1.0.0 `translate_error_kind` consumers; still present for
back-compat) had a non-exhaustive `match e { … }` against
`graph::Error` and didn't cover the new `AttributesTooLarge` variant
added in v1.3.2. Local feature-set used during dev (`pyo3 sqlite
cirisgraph`) compiled clean; CI's wheel feature combo surfaced the
match.

Fix: add `crate::graph::Error::AttributesTooLarge { .. }` to the
caller-fault arm alongside `InvalidArgument` / `NotAuthorized` /
`Conflict` / `NotFound`. Maps to `PyValueError` (caller-fault),
matching the typed-exception kind already in v1.0.0's
`translate_error_kind` path.

No surface change. v1.3.3 is the first 1.3.x wheel of v1.3.2's
bulk_import work that publishes to PyPI.

## [1.3.2] — 2026-05-16

**`bulk_import` mode + typed `AttributesTooLarge` (closes #50).**
Follow-up to v1.3.1 #49 surfaced by CIRISAgent's datum-cutover migration:
1 of 989 legacy `graph_nodes` rows was a 1.67 MiB `conversation_summary`
that the AV-45 1 MiB attributes cap rejected. The cap is a load-bearing
safety check for steady-state writes, but bulk historical migration
needs an escape hatch.

### Surface changes

- **New `bulk_import: bool` parameter** on `GraphService::upsert_node`
  and `GraphService::upsert_edge`. `true` skips the AV-45 cap. Default
  `false` preserves existing semantics for hot-path writes.
- **New `Error::AttributesTooLarge { bytes, cap }` variant** with
  stable `kind = "cirisgraph_attributes_too_large"`. Replaces the
  opaque `Error::InvalidArgument("attributes too large: …")` string
  callers had to grep for. PyO3 surfaces this via the typed-exception
  hierarchy (`Permanent` class for migration-side handling).
- **PyO3 `cirisgraph_upsert_node` / `cirisgraph_upsert_edge`** now
  take an optional `bulk_import` kwarg (default `False`).

### What's NOT in this cut

- **Per-node-type caps** (ask #2 from #50): bigger config surface
  (per-type registry + env override per type). Deferred. The
  `bulk_import` flag covers the migration case; if steady-state
  conversation_summary writes are also legitimately oversize, file a
  follow-up.

### Backward compatibility

The trait signature change is breaking for direct Rust consumers
holding `dyn GraphService` (which doesn't compile anyway — RPITIT
isn't object-safe) or composing the trait in tests. PyO3 callers
on v1.3.1 keep working — `bulk_import` defaults to `False` matching
prior behavior.

Callers grepping for `"attributes too large"` in `InvalidArgument`
strings need to update to match on the new typed `AttributesTooLarge`
variant OR check `err.kind() == "cirisgraph_attributes_too_large"`.
The string form is gone.

### Tests

Three new SQLite tests:
- `upsert_node_bulk_import_skips_attribute_cap` — 1.5 MiB blob: rejected
  with typed `AttributesTooLarge` when `bulk_import=false`; lands when
  `bulk_import=true`.
- Existing `cirisgraph_sqlite_round_trip_full_lifecycle` + PG analog
  updated to assert the new typed variant.

CIRISAgent's `tools/ops/migrate_to_persist.py` can drop the
oversize-row workaround now and pass `bulk_import=True` for migration
writes.

## [1.3.1] — 2026-05-16

**CIRISAgent 2.9.0 cutover support cut.** Two upstream asks from
[CIRISAgent#763](https://github.com/CIRISAI/CIRISAgent/issues/763)
Lane A bundled into one release: documentation for the audit-chain
bridge mechanism + Lane C federation identity registration, plus the
[#49](https://github.com/CIRISAI/CIRISPersist/issues/49) timestamp
preservation fix on `cirisgraph_upsert_node` / `cirisgraph_upsert_edge`.

### `docs/AUDIT_CHAIN_BRIDGE.md` (NEW)

Operational documentation covering bridge-entry mechanism for rooting
a new `cirisaudit` chain on top of an existing chain, `tenant_id`
semantics (opaque, caller-defined, stable; don't change mid-chain),
`signing_key_id` registration flow (one-time `federation_put_public_key`
at boot; idempotent), 2.9.0 first-boot flow pseudo-code, trust
hierarchy registration call shapes for Lane C C3.

Unblocks **CIRISAgent#763 A0b** (audit chain re-root) and **Lane C**
(federation verify + steward signing wiring).

### `#49` timestamp preservation

`cirisgraph_upsert_node` and `cirisgraph_upsert_edge` previously
stamped `chrono::Utc::now()` / SQL `NOW()` on every write, ignoring
the caller-supplied `updated_at` / `created_at` fields on `GraphNode`
and `GraphEdge`. Required-but-ignored.

Fix:
- `src/graph/postgres.rs::upsert_node` — INSERT VALUES now binds
  `node.updated_at` and `node.created_at`; ON CONFLICT UPDATE uses
  `EXCLUDED.updated_at`.
- `src/graph/sqlite.rs::upsert_node` — same: `fmt_datetime(node.
  updated_at)` and `fmt_datetime(node.created_at)` passed through.
- Same fix on `upsert_edge` (both backends).

Two regression tests in `src/graph/sqlite.rs::tests` reproducing the
#49 body's historical-import scenario.

Closes **CIRISPersist#49**. Unblocks **CIRISAgent#763 A0a** — the
agent can use the typed `engine.cirisgraph_upsert_node()` API for
bulk migration instead of bypassing to direct sqlite3 INSERT.

### What's NOT in this cut

- **PyO3 GIL boundary perf baseline** (low-priority ask) — deferred.
  CIRISAgent Memory Benchmark scenario during Lane A integration
  tests will surface any hot-path regression empirically.

## [1.3.0] — 2026-05-15

**M2 cut: trust hierarchy absorption + role-tag enforcement
(closes #46 + #47).** Persist absorbs `CIRISNodeCore`'s `crate::trust`
module surface — the 5 shapes (`TrustType`, `TrustRelationship`,
`TrustGrant`, `TrustRow`, `TrustFilter`) and the 4 trait methods
(`grant_trust`, `revoke_trust`, `lookup_trust`, `list_trusted_keys`)
land on the existing `FederationDirectory` trait. NodeCore's local
placeholder trait in `src/trust.rs` becomes
`pub use ciris_persist::federation::FederationDirectory` (or the
convenience alias under `ciris_persist::cirisnode::`). Per-row role
tags on `federation_keys` ship in the same migration to enforce
pipeline + secrets writer/reader/admin tiers (CIRISPersist#46 — the
deliverable that v1.1.0 deferred). #45 already shipped in 1.1.2 and
is unchanged.

### V020 migration — single cut for both dialects

- **`federation_keys` trust hierarchy columns**: `consent_role`
  (CIRISAgent#760 §RC, flat enum), `trust_type`, `trust_relationship`,
  `trust_domains`, `trusted_at`, `trusted_by`, `expires_at`. PG ships
  CHECK constraints (`federation_keys_no_self_trust`,
  `federation_keys_registry_requires_domains`) NOT VALID so legacy
  rows skip validation; SQLite enforces both at the API surface
  (`FederationDirectory::grant_trust` /
  `crate::store::memory::validate_trust_grant`) since `ALTER TABLE
  ADD CHECK` isn't supported.
- **`federation_keys.roles` TEXT[] (PG) / TEXT JSON-array (SQLite)**
  for the CIRISPersist#46 role-tag deliverable. `KeyRecord` gains a
  `roles: Vec<String>` field with `#[serde(default)]` so v1.2.x wire
  shapes deserialize unchanged.
- **`edge_detection_events` table** for LensCore's
  `UnconsentedExternalProbe` / `ExcessiveRecursion` /
  `ConsentGateLeak` detector signals. FK to `federation_keys(key_id)`
  + standard CIRISPersist audit envelope.
- **`audit_log` CHECK vocabulary extension** adds `trust_granted` +
  `trust_revoked` to the V018 vocabulary (CIRISAgent#756 Q4 verdict
  — state transitions live in the audit chain). Folded into V020 on
  the PG side; SQLite stays convention-only per the V018 deferral
  note.

### New trait surface

- `FederationDirectory::grant_trust(grant)` — UPSERT semantics on
  `federation_keys.key_id`, preserves pubkey + signature envelope
  from prior `put_public_key`. Self-trust + Registry-without-domains
  rejected at the API boundary with `Error::InvalidArgument`.
- `FederationDirectory::revoke_trust(key, revoked_by)` — sets
  `expires_at = NOW()`. Idempotent.
- `FederationDirectory::lookup_trust(key)` — raw row, no transitive
  resolution. NodeCore composes `resolve_trust` on top.
- `FederationDirectory::list_trusted_keys(filter)` — relationship +
  domain + type AND-filtered; expired rows excluded unless
  `include_expired=true`.
- `KeyRecord.roles: Vec<String>` (additive field, serde-default).
- `AuditEventType::TrustGranted` / `TrustRevoked` (new variants).

### Role-tag enforcement (CIRISPersist#46)

- **Pipeline ingest** (`POST /api/v1/pipeline/ingest`): after edge
  signature verifies, fetches the edge's `KeyRecord` and requires
  `cirislens_pipeline_writer` OR `cirislens_secrets_writer` in the
  roles list. Rejects with 403 + kind `pipeline_invariant_role_tag`.
- **Secrets routes** (`src/server/secrets.rs`): per-route reader /
  writer / admin tier enforcement via `verify_and_authorize`. Read
  routes (list / retrieve / filter_config / stats / access_logs)
  accept `cirislens_secrets_reader` and higher; mutating routes
  (store / try_claim / recall / encrypt / decrypt / put_filter_config
  / reencrypt_all / forget) require `cirislens_secrets_writer` or
  higher; `rotate_master_key` requires `cirislens_secrets_admin`.
  Rejects with 403 + kind `secrets_role_tag`.

### PyO3 surface

Four new `Engine` methods on the backend-dispatch surface:
`federation_grant_trust(grant_json)`,
`federation_revoke_trust(key, revoked_by)`,
`federation_lookup_trust(key) → Option[str]`,
`federation_list_trusted_keys(filter_json) → str`. JSON in/out for
complex types; primitive types as `&str` args. Errors flow through
the existing `federation_err_to_py` shape (kind tokens
`federation_invalid_argument` → `Permanent`, etc.).

### Convenience re-export

`ciris_persist::cirisnode` module gains a `pub use crate::federation`
re-export bundle (`FederationDirectory`, `TrustGrant`, `TrustRow`,
`TrustFilter`, `TrustType`, `TrustRelationship`) so NodeCore can
import via either the canonical `ciris_persist::federation::*` path
or the sibling-pattern `ciris_persist::cirisnode::*` path that
matches its existing `NodeCoreService` import shape.

### Audit chain integration

`grant_trust` and `revoke_trust` do NOT auto-write audit chain
entries — the chain is self-signed (AV-49) and requires the caller's
Ed25519 key, which persist doesn't hold. Callers compose the pair:
write the trust row via this trait, then write an `AuditEntry` with
`action_type='trust_granted'` (or `trust_revoked`) via
`AuditService::record_entry` / `try_claim_event`. The V020 CHECK
extension + `AuditEventType` enum variants are the vocabulary
contract; the actual sign-and-write stays at the caller.

### Tests added

8 new tests on the SQLite arm + 3 on the Postgres arm covering the
seven M1-validated shapes (round-trip, self-trust reject,
Registry-without-domains reject, revoke idempotent, relationship
filter, include_expired filter, audit vocab round-trip) plus the
edge_detection_events smoke test and a roles-column round-trip
smoke test. `tests/qa_harness.rs` schema_history expectation bumped
19 → 20 to match V020.

### Migrations

- `migrations/postgres/lens/V020__federation_keys_trust_hierarchy.sql`
- `migrations/sqlite/lens/V020__federation_keys_trust_hierarchy.sql`

### Constraints honored

- `FederationDirectory` existing trait methods UNCHANGED. Trust
  methods are additive.
- `KeyRecord` wire shape preserved — the new `roles` field has
  `#[serde(default)]` so v1.2.x writers/readers stay compatible.
- No new dependencies. Trust types compose from chrono + serde +
  the existing federation error tree.
- NodeCore's `src/trust.rs` contract mirrored exactly. Zero
  deviation from the trait + 5 supporting type shapes.

## [1.2.1] — 2026-05-15

**v1.2.0 PG integration test fix.** v1.2.0 tag CI hit two PG-side
failures in the new maintenance test fixtures + impl:

1. **Test fixture**: bound `&"{}"` to a `jsonb` column. Even with
   `$5::jsonb` SQL cast, tokio-postgres rejects `&str → jsonb` because
   param-type negotiation runs before SQL casts. Fixed by binding via
   `serde_json::json!({})`.
2. **Impl**: `make_interval(secs => $1)` with an `i64` bind. PG's
   `secs` parameter is `double precision`, not `bigint`; binding i64
   raises `WrongType { postgres: Float8, rust: "i64" }`. Fixed by
   changing `fixed_seconds` return type i64 → f64 across all four
   call sites (telemetry-custom, secrets, incidents, federation).

Both surfaced only on the CIRISVerify v2.1.x CI matrix (the live PG
test path) — local SQLite + no-DB integration paths didn't trip them.

No surface change. v1.2.1 is the first 1.2.x wheel that reaches PyPI.

## [1.2.0] — 2026-05-15

**Maintenance ops absorbed + DatabaseMaintenance reclassification (closes #48).**
Agent's `DatabaseMaintenanceService` splits like `AuthenticationService` +
`AdaptiveFilterService` did before it: **operations** (VACUUM, archive expired,
prune audit chain, consolidate periods, rotate master keys) move to persist;
**scheduling** (when/how often) stays at agent's `TaskSchedulerService`. The
agent-side service disappears as a separate concern; it collapses into
TaskScheduler invoking `engine.maintain()`.

### New surface

- **`MaintenanceService` trait** in `src/maintenance/service.rs` with 4
  methods: `vacuum_substrate`, `archive_expired(ArchiveWindow)`,
  `prune_audit_chain(tenant, before)`, `maintain()` umbrella.
- **`Engine::maintenance()` accessor** + new `EngineMaintenance { Postgres |
  Sqlite }` enum (trait isn't object-safe — same dispatch shape as the
  existing `BackendDispatch`).
- **PyEngine methods**: `maintenance_vacuum()`, `maintenance_archive_expired(
  window=None)`, `maintenance_prune_audit_chain(tenant, before)`,
  `maintain()`. JSON-encoded report returns. `maintenance_backend` →
  `Transient` exception class.

### Substrate retention defaults

| Module | Column | Default | Notes |
|---|---|---|---|
| telemetry raw observations | `expires_at` | substrate-defined per row (V015 TTL) | producer sets; archive deletes physically |
| secrets access_log | `created_at` | 30 days | |
| incidents (closed) | `last_seen_at` | 90 days | V016 has no `updated_at`; `last_seen_at` is the resolution timestamp |
| federation_keys (expired) | `valid_until` | 180 days | persists revocations live in `federation_revocations`; `valid_until` is the operational expiry analog. Per-module key: `federation_keys_expired` |

### Postgres VACUUM behavior

VACUUM cannot run inside a transaction. The impl uses
`client.batch_execute("VACUUM ANALYZE")` on a deadpool-checked-out
transaction-free client. Documented in `src/maintenance/postgres.rs`.

### SQLite datetime gotcha

Rows in V010/V015/V016 mix RFC 3339 (`T` separator, microsecond
precision) and SQLite-default (`YYYY-MM-DD HH:MM:SS` space separator).
Direct string `<` comparison is lexicographically wrong across the two
shapes (space < `T`). All comparisons use `julianday(col) < julianday(
'now', ?)` to parse both formats and produce a numeric scalar.

### `prune_audit_chain` stub

Returns `PruneReport { entries_removed: 0, new_anchor_id: None }` on
both backends. Real semantics depend on **CIRISAgent#760** Counter-RII
review-window guidance — how long the chain must stay re-derivable
for steward review determines the pruning policy. Implementation
deferred to the v1.2.x → v1.3.x range once #760 resolves.

### Tests

+9 tests: 5 SQLite in-memory + 4 PG (gated on `CIRIS_PERSIST_TEST_PG_URL`)
+ 1 stable-kind()-tokens unit. Lib suite: 301/301 passing locally.

### Post-fold service count (locked)

| Bucket | Count |
|---|---|
| Persist substrate (direct + prelude + this) | **10 of 22** |
| LensCore-owned (Audit, persist hosts substrate) | 1 of 22 |
| Edge-owned (transit-touch) | 2 of 22 |
| Stays at agent | 10 of 22 (DatabaseMaintenance folded into TaskScheduler) |

## [1.1.2] — 2026-05-15

**Hardening cut: ReasoningEventType forward-compat + verify 2.1.5 +
CI hardening playbook.**

### `ReasoningEventType::Unknown` (closes #45)

`#[serde(other)] Unknown` variant on `ReasoningEventType`. Closes the
second half of CIRISLens#13 — the 48h prod outage where agents
emitted `parent_event_type="UNKNOWN_PARENT"` (an internal fallback,
not a TRACE_WIRE_FORMAT §4 variant) and persist rejected via
`Error::Json(_)` → `schema_malformed_json` → infinite agent retries.

- `src/schema/events.rs` — add `#[serde(other)] Unknown` variant.
  `as_str()` returns `"UNKNOWN"`; `from_wire_str("UNKNOWN")` returns
  Some(Unknown). Mirrors the `ComponentType::Unknown` shape that
  shipped in v0.1.x.
- `src/store/decompose.rs` — exhaustive match arm: `Unknown` maps to
  `ComponentType::Unknown` so the row→struct path stays defined.
- Regression test asserts `serde_json::from_str("UNKNOWN_PARENT")`,
  `"SOME_FUTURE_VALUE"`, etc. all parse to `Unknown` instead of
  erroring. AV-15 safe: catchall echoes no attacker-controlled
  bytes; serializes back as the constant `"UNKNOWN"`.

v1.1.1's `Error::Json::detail()` fix (#44) surfaced the failures;
v1.1.2's `serde(other)` prevents them entirely. Pair complete.

### CIRISVerify pin bump 2.0.5 → 2.1.5

- `Cargo.toml` — `ciris-verify-core` git tag bumped to `v2.1.5`.
  The 2.1.x series is CIRISVerify's CI hardening arc; library
  surface unchanged from 2.0.5.
- `pyproject.toml` — `ciris-verify>=2.1.5,<3`.
- `.github/workflows/ci.yml` — `ciris-build-sign` tarball download
  bumped to `v2.1.5` (matches Rust git-pin floor).

### CI hardening playbook (from CIRISVerify v2.1.x arc)

- **`gh release download` retry** on the `ciris-build-sign` tarball
  fetch (3 attempts with backoff). Absorbs GitHub API transient 5xx
  / network blips.
- **`pip install` retry** on the three pip-install sites (maturin +
  pytest + venv-scoped). Same 3-attempt-with-backoff shape against
  PyPI blips.
- **`continue-on-error: true`** on every `Swatinem/rust-cache@v2`
  use site (4 sites: linux test, macos test, ios build, lint).
  Cache miss / corruption shouldn't fail the whole job — recompile
  from scratch is slower but correct.
- **Existing**: `cache-bin: false` on macOS already in place from
  v0.7.2 (the macOS x86_64 shim shadow fix). v2.1.4-style active
  heal not needed because we never hit the shadow on persist's
  macos-14 runners.

No `shell: bash` overrides needed — persist's matrix is Linux + macOS
+ iOS cross-compile only, no Windows runners (the v2.1.5 pwsh fix
target).

No surface change. v1.1.2 is a hardening cut on top of v1.1.1's
substrate.

## [1.1.1] — 2026-05-15

**v1.1.0 with no-features compile fix.** v1.1.0 tag CI failed at
`cargo test --test wire_format_fixtures` (no-features integration test
target). `src/engine.rs:69` imported `crate::store::Backend`
unconditionally, but the trait is only reachable + used when one of
the `postgres` / `sqlite` features is on. Under no-features, the
import was unused → `-D warnings` rejected the build.

- `src/engine.rs` — feature-gate the `Backend` import on
  `any(feature = "postgres", feature = "sqlite")`. `StoreError` import
  stays unconditional (used by `EngineError` variant regardless of
  backend).

No surface change. v1.1.0 is the substantive cut; v1.1.1 is the first
wheel of the 1.1.x series that publishes to PyPI.

## [1.1.0] — 2026-05-14

**Edge wire-transport substrate complete + Pipeline polymorphic.** v1.0.x
shipped the agent-adoption substrate; v1.1.0 ships the federation
wire-transport substrate. The combined surface unblocks CIRISEdge
v0.2.0 (polymorphic `pipeline.run(envelope)` regardless of message
type) + CIRISLensCore#7 (`init_edge_runtime` PyO3 fn) + sovereign-mode
Reticulum agents (Engine + substrate constructors without PyEngine).

### Path A: polymorphic Pipeline (closes CIRISPersist#33 parts 1-2)

`Pipeline` + `Stage` are now generic over a new `WireEnvelope` trait.
`BatchEnvelope` impls it (one body per component); new
`InlineTextEnvelope` impls it (single body) for SPEAK / LLM-prompt /
WBD / DSAR flows.

- `src/pipeline/wire_envelope.rs` — `WireEnvelope` trait
  (`canonical_bytes`, `text_bodies`, `mutate_body`, `body_count`,
  `scrub_level`) + `MatchAddress` enum (`BatchComponent { index,
  json_path } | InlineText { json_path }`) replacing v1.0.x's flat
  `component_index: usize` + `json_path` pair on `ContentClassMatch`.
- `src/pipeline/inline_text.rs` — new `InlineTextEnvelope` for inline
  text flows.
- `ClassifyStage`, `ScrubStage`, `EncryptAndStoreStage<S, E>` are now
  `Stage<E: WireEnvelope>` generic.
- `ExtractStage` stays `Stage<BatchEnvelope>` — `Features` projection
  is structurally trace-coupled per FSD §5.1.
- Three factories: `default_inbound_pipeline<S>` (full 4-stage on
  BatchEnvelope), `default_outbound_pipeline<E>()` (Classify + Scrub
  generic over E), `default_speak_pipeline<S>` (Classify + Scrub +
  EncryptAndStore on InlineTextEnvelope — agent responses CAN
  contain secrets to encrypt-and-store before they leave).

Wire-format note: the matcher catalog was stubbed in v1.0.x; no
production `classifications` JSONB blobs carry real matches. The
v1.1.0 `MatchAddress` shape is the canonical shape; no migration
needed.

### Substrate constructors decoupled from Engine (closes #43)

Three public APIs for sovereign-mode Reticulum + lens-core in-process
consumers who need substrate primitives without the full PyEngine:

- `Engine::with_signer(Arc<StewardSigner>, dsn)` /
  `Engine::with_signer_arcs(SigningKey, key_id, Option<Arc<dyn
  PqcSigner>>, pqc_key_id, dsn)` — new Rust-side `Engine` struct
  composing `BackendDispatch { Postgres | Sqlite }` + `Arc<
  StewardSigner>`. URL-sniff constructor mirrors PyEngine. Accessors:
  `federation_directory()`, `edge_outbound_queue()`, `signer()`.
- `FederationDirectorySqlite::open(db_path) -> Arc<SqliteBackend>` —
  standalone constructor; no Engine required.
- `EdgeOutboundQueueSqlite::open(db_path) -> Arc<SqliteBackend>` —
  same shape.

PyEngine untouched — purely additive Rust-side surface.

Trait-shape adaptation: `FederationDirectory` / `OutboundQueue` /
`Backend` use RPITIT and aren't object-safe, so the wrappers return
concrete `Arc<SqliteBackend>` (which implements all three traits).
CIRISEdge's blanket impl in `src/outbound.rs:102` handles
type-erasure on their side.

### Error::Json(_)::detail() surfaces serde_json msg (closes #44)

`schema::Error::Json(_)::detail()` now returns `Some(e.to_string())`
instead of `None`. CIRISLens#13 operator diagnostics: bridge sees
`PERSIST_DELEGATE_REJECT_DETAIL: 'missing field \`component_type\` at
line 1 column 247'` instead of `None`. AV-15 safe: serde_json's
`Display` carries field names from the Rust struct + structural
positions, not attacker-controlled content.

### POST /api/v1/pipeline/ingest route (closes #33 part 3)

Edge wire-transport ingest. Accepts a `PipelineEnvelope`, verifies the
edge_signature + inner agent signature, validates FSD §4.3
invariants, enqueues the inner BatchEnvelope with the sidecar
attached.

Six invariant kind tokens: `pipeline_invariant_schema_version`,
`_edge_signature`, `_inner_signature`, `_pii_scrubbed`,
`_classifications_count`, `_orphan_secret`. Queue API extended with
`try_submit_with_sidecar(bytes, sidecar)`.

Two v1.1.x follow-ups documented:
1. Role-tag check on `edge_key_id` (KeyRecord needs a role-list
   field; V020+ migration).
2. Persister sidecar consumption — today the sidecar is plumbed
   through + logged at debug level but the persister still re-runs
   scrub + extract on the inner envelope. Edge-signed sidecar
   consumption is the next step.

### secrets-server axum routes + FederatedSecretsClient (closes #33 part 4)

15 HTTP routes mirroring the 18-method `SecretsService` trait (3
methods stay in-process only: `process_incoming_text`,
`decapsulate_secrets_in_parameters`, `test_encryption`).

- `src/server/secrets.rs` — 13 handlers serving 15 routes (`/secrets/
  {uuid}` does GET + DELETE; `/secrets/filter_config` does GET +
  PUT). Hybrid sign-verify on inbound bodies. Three-tier role-tag
  design (`cirislens_secrets_reader` / `_writer` / `_admin`) baked
  into docs; enforcement deferred to v1.1.x with KeyRecord schema
  addition.
- `src/secrets/wire.rs` — 16 typed request/response structs +
  `SecretsErrorResponse` with stable kind() tokens. Stable across
  v1.x.
- `src/secrets/client.rs` — `FederatedSecretsClient` impls
  `SecretsService`. New `secrets-client` Cargo feature. reqwest
  rustls-tls (federation transport posture). Mock-HTTP-free tests
  using `std::net::TcpListener` + spawn_blocking.

Notable handler-shape divergences from the trait (documented per
handler):
- `GET /secrets/{uuid}` is UUID-keyed for federation addressability;
  delegates to `recall_secret(uuid, "http retrieve", accessor,
  decrypt=true)`.
- `POST /secrets/decrypt` carries ciphertext as base64 in JSON body
  (not raw binary) so the entire request fits one canonical
  sign-bundle.
- `POST /secrets/reencrypt_all` takes raw new-master-key bytes
  (base64); bytes-into-software-key-cache loading deferred.
- `GET /secrets/access_logs` filters client-side post-fetch (trait
  doesn't expose accessor/since/until filters); push-down deferred.
- `try_claim_secret` 200 + outcome-field for both `Stored` and
  `AlreadyClaimed` (no 409 — both outcomes carry in body).

### What's deferred to v1.2.0

- Role-tag enforcement on KeyRecord (needs V020+ schema addition).
- Persister sidecar consumption (today sidecar plumbed + logged but
  not consumed).
- Pipeline pyo3 wraps for `engine.pipeline().run()` from Python.
- Async-native pyo3 methods.
- Reencrypt-all bytes loading into the software-key cache.
- Access-logs filter push-down to persister query.

### Test count

v1.0.3 → v1.1.0: 339 → 270+ tests per feature combo. Full lib
suite with `secrets-server secrets-client postgres sqlite cirisgraph
cirisaudit cirisnode telemetry cirisincident classify scrub extract`:
all green.

## [1.0.3] — 2026-05-14

**v1.0.2 with Python wrapper re-export fixup.** v1.0.2 tag CI failed
the typed-exception-hierarchy smoke because the inner Rust pyo3 module
registers `PersistError` / `NotFound` / `Conflict` / `Transient` /
`Permanent`, but the Python wrapper at `python/ciris_persist/
__init__.py` only re-exported `Engine` + `LensQueryError` from the
inner module. Agent code doing `from ciris_persist import NotFound`
saw `ImportError`.

- `python/ciris_persist/__init__.py` — adds the four typed exception
  classes + base `PersistError` to both the import statement and
  `__all__`. Now `from ciris_persist import NotFound, Conflict,
  Transient, Permanent, PersistError` works as documented.

No substrate change. v1.0.0–v1.0.2 tags remain on their commits;
v1.0.3 is the first wheel that actually publishes to PyPI with the
agent-facing exception classes reachable.

## [1.0.2] — 2026-05-14

**v1.0.1 with Python smoke test fixup.** v1.0.1 tag CI failed because
the `test_sqlite_engine.py` Python smoke tests I wrote assumed an
Engine constructor signature with only `(dsn)`, but the real signature
is `Engine(dsn, signing_key_id, scrubber=None, steward_key_id=None,
steward_key_path=None)`. Full Engine construction needs a keyring +
signing-key fixture; the Rust-side substrate tests
(`secrets::sqlite::tests::*`, `cirisnode::sqlite::tests::*`, etc.)
already exercise the in-memory SQLite path end-to-end at the substrate
level, so the Python smoke test scope is narrowed to just the
agent-facing exception-hierarchy export check.

- `tests/python/test_sqlite_engine.py` — keep the
  `test_typed_exception_hierarchy_exported` check (verifies
  `PersistError` / `NotFound` / `Conflict` / `Transient` / `Permanent`
  are exported + form a clean inheritance chain extending Python's
  `Exception`). Drop the three Engine-construction tests.

No surface or behavioral changes from v1.0.0 / v1.0.1. The v1.0.0 +
v1.0.1 tags remain on their commits as a record of the cut; v1.0.2 is
the first wheel that actually publishes to PyPI.

## [1.0.1] — 2026-05-14

**v1.0.0 with CI test fixup.** v1.0.0 tag CI hit two issues that
gated the wheel publish; this is the first usable 1.x wheel on PyPI.

- `migrations/postgres/lens/V019` — drop nested `BEGIN`/`COMMIT`
  (refinery wraps each migration in its own tx; nested interacts
  poorly with tokio-postgres expression-index parsing) + drop
  `::timestamptz` cast on `(attributes->>'period_start')` (STABLE
  function, rejected as index expression with SQLSTATE 42P17).
  Canonical RFC 3339 strings sort lexicographically equivalently
  for the same offset.
- `tests/qa_harness.rs::av26_concurrent_boot_advisory_lock` —
  bumped `schema_history` count expectation 1..=16 → 1..=19 to
  match V017 (atomic-claim) + V018 (action_type CHECK) + V019
  (consolidation_level) additions.

No surface or behavioral changes from v1.0.0. The v1.0.0 tag stays
on the same commit (`8067a87`) as a record of the substrate-
completion cut; v1.0.1 is the first published wheel of the 1.x series.

## [1.0.0] — 2026-05-14

**Substrate-completion + CIRISAgent v2.9.0 adoption cut.** The "1.0"
means: every CIRISAgent service the migration roadmap names as
persist-bound (11 of 22) is reachable from the wheel, on every
deployment platform (server Postgres + sovereign-mode / Pi / iOS
SQLite). Agent team signed off (CIRISAgent#755 + #756); persist
absorbs 9 services already (v0.9.4 Rust parity + this release's
PyO3 SQLite wraps) and unblocks the remaining 2 (transit-touch
Secrets + AdaptiveFilter classification via the pipeline orchestrator).

### What v1.0.0 ships

**PyO3 SQLite via URL-sniff (CIRISAgent#755 Option A)**

- Single `Engine` Python class. Constructor sniffs the connection
  URL: `postgresql://` / `postgres://` → Postgres backend;
  `sqlite:///path` / `sqlite::memory:` / `sqlite:///:memory:` →
  SQLite backend. Unknown scheme → `ValueError`.
- Internal `BackendDispatch { Postgres, Sqlite }` enum; every
  substrate method matches on it. Python-side API is identical
  across backends — agent code is backend-blind beyond construction.
- 51 substrate-service methods backend-dispatched: 18 secrets, 15
  cirisnode, 7 cirisgraph, 4 telemetry, 4 incident, 3 audit. All
  call into the SQLite sub-backends shipped v0.8.4-v0.9.4
  (`SqliteSecretsBackend`, `SqliteNodeCoreBackend`, etc.) which share
  one `Arc<Mutex<Connection>>` handle for zero-cost dispatch.
- 60 non-substrate methods stay Postgres-only (verify, attestation,
  federation_keys CRUD, revocations, cold-path PQC sweep, outbound
  queue, ingest). Agent team explicitly deferred verify/attestation
  pyo3-SQLite wraps to v1.0.1.

**Typed Python exception hierarchy (CIRISAgent#755 sign-off)**

- `PersistError(Exception)` base + 4 subclasses: `NotFound`,
  `Conflict`, `Transient` (retryable — backend timeouts / pool
  exhaustion), `Permanent` (don't-retry — validation, crypto, internal
  bugs, hardware unavailable, not authorized).
- Substrate `kind()` tokens (`secrets_not_found`, `audit_conflict`,
  `telemetry_backend`, etc.) auto-translate to the right class via
  `translate_error_kind()` on every backend-dispatched method.
- Agent's `from ciris_persist import NotFound, Conflict, Transient,
  Permanent` and `try: ... except NotFound: ...` patterns work directly.

**Pipeline orchestrator (CIRISPersist#33 parts 1-2)**

- `Pipeline` struct + `PipelineBuilder` + `Stage` / `ErasedStage`
  traits (v0.7.5).
- Four concrete stages (commit 5d92cc1, sub-agent's pipeline port):
  - `ClassifyStage` — per-component classify matchers → outer-vec
    of `Vec<ContentClassMatch>` (matcher catalog ships post-1.0.0).
  - `ScrubStage` — `scrub::scrub_trace` redacts payload in-place;
    `fields_modified` summed; `pii_scrubbed` flipped.
  - `EncryptAndStoreStage<S>` — SecretsService transit-touch stub
    (cleartext-capture deferred — `ContentClassMatch` doesn't yet
    carry pre-scrub spans).
  - `ExtractStage` — populates `state.features` from the first
    CompleteTrace (v0.7.5).
- Two direction-aware factories (CIRISAgent#756 concern #1):
  - `default_inbound_pipeline(secrets, actor_id)` — Classify → Scrub
    → EncryptAndStore → Extract. For network → agent ingest path.
  - `default_outbound_pipeline()` — Classify + Scrub only (no
    encrypt_and_store: outbound never stores secrets; no extract:
    outbound isn't a corpus row). For agent SPEAK → network path.

**Atomic-claim primitive (CIRISAgent#756 concern #2)**

- `ClaimResult<R> { Stored(R), AlreadyClaimed(R) }` shared type;
  re-exported via prelude.
- `SecretsService::try_claim_secret(plaintext, ...)` — HMAC-SHA256
  under active master key as the dedup hash. Race-safe via PG
  `INSERT … ON CONFLICT DO NOTHING RETURNING` / SQLite `INSERT OR
  IGNORE` + read-back-by-content-hmac. Master-key rotation is the
  dedup boundary (rotation → same plaintext re-claims).
- `AuditService::try_claim_event(content_hash, event, accessor)` —
  caller-computed sha256 over canonical envelope bytes. Same
  race-safe pattern; returns `AuditEventRef { entry_id, tenant_id,
  sequence_number }`.
- V017 migration (both dialects) adds the `content_hmac BLOB UNIQUE`
  / `content_hash BYTEA UNIQUE` columns (nullable, NULLS-DISTINCT
  UNIQUE on PG; partial unique index on SQLite).

**Audit / telemetry shape locked-in from agent team verdicts**

- **Q2 (action_type vocabulary)** — V018 migration adds `NOT VALID`
  CHECK constraint on PG `cirislens.audit_log.action_type` with the
  21-value vocabulary sourced from CIRISAgent's `AuditEventType`
  enum (10 handler / 5 system / 6 wallet variants). Convention-only
  on SQLite (`ALTER TABLE ADD CONSTRAINT CHECK` isn't supported).
  Additive-only evolution committed in lockstep with agent.
  New `AuditEventType` enum in `src/audit/types.rs` for typed callers.
- **Q4 (graph-node side absorption)** — new
  `AuditService::query_by_correlation_id(tenant, corr_id, filter)`.
  Lets agent collapse the dual-write (hash-chain row + graph node
  with correlation_id) to single-source. PG impl uses `payload @>
  jsonb_build_object('correlation_id', $2)`; SQLite uses
  `json_extract(payload, '$.correlation_id') = ?`.
- **Q7 (4-tier consolidation)** — `ConsolidationLevel` enum (Basic
  / Daily / Weekly / Monthly) on `TelemetryService::consolidate_
  period(start, end, level)`. V019 migration adds `consolidation_
  level TEXT NOT NULL DEFAULT 'basic'` column to `cirisgraph.nodes`
  (tier-scoped TSDB summaries). Basic tier aggregates raw
  observations; Daily/Weekly/Monthly aggregate prior-tier summaries.
  Load-bearing for 4GB RAM target on Pi / sovereign deployments.

**Documentation**

- `docs/TELEMETRY_TAG_CONVENTIONS.md` — codifies CIRISAgent's
  canonical telemetry tag keys (handler, action, path_type,
  source_module, thought_id, service, model, api_base, metric_type,
  service_name) as substrate vocabulary. Drops redundant
  `tags["source"]` / `tags["timestamp"]`.

### What's deferred to v1.0.1+ (NOT 2.9.0-blocking)

- PyO3 SQLite wraps for verify / attestation / federation_keys /
  steward signing. Agent already invokes these via persist prelude
  (not pyo3) so 2.9.0 isn't blocked.
- Pipeline pyo3 wraps (`engine.pipeline().run(envelope)` from
  Python). Agent's 2.9.0 cutover plan (cirisgraph → audit/telemetry/
  incident → secrets) doesn't reach pipeline orchestration.
- Async-native pyo3 methods. Agent team explicitly OK'd
  `asyncio.to_thread()` bridging if persist stays sync.
- POST /api/v1/pipeline/ingest HTTP route + `FederatedSecretsClient`
  (#33 parts 3-4) — Edge wire transport; not substrate.

### Series-completion narrative

| Bucket | Count | Status |
|---|---|---|
| Persist-bound, already absorbed (v0.9.4 Rust parity + v1.0.0 PyO3 SQLite) | 9 / 22 | ✓ |
| Persist-bound, unblocked by #33 pipeline orchestrator (lands v1.0.0) | 2 / 22 | ✓ |
| Stays at agent permanently (governance + lifecycle + LLM + host metrics) | 11 / 22 | by design |

After 1.0.0, every CIRISAgent service the migration roadmap names as
persist-bound is reachable from the wheel on every deployment
platform. Subsequent persist work (v1.x) is verify/attestation pyo3
parity, pipeline pyo3 wraps, Edge wire-transport (#33 parts 3-4),
and the matcher catalog ship that fills in ClassifyStage's currently-
stubbed output.

## [0.9.4] — 2026-05-14

**NodeCoreService SQLite parity (closes CIRISPersist#40)** — the
final SQLite parity piece for the v0.6.1+ substrate. Every persist
module that ships a typed-write surface (cirisgraph, cirisaudit,
telemetry, cirisincident, secrets, cirisnode) now runs on both
backends.

### What landed

- **`cirisnode` feature decoupled from `postgres`.** Cargo.toml is
  now `cirisnode = []`; pair with either backend (or both). Trait,
  wire types, and dialect-agnostic signature-verify (`verify.rs`)
  are backend-agnostic.
- **`migrations/sqlite/lens/V011__cirisnode_consensus.sql`** —
  7-table federation-consensus schema (contributions, votes,
  credits_ledger, expertise_ledger, moderation_events,
  slashing_attestations, reconsideration_requests,
  reconsideration_attestations). Same audit envelope shape as the
  Postgres V011 (signature / signing_key_id / signature_verified /
  original_content_hash / scrub_signature_classical /
  scrub_signature_pqc / scrub_key_id / scrub_timestamp /
  pqc_completed_at / persist_row_hash). Dialect translations:
  UUID→TEXT 36-char, JSONB→TEXT canonical JSON, TIMESTAMPTZ→RFC
  3339, BYTEA→BLOB, DOUBLE PRECISION→REAL, BOOLEAN→INTEGER 0/1,
  flat-prefixed `cirisnode_*` table names (no schema namespace).
- **`migrations/sqlite/lens/V012__cirisnode_promotion_attestations.sql`**
  — canonical-promotion attestation table (#32). `target_ids
  UUID[]` translates to TEXT JSON-array; reverse-lookup via
  `EXISTS (SELECT 1 FROM json_each(target_ids) WHERE value = ?)`
  on the read path instead of the Postgres GIN index.
- **`src/cirisnode/sqlite.rs`** — `SqliteNodeCoreBackend` impl of
  all 14 `NodeCoreService` methods (8 typed-writes + 5 reads +
  `put_promotion_attestation`). Per-call `tokio::task::
  spawn_blocking` around the shared `Arc<Mutex<Connection>>`
  handle; `BEGIN IMMEDIATE` (database-level RESERVED lock) replaces
  Postgres `SELECT … FOR UPDATE` for `put_promotion_attestation`'s
  multi-statement transaction (INSERT attestation + UPDATE N target
  rows + verify total_affected matches target_ids.len() + rollback
  on mismatch).
- **Cursor pagination**: expanded OR form `WHERE submitted_at < ?N
  OR (submitted_at = ?N AND contribution_id < ?M) ORDER BY DESC
  LIMIT ?+1` instead of row-value tuple comparison, for broad
  SQLite-version compatibility.

### Signature-verify invariant unchanged

The hybrid Ed25519 + ML-DSA-65 verify path lives in `src/cirisnode/
verify.rs` and is shared by both backends — same as v0.7.x. The
SQLite impl calls `super::verify::verify_envelope_signed(...)`
byte-for-byte identically to the Postgres impl. No duplication, no
divergence.

### Tests

`cirisnode::sqlite::tests::cirisnode_sqlite_round_trip_full_lifecycle`
exercises all 14 trait methods + the promotion-attestation
transactional path (including a rollback-on-mismatch sub-test).
13/13 cirisnode tests pass with `--features "cirisnode sqlite"`;
no regression with `--features "cirisnode postgres"` or both.

### Series-completion note

After v0.9.4 lands, every CIRISAgent service in the migration
roadmap's persist-bound set (Memory / Config / Audit / Telemetry /
TSDB / IncidentMgmt / Secrets / SecretsToolService) has full
Postgres + SQLite parity. Sovereign-mode, Pi, iOS, server — all
platforms supported. cirisnode itself isn't an agent-adoption
dependency (it's CIRISNodeCore-track for federation-consensus
rows), but its inclusion completes the v0.6.1+ matrix.

## [0.9.3] — 2026-05-13

**SecretsService SQLite parity (closes CIRISPersist#39).** The
`secrets` feature now compiles + runs on the SQLite backend, on a par
with the v0.6.1-α5 Postgres impl. CIRISAgent's sovereign-mode / iOS /
Pi deployments — which ship persist with SQLite-only — can now adopt
the full `SecretsServiceProtocol` surface (18 methods) without
needing a Postgres daemon.

### What landed

- **`secrets` feature decoupled from `postgres`.** Cargo.toml feature
  is now `secrets = ["classify", "ciris-crypto/aes-gcm",
  "ciris-crypto/kdf", "ciris-crypto/hmac", "ciris-crypto/random"]`.
  Either backend (or both) can be enabled alongside `secrets`; the
  trait + crypto facade + key cache are backend-agnostic.
- **`migrations/sqlite/lens/V010__cirislens_secrets.sql`** — 5-table
  schema with dialect translations:
  - `cirislens_secrets_secrets` (BYTEA→BLOB ciphertext/salt/nonce,
    TEXT[]→TEXT JSON-array for auto_decapsulate_for_actions, UUID→
    TEXT 36-char hyphenated, TIMESTAMPTZ→RFC 3339 TEXT).
  - `cirislens_secrets_access_log` (BIGSERIAL→INTEGER PRIMARY KEY
    AUTOINCREMENT log_id; same CHECK on `operation`).
  - `cirislens_secrets_master_key_meta` (self-referencing
    `rotated_to`; same partial index on the active row).
  - `cirislens_secrets_filter_config` (JSONB→TEXT canonical JSON).
  - `cirislens_pseudonyms` (BLOB original_hash PK).
- **`src/secrets/key_cache.rs`** — process-static software master-key
  cache extracted from the Postgres impl so both backends share one
  in-memory key store. No behavioral change for Postgres callers.
- **`src/secrets/sqlite.rs`** — `SqliteSecretsBackend` with all 18
  `SecretsService` trait methods. Per-call `tokio::task::
  spawn_blocking` around the shared `Arc<Mutex<rusqlite::Connection>>`
  handle; `BEGIN IMMEDIATE` (database-level RESERVED lock) replaces
  Postgres `SELECT … FOR UPDATE` for the `reencrypt_all` rotation
  transaction. The 8 `operation` CHECK-constraint values, the audit
  invariant (every method writes a log row before returning), and
  the wire-type round-trip behavior match the Postgres impl 1:1.
- **`process_incoming_text` + `decapsulate_secrets_in_parameters`**
  stub to `SecretsError::Internal("v0.9.3 SQLite: pipeline
  orchestration deferred …")` — same behavior as the Postgres v0.6.1-
  α5 stubs (these wait on the v0.6.2 pipeline orchestration that
  CIRISPersist#33 tracks).
- **`migrate_to_hardware_key`** returns `HardwareKeyUnavailable`,
  same as Postgres. Lands when `ciris-keyring/symmetric-derivation`
  feature ships upstream.

### Crypto invariant unchanged

The single import site of `ciris_crypto::*` is still
`src/secrets/crypto.rs`. The SQLite impl routes through that facade
byte-for-byte identically to the Postgres impl. Persist takes ZERO
direct primitive deps; the boundary is auditable in one file (FSD
§7.5a — crypto-through-ciris-crypto).

### Tests

`secrets::sqlite::tests::secrets_sqlite_round_trip_full_lifecycle`
exercises 13 phases against an in-memory SQLite: rotate → encrypt /
decrypt direct → store / retrieve → list / recall / forget →
filter_config CRUD → audit-log readback → service stats / health →
the two pipeline-stage stubs. Mirrors the Postgres lifecycle test
exactly. All 18 secrets-module tests pass with `--features "secrets
sqlite"`; no regression with `--features "secrets postgres"` or
`--features "secrets sqlite postgres"`.

### Why v0.9.3 isn't tagged yet

CIRISRegistry#13 (HTTP 500 on `/v1/builds` POST for ciris-persist —
likely missing `trusted_primitive_keys` row) is still blocking the
v0.9.2 publish workflow. Per user direction, v0.9.3 lands on `main`
now so downstream consumers can read the source; the tag + PyPI
publish will follow once the registry side unblocks.

## [0.9.2] — 2026-05-14

**Multi-target build registration via `ciris-build-sign register`
(closes CIRISPersist#42).** Persist's CI now produces and registers
**four per-target BuildManifests** in the CanonicalBuild v2 shape
(CIRISVerify v2.0.3+), unblocking `verify_tree(project=
"ciris-persist", target=…)` for every deployment class — including
iOS + Android consumers that rebuild persist's Rust from source
and verify the Python wrapper tree.

### What landed in CI

- **`ciris-build-sign` tarball bumped** v1.8.0 → v2.0.5. Brings the
  `register` subcommand + CanonicalBuild v2 multi-target shape.
- **Four manifests signed per release** (was one):
  - `python-source-tree` — file-tree hash over `python/ciris_persist/`
    (`.py` + `.pyi` only; excludes `__pycache__`, `.pyc`, `.pyo`,
    `.so`, `.dylib`, `.dll`). Covers what iOS / Android agents
    walk when they verify persist's installed Python wrappers.
  - `x86_64-unknown-linux-gnu` — `binary_hash = sha256(wheel.whl)`
    for the Linux x86_64 wheel.
  - `aarch64-unknown-linux-gnu` — same shape, Linux aarch64 wheel.
  - `aarch64-apple-darwin` — same shape, macOS arm64 wheel.
- **`ciris-build-sign register`** replaces the custom curl POST to
  `/v1/verify/binary-manifest`. Writes the `builds` parent row
  signed over all per-target manifest hashes, plus per-target
  `binary_manifests` (binary mode) and `function_manifests`
  (source-tree mode) rows to `/v1/builds`.
- **Round-trip verify** updated to `GET /v1/builds/<v>?project=
  ciris-persist` (parent row) **plus** per-target
  `&target=<name>` GETs for every signed target. Fails the build
  if ANY target's round-trip fails.

### Why iOS + Android needed this

`pip install ciris-persist` doesn't work on iOS/Android (no Python
wheels for those platforms). Agents on those platforms embed the
persist Python wrappers via PyOxidizer/Buildozer-style packaging
and rebuild persist's Rust from source. Without a registered
`python-source-tree` manifest, `verify_tree(project="ciris-persist",
root=<embedded-persist-dir>, ...)` returns `registry_error` /
`valid=false`. v0.9.2 closes that gap.

### Library / wheel surface unchanged

No code changes. The Rust trait surfaces, FFI shapes, wire
formats, and the published wheel contents are byte-for-byte
identical to v0.9.1. Only the CI registration shape changed.
Existing v0.9.1 consumers can continue using the old
`/v1/verify/binary-manifest` cached row; new consumers (or any
post-v0.9.2 deployment) get the multi-target CanonicalBuild v2
path automatically.

### Tests

- 349/349 lib pass against live `ciris-qa-postgres` + in-memory
  SQLite (unchanged from v0.9.1).
- `python3 -c "import yaml; yaml.safe_load(...)"` on the rewritten
  workflow passes.
- The register / round-trip flow only validates end-to-end against
  the live CIRISRegistry in tag CI; local pre-push can't exercise
  it. The tag CI is the integration gate.

### References

- CIRISPersist#42 — register persist builds in multi-project verify
  expansion (closes here).
- CIRISVerify#8 — CanonicalBuild v2 with per-target rows (v2.0.3).
- CIRISVerify v2.0.5 — `ciris-build-sign register` subcommand + the
  iOS hardware-marker self-heal + Mach-O `__TEXT` hash parity (the
  three fixes v0.9.1 picked up at the Rust-library level; v0.9.2
  now uses the matching `register` CLI).

## [0.9.1] — 2026-05-14

**Verify pin bump v2.0.2 → v2.0.5.** Updates the Rust-side
`ciris-keyring` + `ciris-verify-core` + `ciris-crypto` git pins
(all from the CIRISVerify monorepo) AND the Python-side
`ciris-verify` PyPI floor. Aligns persist with what CIRISAgent
v2.9.0 expects.

### What's in v2.0.5 (vs v2.0.2)

- **v2.0.3** — CanonicalBuild v2 with `target` field (closes
  CIRISVerify#8).
- **v2.0.4** — Self-heal orphaned hardware markers on iOS
  reinstall. iOS-specific; relevant to CIRISAgent v2.9.0 on iOS
  device deployments.
- **v2.0.5** — Single-source-of-truth `__TEXT` hash for Mach-O
  sign/runtime parity (closes CIRISVerify#19). Fixes
  sign-verifies-but-runtime-rejects edge case on macOS + iOS.

### Why this matters for v2.9.0

The agent's iOS-device deployment path benefits from v2.0.4's
hardware-marker self-heal directly — without it, an agent app
reinstall on iOS could leave the hardware-keyring marker file
stale and refuse to boot until manual cleanup. v2.0.5's Mach-O
hash fix matters for the build-manifest verify path that lens-core
inherits transitively.

### What changed at the persist layer

- `Cargo.toml`: 3 git-pin lines bumped (`ciris-keyring`,
  `ciris-verify-core`, `ciris-crypto`) from `tag = "v2.0.2"` to
  `tag = "v2.0.5"`.
- `pyproject.toml`: `ciris-verify>=1.8.6,<2` → `ciris-verify>=2.0.5,<3`.
  Upper bound moved to `<3` per the semver-major convention.
- No persist-side code changes. Trait surfaces, FFI shapes, and
  wire formats are unchanged.

### Tests

- 349/349 lib pass against live `ciris-qa-postgres` + in-memory
  SQLite.
- Clippy `-D warnings` clean across the full feature matrix.
- Cargo.lock updated; git-deps re-locked at v2.0.5
  (`dcc8b4ed`).

## [0.9.0] — 2026-05-13

**CIRISAgent 2.9.0 adoption cut — 6 of 22 services absorbed with
SQLite + Postgres parity across the full deployment matrix.**

This release closes the substrate-readiness gap that blocks
CIRISAgent's Phase 1B migration on sovereign-mode / Pi-class / iOS
device deployments (CIRIS_DB_URL = SQLite). Every v0.8.x trait
surface now runs against both backends; the agent team can `pip
install ciris-persist==0.9.0` and begin the substrate cutover
without fragmenting their deployment shapes.

### Substrate-bound services absorbed (Postgres + SQLite both)

| Persist module | CIRISAgent service absorbed | Substrate releases |
|---|---|---|
| **cirisgraph** | MemoryService (LocalGraphMemoryService) + ConfigService (GraphConfigService) | v0.8.0 PG, v0.8.4 SQLite |
| **cirisaudit** | AuditService (hash-chained, Ed25519-signed) | v0.8.1 PG, v0.8.5 SQLite |
| **telemetry** | TelemetryService + TSDBConsolidationService (6h rollup) | v0.8.2 PG, v0.8.6 SQLite |
| **cirisincident** | IncidentManagementService (correlation + state machine) | v0.8.3 PG, v0.8.7 SQLite |

That's **6 of the 22 CIRISAgent services** covered by 4 persist
modules. The remaining 16 are either reasoning-bound (stay in
Python: WiseAuthority, Visibility, Consent, SelfObservation, LLM,
RuntimeControl, AdaptiveFilter-LLM-tuning-half) or process-local
infrastructure (TimeService, ShutdownService, InitializationService,
ResourceMonitor, TaskScheduler, DatabaseMaintenance).

### iOS hardening (CIRISVerify v1.6.4 lesson applied)

- `rusqlite` is target-conditional in Cargo.toml: `bundled` feature
  on non-iOS targets (clean manylinux wheels); no `bundled` on iOS
  (links against system libsqlite3 — bundled would duplicate
  sqlite3 symbols with iOS's system one, tripping `libRPAC.dylib`
  (SQLiteDatabaseTracking) assertions).
- `SqliteBackend` connection-init pragmas include
  `busy_timeout = 30000` (matches CIRISAgent iOS 30s timeout —
  universal-hygiene applied per the user's "if the pattern helps
  with other platforms, apply universally" guidance).

### What's DEFERRED to v0.9.1+

- **secrets SQLite** (v0.6.1 module) — Postgres ships; SQLite parity
  is ~1100 LOC of careful crypto-path port. Tracked as v0.9.1 cut.
  Agent team can adopt v0.9.0 for the 4 modules above and keep
  their existing in-process `ciris_engine/logic/secrets/` while
  v0.9.1 lands.
- **cirisnode SQLite** (v0.7.x module) — Postgres ships; SQLite
  parity tracked as v0.9.2 cut. **CIRISAgent v2.9.0 does NOT consume
  cirisnode** (cirisnode is the CIRISNodeCore consumer track for
  federation-consensus rows; the agent only uses
  `ciris_adapters/cirisnode/` as an HTTP shipper which gets replaced
  by CIRISNodeCore in Step 4 of the 4-step migration trajectory).
- **Pipeline orchestrator HTTP route** (CIRISPersist#33 pieces 3-5
  — HTTP ingest handler, FederatedSecretsClient, role-tag
  enforcement) — substantial server-side work, deferred.

### Tests

- **349/349 lib pass against live PG** (`ciris-qa-postgres`).
- **All SQLite tests pass against in-memory SQLite** (per-module
  full-lifecycle integration tests).
- Clippy `-D warnings` clean across the full feature matrix:
  `cirisaudit cirisgraph postgres sqlite pyo3 cirisnode secrets
  telemetry cirisincident extract classify scrub`.
- Pre-push hook runs both backends; CI matrix expanded to include
  `darwin-aarch64 (no postgres)` SQLite-only build.

### References

- CIRISPersist#34 / #35 / #36 / #37 — Postgres substrate cuts
  (closed in v0.8.0–v0.8.3).
- CIRISPersist#38 — SQLite parity tracking. v0.9.0 closes the
  4-of-6 module pieces; v0.9.1 secrets SQLite + v0.9.2 cirisnode
  SQLite tracked separately.
- CIRISVerify v1.6.4 — iOS rusqlite-bundled symbol-duplication
  fix establishing the pattern v0.9.0 inherits.
- `memory/project_migration_roadmap.md` — the 4-step substrate-
  substitution sequence (persist → edge → lens-core → node-core).

## [0.8.7] — 2026-05-13

**cirisincident SQLite parity** (v0.9.0 cut α4 toward CIRISPersist#38).

- `src/incident/sqlite.rs` — `SqliteIncidentBackend` impl of
  `IncidentService` (4 methods, AV-55 + AV-56 preserved).
- JSONB-array `?|` / `?&` / `?` operators translate to
  `EXISTS (SELECT 1 FROM json_each(correlation_keys) WHERE …)`
  subqueries. Dedup probe joins `json_each` on both the existing
  row's keys array AND the new incident's keys array.
- State-machine `FOR UPDATE` semantics → `BEGIN IMMEDIATE` (same
  pattern as cirisaudit SQLite).
- Partial index `WHERE state IN ('open', 'investigating')` ports
  directly (SQLite supports partial indexes).
- `cirisincident = []` decoupled.

Tests: 1/1 cirisincident SQLite test (full lifecycle) against
in-memory SQLite. 349/349 lib pass across both backends.

| v0.9.0 roadmap | Postgres | SQLite |
|---|---|---|
| secrets | ✓ | pending |
| cirisnode | ✓ | pending |
| cirisgraph | ✓ | ✓ v0.8.4 |
| cirisaudit | ✓ | ✓ v0.8.5 |
| telemetry | ✓ | ✓ v0.8.6 |
| **cirisincident** | ✓ | **✓ v0.8.7** |

Two modules remain before the v0.9.0 cut: secrets (v0.6.1) +
cirisnode (v0.7.x). Both have crypto + signing-verify paths that
are dialect-agnostic, so the SQLite work is migration + row-shape
translation only.

## [0.8.6] — 2026-05-13

**telemetry SQLite parity** (v0.9.0 cut α3 toward CIRISPersist#38).

- `src/telemetry/sqlite.rs` — `SqliteTelemetryBackend` impl of
  `TelemetryService` (4 methods including the full
  `consolidate_period` rollup). Summary nodes UPSERT directly
  against `cirisgraph_nodes` (shared schema with v0.8.4).
- Dialect translations: `UNNEST'd INSERT … SELECT` →
  prepared-statement loop in `BEGIN IMMEDIATE` transaction;
  `INTERVAL '3600 seconds'` → `datetime('now', '-3600 seconds')`;
  JSONB labels → TEXT JSON; PG `attributes @> {predicate}` →
  per-key `json_extract` equality checks.
- **Subtle bug + fix on prior-period probe**: chrono's default serde
  for `DateTime<Utc>` emits nanosecond precision, but `fmt_datetime`
  uses microsecond. Stored attributes JSON had nanos; query bound
  had micros. Lex compare on RFC 3339: `'7' (nanos digit) < 'Z'
  (Z-suffix)` at the precision boundary, falsely matching every
  summary as its own predecessor and creating spurious
  TEMPORAL_NEXT edges. Fix: truncate `period_start`/`period_end` to
  microseconds before serializing summary attributes.
- `migrations/sqlite/lens/V015__cirisgraph_telemetry.sql`.
- `telemetry = ["cirisgraph"]` — no backend requirement; pairs via
  cirisgraph.

Tests: 2/2 telemetry SQLite tests (full lifecycle + AV-53 lock
contention) against in-memory SQLite. 348/348 lib pass across both
backends.

| v0.9.0 roadmap | Postgres | SQLite |
|---|---|---|
| secrets | ✓ | pending |
| cirisnode | ✓ | pending |
| cirisgraph | ✓ | ✓ v0.8.4 |
| cirisaudit | ✓ | ✓ v0.8.5 |
| **telemetry** | ✓ | **✓ v0.8.6** |
| cirisincident | ✓ | pending |

## [0.8.5] — 2026-05-13

**cirisaudit SQLite parity** (v0.9.0 cut α2 toward CIRISPersist#38).

- `src/audit/sqlite.rs` — `SqliteAuditBackend` impl of `AuditService`.
  Hash-chain semantics (AV-49 entry_hash re-derive, AV-50
  verify_chain typed breaks, AV-51 tenant isolation) preserved
  byte-for-byte.
- Per-tenant tail-lock translation: Postgres `SELECT … FOR UPDATE`
  → SQLite `BEGIN IMMEDIATE` (database-level RESERVED lock). Coarser
  than per-row, but combined with v0.8.4's `PRAGMA busy_timeout =
  30000` serializes writers safely without deadlock risk.
- Dialect translations: BYTEA → BLOB (32-byte sha256 hashes raw),
  TIMESTAMPTZ → RFC 3339 TEXT, JSONB payload → TEXT JSON, UUID →
  TEXT. Same shape as v0.8.4 cirisgraph SQLite.
- `migrations/sqlite/lens/V014__cirislens_audit_log.sql` — flat
  schema (`cirislens_audit_log` table).
- `cirisaudit = []` decoupled from `["postgres"]`.

Tests: new `cirisaudit_sqlite_round_trip_full_lifecycle` against
in-memory SQLite mirrors the v0.8.1 Postgres lifecycle (genesis →
replay reject → gap reject → wrong-prev reject → 3-entry chain →
verify_chain Ok → tenant isolation → empty-tenant reject → direct-
UPDATE tamper surfaces EntryHashMismatch). 346/346 lib pass across
both backends.

| v0.9.0 roadmap | Postgres | SQLite |
|---|---|---|
| secrets | ✓ | pending |
| cirisnode | ✓ | pending |
| cirisgraph | ✓ | ✓ v0.8.4 |
| **cirisaudit** | ✓ | **✓ v0.8.5** |
| telemetry | ✓ | pending |
| cirisincident | ✓ | pending |

## [0.8.4] — 2026-05-13

**cirisgraph SQLite parity + iOS-conditional rusqlite (v0.9.0 cut α1
toward CIRISPersist#38).** First piece of the SQLite parity track
that closes the gap between persist's v0.6.1+ Postgres-only modules
and CIRISAgent's full deployment matrix (Postgres for federated;
SQLite default for sovereign-mode / Pi-class / iOS device).

### What landed

- **iOS-conditional `rusqlite`** — Cargo.toml splits the `rusqlite`
  dep across `cfg(target_os = "ios")` (no `bundled` feature; links
  against iOS's system libsqlite3) and `cfg(not(target_os =
  "ios"))` (keeps `bundled` for clean manylinux wheel builds). This
  is the **exact same fix CIRISVerify v1.6.4 made** for Apple's
  `libRPAC.dylib` (SQLiteDatabaseTracking) — bundled rusqlite
  duplicates sqlite3 symbols, which trips libRPAC's two-dylib
  assertion on iOS. Per deepwiki inspection of CIRISAgent's hard-
  won-victory pattern.
- **`PRAGMA busy_timeout = 30000`** added to `SqliteBackend`
  connection-init pragmas (matches CIRISAgent's iOS 30s timeout;
  applies universally — Pi-class + dev-laptop SQLite workloads
  benefit from the wait-don't-fail-fast behavior).
- **`SqliteBackend::conn_handle()`** — public accessor for the
  shared `Arc<Mutex<Connection>>` so sibling modules ride the same
  underlying connection.
- **`cirisgraph = []`** feature decoupled from `["postgres"]` — the
  trait surface is backend-agnostic; pair `cirisgraph` with either
  `postgres` or `sqlite` per deployment shape.
- **`src/graph/sqlite.rs`** — `SqliteGraphBackend` impl of
  `GraphService`. Same 7 methods, same AV-45..AV-48 semantics.
  Dialect translations: JSONB→TEXT (canonical JSON), GIN→
  expression-indexed `json_extract` predicates, `text[]` params→
  `json_each(?)` joins, UUID→TEXT (36-char hyphenated), TIMESTAMPTZ→
  RFC 3339 TEXT, `NOW()`→`datetime('now', 'subsec')`. Recursive
  CTE shape restructured for SQLite (no nested-LIMIT in recursive
  arm; per-level fan-out moves to outer LIMIT — `max_depth ×
  per_level_limit` upper bound).
- **`migrations/sqlite/lens/V013__cirisgraph_nodes_edges.sql`** —
  flat schema (no PG "schema" namespace; tables prefixed
  `cirisgraph_nodes` / `cirisgraph_edges`).

### Tests

- New `graph::sqlite::tests::cirisgraph_sqlite_round_trip_full_lifecycle`
  in-memory SQLite test mirrors the v0.8.0 Postgres lifecycle test
  exactly: 13 assertions covering upsert × 3 → get → AV-48 version
  conflict → update with correct version → AV-45 oversize reject →
  3-edge cycle (`OWNS`/`SUMMARIZES`) → directional edges →
  relationship-allowlist filter (via `json_each`) → AV-46 bounds →
  2-hop traverse via recursive CTE → query_nodes with scope+type →
  AV-47 None-scope reject → hard cascade delete.
- 345/345 full lib pass against **both backends** (live
  ciris-qa-postgres + in-memory SQLite); clippy `-D warnings`
  clean across the full feature matrix including `sqlite`.

### Why SQLite parity matters for v2.9.0 cutover

CIRISAgent's `CIRIS_DB_URL` env-var dialect switch lets operators
choose backend at deployment time. SQLite is the default for
sovereign-mode (single-agent + lens on a Pi), Pi-class deployments,
and iOS-device deployments. Postgres-only v0.6.1+ substrate would
fragment the agent's deployment matrix on adoption. v0.8.4 closes
the first piece (cirisgraph); subsequent v0.8.x alphas add SQLite
parity for cirisaudit (#35 follow-on), telemetry (#36),
cirisincident (#37), secrets (#19), then v0.9.0 ships as the
agent-ready cut.

### v0.9.0 roadmap (issue #38)

| Module | Postgres | SQLite |
|---|---|---|
| secrets (v0.6.1) | ✓ | pending |
| cirisnode (v0.7.x) | ✓ | pending |
| **cirisgraph (v0.8.0)** | ✓ | **✓ v0.8.4** |
| cirisaudit (v0.8.1) | ✓ | pending |
| telemetry (v0.8.2) | ✓ | pending |
| cirisincident (v0.8.3) | ✓ | pending |

### References

CIRISPersist#38 (tracking — substrate prerequisite for CIRISAgent
2.9.0 adoption). CIRISVerify v1.6.4 changelog — same iOS rusqlite
fix established the pattern. CIRISAgent's iOS SQLite hard-won
victory (deepwiki, `ciris_engine/logic/persistence/db/core.py`) —
the Rust-relevant pieces (system SQLite on iOS, WAL, busy_timeout
30s) ported here; Python-specific pieces (GC-suppressing
connection/cursor proxies, thread-local handles) don't translate
to Rust's typed connection-pool model.

## [0.8.3] — 2026-05-13

**Incident records substrate (closes CIRISPersist#37).** Last of
the five v0.8.x Phase 1B Postgres substrate cuts. Absorbs
CIRISAgent's `IncidentManagementService` — correlation-keyed dedup
on record + open→investigating→resolved→closed state machine.

### What landed

- **V016 migration** — `cirislens.incident_records` with severity
  CHECK (`info | warning | error | critical`), state CHECK (`open
  | investigating | resolved | closed`), JSONB `correlation_keys`
  array. Partial index on `(tenant_id, state, last_seen_at) WHERE
  state IN ('open', 'investigating')` keeps the hot-path open-
  incidents query small even as resolved/closed accumulate. GIN
  index on `correlation_keys` serves the reverse-lookup path.
- **Wire types** — `Incident`, `IncidentState` (snake_case serde,
  4-step monotonic ladder), `IncidentSeverity`, `IncidentFilter`,
  `IncidentCursor`, `IncidentListPage`, `IncidentTransition`,
  `IncidentRef` (lightweight reference for `correlate` results).
- **`IncidentService` trait** — 4 methods:
  - `record_incident` — correlation-keyed dedup probe within
    `(tenant_id, category)`; bumps `occurrences` + `last_seen_at`
    on existing OPEN/INVESTIGATING match, else inserts fresh row.
    AV-56 bounds enforced before any SQL.
  - `transition_state` — reads current state under `FOR UPDATE`,
    asserts forward ladder progress (AV-55), stamps
    `resolved_at` + `resolution_notes` on Resolved/Closed
    transitions.
  - `list_incidents` — tenant-scoped cursor-paged listing with
    state / severity / category / `has_correlation_keys` filters.
  - `correlate` — reverse-lookup via GIN on `correlation_keys`.
- **PostgresBackend impl** — JSONB `?|` for dedup probe (any-key
  overlap), `?` for single-key correlate, `?&` for filter
  containment.
- **PyO3 surface** — 4 `Engine.incident_*` methods.

### Threat-model anchors (THREAT_MODEL.md §4)

- **AV-55** — state-machine bypass: `transition_state` reads
  current under FOR UPDATE, asserts `current.rank() < new.rank()`,
  rejects regressive/same-state transitions with
  `InvalidTransition`. Closed incidents do NOT dedup against new
  records (dedup probe gated on open/investigating only).
- **AV-56** — correlation_keys abuse: max 32 keys per incident,
  max 256 bytes per key; empty strings rejected. Enforced at
  trait surface before SQL.

### Tests

- 8/8 incident tests against live `ciris-qa-postgres`:
  state-ladder monotonicity unit tests + sql round-trip + serde
  + 1 full-lifecycle integration test covering insert → dedup
  (overlapping keys bump occurrences) → cross-category isolation
  (same keys, different category, new row) → AV-56 oversized
  rejects → AV-55 forward transitions → AV-55 backflow reject →
  notes-required reject → resolved+closed transitions → closed
  incidents don't dedup new records → correlate + list filters →
  tenant isolation → NotFound on missing incident.
- 330/330 full lib pass (+8 from v0.8.2); clippy `-D warnings`
  clean across the full feature matrix.

### Phase 1B substrate cuts — complete (Postgres side)

| Issue | Release | Service absorbed | Tests | Status |
|---|---|---|---|---|
| #34 | v0.8.0 | MemoryService + ConfigService (cirisgraph) | 9/9 | ✓ |
| #35 | v0.8.1 | AuditService (cirisaudit) | 12/12 | ✓ |
| #36 | v0.8.2 | TelemetryService + TSDBConsolidationService | 7/7 | ✓ |
| #37 | v0.8.3 | IncidentManagementService | 8/8 | ✓ |

### NOT YET ready for CIRISAgent 2.9.0 cutover

CIRISAgent supports both **PostgreSQL AND SQLite** backends
(`CIRIS_DB_URL` env-var dialect switch — Postgres for federated
deployments, SQLite default for sovereign-mode / Pi-class /
iOS-device deployments). The v0.6.1+ Rust substrate (secrets,
cirisgraph, cirisaudit, telemetry, cirisincident, cirisnode) is
**Postgres-only** as of v0.8.3. SQLite parity is required before
the agent team can adopt persist on the full deployment matrix.

The v0.8.x trait surfaces + wire types + schema designs ARE
locked at v0.8.3 — SQLite impls slot in behind the same
`Backend`-style traits without breaking the consumer API.
Tracking: **v0.9.0 SQLite parity cut** (next issue to file).

### Closes

CIRISPersist#37.

## [0.8.2] — 2026-05-13

**Telemetry + TSDB consolidation substrate (closes CIRISPersist#36).**
Absorbs CIRISAgent's `TelemetryService` + `TSDBConsolidationService`
write/read paths. Step 1B continuation — the third of five v0.8.x
substrate cuts (cirisgraph #34 ✓, cirisaudit #35 ✓, telemetry #36 ✓,
incidents #37 pending, auth_tokens v0.9.x).

### Two-storage-shape design

Raw observations land in `cirisgraph.telemetry_metrics` (high-
frequency, 24h-lived, no audit envelope — ephemeral); the 6-hour
consolidator rolls them up into `tsdb_summary` nodes in
`cirisgraph.nodes` (V013) with `TEMPORAL_NEXT` / `TEMPORAL_PREV`
edges between adjacent summaries. Splitting raw + summary keeps the
cirisgraph write path cheap + auditable for the agent's semantic
graph; gives telemetry a flat-table fast path; lets the rolled-up
summary carry the audit envelope on behalf of the period it
summarizes.

### What landed

- **V015 migration** — two new tables in the cirisgraph schema:
  - `cirisgraph.telemetry_metrics` — raw observations; index on
    `(tenant_id, metric_name, observed_at)` for window scans;
    partial-key index on `expires_at` for the reaping path.
  - `cirisgraph.consolidation_locks` — multi-instance coordination;
    PK `(period_start, tenant_id)`; `locked_at` index for AV-53
    stale-lock detection.
- **Wire types** — `MetricObservation`, `MetricSummary`,
  `MetricFilter`, `MetricCursor`, `MetricListPage`,
  `ConsolidationRequest`, `ConsolidationOutcome { ran,
  broke_stale_lock, metrics_consolidated, summaries_written,
  edges_created, raw_metrics_deleted }`.
- **`TelemetryService` trait** — 4 methods: `record_metric`,
  `record_metrics_batch` (UNNEST-backed bulk insert),
  `list_metrics` (tenant-scoped cursor-paged), `consolidate_period`
  (the lock-acquire → aggregate → upsert-summary → write-edge →
  delete-raw → release-lock flow).
- **PostgresBackend impl**:
  - Aggregation via SQL `GROUP BY metric_name` with
    `SUM/MIN/MAX/AVG/COUNT(DISTINCT labels)` for label-cardinality
    observability (AV-52 telemetry signal).
  - Summary node UPSERT mirrors cirisgraph's `upsert_node` SQL
    shape — version-bumps on re-rollup (idempotent).
  - Prior-period lookup via `attributes @> {metric_name,
    tenant_id} AND (attributes->>'period_start')::timestamptz <
    period_start` — guarantees the TEMPORAL_NEXT source node exists
    (AV-54) and avoids self-edges on re-rollup.
  - Stale-lock auto-break via `UPDATE … WHERE locked_at < NOW() -
    INTERVAL '3600 seconds'` with the interval embedded (compile-
    time constant, no injection surface).
- **PyO3 surface** — 4 `Engine.telemetry_*` methods. JSON-in /
  JSON-out; `catch_panic` discipline; `telemetry::Error → PyErr`
  via `telemetry_err_to_py`.

### Threat-model anchors (THREAT_MODEL.md §4)

- **AV-52** — labels JSONB size cap (default 4 KiB; configurable);
  bulk path validates every row BEFORE any I/O. Cardinality cap
  per-(tenant, metric_name) is observability-only via
  `unique_label_combinations` field on summaries — runtime
  enforcement deferred until a real consumer trips the soft limit.
- **AV-53** — consolidation lock starvation: stale locks (>1h)
  auto-break with telemetry-actionable signal in
  `broke_stale_lock: true`. Failure-path lock release prevents
  orphaned locks on transient rollup errors.
- **AV-54** — TEMPORAL_NEXT chain integrity: pre-write lookup
  confirms prior summary exists; idempotent on re-rollup.

### Tests

- 7/7 telemetry tests against live `ciris-qa-postgres`:
  - 3 unit tests (error-kind stability, AV-52 default cap, AV-53
    stale threshold)
  - 2 serde round-trip tests
  - 1 full-lifecycle integration test covering record × 7 → AV-52
    oversized-labels reject → list with time-window + tenant
    filter → empty-tenant reject → consolidate period A
    (7 metrics → 3 summaries → 0 edges → 7 raw deleted) →
    idempotent re-run → write metrics in period B → consolidate
    period B (2 summaries + 2 TEMPORAL_NEXT edges to period A)
  - 1 lock-contention test (plant a fresh lock, confirm
    `consolidate_period` returns `ran=false`)
- 322/322 full lib pass (+7 from v0.8.1); clippy `-D warnings`
  clean across the full feature matrix.

### Unblocks (CIRISAgent migration)

- `TelemetryService` — record + list paths via the trait.
- `TSDBConsolidationService` — `consolidate_period` is the
  direct port of the agent's 6h rollup.

### References

CIRISPersist#36 (closes). Threat model: AV-52..AV-54.

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
