# Changelog

All notable changes per release. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) +
[Semantic Versioning](https://semver.org/spec/v2.0.0.html), with mission /
threat-model citations because this crate's audit story is the point.

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
