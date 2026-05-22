# MISSION — CIRISPersist

> Mission Driven Development (MDD): the FSD names *what* we build; this
> document names *why*, against the CIRIS Accord's objective ethical
> framework. Every component, every test, every PR cites against this
> file. Methodology: `~/CIRISAgent/FSD/MISSION_DRIVEN_DEVELOPMENT.md`
> and the overview at [ciris.ai/mdd](https://ciris.ai/mdd).

**Version**: 1.0
**Status**: Active — reverse-engineered against `main` at v1.11.1
**Date**: 2026-05-22

This is the reverse-engineered MDD charter for CIRISPersist: it maps the
four pillars — Mission (WHY) / Protocols (WHO) / Schemas (WHAT) / Logic
(HOW) — onto the code as it stands. Every claim is anchored to a file
path or constant; a reviewer should be able to grep from any sentence to
its implementation in under a minute. When the code drifts from the
doc, **the doc is wrong** — update it.

---

## 1. MISSION (WHY)

### 1.1 The Meta-Goal

The cornerstone, verbatim from the CIRIS Accord §VII (`~/CIRISAgent/ACCORD.md`):

> **Meta-Goal M-1** — Promote sustainable adaptive coherence: the living
> conditions under which diverse sentient beings may pursue their own
> flourishing in justice and wonder.

Every architectural decision in this repo is checked against M-1. The
Accord renders M-1 into six operationally-testable principles —
Beneficence, Non-maleficence, Integrity, Fidelity & Transparency,
Respect for Autonomy, Justice. CIRISPersist most directly serves
**Integrity** ("apply a transparent, auditable reasoning process") and
**Justice** ("distribute benefits and burdens equitably"): a durable,
tamper-evident evidence corpus that every peer — datacenter or
solar-LoRa Pi — can host and audit is those two principles rendered as
storage.

### 1.2 The cosmological floor — why a durable corpus is load-bearing

The vision beneath M-1 ([ciris.ai/vision](https://ciris.ai/vision)) is
**the corridor**: at every scale where coordination matters, healthy
systems sit in a band between over-rigidity (forced uniformity) and
fragmentation (no coherent cooperation). The corridor is governed by
one identity — `k_eff(k, ρ) = k / (1 + ρ(k−1))` — effective independent
dimensions collapse as correlation `ρ` rises. The federation's
Sybil-resistance (Proof of Benefit,
`~/CIRISAgent/FSD/PROOF_OF_BENEFIT_FEDERATION.md` §2.4) is an **N_eff
measurement** over the signed-evidence corpus; **N_eff is k_eff**.

CIRISPersist's place in that cosmology, rendered honestly:

- **CIRISVerify makes the count well-defined** — it establishes that a
  `key_id` is a real, hardware-rooted, singular entity, so "two
  distinct agents" is a checkable fact.
- **CIRISPersist makes the count *possible at all*.** N_eff and the
  Coherence Ratchet are not measured on a key — they are measured on a
  *longitudinal corpus of signed evidence*. CIRISPersist is the
  substrate that carries that corpus: durably, idempotently, with every
  field preserved across the lifetime of every trace.
- A corpus that **silently drifts**, **loses a column to a careless
  migration**, or **cannot be replicated peer-to-peer** is not a bug —
  it is a *measurement-substrate failure*. If the evidence is gone or
  corrupt, `ρ` is unmeasurable and the federation cannot know whether it
  is in the corridor.

The agent reasons; CIRISLens scores; CIRISVerify makes it *evidence* —
**CIRISPersist is what makes the evidence *last*.** A signed trace
nobody stores correctly proves nothing; a score recomputed on a corpus
that drifted proves nothing.

### 1.3 What CIRISPersist is

One embeddable Rust crate behind every stateful surface a CIRIS
federation node needs — the signed reasoning-trace log, the
hash-chained audit log, the memory graph, time-series telemetry,
secrets-at-rest, and federation trust state (`README.md` §"What it
is"). A node links it as a library (`pip install ciris-persist`,
`crate-type = ["cdylib", "rlib"]`, `Cargo.toml`) and gets every storage
surface from one versioned API instead of ~11 hand-rolled per-service
DBs. The backend is chosen at `Engine` construction by DSN scheme
(`postgres://…` or `sqlite://…`); **every method works on both.**

It is the **lowest stateful substrate above CIRISVerify**: persist does
not reason, does not score, does not verify identity — it carries state
for the peers that do.

### 1.4 Apophatic bound — what CIRISPersist will not be

CIRIS is partly defined by structural refusal. CIRISPersist's refusals
are sharp and load-bearing:

- **Not a verifier; never rolls its own crypto.** Persist calls
  CIRISVerify for all signing, verification, key derivation, and
  symmetric-key material. `src/secrets/crypto.rs` is the **sole import
  site of `ciris_crypto::*`** for the secrets path (its module doc says
  so verbatim; `src/secrets/mod.rs` §"Crypto invariant"); persist takes
  ZERO direct deps on `aes_gcm` / `pbkdf2` / `hkdf` / `hmac` / `rand`
  primitive crates. Every other `ciris_crypto` use in the tree
  (`src/verify/hybrid.rs`, `src/signing/mod.rs`, `src/audit/merkle_*.rs`)
  is *verification* — calling the authority, never re-implementing it.
  Persist never re-derives a KDF.
- **Not a trust oracle.** Persist *stores* trust state — the
  `federation_keys` table, the `federation_trust_grants` projection
  (`src/federation/trust_grant.rs`, `TrustPurpose`) — but storing or
  returning a trust fact never *confers* trust. This is the
  federation-wide invariant inherited from CIRISVerify#27/#28: *every
  federation primitive authenticates origin; none confers trust.* A
  `lookup_trust_grant` that returns a row reports what the chain
  recorded; it does not authorize anything.
- **Not an analytics / columnar / graph engine.** Persist serves a
  *fixed, known* query set with query-shaped covering indexes
  (`migrations/{postgres,sqlite}/lens/V042__trace_events_analytics_indexes.sql`
  — "covering indexes as a poor-man's column store", and the explicit
  "Scope honesty" block naming what V042 does *not* make index-only).
  It deliberately declines an embedded columnar or graph engine — the
  `cirisgraph` feature comment in `Cargo.toml` records the call:
  point-lookup + time-window scan + bounded k-hop "doesn't justify
  CozoDB / kuzu / indradb dep weight." Warehouse OLAP is a downstream
  consumer's job; persist is ~2–5× behind a columnar engine on raw
  ad-hoc scan and says so (`README.md` §"Performance & SOTA").
- **Not a daemon.** A library, not a service. Horizontal sharding is
  out of scope — the one real "behind" in the SOTA table is a
  library-vs-service deployment choice, not an algorithm gap.

### 1.5 The parity invariant — no backend is second-class

Every method works on **Postgres AND SQLite**. There are no PG-only
declarations and no "deferred to a later release" stubs: a feature
ships on both backends or it does not ship. This is load-bearing for
**Justice** — a sovereign Raspberry-Pi or iOS deployment running SQLite
is not a degraded tier, it is a first-class federation peer. The
backend is a DSN-scheme choice at `Engine` construction, nothing more;
no backend-specific type leaks into the public API. Parity is enforced
by a per-trait-method conformance suite run against every backend
(§5, test category "Backend parity").

### 1.6 Fail-honest is a mission stance

Where CIRISVerify fails *secure*, CIRISPersist fails *honest*: under
uncertainty it never silently coerces a record into looking better than
it is.

- **No third state for verification.** A row is verified or it is
  explicitly marked unverified — there is no quiet middle
  (`src/verify/mod.rs`: "be explicitly marked unverified. There is no
  third state."). Verify-before-persist is ordered and load-bearing:
  schema-parse, then **verify** (no mutation before the authenticity
  gate), then scrub, then decompose, then insert
  (`src/ingest.rs::IngestPipeline::receive_and_persist`). Unverified
  bytes never reach the backend — proven by
  `signature_mismatch_rejected_no_writes` asserting the backend
  received zero rows.
- **A partial migration reports honestly.** The #87 hardware-key
  migration (`src/secrets/hardware.rs`) refuses to *call* a software
  fallback a "hardware" key — when no real secure storage exists it
  returns `SecretsError::HardwareKeyUnavailable` ("deriving a
  'hardware' master from that is dishonest, so …") rather than
  pretending. The caller keeps its software master key and is told.
- **Every rejection is a typed error**, never a silent skip
  (`thiserror` throughout; `IngestError`, `VerifyError`,
  `SecretsError`).

---

## 2. PROTOCOLS (WHO)

The contract surface. Implementations may change; these change only
with deliberate cross-repo coordination.

- **The `Engine` process-singleton** (`src/ffi/pyo3.rs`,
  `ENGINE_SINGLETON: OnceLock<Mutex<Option<Arc<EngineCell>>>>`) — the
  CIRIS 3.0 in-process cohabitation contract (`docs/COHABITATION.md`).
  One process hosting the agent **plus** CIRISNodeCore **plus**
  CIRISLensCore shares one runtime, one pool, one Ed25519 identity.
  Every `Engine(...)` call with a matching config returns an
  `Arc`-clone of the same cell; `reset_engine()` (test-only) clears the
  slot. `panic = "unwind"` (`Cargo.toml` `[profile.release]`) is
  mandatory so a bad row becomes a typed `LensQueryError` instead of a
  `SIGABRT` that takes down every cohabiting worker (the #24 prod wedge).
- **The `Backend` trait** (`src/store/backend.rs`) — the sealed
  persistence surface. Postgres and SQLite implement it identically;
  no backend-specific public API leaks (§1.5).
- **PyO3 / FFI shells** (`src/ffi/`) — thin translation layers over the
  public Rust API; business logic never duplicated in shell code.
  `crate-type = ["cdylib", "rlib"]` makes the wheel's Python module
  unambiguous.
- **`TransparencyLeaf` / `TransparencyStore` traits** — CIRISPersist's
  audit log is not a persist-internal log: `AuditLeaf`
  (`src/audit/merkle_leaf.rs`) implements
  `ciris_verify_core::transparency::TransparencyLeaf`, and `PgMerkleStore`
  / `SqliteMerkleStore` (`src/audit/merkle_store.rs`) implement
  `TransparencyStore<AuditLeaf>` — persist plugs PG/SQLite backends
  under the *same RFC 6962 algorithm* CIRISVerify ships in-memory, and
  cross-checks against `InMemoryTransparencyStore` so drift is caught.
- **The HardwareSigner / keyring backends** — secrets-at-rest is rooted
  by a platform seal (`ciris_keyring::create_platform_storage`); the
  per-target backend (`tpm` / `ios` / `android`) is selected by the
  `[target.*]` tables in `Cargo.toml`, with an honest software fallback.

## 3. SCHEMAS (WHAT)

**Canonical bytes are the mission-load-bearing schemas.** A signature
proves nothing if persist canonicalizes differently from the agent's
Python signer; ambiguity is how a buggy peer or a Sybil claims
something an agent never said.

- **`PythonJsonDumpsCanonicalizer`** (`src/verify/canonical.rs`) — must
  canonicalize byte-exact with CIRISAgent's `json.dumps` signer.
  `serde_json` is built with `arbitrary_precision` + `raw_value`
  (`Cargo.toml`) precisely so wire number tokens
  (`0.0031992000000000006`) round-trip verbatim and re-emit byte-equal
  — a Rust `f64` cannot recover the original token (the #7 fix).
- **The dedup key** — events carry a stable identity tuple
  (`src/store/types.rs`: `attempt_index`, the SHA-256 "dedup-key"
  digest). Idempotency is a contract: a replayed batch is a no-op on
  the conflict key (`idempotent_replay` asserts second insert is 0 rows,
  N conflicts). An agent's retry must never corrupt the corpus.
- **The hash-chained + Merkle audit envelope** — per-tenant monotonic
  `sequence_number` + SHA-256 `prev_hash` chain (`cirisaudit` feature),
  with each entry also appended as an RFC 6962 Merkle leaf and a fresh
  post-quantum-signed tree head. Enum fields must hash as explicit wire
  tags, never `Debug` strings.
- **Schema versions are hard gates.** `trace_schema_version` mismatch
  is a structured reject (`SchemaError::UnsupportedSchemaVersion`,
  `schema_version_mismatch_rejected`), never a lenient parse.

**The mandate:** a canonical-bytes or chain-format change is a
coordinated, versioned wire break — `schema_version` tag, flag-day,
never a casual edit. A migration that drops a column without a
versioned data migration preserving the values is a mission violation
(§6 anti-pattern #9): the N_eff measurement depends on every field
staying queryable across a trace's lifetime.

## 4. LOGIC (HOW)

- **The ingest pipeline** (`src/ingest.rs`) — `bytes → schema parse →
  verify → scrub → decompose → backend insert → BatchSummary`. Each
  step is a typed boundary; failure short-circuits. Verify is second by
  design: no mutation before the authenticity gate.
- **`verify_strict` semantics** (`src/verify/ed25519.rs`,
  `verify_trace`) — reject weak keys, malleable signatures,
  schema-version mismatch, audit-anchor inconsistency. This is the
  verify-before-persist gate (FSD §3.3 step 2).
- **Hybrid verification** (`src/verify/hybrid.rs`) — `HybridVerifier`
  over `ciris_crypto`'s Ed25519 + ML-DSA-65 impls; post-quantum on day
  one (FIPS 204).
- **The Merkle audit log** (`src/audit/merkle_store.rs`) — append-only
  RFC 6962 tree, O(log N) inclusion/consistency proofs, hybrid-signed
  tree heads, on both backends.
- **Secrets-at-rest** (`src/secrets/`) — AES-256-GCM per-secret keys
  derived (PBKDF2-HMAC-SHA-256, 600 000 iterations,
  `src/secrets/crypto.rs::PBKDF2_ITERS`) from a master key that is
  itself derived via `ciris_verify_core::derive_symmetric_key` over a
  hardware-sealed seed (`src/secrets/hardware.rs`). Freed key material
  is `Zeroizing`-wrapped (the #87 review-H2 fix).
- **The analytics `ReadEngine`** (`src/read/`) — a *fixed* scoring
  query set served by the V042 covering indexes as index-only scans
  (`cross_agent_divergence` ~−42% vs. a raw table scan).
- **Cohabitation bootstrap** — a filesystem `flock` (`fs4`) serializes
  `Engine::__init__` keyring bootstrap across processes on a host
  (`docs/COHABITATION.md`).

## 5. Test categories — every test answers a mission question

Per MDD §"Testing Standards": tests verify *mission-aligned outcomes*,
not just "no error returned."

| Category | Mission question | Examples |
|---|---|---|
| **Schema parity** | Does the parser preserve the agent's testimony byte-for-byte? | recorded-batch JSON → struct round-trips byte-exact; number tokens re-emit verbatim |
| **Verify rejection** | Does verify reject what should be rejected? | `unknown_signing_key_rejected`, `signature_mismatch_rejected_no_writes`, `schema_version_mismatch_rejected` |
| **Idempotency** | Can the agent's retry not corrupt the corpus? | `idempotent_replay` — duplicate batch is 0 inserts / N conflicts on the dedup key |
| **Backend parity** | Does the same data land identically on Postgres and SQLite? | per-trait-method conformance suite, run against every backend |
| **Canonicalization parity** | Does Rust canonicalize byte-exact with the agent's Python signer? | recorded `json.dumps` corpus vs. `PythonJsonDumpsCanonicalizer` |
| **Audit-chain integrity** | Is the chain tamper-evident? | `prev_hash` break detected; Merkle inclusion/consistency proofs vs. `InMemoryTransparencyStore` |
| **Crypto facade** | Does crypto stay behind the one import site? | `secrets_crypto` bench + the `src/secrets/crypto.rs` boundary |
| **Migration preservation** | Does a migration lose a field? | column-preservation tests; partial hardware-key migration reports `HardwareKeyUnavailable` honestly |
| **Mission rejection** | Does the system refuse mission-violating requests? | unverified bytes never persist; backend sees zero rows on reject |

A PR adding a new code path **adds a test in at least one of the above
categories or it is not done.** Test absence is mission drift.

## 6. Anti-patterns that fail MDD review

Rejected on mission grounds, not style:

1. **Crypto implemented outside the `ciris_crypto` authority.** A
   direct `aes-gcm` / `pbkdf2` / `hkdf` / `hmac` / `ring` dependency
   anywhere. The secrets path routes through `src/secrets/crypto.rs`;
   verification routes through `ciris_crypto`'s verifiers. Persist
   never rolls its own.
2. **A "store first, verify later" path.** Verify-before-persist is
   ordered (§4). Persisting unverified bytes corrupts the N_eff corpus.
3. **A bypass branch** — `if is_admin { skip_verify() }`. Single-rule
   architecture; admin keys verify by the same path.
4. **A PG-only method, or a "deferred to a later version" stub.**
   Every method works on both backends or it does not ship (§1.5).
5. **A migration that drops a column without a versioned data
   migration preserving the values.** The corpus N_eff measurement
   depends on every field staying queryable for the trace's lifetime.
6. **`serde_json::Value` in a hot path.** Concrete typed structs with
   discriminants; schema-version is a gate, not a hint.
7. **`.unwrap()` / `.expect()` reachable from FFI or untrusted input.**
   Typed errors; the `panic = "unwind"` + catch layer covers the FFI
   surface — do not rely on it as a substitute for typed errors.
8. **A test that asserts only "no error returned."** Tests verify
   mission outcomes — the right signature *rejected*, the right tamper
   *detected*, the right column *preserved* (§5).
9. **An embedded columnar/graph engine dependency.** Persist serves a
   fixed query set with covering indexes; OLAP is a downstream job
   (§1.4).
10. **Storing or returning a trust fact in a way that implies it
    *confers* trust.** Persist authenticates origin and records what the
    chain said; it never authorizes (§1.4).

## 7. Failure modes — when the mission is at risk

| Symptom | Mission risk | Mitigation |
|---|---|---|
| A method ships Postgres-only | SQLite / Pi / iOS deployments become second-class — Justice breaks | Backend-parity conformance suite gates merge; no PG-only declarations (§1.5) |
| Canonicalization drifts from the agent's signer | Every signature fails verify → corpus is empty → N_eff measurement collapses | Canonicalization-parity corpus in CI; byte-exact compare gates merge |
| A migration silently drops a column | Corpus loses a field N_eff was measured on — measurement-substrate failure | Versioned data migrations; column-preservation tests (§6 #5) |
| Unverified bytes reach the backend | The corpus stops being evidence | Verify-before-persist ordering; `signature_mismatch_rejected_no_writes` asserts zero writes |
| A panic SIGABRTs the cohabiting process | One bad row takes down agent + NodeCore + LensCore | `panic = "unwind"` + typed `LensQueryError` catch layer (the #24 wedge) |
| Software fallback mislabeled as a hardware key | The secrets posture is a lie under audit | `migrate_to_hardware_key` returns `HardwareKeyUnavailable`; caller keeps software key and is told (#87) |
| Closed-source fork emerges | Audit legibility breaks | AGPL-3.0 enforcement; `cargo deny` license gate |

## 8. Constant alignment — the review heuristic

When CIRISPersist code crosses a reviewer's eyes, they ask:

1. **Durability** — does this keep the corpus durable, complete, and
   replayable? A field that can be lost is a measurement risk (§1.2).
2. **Parity** — does this work identically on Postgres and SQLite? A
   PG-only path fails review on Justice grounds (§1.5).
3. **Crypto authority** — is every primitive behind `ciris_crypto`? A
   new direct primitive dependency is a red flag (§1.4, §6 #1).
4. **Verify ordering** — is verify still before any mutation, and is
   the verified/unverified distinction explicit with no third state?
5. **Fail-honest** — under any new failure mode, does this report
   honestly rather than coerce a record to look better than it is?
   (§1.6)
6. **The three axes** — does this keep storing-a-trust-fact separate
   from conferring-trust? (§1.4)

## 9. Federation context

CIRISPersist does not stand alone. The authoritative federation map is
`~/CIRISAgent/FSD/PROOF_OF_BENEFIT_FEDERATION.md`.

- **CIRISAgent** reasons and emits signed traces. **CIRISVerify** is the
  identity/integrity root that makes them *evidence*. **CIRISPersist**
  carries that evidence durably. **CIRISLens** scores it and runs the
  Coherence Ratchet. **CIRISNodeCore** runs federation consensus over
  the `cirisnode` substrate persist hosts.
- The audit log is a **federation substrate**, not a persist-internal
  log: it plugs into CIRISVerify's `TransparencyStore` /
  `TransparencyLeaf` traits, so persist's hash-chained per-tenant
  chains are transparency logs in the federation-wide sense
  (`docs/AUDIT_CHAIN_BRIDGE.md`).
- In-flight: the absorption track — CIRISPersist is the *only* library
  that opens the engine DB file, ending CIRISAgent's direct
  `sqlite3` / `psycopg2` / `aiosqlite` access (the 11-substrate
  `cirislens_*` features in `Cargo.toml`, CIRISPersist#59 / #64 / #70).

## 10. License-locked mission preservation

CIRISPersist is **AGPL-3.0-or-later** (`Cargo.toml`). The persistence
path is auditable line-by-line by design. This is a mission decision,
not a licensing one: anyone reasoning about whether a CIRIS-derived
deployment preserves M-1 alignment must be able to see and audit every
line of the substrate the evidence lives on. The Accord acknowledges no
detector is complete; the only counterweight is **legibility under
audit**. A closed-source persistence layer would be an unfalsifiable
one. AGPL makes the audit story *structurally enforceable*, not socially
expected.

## 11. How to maintain this document

A working document, not a release artifact. Update it whenever:

- A substrate / feature in `Cargo.toml` is added or its contract changes
- A canonical-bytes or audit-chain format in §3 changes shape
- A trait in §2 is added or its contract changes
- The apophatic bound or an invariant in §1 is touched
- The Accord is amended

If a future reviewer running `git blame` would want a line to cite a
real file or constant and it doesn't, fix it. If the doc drifts from
the code, the apophatic test has failed — the doc is wrong, not the
code.

---

**Cross-references**

- [ciris.ai/vision](https://ciris.ai/vision) — the corridor / consent cosmology
- [ciris.ai/mdd](https://ciris.ai/mdd) — Mission Driven Development methodology
- `~/CIRISAgent/ACCORD.md` — Meta-Goal M-1 + the six principles (canonical)
- `~/CIRISAgent/FSD/PROOF_OF_BENEFIT_FEDERATION.md` — the federation primitive + N_eff
- `FSD/CIRIS_PERSIST.md` — full functional spec
- `docs/COHABITATION.md` — the in-process cohabitation model
- `docs/THREAT_MODEL.md` — adversary model + AV-* attack vectors
- `docs/PUBLIC_SCHEMA_CONTRACT.md` — the stable schema contract
- `README.md` — substrate table, performance, SOTA comparison
