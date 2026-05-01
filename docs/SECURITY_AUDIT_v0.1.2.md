# Security Audit — `ciris-persist` v0.1.2

**Status:** Pass 3 (SOTA / best-practice gap analysis) of the
post-0.1.1 audit. Companion to `docs/THREAT_MODEL.md` (which
catalogs the threats) — this document catalogs the **defense-in-depth
gaps** measured against current Rust security best practice and
the federation-primitive literature the FSD cites.

**Audit date:** 2026-05-01.
**Crate state:** v0.1.2 at commit `d9330ee`.
**Methodology:** §1 below.
**Companion docs:** [`docs/THREAT_MODEL.md`](THREAT_MODEL.md),
[`MISSION.md`](../MISSION.md), [`FSD/CIRIS_PERSIST.md`](../FSD/CIRIS_PERSIST.md).

---

## 1. Methodology

This pass is distinct from the threat model in scope:

- **Threat model** asks: *"what attacks does the system face, and
  how does it defend?"* — it's the adversary-eye view.
- **Security audit (this doc)** asks: *"what does current Rust
  + federation SOTA think we should be doing that we aren't?"* —
  it's the defender-eye view, hunting for unknown unknowns.

The two intersect: a defense-in-depth gap surfaced here can be a
new attack vector for the threat model. When that happens it's
catalogued in §3 and back-referenced into THREAT_MODEL.md.

### Tools / checks run

| Check | Tool | Coverage |
|---|---|---|
| Known CVEs in deps | `cargo audit` | 299 crates; 0 vulnerabilities |
| License + advisory enforcement | `cargo deny` | All deps; AGPL-family + permissive only; clean |
| Dep tree review | `cargo tree --features all` | No abandoned crates; no unmaintained-track records |
| Memory unsafety | `grep "unsafe " src/` | Zero `unsafe` blocks in our code |
| Lint baseline | `cargo clippy -- -D warnings` | Clean |
| Lint pedantic | `cargo clippy -- -W clippy::pedantic` | 154 warnings reviewed; 9 are real defense-in-depth gaps (catalogued §3) |
| Fmt | `cargo fmt --all -- --check` | Clean |
| Test rigor | `cargo test --features all` | 92 lib + 9 fixture; missing fuzz / property-based |
| Migration shape | `psql --dry-run` (manual review) | V001 idempotent IF NOT EXISTS; lens-compat |

### SOTA references this audit checked against

- [Rust Secure Code Working Group recommendations](https://anssi-fr.github.io/rust-guide/) (ANSSI; updated 2026)
- [The Rustonomicon — security-relevant invariants](https://doc.rust-lang.org/nomicon/)
- [`cargo-deny`/`cargo-audit` user guides](https://embarkstudios.github.io/cargo-deny/)
- [SLSA v1.0 supply-chain framework](https://slsa.dev/)
- [OWASP API Security Top 10 (2026)](https://owasp.org/API-Security/)
- [PyO3 — handling panics across the FFI](https://pyo3.rs/main/exception.html)
- [tokio-postgres TLS guide](https://docs.rs/tokio-postgres/latest/tokio_postgres/) — `MakeTlsConnector` patterns
- PoB §6 (residual quantum risks) and §5.6 (rate limiting per agent)
- TRACE_WIRE_FORMAT.md §6 (`attempt_index` semantics) for the integer-bounds question
- Federation literature on replay-window enforcement (out-of-protocol replay-cache patterns)

---

## 2. Positive findings — what we do well

These are the things current SOTA *also* does, that we already do.
Worth naming so they don't get lost when we look at the gaps below.

| Practice | Evidence |
|---|---|
| **Zero `unsafe` in our code** | `grep "unsafe " src/` returns nothing |
| **Typed errors at every layer** | `schema::Error`, `verify::Error`, `scrub::ScrubError`, `store::Error`, `ingest::IngestError`, `journal::JournalError`, `queue::QueueError`. No `anyhow` in the library; only the `thiserror` enum-per-layer pattern. |
| **Strict-verify Ed25519** | `key.verify_strict(...)` rejects malleable signatures, weak keys, small-order points. (verify/ed25519.rs) |
| **Parameterized SQL only** | No format-string SQL anywhere; tokio-postgres typed binding throughout (postgres.rs, ffi/pyo3.rs) |
| **`ON CONFLICT DO NOTHING` matched to UNIQUE index** | Conflict target spelled out fully; no implicit-PK conflicts |
| **`refinery` migrations with idempotent `IF NOT EXISTS`** | V001 no-ops on extant lens DBs (THREAT_MODEL.md AV-11 reconciliation) |
| **Pluggable canonicalizer** | Not married to one signing convention; `Canonicalizer` trait + Python-compat impl + RFC8785 dev-test impl |
| **Bounded queue + journal-on-failure** | `DEFAULT_QUEUE_DEPTH=1024`; outage-tolerant (FSD §3.4 #1, #2) |
| **Backpressure honest** | 429 + `Retry-After` instead of silent drop (FSD §3.4 #5) |
| **Body-size cap** | `DefaultBodyLimit::max(8 MiB)` (v0.1.2 AV-7) |
| **Recursion-depth cap on `data` blobs** | `MAX_DATA_DEPTH = 32` (v0.1.2 AV-6) |
| **Schema-version strict allowlist** | `SUPPORTED_VERSIONS` is `&[&str]`, not regex (FSD §3.4 #3) |
| **Public-key directory with revocation + expiry** | Lens-canonical schema includes `revoked_at`, `revoked_reason`, `expires_at` (v0.1.2 Path B) |
| **Error sanitization at FFI boundary** | `kind()` tokens for HTTP / PyO3; verbose form to tracing logs only (v0.1.2 AV-15) |
| **AGPL-3.0+ license-locked** | `cargo deny` enforces; closed-source forks blocked structurally |
| **No `serde_json::Value` in verify hot path** | Every event variant has a typed accessor; `data` JSONB is opaque-by-design at storage time |
| **Mission-aligned tests** | 101 tests organized by mission category (MISSION.md §4) |
| **Real-fixture integration tests** | 9 tests against captured signed traces from CIRISAgent `release/2.7.8` |
| **CI matrix multi-arch** | linux x86_64 + aarch64 cross-compile + macOS + iOS device + lint + audit + wheel |
| **`cargo audit` clean** | 0 vulnerabilities across 299 deps |
| **`cargo deny` clean** | License + advisory audit clean |

These are the load-bearing properties the lens team's integration
should depend on. The gaps below don't undermine them; they ask
"what else *should* we be doing?"

---

## 3. New attack vectors discovered (extends THREAT_MODEL.md)

Five new attack vectors surfaced in this pass that THREAT_MODEL.md
v0.1.2 doesn't yet catalog. Each maps to a specific code site.

### AV-17: Integer truncation on `attempt_index`

**Severity: P0** (defense-in-depth — extends AV-9 dedup-key concern).

**Attack**: Adversary submits a component with
`"attempt_index": 4294967296` (`u32::MAX + 1` as i64). The
`schema::TraceComponent::attempt_index()` does `n as u32`, which
silently truncates to `0`, colliding with the legitimate first-attempt
row on the dedup tuple (THREAT_MODEL.md AV-9 already extended the
tuple to include `agent_id_hash`, but truncation is orthogonal:
within the *same* agent, the attacker can pre-claim their *own*
`attempt_index=0` row by submitting a `2^32` later).

Same risk in postgres.rs's `row.attempt_index as i32` path: u32
values above `2^31 - 1` wrap to negative.

**Code sites**:
- `src/schema/trace.rs:60` — `Ok(n as u32)`
- `src/store/postgres.rs:185` — `params.push(Box::new(row.attempt_index as i32))`
- `src/store/postgres.rs:278-279` — `parent_attempt_index` and `attempt_index` casts on `trace_llm_calls` insert

**Mitigation**: enforce a hard cap `MAX_ATTEMPT_INDEX = 1024` on
parse. Legitimate retry counts bounded by FSD §5.5 / agent
`recursive_processing.py` are < 5; 1024 is overkill for safety.
Use `try_into()` with a typed error variant
(`Error::AttemptIndexOutOfRange { got, max }`) instead of `as`.

**Recommended for v0.1.3 hot-fix.**

### AV-18: Plaintext Postgres connection

**Severity: P1** (operational — affects sovereign-mode deployments).

**Attack**: a sovereign-mode lens with a remote Postgres (e.g., Pi
in the field, RDS instance over WAN) sends signed traces over
plaintext to the DB. Network observer between the lens and the DB
sees the agent's testimony in cleartext. TLS at the *agent → lens*
HTTP boundary doesn't help here.

**Code site**: `src/store/postgres.rs:83` —
`cfg.create_pool(Some(Runtime::Tokio1), NoTls)`

**Mitigation**: optional `tls` feature pulling in
`tokio-postgres-rustls` or `postgres-native-tls` (we already have
the latter transitively). Configurable via DSN params (`sslmode=verify-full`)
or env var.

**Recommended for v0.1.3 hot-fix** (one new optional feature flag).

### AV-19: No graceful shutdown for the Phase 1.1 standalone server

**Severity: P1** (operational — Phase 1.0 PyO3 path inherits FastAPI's signal handling, so this is Phase 1.1-only).

**Attack**: Operator sends `SIGTERM` to the standalone Rust binary
during a busy ingest period. The bounded queue still has work; the
persister task is mid-batch; in-flight Postgres transactions get
killed mid-commit. Some signed batches end up neither committed
nor journaled.

**Code site**: `src/server/mod.rs::router()` — no shutdown channel
plumbed through.

**Mitigation**: `tokio::signal::ctrl_c()` + drain protocol. On
SIGTERM: stop accepting new requests (close the producer side of
the queue), let the persister drain pending work, *then* exit. The
journal already preserves bytes-on-failure, but graceful shutdown
prevents in-flight commits from being lost mid-transaction.

**Recommended for v0.1.3 hot-fix** (~30 lines + a test).

### AV-20: No statement timeout on Postgres

**Severity: P2** (operational).

**Attack**: A pathological Postgres lock (other tenant's long
transaction, dead replica, etc.) causes our queries to hang
indefinitely, holding a connection from the pool. Pool exhausts
under load; the lens stops ingesting; agents pile retries onto the
queue.

**Code site**: `src/store/postgres.rs::PostgresBackend::connect()`
— no `statement_timeout` set.

**Mitigation**: `client.execute("SET statement_timeout = '30s'", &[])`
on connection acquisition. Configurable via env var.

**Recommended for v0.2.x.**

### AV-21: No per-agent rate limiting

**Severity: P2** (federation primitive).

**Attack**: A single legitimate agent (or one that registered a
key but is misbehaving) submits at a rate that saturates the queue,
denying other agents service. PoB §5.6 gestures at this as
"acceptance policy" but the persistence layer has no per-agent
enforcement.

**Mitigation**: Token-bucket per `agent_id_hash` (or per
`signature_key_id`). Cap default 100 batches/sec/agent;
configurable. When exceeded, agent gets 429 instead of the
shared queue's 429. Fairness across agents under load.

**Recommended for v0.2.x.** Phase 2 peer-replicate will need this
shape anyway for cross-peer rate-limiting.

### AV-22: No clock-skew validation on incoming timestamps

**Severity: P2** (federation primitive).

**Attack**: An attacker (or a misconfigured agent) submits batches
with `batch_timestamp: "1970-01-01T00:00:00Z"` or
`"2099-12-31T23:59:59Z"`. The lens accepts and stores them. The
PoB §2.4 N_eff measurement window now has noise from
out-of-window data; retention policies (compression at 7d, drop at
30d) misbehave.

**Code site**: `src/schema/envelope.rs::BatchEnvelope::from_json` —
`batch_timestamp`, `consent_timestamp`, plus per-trace
`started_at`, `completed_at` are all unbounded.

**Mitigation**: bound timestamps to `[now - 7 days, now + 5 minutes]`.
Out-of-window → typed `Error::ClockSkew { got, allowed }`. The
±5min upper bound matches CIRISVerify's clock assumption (its
THREAT_MODEL.md §6 #5).

**Recommended for v0.2.x.**

### AV-23: `consent_timestamp` range unconstrained

**Severity: P3** (correctness — not exploitable, but data-quality drift).

**Attack-adjacent**: an agent shipping `consent_timestamp` in the
year 1990 silently records pre-existence consent claims. The
FastAPI path the lens currently uses returns 422 if missing
(TRACE_WIRE_FORMAT.md §1 invariant), but doesn't bound the value.

**Mitigation**: `consent_timestamp` must be in range
`[2020-01-01, batch_timestamp]`. Track for v0.2.x; mostly a
data-quality concern unless an attacker uses it to game retention
queries.

---

## 4. Hardening gaps (general defense-in-depth)

These are gaps in the *defense scaffolding*, not specific to any
attack vector. Each is a one-line change or a small subsystem
that current Rust SOTA recommends.

### 4.1 `#![forbid(unsafe_code)]` (P1)

**Gap**: `src/lib.rs` doesn't `forbid(unsafe_code)`. We don't
*have* any `unsafe` code, but the absence of the gate means a
future PR could introduce some without anyone noticing.

**Recommended fix**: `#![forbid(unsafe_code)]` at the top of
`src/lib.rs`. v0.1.3 hot-fix scope. (Note: PyO3 + redb + tokio-postgres
all have transitive `unsafe`, which is fine and out of our scope —
forbidding only applies to our crate.)

### 4.2 `panic = "abort"` in release profile (P1)

**Gap**: A panic in the persister task (e.g., a future
`unwrap()` we haven't audited yet, or a bug in a transitive dep)
unwinds and propagates up the tokio runtime. With abort, the
process dies fast and the supervisor (systemd, k8s) restarts —
which exercises the journal-replay path. With unwind (the default),
the process can end up in a weird half-shut state with no
restart trigger.

**Recommended fix**:

```toml
[profile.release]
panic = "abort"
```

v0.1.3 hot-fix scope.

### 4.3 `overflow-checks = true` on release (P1)

**Gap**: Default Rust release builds disable overflow checks for
performance. AV-17 (integer truncation on `attempt_index`) is the
exact class of bug overflow checks would have caught at runtime.

**Recommended fix**:

```toml
[profile.release]
overflow-checks = true
```

The performance cost is single-digit-percent for typical code.
v0.1.3 hot-fix scope, paired with AV-17's typed-error fix.

### 4.4 `#![deny(missing_docs)]` for public API (P3)

**Gap**: Public items can ship without doc comments. Most of our
public API *is* documented (mission-driven docs are dense), but
without a deny gate, future additions can ship undocumented.

**Recommended fix**: `#![deny(missing_docs)]` at lib root. Track
for v0.2.x; minor PR ergonomics improvement.

### 4.5 `clippy.toml` with MSRV pin + extra lint levels (P2)

**Gap**: No `clippy.toml`. CI runs `cargo clippy -- -D warnings`
which catches the default lint set. Rust 1.95 added
`cloned_ref_to_slice_refs` (we hit it in v0.1.1) — the next Rust
release will add more. Without a pinned MSRV and a tracked lint
set, a clippy version bump on the runner can break CI for
unrelated reasons.

**Recommended fix**: `clippy.toml`:

```toml
msrv = "1.75"
allow-print-in-tests = true
```

Plus selective `#[allow(clippy::pedantic_lint)]` per-item where
appropriate. v0.2.x track.

### 4.6 No graceful shutdown / signal handling (P1)

See AV-19 above; same fix.

### 4.7 No metrics endpoint / OpenTelemetry hooks (P2)

**Gap**: The lens has no operational visibility into the persister
beyond the `/health` endpoint. Mission category §4 "Backpressure"
asserts honesty, but ops needs to see *over time* — queue depth
trend, journal pending count trend, p99 ingest latency.

**Recommended fix**: optional `metrics` feature pulling in
`metrics` + `metrics-exporter-prometheus`. Phase 1 scope. Or:
`tracing` with a structured-fields convention that an
OpenTelemetry collector picks up. Track for v0.2.x.

### 4.8 No correlation IDs in HTTP error responses (P2)

**Gap**: AV-15 sanitization (v0.1.2) emits stable `kind()` tokens
in HTTP responses but no per-request `correlation_id`. Ops can't
correlate a 422 the agent saw with the verbose tracing log line
that explains what content was rejected.

**Recommended fix**: `tower::ServiceBuilder::new().layer(SetXRequestIdLayer)`
or hand-rolled UUID per request, threaded through to the typed
error responses (`detail`, `correlation_id`). v0.2.x track.

### 4.9 `proptest` dev-dep is declared but unused (P3)

**Gap**: `Cargo.toml` declares `proptest = "1"` as a dev-dep. No
proptest-driven property tests exist. Property-based testing on
the canonicalizer (no float drifts on shortest-round-trip outputs),
the dedup-key (no collisions for distinct inputs), and the
schema parser (random JSON doesn't crash) would close the
"unknown unknowns" hatch this audit hunts for.

**Recommended fix**: write 3-5 proptest properties:
- `prop: canonicalize(deserialize(serialize(x))) == canonicalize(x)`
  for any well-formed JSON value
- `prop: dedup_key(row) is unique within a batch iff inputs are unique`
- `prop: BatchEnvelope::from_json(arbitrary_bytes) never panics`

v0.2.x track.

### 4.10 No fuzzing harness (P3)

**Gap**: No `cargo fuzz` target. The wire-format parser is the
adversarial entry point; fuzz coverage would catch undeserializer
panics that escape proptest's structured-input bias.

**Recommended fix**: `cargo fuzz` target hitting
`BatchEnvelope::from_json(&[u8])` with libFuzzer. v0.2.x track;
typical lens deployments run behind a TLS-terminating proxy
that bounds the malformed-input class anyway.

### 4.11 No SLSA wheel provenance (P3)

**Gap**: The maturin wheel published as a CI artifact has no
SLSA v1.0 provenance attestation. A downstream consumer (lens
deploy script pulling the artifact) can't cryptographically
verify which CI run + commit produced it.

**Recommended fix**: GitHub Actions workflow step using
`slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1`.
Bundle the provenance JSON with the wheel artifact. v0.2.x track;
not a current threat (the lens build pulls from a pinned commit
via Dockerfile multi-stage anyway).

### 4.12 No PyO3 panic policy at the FFI boundary (P2)

**Gap**: A panic in Rust code called via PyO3 unwinds across the
FFI boundary, which is undefined behavior. PyO3 wraps panics into
Python exceptions in most cases, but a panic during the
*construction* of the panic message (e.g., panic-in-Drop) can
abort the process from the wrong stack frame.

**Recommended fix**: `std::panic::catch_unwind` wrappers on every
`#[pymethods]` method, converting panics to `PyRuntimeError`. PyO3
0.28 has a built-in pattern for this; we currently rely on its
default behavior.

v0.1.3 hot-fix scope (cheap; defense in depth).

### 4.13 No `release-please` / automated release notes (P3)

**Gap**: Each release tag is hand-written. Conventional Commits +
release-please would automate the CHANGELOG entry from commit
messages. Track for v0.2.x.

---

## 5. Federation-primitive gaps (PoB / FSD-specific)

These don't exist in generic-Rust SOTA — they're specific to the
PoB §2.4 N_eff measurement and the FSD's federation roadmap.

### 5.1 No replay-window enforcement beyond dedup (P2)

**Gap**: AV-3 (replay protection) relies entirely on the
`(agent_id_hash, trace_id, thought_id, event_type, attempt_index, ts)`
UNIQUE index. A captured batch *replayed at a different lens* lands
once cleanly (not a defect — that's the federation behavior PoB
§5.1 calls for). But there's no protection against an attacker
replaying the same batch *to the same lens* after the underlying
data has been retention-dropped (TimescaleDB drops at 30 days; an
attacker with a 31-day-old captured batch can re-claim the dedup
slot).

**Mitigation**: a `seen_batches` table with `(agent_id_hash, batch_hash, first_seen_at)`.
Retain forever. Reject on replay even if `trace_events` rows have
been retention-dropped.

**Recommended for v0.2.x.** Tracked alongside Phase 2 peer-replicate
(FSD §4.5).

### 5.2 No N_eff drift alerting hooks (P3)

**Gap**: PoB §5.9 names continuous N_eff self-monitoring as
partially-resolved. The persistence layer is the substrate the
measurement runs over — exposing structured fields for the score
function to consume cheaply (event-rate per agent, retry distribution,
etc.) is a v0.2.x deliverable.

**Recommended for v0.2.x.**

### 5.3 No agent-key rotation API (P1, tracked in THREAT_MODEL.md AV-11)

Already documented. Key rotation today goes through manual lens
admin tooling against `revoked_at` + `revoked_reason`; explicit
`rotate_public_key(rotation_proof: signed-by-old-key)` is
v0.2.x.

---

## 6. Recommended v0.1.3 hot-fix scope

P0 + P1 items from §3 and §4 that are small, contained, and worth
shipping before the lens hits production load:

```
v0.1.3 — defense-in-depth hot-fix
  □ AV-17: attempt_index integer-truncation guard
      - Cap MAX_ATTEMPT_INDEX = 1024 on parse
      - Replace `as u32` / `as i32` with try_into + typed error
      - Tests: u32::MAX+1 → typed Error::AttemptIndexOutOfRange
  □ AV-18: optional `tls` feature for Postgres
      - tokio-postgres-rustls behind feature flag
      - Document in INTEGRATION_LENS.md (sslmode=verify-full)
  □ AV-19: graceful shutdown on SIGTERM
      - tokio::signal::ctrl_c + drain protocol
      - Producer-side close → persister drains → exit
      - Test: SIGTERM with N pending batches → 0 lost
  □ §4.1: #![forbid(unsafe_code)] at lib root
  □ §4.2: panic = "abort" on release profile
  □ §4.3: overflow-checks = true on release profile
  □ §4.12: catch_unwind wrappers on PyO3 methods

  release shape:
  □ THREAT_MODEL.md updated (AV-17/18/19 catalogued)
  □ CHANGELOG.md entry
  □ Bump to 0.1.3
  □ v0.1.3 tag + GH release
```

**Estimated effort: 4-6 hours** mostly because AV-17 needs
careful test coverage and AV-19 needs a kill-and-replay test
that mirrors the journal-resilience mission category.

## 7. v0.2.x track items

P2 items from this audit, plus Phase 2 prerequisites already
documented:

```
v0.2.x scope
  □ AV-2 / AV-10: peer-replicate audit-chain validation
                  (Phase 2 — FSD §4.5)
  □ AV-11: rotate_public_key(rotation_proof) explicit API
  □ AV-16: timing-oracle hardening on key-directory enumeration
  □ AV-20: statement_timeout on Postgres connections
  □ AV-21: per-agent rate limiting (token bucket)
  □ AV-22: clock-skew validation on incoming timestamps
  □ AV-23: consent_timestamp range gate
  □ §4.4: #![deny(missing_docs)]
  □ §4.5: clippy.toml with MSRV + extra lints
  □ §4.7: metrics endpoint (Prometheus / OTLP)
  □ §4.8: correlation IDs threaded through error responses
  □ §4.9: proptest property suite
  □ §4.10: cargo fuzz harness
  □ §4.11: SLSA wheel provenance
  □ §4.13: release-please automation
  □ §5.1: seen_batches table for cross-retention replay protection
  □ §5.2: N_eff drift alerting hooks
```

---

## 8. Pass 3 verdict

**v0.1.2 baseline is integration-ready** for the lens team's
production cutover. The threat model has zero open
integration-blocking exposures. The five new findings here
(AV-17 through AV-23) and the twelve hardening gaps (§4) are
*defense-in-depth* improvements, not active exposures.

The recommended ordering:

1. **Lens proceeds with v0.1.2 integration** as planned. The
   hardening gaps don't gate this.
2. **v0.1.3 hot-fix lands within the integration window** (4-6
   hours of work on my side) — closes AV-17 (the only P0 from
   this pass) plus the cheap general-hardening gates that buy
   real defense-in-depth at single-digit cost.
3. **v0.2.x track is queued** with the federation-primitive
   work (per-agent rate limiting, replay-window enforcement,
   N_eff drift hooks) plus Phase 2 prerequisites
   (peer-replicate, rotate_public_key).

`cargo audit`: 0 vulnerabilities. `cargo deny`: clean. CI: 7/7
green at every commit since c9b0b68. Mission alignment:
unchanged. The substrate is solid; the audit closes off
defense-in-depth gates around it.

---

## 9. Update cadence

This audit is updated per minor release (v0.1.x → v0.2.0):
re-run the methodology in §1, append findings, supersede the
"recommended next-version scope" sections.

Last updated: 2026-05-01 (Pass 3, v0.1.2 baseline).
