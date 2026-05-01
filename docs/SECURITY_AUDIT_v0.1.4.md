# Security Audit — `ciris-persist` v0.1.4

**Status:** post-Phase-1 SOTA / best-practice gap analysis. Companion
to [`docs/THREAT_MODEL.md`](THREAT_MODEL.md) (which catalogs the
threats); this document catalogs the **defense-in-depth gaps**
measured against current Rust + federation-primitive best practice.

**Audit date:** 2026-05-01.
**Crate state:** v0.1.4 at commit `ae4d659`.
**Methodology:** §1 below.
**Supersedes:** [`SECURITY_AUDIT_v0.1.2.md`](SECURITY_AUDIT_v0.1.2.md)
— historical record of what was open at the v0.1.2 baseline.

---

## TL;DR

Five clean releases (v0.1.0 → v0.1.4). All eight CI jobs green at
v0.1.4. **Eight items from the v0.1.2 audit have closed**; 14 remain
on the v0.2.x track. Four small new gaps surfaced from the v0.1.3
scrub-signing pipeline + v0.1.4 manifest-CI scaffold (§4).

```
substrate state at v0.1.4
  cargo audit:               0 vulnerabilities (767 deps via cargo tree)
  cargo deny:                advisories OK, bans OK, licenses OK, sources OK
  unsafe in our code:        0 (forbid(unsafe_code) at lib root)
  test count:                111 (95 lib + 9 fixture + 7 QA harness)
  CI matrix:                 8/8 green
  clippy --all -- -D warnings: clean
  cargo fmt --check:         clean
```

The v0.1.2 audit's "P0 + P1 — fix in v0.1.3 hot-fix scope" list:
**every item closed**. AV-17, AV-18, AV-19 mitigated; the four cheap
hardening gates landed; §4.12 PyO3 catch_unwind subsumed by
`panic = "abort"`.

---

## 1. Methodology

Same checks as the v0.1.2 audit, re-run at v0.1.4 baseline:

| Check | Tool | v0.1.4 result |
|---|---|---|
| Known CVEs | `cargo audit` | 0 vulnerabilities |
| RUSTSEC unmaintained-track | `cargo audit` | 2 warnings (`derivative`, `instant`); both ignored in `deny.toml` per v0.1.4 reconciliation, transitively via `ciris-keyring` |
| License + sources | `cargo deny check` | OK |
| `unsafe` in our code | `grep "unsafe " src/` | 0 (`#![forbid(unsafe_code)]` enforces) |
| Lint baseline | `cargo clippy -- -D warnings` | clean |
| Lint pedantic | `cargo clippy -- -W clippy::pedantic` | sampled; remaining warnings are stylistic, no real defense-in-depth gaps surfaced |
| `cargo fmt --check` | rustfmt 1.95 | clean |
| Test rigor | `cargo test --all-features` | 111 passing |
| QA harness | `cargo test --test qa_harness --release` | 7/7 scenarios green |
| Migration shape | manual review of V001 + V003 | additive `IF NOT EXISTS`, lens-compat |
| Build manifest | `tools/ciris_manifest.py generate + sign` | 53 files manifest, signed Ed25519 |

### SOTA references

Same as v0.1.2 audit — Rust Secure Code Working Group, Rustonomicon,
cargo-deny + cargo-audit user guides, SLSA v1.0, OWASP API Security
Top 10 (2026), PyO3 panic-handling guide, tokio-postgres TLS guide.
Plus federation-primitive material from PoB §6 and TRACE_WIRE_FORMAT.md.

---

## 2. Closed since v0.1.2

The v0.1.2 audit recommended a v0.1.3 hot-fix scope. **All eight
items shipped:**

| Item | Severity | Resolution | Commit |
|---|---|---|---|
| AV-17 attempt_index integer truncation | P0 | `MAX_ATTEMPT_INDEX = 1024` + `try_into` + typed `Error::AttemptIndexOutOfRange`; all `as u32`/`as i32` casts replaced; `overflow-checks = true` is the runtime backstop | v0.1.3 (`84ad06e`) |
| AV-18 plaintext Postgres connection | P1 | optional `tls` Cargo feature → `tokio-postgres-rustls` + `rustls-native-certs` | v0.1.3 (`9fabbe9`) |
| AV-19 lost in-flight commits at SIGTERM | P1 | `spawn_persister` returns `(IngestHandle, PersisterHandle)`; drop senders + `await persister.shutdown()` drains; new `shutdown_signal()` helper | v0.1.3 (`5ee68d9`) |
| §4.1 missing `forbid(unsafe_code)` | P1 | `#![forbid(unsafe_code)]` at lib root | v0.1.3 (`84ad06e`) |
| §4.2 no `panic = "abort"` | P1 | `[profile.release] panic = "abort"` | v0.1.3 (`84ad06e`) |
| §4.3 no `overflow-checks = true` | P1 | `[profile.release] overflow-checks = true` | v0.1.3 (`84ad06e`) |
| §4.6 no graceful shutdown | P1 | (duplicated AV-19; resolved together) | v0.1.3 |
| §4.12 PyO3 catch_unwind boundary | P2 | RESOLVED — subsumed by §4.2's `panic = "abort"` (no unwind to UB on); Option A vs B trade-off documented | v0.1.3 (CHANGELOG) |

Plus the cargo-deny posture got cleaner in v0.1.4:

| Item | Severity | Resolution | Commit |
|---|---|---|---|
| cargo-deny wildcard on ciris-keyring git dep | low | added `version = "1.6"` field | v0.1.4 (`ae4d659`) |
| RUSTSEC-2024-0388 derivative unmaintained | low | documented + ignored in `deny.toml`; transitive via ciris-keyring TPM stack; proc-macro only, no runtime exposure | v0.1.4 |
| RUSTSEC-2024-0384 instant unmaintained | low | documented + ignored; Phase 2.3 Reticulum work likely replaces this branch | v0.1.4 |

**QA harness landed as permanent CI gate** (v0.1.4 — `tests/qa_harness.rs`).
Seven stress scenarios exercising AV-5 / AV-6 / AV-9 / AV-17 / AV-19 /
AV-24 + concurrent-agents at scale. All seven green against v0.1.3
substrate; runs on every PR going forward.

---

## 3. New gaps surfaced by v0.1.3 + v0.1.4 changes

The scrub-signing pipeline + manifest-CI scaffold introduced four
small gaps not present in the v0.1.2 audit. None are integration-blocking;
each has a clean v0.2.x track item.

### 3.1 ciris-keyring `get_platform_signer` failure mode (P2)

**Gap**: `Engine.__init__` calls
`ciris_keyring::get_platform_signer(alias)` synchronously inside
`runtime.block_on(...)`. If the keyring backend is unavailable
(headless Linux with no Secret Service daemon AND no software fallback
configured; locked Keychain on macOS; permissions issue on the keystore
file), the call returns `Err(KeyringError)` which becomes a
`PyRuntimeError("ciris-keyring: ...")`. That's the right shape for
the *Python caller* — but for the **standalone `axum` server path**
(Phase 1.1 deployment shape), there's no clean equivalent: a future
`main.rs` that constructs the signer at startup gets a typed Result,
but no documented "try software fallback when hardware is missing"
escape hatch.

**Recommendation**: add a `Engine::with_software_fallback(...)`
constructor (or env flag `CIRIS_PERSIST_SOFTWARE_FALLBACK=1`) that
explicitly opts into `Ed25519SoftwareSigner` if `get_platform_signer`
fails. THREAT_MODEL.md AV-25 already names software fallback as a
documented residual; this just makes the operator's choice
machine-readable. v0.2.x.

### 3.2 `tools/ciris_manifest.py` CIRIS_BUILD_SIGN_KEY echo risk (P3)

**Gap**: the manifest `sign` subcommand reads a 32-byte Ed25519
seed from `CIRIS_BUILD_SIGN_KEY` env var. GitHub Actions auto-masks
declared secrets in stdout, but a CI step that runs `set -x` (verbose
shell tracing) before invoking the script could echo the value into
unmasked log lines. Today our `.github/workflows/ci.yml` doesn't
use `set -x`, so this is theoretical, but the python script reads
the env var as a raw string with no on-write redaction.

**Recommendation**: in v0.2.x, swap the env-var path for the planned
`ciris-keyring-sign-cli` Rust helper (per
`docs/TODO_REGISTRY.md` §3). The seed never appears in any process's
environment after that.

### 3.3 `register` subcommand exit-99 silent-skip risk (P3)

**Gap**: `tools/ciris_manifest.py register` exits 99 with a structured
TODO message (CIRISRegistry doesn't support `project="ciris-persist"`
yet). A future workflow author who copy-pastes the example with
`continue-on-error: true` would silently skip registration without
noticing. Not currently exploitable — no `register` step in our CI
yet — but worth flagging when that step lands.

**Recommendation**: when CIRISRegistry ships persist support, the
new CI step MUST omit `continue-on-error`. Add a CI-lint check that
greps for `continue-on-error` near `ciris_manifest.py register` and
fails the workflow if found. v0.2.x.

### 3.4 Per-batch latency tax under software signing (P3 — informational)

**Gap**: FSD §3.3 step 3.5 promises ~30 µs / sign on hardware-backed
keys, ~100 µs on software fallback. Production deployments running
on a TPM-less VM (sovereign-mode dev environments, CI runners) will
see ~10× the latency. For the agent's default `batch_size = 10` × 14
components = 140 sign calls, that's ~14 ms per batch on software vs
~4 ms on hardware. No correctness impact; bounded predictable cost.

**Recommendation**: doc-only. Add a `tracing::info!` at signer
construction logging which signer variant is in use ("hardware-backed"
vs "software fallback"), so ops can see the distinction in deployment
logs. Already implicit in `ciris-keyring`'s tracing output; surface
it in our wrapper. v0.2.x.

---

## 4. Hardening gaps still open at v0.1.4

From the v0.1.2 audit's §4 — what hasn't shipped yet:

### Operational gates

- **§4.4** `#![deny(missing_docs)]` for public API. Most public items
  *are* documented (mission-driven docs are dense), but no gate
  enforces. P3.
- **§4.5** `clippy.toml` with MSRV pin + extra lint levels. Without
  it, a clippy version bump on the runner can break CI for unrelated
  reasons (we hit this once between Rust 1.93 and 1.95). P2.
- **§4.7** No metrics endpoint. `/health` exposes queue depth +
  journal pending; ops needs *trends* (p99 ingest latency, conflict
  rate over time, signing-tax distribution). Optional `metrics`
  feature pulling in `metrics-exporter-prometheus`, or `tracing` with
  a structured-fields convention an OTLP collector consumes. P2.
- **§4.8** No correlation IDs in HTTP error responses. AV-15 closed
  the verbose-error-leak surface; correlation IDs are the next step
  so ops can match a 422 the agent saw with the verbose tracing log
  line. `tower::ServiceBuilder::new().layer(SetXRequestIdLayer)`
  pattern. P2.
- **§4.9** `proptest` dev-dep declared but unused. Property tests on
  the canonicalizer (no float drifts on shortest-round-trip outputs),
  the dedup-key (no collisions for distinct inputs), and the schema
  parser (random JSON doesn't crash) would close the unknown-unknowns
  hatch. P3.
- **§4.10** No `cargo fuzz` harness. Wire-format parser is the
  adversarial entry; fuzz coverage catches deserializer panics that
  proptest's structured-input bias misses. P3.
- **§4.11** No SLSA v1.0 wheel provenance. Maturin wheel + manifest
  upload are CI artifacts but lack the cryptographic provenance
  attestation that downstream consumers can verify against the
  github-actions runner identity. P3.
- **§4.13** No `release-please` automation. Each release tag is
  hand-written; Conventional Commits + automated CHANGELOG would
  remove a class of release-note drift bugs. P3.

### Federation-primitive gaps

- **§5.1** No replay-window enforcement beyond dedup. AV-3 (replay
  protection) relies on the dedup index; once retention drops the
  underlying rows (TimescaleDB `add_retention_policy` at 30 days),
  an attacker with a 31-day-old captured batch can re-claim the
  dedup slot. A `seen_batches` table with `(agent_id_hash,
  batch_hash, first_seen_at)` retained forever closes this. P2,
  paired with Phase 2 peer-replicate work (FSD §4.5).
- **§5.2** No N_eff drift alerting hooks. PoB §5.9 names continuous
  N_eff self-monitoring as partially-resolved at the lens scoring
  layer; persistence-side hooks (per-agent event-rate fields, retry
  distribution) make the score-function's job cheap. Phase 2.3
  prereq. P3.
- **§5.3** No agent-key rotation API. THREAT_MODEL.md AV-11: the
  v0.1.2 lens-canonical schema has `revoked_at` + `revoked_reason`
  + `added_by`, but explicit
  `rotate_public_key(rotation_proof: signed-by-old-key)` API is
  v0.2.x scope. P1 — highest-priority of the open gaps.

### Operational details surfaced by the threat model

- **AV-20** no `statement_timeout` on Postgres. P2.
- **AV-21** no per-agent rate limiting. P2 — federation-primitive
  adjacent (PoB §5.6 acceptance policy).
- **AV-22** no clock-skew validation on incoming timestamps. P2.
- **AV-23** `consent_timestamp` range unconstrained. P3.
- **AV-16** side-channel timing on key directory enumeration. P2 —
  research-grade.

---

## 5. Recommended v0.1.5 / v0.2.0 scope

The v0.1.2 audit's P0 + P1 list shipped in v0.1.3 + v0.1.4. The
remaining items split into a focused next-cut and a longer track.

### v0.1.5 hot-fix candidates (cheap defense-in-depth)

```
□ §4.5  clippy.toml — MSRV pin + extra lint levels (one-line fix)
□ §3.4  Log signer variant at construction (1-line tracing::info!)
□ §3.1  Engine::with_software_fallback or env flag
        (~30 lines + a regression test)
□ §4.4  #![deny(missing_docs)] at lib root (one-line + grep-fix)
```

Estimated 2-3 hours. None of these are blocking for lens
integration; they're hygiene that compounds with the v0.1.3+v0.1.4
substrate.

### v0.2.0 scope (federation-primitive completeness)

```
□ AV-11  rotate_public_key(rotation_proof) explicit API — P1
□ AV-2 / AV-10  peer-replicate audit-chain validation — Phase 2
□ §5.1   seen_batches table for cross-retention replay protection
□ §5.2   N_eff drift alerting hooks (Phase 2.3 prereq)
□ AV-20  statement_timeout on Postgres
□ AV-21  per-agent rate limiting (token bucket per agent_id_hash)
□ AV-22  clock-skew validation
□ §4.7   metrics endpoint (Prometheus / OTLP)
□ §4.8   correlation IDs threaded through error responses
□ §3.2   ciris-keyring-sign-cli helper binary (cross-repo with CIRISVerify)
```

Phase 2 peer-replicate is the centerpiece — once that lands, AV-2 +
AV-10 + §5.1 + §5.2 all fall into place together.

### v0.3.0+ track (research / long-tail)

```
□ AV-16  timing-oracle hardening (constant-response wrapper)
□ §4.9   proptest property suite
□ §4.10  cargo fuzz harness on BatchEnvelope::from_json
□ §4.11  SLSA v1.0 wheel provenance
□ §4.13  release-please automation
□ AV-23  consent_timestamp range gate
□ §3.4   per-batch latency observability (when metrics endpoint lands)
```

---

## 6. Mission-alignment posture

Every gap above is *defense-in-depth*. **None breaks a mission
guarantee** the substrate already provides:

- **Cryptographic provenance** — every persisted row carries a signed
  scrub envelope (FSD §3.3 step 3.5; v0.1.3). Verifiable by any peer
  with the deployment's public key. THREAT_MODEL.md AV-24 closed.
- **One key, three roles** — same Ed25519 key signs provenance,
  addresses Reticulum (Phase 2.3), publishes to registry (PoB §3.2).
- **Verify before persist** — MISSION.md §3 anti-pattern #2 enforced
  unconditionally; signature_verified=false rows are structurally
  unreachable.
- **Idempotency under contention** — dedup tuple includes
  agent_id_hash (THREAT_MODEL.md AV-9; v0.1.2). Cross-agent collision
  validated under stress (QA harness scenario D).
- **Honest backpressure** — 429 + `Retry-After` on saturation, never
  silent drop. Validated under stress (QA harness scenario A: 768
  concurrent rows, no drops).
- **Outage tolerance** — redb journal + graceful drain (FSD §3.4 #2;
  AV-19). Validated under stress (QA harness scenario F: 64 batches
  under load, all 256 rows landed on shutdown).

The substrate is solid. The remaining audit items are the
defense-scaffolding that makes operating the substrate at scale
easier; they're not blockers for the lens-team integration that's
already in flight.

---

## 7. Verdict

**v0.1.4 is integration-ready and substrate-stable.** Five clean
releases, all 8 CI jobs green, 111 tests including the 7-scenario
QA harness, every P0 + P1 gap from the v0.1.2 audit closed.

The v0.1.5 hot-fix candidates are nice-to-have at this point — the
production lens cutover need not wait for them. The v0.2.0 scope is
federation-primitive completeness work that pairs with Phase 2
peer-replicate (FSD §4.5) when that becomes the next mission-driven
ask.

For the lens team currently mid-integration: **stay on v0.1.4 + the
scrub-signing pipeline shape**. v0.1.5 hot-fixes will land
transparently (no API change). v0.2.0 will be a deliberate breaking-
change cycle with its own threat-model + audit pass.

---

## 8. Update cadence

This audit is updated per minor release (v0.1.x → v0.2.0):
re-run the methodology in §1, append findings, supersede the
"recommended next-version scope" sections.

Last updated: 2026-05-01 (Pass 4, v0.1.4 baseline).
