# Crate Recommendations — license-aligned dependency choices for `ciris-persist`

**Status:** Informational — input to Cargo.toml as Phase 1 implementation lands.
**Author:** Eric Moore (CIRIS Team) with Claude Opus 4.7
**Created:** 2026-04-30
**Companion:** `FSD/CIRIS_PERSIST.md` (the spec these dependencies serve)

This document is the result of an ecosystem survey done before Phase 1 implementation
starts. Each recommendation is current as of 2026-04-30, with crates.io metadata
pulled the same day. The crate the FSD already names is the recommendation in most
cases — the value here is verifying it's still alive, license-clean, and that no
better-fit alternative has emerged.

For each entry: **license**, **latest version (release date)**, **recent download
volume**, then the recommendation. Anything in `[brackets]` is an open decision that
would benefit from a separate FSD section before being settled.

---

## 1. License gate

The crate is `AGPL-3.0-or-later` (`Cargo.toml:5`). Compatible upstream licenses,
in order of how routinely they appear in this list:

- **MIT, BSD-2/3-Clause, ISC, Unlicense, Apache-2.0** — permissive; one-way compatible
  with AGPL. No friction.
- **MPL-2.0** — file-level copyleft; can be combined with AGPL. The MPL-2.0 files
  themselves remain MPL inside the larger AGPL whole.
- **GPL-3.0-or-later, AGPL-3.0-or-later** — same family; matches.

Rejected without further review: **SSPL, BSL/Business Source, Elastic License,
Confluent Community, anything labeled "non-commercial"**, custom proprietary.
None appear in this list.

**One AGPL-on-AGPL note:** picking an AGPL upstream (e.g. Leviculum below) does
not break our license but does mean *anyone consuming `ciris-persist` is locked
to AGPL too*. The FSD's intent is for `ciris-persist` itself to be AGPL — that's
fine. Where a permissive alternative exists with comparable quality, prefer it,
because it leaves downstream users with more flexibility.

## 2. Phase 1 — lens trace ingest

These are the dependencies the lens cutover needs. All confirmed live, maintained,
and license-clean.

### 2.1 Async runtime — `tokio`

| | |
|---|---|
| License | MIT |
| Latest | 1.52.1 (2026-04-16) |
| Recent dl | 132M |

**Recommendation:** `tokio = { version = "1", features = ["rt-multi-thread", "sync", "macros", "signal"] }`

No alternative seriously considered — `tokio` is the foundation everything else in
this list assumes.

### 2.2 PostgreSQL client — `tokio-postgres` + `deadpool-postgres`

| | tokio-postgres | deadpool-postgres |
|---|---|---|
| License | MIT OR Apache-2.0 | MIT OR Apache-2.0 |
| Latest | 0.7.17 (2026-03-30) | 0.14.1 (2024-12-18) |
| Recent dl | 9.9M | 4.1M |

**Recommendation as the FSD names:** `tokio-postgres` with `deadpool-postgres` for
pooling. `BinaryCopyInWriter` is the path to satisfy §3.3's "Batch INSERT via COPY
... FROM STDIN BINARY" requirement — `tokio_postgres::binary_copy::BinaryCopyInWriter`
serializes rows directly to Postgres binary format. (`docs.rs/tokio-postgres`).

**TimescaleDB**: no Rust-specific TimescaleDB client exists; `create_hypertable`,
compression policies, and retention policies are issued as plain SQL through
`tokio-postgres`. The §7 FSD open question about TimescaleDB-extension-presence
detection (`SELECT extname FROM pg_extension`) is solvable in plain SQL.

**LISTEN/NOTIFY**: built into `tokio-postgres`'s `Connection::poll_message`. No
external `postgres-notify` wrapper needed for the §4.4 federation hook.

**Alternative considered:** `sqlx` (0.9.0-alpha.1, last updated 2025-10-15) is on
an alpha track and currently lags `tokio-postgres` for production use. Compile-time
checked queries are tempting but the FSD §6 explicitly rejects ORM/DSL approaches.
Stay on `tokio-postgres`.

**Pool alternative:** `bb8` (MIT, 0.9.1) — viable, smaller community. `deadpool`
is the more common choice and what the FSD names; stay with it.

### 2.3 Local journal — `redb`

| | |
|---|---|
| License | MIT OR Apache-2.0 |
| Latest | 4.1.0 (2026-04-19) |
| Recent dl | 1.9M |

**Recommendation:** `redb`. The FSD §3.4 already names it; this verifies the lean.
Now at 4.x (was 1.0 in 2023), file-format stable with documented upgrade path,
single-file embedded ACID DB, no_std-capable. Right shape for the §3.4 outage-
tolerance journal at `/var/lib/cirislens/journal.redb`.

**Alternatives considered:**
- **`fjall`** (MIT OR Apache-2.0, 3.1.4 / 2026-04-14, 580k dl) — LSM-tree, newer,
  capable. Different perf characteristics (write-heavy LSM vs. balanced B-tree).
  Redb is closer to what the journal's append-and-replay shape wants; LSM's
  compaction overhead is wasted for an ephemeral outage queue.
- **`sled`** (MIT OR Apache-2.0, 1.0.0-alpha.124 / 2024-10-11) — perpetual alpha,
  and the FSD already noted it as unmaintained. Reject.
- **`sanakirja`** (2.0.0-beta) — copy-on-write transactional store, low download
  volume, niche. Not worth the bet over redb.

### 2.4 Cryptography — Ed25519 + SHA-256

| | ed25519-dalek | sha2 |
|---|---|---|
| License | BSD-3-Clause | MIT OR Apache-2.0 |
| Latest | 3.0.0-pre.6 (2026-02-04) | (RustCrypto family) |
| Recent dl | 39M | n/a (use `sha2` from RustCrypto) |

**Recommendation:** `ed25519-dalek = "2"` (stay on stable 2.x line; 3.0 is in
pre-release as of Feb 2026 — track but don't adopt yet) and `sha2 = "0.10"` from
RustCrypto. Use `VerifyingKey::verify_strict` per the §3.3 verify path; it rejects
weak-key edge cases and small-order points. `zeroize` (Apache-2.0 OR MIT, 1.8.2)
is already a transitive dep of `ed25519-dalek`; no extra import needed for key
hygiene.

### 2.5 Canonical JSON — **decision required**

| | serde_json_canonicalizer | canon-json (bootc-dev) |
|---|---|---|
| License | MIT | (RFC 8785 implementation) |
| Latest | 0.3.2 (2026-02-03) | n/a |
| Recent dl | 903k | small |

**This is the only Phase 1 dependency that needs an architectural decision before
Cargo.toml lands.** The wire format §8 specifies the signed bytes as:

```python
json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
```

That **is not RFC 8785 JCS**. Two divergences matter for byte-exact reproducibility:

1. Python's `json.dumps` defaults to `ensure_ascii=True` — non-ASCII characters
   become `\uXXXX` escapes. JCS emits raw UTF-8.
2. Python `sort_keys` orders by Python's str ordering (Unicode codepoint, UTF-32
   semantics for keys with characters above U+FFFF). JCS sorts by UTF-16 code unit
   order, which differs for non-BMP characters (mostly emoji + rare scripts).

For the canonical envelope keys (`trace_id`, `thought_id`, …) all ASCII, both
conventions agree. For payload *values* containing non-ASCII (Spanish content,
non-Latin scripts, emoji in user-supplied text), `serde_json_canonicalizer` would
produce **different bytes than the agent's signer**, and signature verification
would fail.

Three paths, listed worst to best:

1. **Implement Python-compatible canonicalization in Rust ourselves**, byte-exact
   match for `json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=True)`.
   Cheap to write — it's a serde_json `Formatter` impl + a sort-keys Map serializer
   + an ASCII-only escape policy. Test parity by round-tripping a corpus through
   both Rust and Python and comparing bytes. **Lean: this — fits the FSD's "no
   agent change in Phase 1" constraint.**
2. **Get the agent to flip to JCS** (RFC 8785) and use `serde_json_canonicalizer`
   in the lens. Cleaner long-term — JCS is a published RFC. Requires an agent
   change, which the FSD §3.6 explicitly says Phase 1 doesn't need; this would
   move that line.
3. **Ship `serde_json_canonicalizer` and accept silent verification failures on
   non-ASCII payload bytes.** Reject — undermines the verify-before-persist
   contract in §3.3.

Add this as Phase 1 open question §3.10 — "canonicalization byte-equivalence
implementation." Implementation cost for path 1 is ~1 day including a parity
test corpus.

### 2.6 HTTP server — `axum`

| | |
|---|---|
| License | MIT |
| Latest | 0.8.9 (2026-04-14) |
| Recent dl | 71M |

**Recommendation as the FSD names.** `axum` 0.8.x with the `tower` middleware
stack is the right shape for a small ingest endpoint. `actix-web` (MIT) edges out
on raw req/s but Tower's middleware composability fits the §3.4 backpressure /
journal-replay / health-probe pattern more directly. Stay on `axum`.

`tower` (MIT, 0.5.3, 100M dl) and `hyper` come in transitively. No additional
choice.

### 2.7 PyO3 — Python bindings

| | |
|---|---|
| License | MIT OR Apache-2.0 |
| Latest | 0.28.3 (2026-04-02) |
| Recent dl | 34M |

**Recommendation:** `pyo3 = { version = "0.28", features = ["extension-module", "abi3-py311"] }`.
The 0.28 series is the current stable; abi3-py311 means a single wheel works
across Python 3.11+ (matches the agent's deployment Python). Pair with `maturin`
on the build side.

§7 open question 2 (sync vs async PyO3 entrypoint): lean **synchronous** as the
FSD already does. PyO3's `pyo3-asyncio` is real but adds a runtime translation
layer; FastAPI runs the handler in a threadpool already, so a sync `pyo3::Python`
call is simpler and matches the existing pattern in `cirislens-core`.

### 2.8 Serialization — `serde` + `serde_json`

| | |
|---|---|
| License | MIT OR Apache-2.0 (both) |
| | (industry baseline; no alternative) |

**Recommendation:** standard `serde = { version = "1", features = ["derive"] }`,
`serde_json = "1"`. The FSD §3.3 explicitly forbids `serde_json::Value`-then-extract;
implement concrete `BatchEnvelope` / `CompleteTrace` / `TraceComponent` / per-event
structs with serde derive. No exotic deps.

### 2.9 Datetime — `chrono`

| | chrono | jiff |
|---|---|---|
| License | MIT OR Apache-2.0 | Unlicense OR MIT |
| Latest | 0.4.44 (2026-02-23) | 0.2.24 (2026-04-23) |
| Recent dl | 105M | 35M |

**Recommendation:** `chrono` with `serde` feature, **as the FSD names**.

`jiff` (BurntSushi's newer datetime library) is more correct on DST/calendar math
and the broader Rust community is migrating, but:

1. `tokio-postgres`'s `with-chrono-0_4` feature gives direct `TIMESTAMPTZ ↔
   DateTime<Utc>` mapping; `jiff` would need a manual conversion layer.
2. The agent and lens already speak ISO-8601 strings on the wire; we don't do
   calendar arithmetic in `ciris-persist`. The DST/calendar safety jiff offers
   isn't load-bearing here.
3. `chrono`'s 105M dl/recent vs jiff's 35M means more transitive ecosystem.

Revisit on jiff 1.0 release if cross-stack migration follows. Until then, chrono.

### 2.10 Errors + tracing

| | |
|---|---|
| `thiserror` | MIT OR Apache-2.0, 2.0.18, 214M dl |
| `tracing` | MIT, 0.1.44, 118M dl |
| `tracing-subscriber` | (bundled, MIT) |

**Recommendation:** `thiserror = "2"` for crate error enums; `anyhow = "1"` only
for the bin targets (`bins/cirislens-ingest.rs`), not in the library. `tracing` +
`tracing-subscriber` for instrumentation, keyed to the existing CIRIS log shape.

### 2.11 Migration runner — `refinery`

| | refinery | sqlx-migrate / sqlx::migrate! |
|---|---|---|
| License | MIT | MIT OR Apache-2.0 |
| Latest | 0.9.1 (2026-04-15) | tied to sqlx |
| Recent dl | 1.7M | (subset of sqlx) |

**Recommendation:** `refinery` with `tokio-postgres` and (Phase 2) `rusqlite`
adapters. Numbered SQL files in `migrations/postgres/lens/`,
`migrations/postgres/agent/`, `migrations/sqlite/agent/` — matches the FSD §3.1
layout. `refinery` is the de-facto standard outside sqlx and works with both
backends without bringing the sqlx engine.

`sqlx::migrate!` is good but pulls in sqlx, which we're not using. Skip.

---

## 3. Phase 2 — agent signed-events + TSDB

### 3.1 SQLite client — `rusqlite`

| | |
|---|---|
| License | MIT |
| Latest | 0.39.0 (2026-03-15) |
| Recent dl | 13M |

**Recommendation:** `rusqlite = { version = "0.39", features = ["bundled", "chrono", "serde_json"] }`.
The `bundled` feature builds SQLite from source — required for iOS to avoid the
system SQLite that triggers Apple's `SQLiteDatabaseTracking` warning the FSD §5.3
calls out as a Python pain point.

**SQLCipher option** (Phase 2 if encrypted-at-rest is needed): `rusqlcipher`
(based on rusqlite) or `rusqlite` with `bundled-sqlcipher` feature. Decision
deferred — the FSD doesn't require encrypted-at-rest, and the secrets-manager
encryption boundary stays *above* the persistence layer (§5.7).

### 3.2 C ABI for iOS — `cbindgen` + `swift-bridge` *or* `uniffi`

| | cbindgen | swift-bridge | uniffi |
|---|---|---|---|
| License | MPL-2.0 | Apache-2.0/MIT | MPL-2.0 |
| Latest | 0.29.2 (2025-10-21) | 0.1.59 (2026-01-06) | 0.31.1 (2026-04-13) |
| Recent dl | 11M | 238k | 1.8M |

**Two viable paths, decision required**:

**Path A — `cbindgen` + `swift-bridge`:** generate a C header from Rust, then
hand-write the Swift glue or use `swift-bridge` for ergonomic Swift↔Rust. Maps
to what `CIRISLens/cirislens-core` does today for its Rust verify edge. Lower
ceremony for a small ABI surface. Workflow: tag the FFI types with
`#[swift_bridge::bridge]`, run `swift-bridge-build`, get a Swift package out.

**Path B — `uniffi`** (Mozilla, used in production by Firefox application-services):
generate Swift, Kotlin, Python, *and* Ruby from one UDL/proc-macro definition.
One toolchain for iOS Swift, Android Kotlin, *and* the Python bindings for the
agent. Could replace PyO3 for the Python side. *But*:
- `uniffi` is at 0.31.x and has explicit "internal work going on, lots of breaking
  changes possible" warnings in its README. Mozilla uses it in production but
  acknowledges pre-1.0.
- The FSD §3.1 commits to PyO3 for Phase 1 already; flipping the agent's Python
  bindings to uniffi mid-stream is migration cost.
- uniffi's UDL is its own type-definition layer; PyO3 lets us keep Rust types as
  the source of truth. The FSD §11 bias toward "schemas generated *from* Rust" is
  cleaner with PyO3 + cbindgen + ts-rs than with uniffi's centralized UDL.

**Lean: Path A** (cbindgen + swift-bridge for iOS, keep PyO3 for Python). uniffi
becomes interesting if Phase 3 Kotlin Multiplatform support is named as a hard
requirement — at that point, run a spike. Until then, the simpler stack wins.

### 3.3 Federation transport — `Reticulum-rs` *or* `Leviculum`

| | Reticulum-rs (Beechat) | Leviculum (Lew_Palm) |
|---|---|---|
| License | **MIT** | **AGPL-3.0** |
| Repo | github.com/BeechatNetworkSystemsLtd/Reticulum-rs | codeberg.org/Lew_Palm/leviculum |
| crates.io | `reticulum 0.1.0` (2025-10-14) — early publish, current dev on git main | not on crates.io |
| Stars | 263 | 8 |
| Last push | 2026-04-22 | 2026-05-01 |
| Status | active, FOSDEM 2026 talk scheduled | active, claims wire-compat with Python upstream + LoRa |

**Recommendation: lean Reticulum-rs**, with a Phase 2.3 spike against Leviculum
before commit.

Reasoning:

- **Reticulum-rs is MIT.** That keeps `ciris-persist`'s license ergonomics intact:
  AGPL-on-MIT is fine, and consumers of `ciris-persist` who want to swap in a
  permissive build path remain unblocked at the transport layer.
- **Leviculum is AGPL-3.0.** Same family as `ciris-persist`, no compat issue —
  but it pulls the entire dependency chain into AGPL strict, narrowing future
  options if a sovereign-mode agent wants to license its build differently.
- Reticulum-rs has 33× the visibility (263 vs 8 stars) and a public conference
  presence (FOSDEM 2026); Leviculum is one developer's recent independent push.
- Leviculum claims protocol-completeness including LoRa earlier than Reticulum-rs
  has documented; this is the property the FSD §5.7 says justifies a trial spike.

PoB §5.7 already calls for the spike. This recommendation matches it: build
Phase 2 against `Reticulum-rs` git main; revisit Leviculum only if the LoRa or
embedded story doesn't materialize on the Reticulum-rs side.

**Both forks rely on the upstream Python protocol's wire format**, so a switch
between the two later is a build-system change, not a protocol break.

**Pinning:** since Reticulum-rs's published `reticulum 0.1.0` (Oct 2025) is far
behind the active git work, depend on a git revision in Cargo.toml until they
publish a new release:

```toml
reticulum = { git = "https://github.com/BeechatNetworkSystemsLtd/Reticulum-rs",
              rev = "<pinned commit>" }
```

Track the commit in CI pinning. Move to `version = "x.y"` when they cut a release
on crates.io that includes the Channel module.

---

## 4. Phase 3 — agent runtime state, memory graph, governance

These don't need new external crates beyond what Phase 1+2 already pulls in.
Phase 3 is mostly Rust-internal: porting Python DAOs to typed Rust functions
backed by `rusqlite` + `tokio-postgres`. Two specific items:

### 4.1 Graph traversal — `petgraph`?

| | |
|---|---|
| License | MIT OR Apache-2.0 |
| Latest | 0.8.3 (2025-09-30) |
| Recent dl | 73M |

**Recommendation: not a dependency for Phase 3 storage.** The FSD §11 leans
"named procedures" (`recall_subgraph(node_id, max_depth, scope)`) over a query
DSL — that's the right call. SQL-side graph traversal stays in SQL; in-memory
traversal during a procedure can be a tiny hand-written BFS without needing
`petgraph`'s full graph algebra.

`petgraph` is great for in-process algorithms (shortest-path, topological sort)
but the agent's graph queries are 2-3 hop scoped extractions, not algorithm-heavy.
Pull it in only if a specific Phase 3 procedure benefits.

### 4.2 Schema generation pipeline — TS / Pydantic / Swift / Kotlin

This is the §11 / §3.1 (FSD §11 open question 8 + §5.8) decision: **how do
client schemas stay in sync with Rust types?** Three slots:

| Target | Crate | License | Status |
|---|---|---|---|
| TypeScript (web client) | `ts-rs` | MIT | 12.0.1 (2026-01-31), 3.3M dl |
| TypeScript alt (rich types) | `specta` | MIT | 2.0.0-rc.24 (2026-03-30), 296k dl |
| TypeScript alt (cross-lang) | `typeshare` | MIT OR Apache-2.0 | 1.0.5 (2026-01-02), 1.85M dl |
| JSON Schema (Pydantic gen, OpenAPI) | `schemars` | MIT | 1.2.1 (2026-02-01), 85M dl |
| Swift | `swift-bridge` | Apache-2.0/MIT | (see §3.2) |
| C header (Kotlin via JNI / iOS) | `cbindgen` | MPL-2.0 | (see §3.2) |
| All-in-one (Swift+Kotlin+Python+Ruby) | `uniffi` | MPL-2.0 | (see §3.2) |

**Recommendation:** `schemars` for the Rust-types → JSON Schema path, then drive
Pydantic generation downstream from JSON Schema (e.g. via `datamodel-code-generator`
in the agent's CI). `ts-rs` for TypeScript — simplest, most-stable, smallest
ceremony.

`specta` is more powerful (richer type-info, runtime metadata) but its ecosystem
target is Tauri; ts-rs's `#[derive(TS)] #[ts(export)]` is enough for what the
web client and iOS Kotlin codegen need. Stay simple.

`typeshare` is the cross-language story (TS + Swift + Kotlin from one annotation)
but its ranges of supported types are narrower than the per-target crates. Only
use if the §3.2 cbindgen+swift-bridge path proves too high-ceremony for iOS Swift
specifically.

---

## 5. Decisions surfaced by this survey

These are points where the ecosystem's current state pushes back on, or extends,
the FSD's existing leans. Each should be addressed before Phase 1 implementation
starts.

### 5.1 Canonical-JSON byte-equivalence (Phase 1 — blocking)

§2.5 above. Python's `json.dumps(..., sort_keys=True, separators=(",", ":"))` is
not RFC 8785 JCS. For ASCII-only payloads the two agree; for non-ASCII payload
content (Spanish, Chinese, accented names, emoji) they diverge. The Rust
canonicalizer must match the Python signer byte-for-byte, OR the agent must flip
to JCS before Phase 1 cuts over.

**Decision:** add as FSD §3.10 "canonicalization byte-equivalence implementation"
open question. Cheapest path: write a custom serde_json `Formatter` + sorted-keys
serializer in `src/verify/canonical.rs` that emits Python-compatible bytes.
Validate via parity test against a corpus of recorded Python `json.dumps` outputs.

### 5.2 redb vs fjall (Phase 1 — soft decision)

§2.3 above. FSD lean is redb; this survey confirms it. Fjall 3.0 is real but its
LSM shape is wrong for the journal pattern. **Decision: stick with redb.**

### 5.3 Reticulum-rs vs Leviculum (Phase 2.3 — tracked spike)

§3.3 above. Lean Reticulum-rs (MIT, larger community); spike Leviculum (AGPL,
LoRa-completeness claim) before locking in. PoB §5.7 already names this; this
survey reinforces it with license / star / activity numbers.

### 5.4 cbindgen + swift-bridge vs uniffi (Phase 2.2 — soft decision)

§3.2 above. Lean cbindgen+swift-bridge; uniffi if Kotlin Multiplatform becomes a
hard requirement.

### 5.5 jiff vs chrono (revisit on jiff 1.0)

§2.9 above. Stay chrono for now; revisit when jiff hits 1.0 *and* `tokio-postgres`
adds first-class jiff support.

### 5.6 Schema generation toolchain (Phase 3 — already in FSD §11)

§4.2 above. Lean: `schemars` → Pydantic, `ts-rs` → TypeScript, `swift-bridge` →
Swift, `cbindgen` → C ABI for Kotlin/JNI. Avoid uniffi until proven necessary.

---

## 6. Cargo.toml shape

The implementation deps the FSD §3.1 promised, now with versions and license
verification. Drop into `Cargo.toml` as features come online:

```toml
[dependencies]
# Always-on (Phase 1+)
tokio       = { version = "1", features = ["rt-multi-thread", "sync", "macros", "signal"] }
serde       = { version = "1", features = ["derive"] }
serde_json  = "1"
ed25519-dalek = "2"
sha2        = "0.10"
chrono      = { version = "0.4", features = ["serde"] }
thiserror   = "2"
tracing     = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "fmt", "json"] }
redb        = "4"
refinery    = { version = "0.9", features = ["tokio-postgres"] }

[dependencies.postgres]   # gate behind feature = "postgres"
tokio-postgres    = { version = "0.7", features = ["with-chrono-0_4", "with-serde_json-1"], optional = true }
deadpool-postgres = { version = "0.14", optional = true }

[dependencies.sqlite]     # gate behind feature = "sqlite"  (Phase 2)
rusqlite = { version = "0.39", features = ["bundled", "chrono", "serde_json"], optional = true }

[dependencies.pyo3]       # gate behind feature = "pyo3"
pyo3 = { version = "0.28", features = ["extension-module", "abi3-py311"], optional = true }

[dependencies.server]     # gate behind feature = "server"
axum  = { version = "0.8", optional = true }
tower = { version = "0.5", optional = true }

[dependencies.peer-replicate]   # gate behind feature = "peer-replicate"  (Phase 2.3)
reticulum = { git = "https://github.com/BeechatNetworkSystemsLtd/Reticulum-rs",
              rev = "<pinned>", optional = true }

[build-dependencies]
# Phase 2.2 (c-abi feature):
cbindgen     = "0.29"
# When iOS Swift bindings land:
swift-bridge-build = "0.1"

[dev-dependencies]
serde_json_canonicalizer = "0.3"   # parity-test canonical bytes; not a runtime dep
```

The `serde_json_canonicalizer` slot is a **dev-dep for the parity test** that
validates our Python-compatible canonicalizer against the JCS reference. It is
not a runtime dep until / unless the agent flips to JCS.

---

## 7. Watchlist

Items to revisit on a quarterly cadence:

1. **`ed25519-dalek 3.0`** — currently 3.0.0-pre.6 (Feb 2026). Track for stable;
   migration is mostly minor type changes.
2. **`sqlx 0.9.x stable`** — currently alpha. If it lands stable and adds a
   genuine ergonomics win for the §3.3 batch path (e.g. compile-time-checked
   COPY), revisit the choice between sqlx and tokio-postgres.
3. **`jiff 1.0`** — see §5.5. Migration becomes worth the cost only after both
   `jiff` and `tokio-postgres` first-class support land.
4. **`uniffi 1.0`** — pre-1.0 today. If it stabilizes and Phase 3 needs Kotlin
   Multiplatform, revisit §3.2.
5. **`Reticulum-rs` crates.io release** — currently shipping git-only for the
   active work. When they publish, switch from git-rev to version pinning.
6. **`fjall` ecosystem maturity** — fjall 3.x is recent; if a future workload
   wants LSM characteristics (write-amp dominated, large datasets), revisit §2.3.

---

## 8. References

- `Cargo.toml` — current Phase-0 stub with feature flags declared, no deps yet.
- `FSD/CIRIS_PERSIST.md` §3.1 — crate layout this set of deps services.
- `FSD/CIRIS_PERSIST.md` §3.4 — robustness primitives (redb journal, bounded queue).
- `FSD/CIRIS_PERSIST.md` §7 — open questions; this document resolves several
  (canonicalization, redb, sqlx, transport choice) and surfaces new ones.
- `context/TRACE_WIRE_FORMAT.md` §8 — canonical bytes spec that drives §5.1.
- `context/PROOF_OF_BENEFIT_FEDERATION.md` §3.2, §5.7 — Reticulum recommendation
  and spike note this document echoes.

Crate metadata (license, version, downloads) pulled from the crates.io API and
GitHub on **2026-04-30**. Re-run before Phase 1 implementation locks the
Cargo.toml; license terms occasionally change at major-version boundaries.
