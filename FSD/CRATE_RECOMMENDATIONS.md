# Crate Recommendations — license-aligned dependency choices for `ciris-persist`

**Status:** Informational — the dependency choices `Cargo.toml` implements, and why.
**Companion:** `FSD/CIRIS_PERSIST.md` (the spec these dependencies serve)

For each dependency: its license, the version line `Cargo.toml` pins, and the reasons for the choice over the alternatives. `Cargo.toml` is the source of truth for exact versions; re-check licenses at major-version boundaries, where terms occasionally change.

---

## 1. License gate

The crate is `AGPL-3.0-or-later` (`Cargo.toml`). Compatible upstream licenses, in order of how routinely they appear:

- **MIT, MIT-0, BSD-2/3-Clause, ISC, Unlicense, Apache-2.0** — permissive; one-way compatible with AGPL.
- **MPL-2.0** — file-level copyleft; can be combined with AGPL. The MPL-2.0 files remain MPL inside the larger AGPL whole.
- **GPL-3.0-or-later, AGPL-3.0-or-later** — same family.

Rejected without further review: **SSPL, BSL/Business Source, Elastic License, Confluent Community, anything labeled "non-commercial"**, custom proprietary.

`deny.toml` enforces the allow-list; the `license-audit` CI job runs `cargo deny check` (licenses, advisories, bans).

**AGPL-on-AGPL note:** an AGPL upstream does not break persist's license, but it ties every consumer to AGPL as well. Where a permissive alternative of comparable quality exists, prefer it — it leaves downstream users more flexibility.

## 2. Lens trace ingest

### 2.1 Async runtime — `tokio`

MIT. `tokio = { version = "1", features = ["rt-multi-thread", "sync", "macros", "signal", "time"] }`. The foundation everything else here assumes.

### 2.2 PostgreSQL client — `tokio-postgres` + `deadpool-postgres`

Both MIT OR Apache-2.0. `tokio-postgres` 0.7 (with chrono, serde_json and uuid support), `deadpool-postgres` 0.14 for pooling, `postgres-types` for custom types. TLS through `tokio-postgres-rustls` + `rustls` (feature `tls`).

Batch writes use parameterized `INSERT ... VALUES ... ON CONFLICT DO NOTHING`, which supports the idempotent conflict path natively (`FSD/CIRIS_PERSIST.md` §3.3 step 6).

**TimescaleDB:** not used. The runtime is plain PostgreSQL + SQLite (`FSD/CIRIS_PERSIST.md` §7 #7).

**Not chosen:** `sqlx` — compile-time-checked queries, but the crate rejects ORM/DSL layers (`FSD/CIRIS_PERSIST.md` §6) and `tokio-postgres` is the more direct path. `bb8` — a viable pool with a smaller community.

### 2.3 Local journal — `redb`

MIT OR Apache-2.0. `redb = "4"`. Single-file embedded ACID store, file-format stable with a documented upgrade path. The right shape for the outage-tolerance journal (`FSD/CIRIS_PERSIST.md` §3.4 #2).

**Not chosen:** `fjall` (LSM tree — compaction overhead is wasted on an append-and-replay outage queue); `sled` (perpetual alpha, unmaintained); `sanakirja` (niche).

### 2.4 Cryptography — Ed25519, ML-DSA-65, SHA-256

- `ed25519-dalek = "2"` (BSD-3-Clause), with `rand_core` and `zeroize`. Verification uses `verify_strict`, which rejects weak keys and small-order points.
- `sha2 = "0.10"` (RustCrypto, MIT OR Apache-2.0).
- `ciris-crypto`, `ciris-verify-core` and `ciris-keyring` from CIRISVerify (pinned by git tag; the three pins move together) supply ML-DSA-65, hybrid signatures, the key-grant and hybrid-KEX primitives, the JCS canonicaliser and the hardware-backed keyring.

### 2.5 Canonical JSON

The trace wire format §8 specifies the signed bytes as:

```python
json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
```

That **is not RFC 8785 JCS**. Two divergences matter for byte-exact reproducibility:

1. Python's `json.dumps` defaults to `ensure_ascii=True` — non-ASCII characters become `\uXXXX` escapes. JCS emits raw UTF-8.
2. Python `sort_keys` orders by codepoint; JCS sorts by UTF-16 code unit, which differs for non-BMP characters.

For ASCII envelope keys both agree. For payload *values* containing non-ASCII (non-Latin scripts, accented names, emoji), a JCS library produces **different bytes than the agent's signer**, and verification fails.

Persist therefore implements both forms itself (§5.1): `PythonJsonDumpsCanonicalizer`, a hand-written byte-exact match for the Python form, and `JcsCanonicalizer`, which delegates to `ciris_verify_core::jcs` so persist, CIRISVerify and the agent share one JCS implementation.

### 2.6 HTTP server — `axum`

MIT. `axum` 0.8 with `tower` 0.5 middleware (feature `server`). Tower's middleware composability fits the backpressure, journal-replay and health-probe pattern (`FSD/CIRIS_PERSIST.md` §3.4).

**Not chosen:** `actix-web` — faster on raw requests per second, but less composable for this pattern.

### 2.7 PyO3 — Python bindings

MIT OR Apache-2.0. `pyo3 = { version = "0.29", features = ["abi3-py310"] }`, built with `maturin`. `abi3-py310` means one wheel covers Python 3.10 and later (lowered from 3.11 for BeeWare iOS; `FSD/PLATFORM_ARCHITECTURE.md` §3.5).

Entry points are **synchronous** from Python (`FSD/CIRIS_PERSIST.md` §7 #2). A Python-side async bridge would add a runtime translation layer; FastAPI already runs handlers in a threadpool.

### 2.8 Serialization — `serde` + `serde_json`

MIT OR Apache-2.0. `serde` with `derive`; `serde_json` with `arbitrary_precision` and `raw_value`. Ingest uses concrete serde-derived structs, never `serde_json::Value`-then-extract (`FSD/CIRIS_PERSIST.md` §3.3).

### 2.9 Datetime — `chrono`

MIT OR Apache-2.0. `chrono` with `serde`.

**Not chosen:** `jiff` — more correct on DST and calendar math, but `tokio-postgres`'s `with-chrono-0_4` gives a direct `TIMESTAMPTZ ↔ DateTime<Utc>` mapping, and persist does no calendar arithmetic; timestamps travel as ISO-8601 strings on the wire.

### 2.10 Errors + tracing

`thiserror = "2"` (MIT OR Apache-2.0) for crate error enums; `anyhow` only where a feature-gated ML backend needs it, never in the library's error surface. `tracing` (MIT) for instrumentation; `tracing-subscriber` is a dev-dependency.

### 2.11 Migration runner — `refinery`

MIT. `refinery` 0.9 with the `tokio-postgres` and `rusqlite` adapters. Numbered SQL files in `migrations/postgres/lens/` and `migrations/sqlite/lens/` (`FSD/CIRIS_PERSIST.md` §3.1). `refinery` works with both backends without bringing in the sqlx engine.

---

## 3. Agent signed events and sqlite

### 3.1 SQLite client — `rusqlite`

MIT. `rusqlite` 0.31 with `backup`, `chrono`, `serde_json` and `functions`.

**Linkage:** desktop targets and iOS link the platform `libsqlite3` dynamically (no `bundled`), so persist and any other extension module in the same process share one SQLite instance. Android builds with `bundled`, because the NDK's libsqlite3 is not guaranteed across vendor builds (CIRISPersist#132; `FSD/PLATFORM_ARCHITECTURE.md` §3.1, §3.2).

**Encryption at rest** is not SQLCipher: the `encrypted-kv` feature and the blob-encryption surface (`FSD/BLOB_ENCRYPTION_AT_REST.md`) encrypt at the application layer.

### 3.2 Native mobile bindings — `cbindgen` / `swift-bridge` / `uniffi`

**Not used.** Persist ships PyO3 for every platform, including iOS (BeeWare) and Android (Chaquopy). The `c-abi` feature is declared and gates no code. If a Rust-native mobile binding is needed, the candidates are `cbindgen` (MPL-2.0) + `swift-bridge` (Apache-2.0/MIT) for iOS, and `uniffi` (MPL-2.0) where one definition must serve both Swift and Kotlin.

### 3.3 Federation transport — `Reticulum-rs` *or* `Leviculum`

**Not a persist dependency.** Transport lives in CIRISEdge, which consumes persist through its outbound queue and directory traits; the `peer-replicate` feature is declared and gates no code.

For the transport layer the license comparison stands: Reticulum-rs (Beechat) is **MIT**; Leviculum is **AGPL-3.0**. Both follow the upstream Python protocol's wire format, so switching between them is a build change, not a protocol break.

---

## 4. Agent runtime state, memory graph, governance

These tables need no external crates beyond the ones above: they are typed Rust services over `rusqlite` and `tokio-postgres`.

### 4.1 Graph traversal — `petgraph`?

**Not a dependency.** Graph reads are named procedures on `GraphService` (`traverse_k_hop`, `query_nodes`, `get_edges_for_node`; `FSD/CIRIS_PERSIST.md` §7 #11). Traversal stays in SQL; the agent's graph queries are 2–3-hop scoped extractions, not algorithm-heavy work.

### 4.2 Schema generation pipeline — TS / Pydantic / Swift / Kotlin

**Not implemented.** Persist ships hand-maintained Python type stubs (`python/ciris_persist/ciris_persist.pyi`). If client-type generation is added, the candidates are `schemars` (MIT; Rust → JSON Schema → Pydantic / OpenAPI) and `ts-rs` (MIT; TypeScript). See `FSD/CIRIS_PERSIST.md` §7 #12.

---

## 5. Decisions

### 5.1 Canonical-JSON byte-equivalence

Python's `json.dumps(..., sort_keys=True, separators=(",", ":"))` is not RFC 8785 JCS: the two agree on ASCII-only payloads and diverge on non-ASCII content. Persist implements the Python form byte-for-byte in `src/verify/canonical.rs` (`PythonJsonDumpsCanonicalizer`, ASCII-only escaping) and the JCS form through `ciris_verify_core::jcs` (`JcsCanonicalizer`). A signed-epoch version gate picks the canonicaliser per row (`FSD/V4_6_JCS_CANONICALIZATION.md`). A parity test checks the Python form against recorded `json.dumps` outputs and asserts that it *disagrees* with the RFC 8785 reference on non-ASCII.

### 5.2 redb vs fjall

`redb` (§2.3). fjall's LSM shape is wrong for the journal pattern.

### 5.3 Reticulum-rs vs Leviculum

Transport is outside persist (§3.3). The choice belongs to CIRISEdge; persist's only requirement is that the deployment's signing key is its transport identity (`FSD/CIRIS_PERSIST.md` §3.4 #7).

### 5.4 cbindgen + swift-bridge vs uniffi

Not taken: persist ships PyO3 on every platform (§3.2).

### 5.5 jiff vs chrono

`chrono` (§2.9).

### 5.6 Schema generation toolchain

Not implemented (§4.2).

---

## 6. Cargo.toml shape

The dependency set, by feature (abridged; `Cargo.toml` is authoritative):

```toml
[dependencies]
# Always on
tokio         = { version = "1", features = ["rt-multi-thread", "sync", "macros", "signal", "time"] }
serde         = { version = "1", features = ["derive"] }
serde_json    = { version = "1", features = ["arbitrary_precision", "raw_value"] }
ed25519-dalek = { version = "2", features = ["rand_core", "zeroize"] }
sha2          = "0.10"
chrono        = { version = "0.4", features = ["serde"] }
thiserror     = "2"
tracing       = "0.1"
redb          = "4"
ciris-keyring / ciris-verify-core / ciris-crypto   # CIRISVerify, one git tag

# feature "postgres"
tokio-postgres    = { version = "0.7", features = ["with-chrono-0_4", "with-serde_json-1", "with-uuid-1"] }
deadpool-postgres = "0.14"
refinery          = "0.9"

# feature "sqlite"
rusqlite = { version = "0.31", features = ["backup", "chrono", "serde_json", "functions"] }   # + "bundled" on Android

# feature "pyo3" / "pyo3-sqlite"
pyo3 = { version = "0.29", features = ["abi3-py310"] }

# feature "server"
axum  = "0.8"
tower = "0.5"

[dev-dependencies]
serde_json_canonicalizer = "0.3"   # RFC 8785 parity reference; not a runtime dep
```

`serde_json_canonicalizer` is a **dev-dependency for the parity test** (§5.1) and backs the test-only `Rfc8785Canonicalizer`; production JCS comes from `ciris-verify-core`. Every dependency passes the license gate (§1) under `cargo deny check` in CI.

---

## 7. Watchlist

1. **`ed25519-dalek 3.0`** — track for a stable release; migration is mostly minor type changes.
2. **`sqlx` stable** — revisit only if it offers a real ergonomics win for the batch-insert path.
3. **`jiff 1.0`** — worth migrating only once `tokio-postgres` supports it first-class.
4. **`uniffi 1.0`** — relevant only if a Rust-native mobile binding is needed (§3.2).
5. **`fjall`** — revisit only if a workload wants LSM characteristics (§2.3).

---

## 8. References

- `Cargo.toml` — the dependency set and feature flags.
- `deny.toml` — the license allow-list (§1).
- `FSD/CIRIS_PERSIST.md` §3.1 — crate layout this set of deps services.
- `FSD/CIRIS_PERSIST.md` §3.4 — robustness primitives (redb journal, bounded queue).
- `FSD/CIRIS_PERSIST.md` §7 — design decisions and open questions.
- `FSD/PLATFORM_ARCHITECTURE.md` — the platform matrix these choices serve.
- `context/TRACE_WIRE_FORMAT.md` §8 — canonical bytes spec that drives §5.1.
- `context/PROOF_OF_BENEFIT_FEDERATION.md` §3.2, §5.7 — the Reticulum transport context for §3.3.
