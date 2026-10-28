# Platform Architecture — robustly supporting every CIRIS deployment target

**Status:** Describes the platform matrix, layering and CI that exist. Targets that are not built are marked **Not implemented**.
**Companions:** `FSD/CIRIS_PERSIST.md` (the spec), `FSD/CRATE_RECOMMENDATIONS.md` (the dep choices)

The crate runs on the lens, the agent server, the agent on iOS and Android, and desktop developer machines. This document describes the architecture that keeps those targets supported, and keeps room for the ones that are not built (Proof-of-Benefit §2.5's solar-LoRa sovereign node, an MCU verify-only relay, a browser runtime).

The framing principle: **decouple the substrate from the surface.** Storage backends, FFI bindings and packaging targets are independent layers; adding one must not require touching the others.

---

## 1. Platforms — the matrix we commit to supporting

| Platform | Triple(s) | Status | Backend | FFI / packaging | Notes |
|---|---|---|---|---|---|
| **Linux server (x86_64)** | `x86_64-unknown-linux-gnu` | Supported; CI tests | postgres / sqlite + redb | PyO3 wheel | Lens ingest. The default. Full test suite with a real postgres. |
| **Linux server (arm64)** | `aarch64-unknown-linux-gnu` | Supported; wheel built on a native arm runner | postgres / sqlite + redb | PyO3 wheel | Cloud arm and Pi-class hosts. |
| **macOS dev (Apple Silicon)** | `aarch64-apple-darwin` | Supported; CI tests (no postgres) | sqlite (postgres works locally) | PyO3 wheel | Developer machines. |
| **macOS dev (Intel)** | `x86_64-apple-darwin` | Sunset target — keep CI green only (§3.5) | sqlite / postgres | PyO3 wheel (manual) | Cache-warm job only. |
| **Windows (x86_64)** | `x86_64-pc-windows-msvc` | Wheel built on release tags | sqlite / postgres | PyO3 wheel | |
| **iOS device** | `aarch64-apple-ios` | Supported; built on main and tags | sqlite (system libsqlite3) | PyO3 abi3 `.so` for BeeWare | §3.1. |
| **iOS simulator** | `aarch64-apple-ios-sim` | Supported; built on main and tags | sqlite (system libsqlite3) | PyO3 abi3 `.so` for BeeWare | §3.1. |
| **Android** | `aarch64-linux-android`, `x86_64-linux-android`, `armv7-linux-androideabi` | Supported; built in CI | sqlite (bundled) | plain `.so` + PyO3 (Chaquopy) abi3 `.so` | §3.2. |
| **Embedded Linux (Pi-class sovereign)** | `aarch64-unknown-linux-gnu` | Uses the Linux arm64 build | sqlite + redb | PyO3 wheel | §3.3. No dedicated CI job. |
| **MCU no_std (sovereign micro)** | `thumbv7em-none-eabihf`, `riscv32imc-unknown-none-elf` | **Not implemented** | none — verify-only | — | §3.4. |
| **Python (lens, agent in-process)** | one wheel per `(os, arch)` above | Supported | (delegated to host) | PyO3 abi3 wheel | §3.5. |
| **Web** | n/a | **Not implemented** (no TypeScript codegen) | n/a | — | §3.6. |
| **WASM (browser)** | `wasm32-unknown-unknown` | **Not implemented** | — | — | §3.7. |

**The targets that demand the most architectural care, because they have the least structural slack:**

1. **iOS** — system SQLite linkage, BeeWare Python packaging, App Store binary-size budget.
2. **Android** — NDK version pinning, three ABIs, 16KB page size on Android 15+.
3. **Python wheel** — `abi3-py310` so one wheel covers every supported Python minor version.

Linux server, macOS dev and Linux Pi-class hosts are close to a strict subset of the Linux x86_64 server target's capability surface, plus or minus a CPU feature flag and a packaging script.

---

## 2. Layered architecture — what makes it robust

The crate is structured in layers, each independently testable:

```
┌────────────────────────────────────────────────────────────────┐
│  Layer 4 — FFI shell                                            │
│  ffi/pyo3.rs   PyO3 entry points (wheel, iOS, Android/Chaquopy) │
│  python/ciris_persist/ciris_persist.pyi   type stubs            │
└────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────▼──────────────────────────────────┐
│  Layer 3 — Public Rust API (the SOURCE OF TRUTH)                │
│  Engine (engine.rs): receive_and_persist, audit, tasks, graph,  │
│  federation, cirisnode, …                                       │
│  Errors via thiserror with stable kind() tokens; async via tokio│
└────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
┌───────▼────────┐  ┌─────────▼────────┐  ┌─────────▼────────┐
│  Layer 2a —    │  │  Layer 2b —      │  │  Layer 2c —      │
│  storage       │  │  trait           │  │  trait Scrubber  │
│  trait Backend │  │  Canonicalizer   │  │  - NullScrubber  │
│  + per-table   │  │  - PythonJson-   │  │  - Callback-     │
│  service traits│  │    Dumps         │  │    Scrubber      │
│  - postgres    │  │  - Jcs (RFC8785) │  │  - pipeline      │
│  - sqlite      │  │                   │  │    stages        │
└────────────────┘  └──────────────────┘  └──────────────────┘
                              │
┌─────────────────────────────▼──────────────────────────────────┐
│  Layer 1 — Pure types and verification                          │
│  schema/    serde-derived structs for the wire format           │
│  verify/    Ed25519, ML-DSA-65 hybrid, SHA-256, canonical bytes │
└────────────────────────────────────────────────────────────────┘
```

The robustness this gives:

- **Layer 1 has no I/O.** Schema definitions and verification logic carry no storage or network dependency. It is not built `no_std` (§3.4).
- **Layer 2 is orthogonal traits.** Storage (`Backend` plus one service trait per table group, each implemented by both backends), canonicalisation (`Canonicalizer`) and scrubbing (`Scrubber`). Each can grow new implementations without touching the others. The sqlite linkage question (system vs bundled) is a per-target build setting, not an architectural question.
- **Layer 3 is the one public Rust API.** The Python surface wraps it; there is no second implementation.
- **Layer 4 is per-language.** Today that is PyO3 only. A C ABI (feature `c-abi`) is declared and gates no code.

Federation transport (Reticulum, HTTP) is not a persist layer; it lives in CIRISEdge, which consumes persist's outbound queue and directory traits.

---

## 3. Per-platform robustness notes

These are the platform-specific concerns that "robustly supported" means in practice.

### 3.1 iOS — the biggest reach platform

The iOS agent runs Python through BeeWare; persist ships a PyO3 abi3 `.so` for it, built by the `ios-build` CI job for `aarch64-apple-ios` (device) and `aarch64-apple-ios-sim` (simulator) and packaged by `ios-package`.

**The robustness commitments:**

- **Cross-compiled with `cargo build`, not maturin.** PyO3 cross-compilation env vars plus BeeWare's Python-Apple-support for the target libpython and `_sysconfigdata` (PyO3 links libpython on iOS).
- **System SQLite, not bundled.** rusqlite links the platform `libsqlite3` dynamically on iOS (as on every desktop target), so persist and any other extension module in the same process share one SQLite instance (CIRISPersist#132).
- **Hardware-backed keys.** `ciris-keyring` uses the iOS keychain / Secure Enclave backend.
- **CI on main and release tags.** PR runs build iOS only when iOS-relevant paths change (`ios-paths` job); main and tag runs always build it. Release tags upload the artifacts to the GitHub Release (`mobile-release`).
- **Release profile.** `lto = "thin"`, `codegen-units = 1`, `strip = "symbols"` keep the library small.

**Not implemented:** a Swift package, `xcframework` and XCTest job (swift-bridge / cbindgen); a C ABI for a Rust-native iOS link.

### 3.2 Android

Built by the `android-ndk` CI job with `cargo-ndk` for three ABIs (`arm64-v8a`, `x86_64`, `armeabi-v7a`) at NDK API level 24, packaged by `android-package` and uploaded to the GitHub Release on tags.

**The robustness commitments:**

- **Bundled SQLite on Android only.** The NDK's libsqlite3 is not guaranteed across vendor builds, so Android builds `rusqlite` with `bundled`.
- **NDK version pinning.** The CI job pins the NDK (`r26b`); bumps are deliberate.
- **Two artifacts per ABI.** A plain `.so` and a PyO3 abi3 `.so` for Chaquopy (with an explicit `libpython3.10` `DT_NEEDED`).
- **16KB page size (Android 15+).** `.cargo/config.toml` links Android targets with `-z max-page-size=16384`.
- **Hardware-backed keys.** `ciris-keyring` uses the Android Keystore / StrongBox backend.

**Not implemented:** an AAR / Kotlin (uniffi) binding.

### 3.3 Embedded Linux (Pi-class) — the LoRa sovereign node

PoB §2.5 describes a resource-bounded agent that locally generates the constraint-network geometry federation needs: a Raspberry Pi 4 / 5 with a LoRa hat, solar-powered, running an agent and lens locally.

**What supports it:**

- **The Linux arm64 build.** The same wheel as cloud arm hosts.
- **Production-grade sqlite backend.** Pi-class deployments use sqlite (`FSD/SQLITE_CONNECTION_MODEL.md`).
- **Bounded memory.** Bounded ingest queue (`DEFAULT_QUEUE_DEPTH = 1024`), no unbounded growth on the ingest path.
- **Outage and power-cycle tolerance.** The `redb` journal holds batches when the database is unreachable and replays them on startup (`FSD/CIRIS_PERSIST.md` §3.4 #2).

**Not implemented:** a dedicated `armv7-unknown-linux-gnueabihf` build; a current-thread tokio runtime feature; a CI job that kills the process mid-ingest on a Pi-class target. The LoRa transport is CIRISEdge's concern.

### 3.4 MCU no_std — the smallest sovereign node

**Not implemented.** There is no `no_std` feature and no MCU CI job; `schema/` and `verify/` use `std`.

The target is kept in view so the architecture does not preclude it: a Cortex-M4F relay would validate a trace's signature and store the signed bytes as opaque flash, with no backend. Getting there needs `schema/` and `verify/` to compile `no_std + alloc`, and a Reticulum implementation with `no_std` support upstream.

### 3.5 Python — the lens path of least resistance

PyO3 0.29, `abi3-py310` (lowered from 3.11 for BeeWare iOS compatibility), built with `maturin`. One wheel per `(os, arch)` pair: `linux-x86_64` (`manylinux_2_34`), `linux-aarch64`, `darwin-aarch64` and `windows-x86_64`. PR runs build `linux-x86_64` only; release tags build all four.

**The robustness commitments:**

- **`abi3-py310`.** One wheel works for Python 3.10 and every later minor version.
- **darwin-x86_64 is a sunset target — keep CI green only.** No wheel is published for it from CI (Intel macOS runner capacity); it can be uploaded manually if a consumer needs it.
- **No `numpy` or `pandas` interop.** The PyO3 surface is pure types: bytes and JSON strings in, JSON-serializable results out. Keeps the wheel slim.
- **Synchronous from Python, async inside.** PyO3 calls run on the caller's thread (for FastAPI, its threadpool); the Rust side runs one tokio runtime and reuses it (`FSD/CIRIS_PERSIST.md` §7 #2).
- **Type stubs.** `python/ciris_persist/ciris_persist.pyi` ships with the wheel so `mypy` / `pyright` work.

### 3.6 Web — types only, runtime never

**The browser does not run `ciris-persist`.** It calls the lens's HTTP API and renders the results.

**Not implemented:** TypeScript type generation (`ts-rs`) and Pydantic / OpenAPI generation from Rust types (`FSD/CIRIS_PERSIST.md` §7 #12).

### 3.7 WASM — the explicit not-yet

**Not implemented; open question.** A lens "live trace verification" pane could run signature verification in WASM against a stream of events, saving a server roundtrip per event. A WASM target would need a storage variant (sqlite via the Origin Private File System) and a browser async-runtime story. It is built only if the lens has a concrete need.

---

## 4. CI matrix — what "robustly supported" means in practice

`.github/workflows/ci.yml`:

| Job | Target | What it runs |
|---|---|---|
| `linux-x86_64-test` | `x86_64-unknown-linux-gnu` | The test suite against a real postgres, one matrix entry per substrate feature set |
| `darwin-aarch64-test` | `aarch64-apple-darwin` | Tests without postgres |
| `darwin-x86_64-cachewarm` | `x86_64-apple-darwin` | Cache warm only, `continue-on-error` (sunset target) |
| `ios-build`, `ios-package` | `aarch64-apple-ios`, `aarch64-apple-ios-sim` | PyO3 cross-compile and packaging (§3.1) |
| `android-ndk`, `android-package` | three Android ABIs | `cargo ndk` build, plain + Chaquopy `.so` (§3.2) |
| `lint` | linux-x86_64 | `cargo fmt --check`; `cargo clippy` on the shipped feature shape and with `--all-features`, `-D warnings` |
| `license-audit` | linux-x86_64 | `cargo deny check` (licenses, advisories, bans) |
| `sqlite-portability` | linux-x86_64 | `scripts/sqlite_portability_witness.sh` (`FSD/MIGRATION_IMMUTABILITY.md` §6) |
| `pyo3-wheel` | per §3.5 | `maturin build --release --strip` |
| `build-manifest`, `attest` | — | Build manifest and provenance attestation |

Per release tag:

| Job | Output |
|---|---|
| `pyo3-wheel` (all four platforms) | abi3 wheels |
| `mobile-release` | iOS and Android artifacts uploaded to the GitHub Release |

Other workflows: `bench.yml`, `mutants.yml` (mutation testing), `reports.yml`, `ci-hygiene.yml`.

A regression on iOS or Android surfaces in CI before it reaches the agent's mobile builds.

---

## 5. Future-proofness commitments — the trait shapes

These trait shapes let new tables, canonical forms and scrubbers arrive without modifying existing implementations.

### 5.1 `trait Backend` and the per-table service traits

`store/backend.rs` defines `Backend: Send + Sync` with native `async fn in trait` (no `async_trait`). It carries the trace-ingest and storage-plane surface: `insert_trace_events_batch`, `insert_trace_llm_calls_batch`, `lookup_public_key`, `run_migrations`, trace deletion and paging, identity resolution, and fountain content storage.

Each agent table group has its own service trait (`TaskService`, `GraphService`, the audit service, …), implemented by both `PostgresBackend` and `SqliteBackend`. A new table group adds a trait and two implementations; it does not modify `Backend`. Every trait method has an implementation on both backends — there is no backend-only door.

### 5.2 `trait Canonicalizer` — two production impls

```rust
pub trait Canonicalizer: Send + Sync {
    fn canonicalize_value(&self, v: &serde_json::Value) -> Result<Vec<u8>, Error>;
}

pub struct PythonJsonDumpsCanonicalizer;  // byte-exact with the agent's json.dumps(sort_keys=True, separators=(",", ":"))
pub struct JcsCanonicalizer;              // RFC 8785 JCS via ciris_verify_core::jcs (FSD/V4_6_JCS_CANONICALIZATION.md)
#[cfg(test)] pub struct Rfc8785Canonicalizer;  // test-only parity reference
```

A signed-epoch version gate (`canonicalizer_for`) selects the canonicaliser per row, so the two forms coexist. They agree on pure-ASCII payloads and diverge on every non-ASCII character (Python escapes `\uXXXX`; JCS emits raw UTF-8). See `CRATE_RECOMMENDATIONS.md` §5.1.

### 5.3 Transport

Persist defines no transport trait. Federation transport (Reticulum, HTTP) lives in CIRISEdge, which consumes persist through the outbound queue and directory traits. See `CRATE_RECOMMENDATIONS.md` §5.3.

### 5.4 `trait Scrubber`

`scrub/mod.rs` defines `Scrubber: Send + Sync`, with `NullScrubber` and `CallbackScrubber` (the host's scrubber, called through a callback). The post-ingest pipeline adds feature-gated stages (`classify`, `scrub`, `scrub-ner`, `extract`; `FSD/POST_INGEST_FILTER_PIPELINE.md`). New scrubbers are trait implementations.

### 5.5 The schema-version contract

`SUPPORTED_VERSIONS: &[&str]` is a constant in `schema/version.rs`. Adding a wire version adds an entry plus the mapping for that version's shape; payloads of an older supported version keep validating against that version.

This is how ingest takes a new wire version without a flag day.

---

## 6. Open architectural questions

1. **Mobile FFI beyond Python.** Is a Rust-native iOS (Swift) or Android (Kotlin) binding needed, or does the Python runtime on both platforms suffice? Today persist ships PyO3 only.
2. **WASM browser runtime.** Built only if the lens grows an in-browser verify pane (§3.7).
3. **MCU no_std.** Depends on a Reticulum implementation with `no_std` support and on `schema/` + `verify/` going `no_std + alloc` (§3.4).
4. **Tokio runtime mode for embedded.** A current-thread runtime option for small Pi-class hosts running agent, lens and radio stack together.
5. **Schema codegen ownership.** Whether persist owns generation of client types (TypeScript, Pydantic) or consumers generate them (§3.6).
6. **Per-platform release cadence.** The crate releases at Linux speed; mobile app projects pin a crate version and bump deliberately.

---

## 7. Phasing

Not applicable: the layers and targets in §1–§5 exist as described; the unbuilt targets are marked **Not implemented** where they appear.

---

## 8. Closing note

Phasing and portability are the same problem viewed from two axes: *which tables are served*, and *which targets and language consumers are reached*. Both fall out of one commitment — **substrate decoupled from surface, a single source of truth in Rust**. With that in place, a new platform target is a CI job and a build script, not an architectural negotiation.
