# Platform Architecture — robustly supporting every CIRIS deployment target

**Status:** Sketch — to be promoted to addendum status once Phase 1 implementation has shaken out the trait shapes named below.
**Author:** Eric Moore (CIRIS Team) with Claude Opus 4.7
**Created:** 2026-04-30
**Companions:** `FSD/CIRIS_PERSIST.md` (the spec), `FSD/CRATE_RECOMMENDATIONS.md` (the dep choices)

The FSD commits the crate to running on lens, agent server, agent iOS, and (Phase 3) the bundled-Python-removed agent across all consumers. This document sketches the architecture that makes that promise robust and **future-proof against the next platform we'll inevitably add** — the one that's already implied by Proof-of-Benefit §2.5's solar-LoRa sovereign node, by Phase 3 §5.8's iOS deployment-size pressure, by the §11 schema-generation question for web/Kotlin clients, and by the WASM browser path that will surface once the lens grows a live trace pane.

The framing principle: **decouple the substrate from the surface.** Storage backends, FFI bindings, and codegen targets are independent layers; adding any one of them must not require touching either of the others.

---

## 1. Platforms — the matrix we commit to supporting

| Platform | Triple(s) | Phase | Backend | FFI | Notes |
|---|---|---|---|---|---|
| **Linux server (x86_64)** | `x86_64-unknown-linux-gnu` | 1 | postgres + redb | pyo3, native bin | Lens ingest. The default. |
| **Linux server (arm64)** | `aarch64-unknown-linux-gnu` | 1 | postgres + redb | pyo3, native bin | Cloud arm + Pi-class agent. |
| **macOS dev (Apple Silicon)** | `aarch64-apple-darwin` | 1 | postgres / sqlite | pyo3 | Developer machines. |
| **macOS dev (Intel)** | `x86_64-apple-darwin` | 1 | postgres / sqlite | pyo3 | Sunset target — keep CI green only. |
| **iOS device** | `aarch64-apple-ios` | 2 | sqlite (bundled) | swift | Replaces bundled-Python persistence. |
| **iOS simulator** | `aarch64-apple-ios-sim`, `x86_64-apple-ios` | 2 | sqlite (bundled) | swift | XCTest. |
| **Android device** | `aarch64-linux-android` | 2.5+ | sqlite (bundled) | kotlin (uniffi) | Future Kotlin Multiplatform. |
| **Android emulator** | `x86_64-linux-android` | 2.5+ | sqlite (bundled) | kotlin | KGP test. |
| **Embedded Linux (Pi-class sovereign)** | `aarch64-unknown-linux-gnu`, `armv7-unknown-linux-gnueabihf` | 2.3 | sqlite + redb | reticulum, native bin | Solar-LoRa sovereign node from PoB §2.5. |
| **MCU no_std (sovereign micro)** | `thumbv7em-none-eabihf` (Cortex-M4F), `riscv32imc-unknown-none-elf` | 3+ stretch | none — verify-only | reticulum (pending no_std upstream) | `schema/` + `verify/` modules only; for trace-validating relay nodes. |
| **Python (FastAPI lens, agent in-process)** | wheel built per-target above | 1 | (delegated to host) | pyo3 wheel | abi3-py311; one wheel per `(os, arch)`. |
| **Web (TypeScript types only)** | n/a | 1 | n/a | ts-rs codegen | Browser consumes generated `.d.ts`, not the runtime. |
| **WASM (browser future)** | `wasm32-unknown-unknown` | open / Phase 3 stretch | sqlite via OPFS (proposed) | wasm-bindgen | Speculative — only if lens grows a browser-direct trace pane. |

**The four targets that demand the most architectural care, because they have the least structural slack:**

1. **iOS** — bundled SQLite (no system linkage), `xcframework` packaging, App Store binary-size budget.
2. **Android** — NDK version pinning, AAR packaging, 16KB page size on Android 15+.
3. **MCU no_std** — `core::` only, no allocator-by-default, code size budget under 256KB flash.
4. **Python wheel** — `abi3-py311` so we ship one wheel per `(os, arch)` pair instead of one per Python-minor-version.

The four targets that come "for free" if the four above are robust:
**Linux server, macOS dev, Linux Pi-class, web TS types.** Each of those is a strict subset of the Linux x86_64 server target's capability surface, plus or minus a CPU feature flag and a packaging script.

WASM is the deliberate not-yet — see §6.

---

## 2. Layered architecture — what makes it robust

The crate is structured in five layers, each independently testable:

```
┌────────────────────────────────────────────────────────────────┐
│  Layer 5 — Codegen surface (build-time only, no runtime cost)   │
│  schemars → JSON Schema → Pydantic / OpenAPI                    │
│  ts-rs    → TypeScript .d.ts                                    │
│  swift-bridge / cbindgen → Swift Package, C header              │
│  uniffi   → Kotlin (when Android lands)                         │
└────────────────────────────────────────────────────────────────┘
           ▲                         ▲                ▲
           │                         │                │
┌────────────────────────────────────────────────────────────────┐
│  Layer 4 — FFI shells (each isolated; adding one ≠ touching     │
│             the others)                                          │
│  ffi/pyo3.rs   pyo3 entry points, Python-friendly ergonomics    │
│  ffi/c.rs      cbindgen-generated C ABI                         │
│  ffi/swift.rs  swift-bridge type bridges (sits over c.rs)       │
│  ffi/uniffi.rs uniffi UDL (Phase 3, if Kotlin Multiplatform     │
│                  becomes a hard requirement)                    │
└────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────▼──────────────────────────────────┐
│  Layer 3 — Public Rust API (the SOURCE OF TRUTH; everything     │
│             above is generated from this)                       │
│  receive_and_persist(bytes) → BatchSummary                      │
│  audit::append, tsdb::record, tasks::*, graph::*                │
│  Errors via thiserror; async via tokio; sync where possible     │
└────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
┌───────▼────────┐  ┌─────────▼────────┐  ┌─────────▼────────┐
│  Layer 2a —    │  │  Layer 2b —      │  │  Layer 2c —      │
│  trait Backend │  │  trait           │  │  trait Transport │
│  (storage)     │  │  Canonicalizer   │  │  (federation)    │
│  - postgres    │  │  - PythonCompat  │  │  - reticulum-rs  │
│  - sqlite      │  │  - JCS (RFC8785) │  │  - leviculum     │
│  - memory      │  │  - future variants│  │  - in-mem testing│
│  - (future:    │  │                   │  │  - (future:      │
│     wasm-OPFS) │  │                   │  │     veilid?)     │
└────────────────┘  └──────────────────┘  └──────────────────┘
                              │
┌─────────────────────────────▼──────────────────────────────────┐
│  Layer 1 — Pure types and verification (no_std-clean)           │
│  schema/    serde-derived structs for wire format               │
│  verify/    Ed25519, SHA-256, chain anchor verification         │
│             — no I/O, no async, no allocator (beyond core::*)   │
│  scrub/     PII scrubber trait + passthrough impl               │
└────────────────────────────────────────────────────────────────┘
```

The robustness this gives you:

- **Layer 1 compiles `no_std`.** That's the load-bearing portability commitment. A Cortex-M4F LoRa relay can validate a wire-format batch without dragging Postgres or tokio into firmware. Schema definitions and verify logic stay portable across every target in §1.
- **Layer 2 is three orthogonal traits.** Backend (storage), Canonicalizer (signing-bytes shape), Transport (federation). Each can grow new impls without touching the others. The sqlite-bundled-vs-system question is a Backend variant, not an FSD-level architectural question.
- **Layer 3 is the ONE public Rust API.** Every other surface (Python, Swift, Kotlin, TS, OpenAPI) is generated from it or wraps it. Renaming a function in Layer 3 means the codegen flags a stale binding *at build time*, not at runtime when a downstream Kotlin client crashes.
- **Layer 4 is per-language.** Adding Dart later means adding `ffi/dart.rs`, not refactoring the Rust API.
- **Layer 5 is build-time only.** The TypeScript / Pydantic / Swift consumers don't even link against this crate at runtime — they consume types generated from it.

This is the same shape `cirislens-core` already proves out at the Rust verify edge; the move here is making that pattern the explicit organizing principle for `ciris-persist` from line one.

---

## 3. Per-platform robustness notes

These are the platform-specific concerns that "robustly supported" actually means in practice. Each one has historically broken cross-platform Rust projects when it wasn't planned for.

### 3.1 iOS — the biggest reach platform

**The pain we're fixing:** bundled Python persistence at `client/iosApp/Resources/app/ciris_engine/logic/persistence/` (FSD §3.5, §5.8). Apple's `SQLiteDatabaseTracking` warning, deployment-size bottleneck, parallel maintenance with the server-side Python persistence module.

**The robustness commitments:**

- **`rusqlite` with `bundled` feature.** Statically link SQLite-from-source, never touch Apple's system SQLite. The bundled SQLite version is pinned to what we test against, eliminating the Apple-system-SQLite-version-drift class of bugs.
- **`xcframework` packaging.** Ship one `.xcframework` containing both `aarch64-apple-ios` (device) and `aarch64-apple-ios-sim` + `x86_64-apple-ios` (simulator). Build via `cargo lipo` or `xcodebuild -create-xcframework`.
- **Static lib only.** Dynamic libraries hit App Store review rules; static lib + Swift package wrapper is the well-trodden path (mozilla/application-services has been doing this for years).
- **Swift Package Manager integration.** `swift-bridge` generates a `Package.swift`-compatible Swift package with `#define`d header paths.
- **Bitcode disabled.** Rust's bitcode story is incomplete; Apple no longer requires bitcode anyway as of Xcode 14+.
- **Pointer authentication (PAC) on aarch64.** Rust 1.74+ handles this correctly. CI must use a recent stable.
- **Binary-size budget.** Strip + LTO + codegen-units=1 in release profile keeps the static lib around 4-6 MB. The bundled Python persistence is 10× larger; even a fat Rust build is a deployment-size win.
- **CI: actual iOS device test.** GitHub Actions has macOS runners; XCTest can drive a real `.xctest` against a simulator booted in CI. Cover the FFI roundtrip on every PR.

**Specific FFI layer:** `swift-bridge` over `cbindgen`. The `swift-bridge::bridge` macro emits both the C ABI (consumed by Kotlin / Dart later) and the Swift glue. Two outputs, one source of truth.

### 3.2 Android — Kotlin Multiplatform-shaped

**Phase 2.5+ target.** Not on the immediate runway but architecturally close enough to iOS that getting iOS right makes Android cheap.

**The robustness commitments:**

- **Same `rusqlite` bundled story.** Android's NDK ships its own SQLite that is similarly version-drifty.
- **NDK version pinning.** Pin to a specific NDK version in CI; bumps are deliberate. Android NDK r28 (2026) is current target.
- **AAR packaging.** Android Archive containing per-architecture `.so` files plus the Kotlin glue.
- **16KB page size (Android 15+).** Build with `-z max-page-size=16384` linker flag. Catches a real production issue that hit a lot of Rust+Android projects in 2025.
- **JNI generation via `uniffi`** *or* hand-written JNI on top of cbindgen's C ABI. Lean uniffi for Android specifically because the JNI ergonomics are painful enough that uniffi's "central UDL" cost is worth paying. (Different call than the iOS case where swift-bridge wins.)
- **Three architectures shipped:** `aarch64` (device), `x86_64` (emulator), `armv7` (older devices, can drop in 2027).

### 3.3 Embedded Linux (Pi-class) — the LoRa sovereign node

**Driven by PoB §2.5's claim** that a single resource-bounded agent can locally generate the constraint-network geometry that L-01 says federation needs. The concrete deployment shape: a Raspberry Pi 4 / 5 with LoRa hat, solar-powered, running a CIRIS agent + lens locally.

**The robustness commitments:**

- **`aarch64-unknown-linux-gnu` + `armv7-unknown-linux-gnueabihf` builds.** First-class CI targets.
- **Smaller default Postgres footprint.** Pi-class deployments use SQLite, not Postgres; the FSD's `sqlite` feature must be production-grade for this target, not just a Phase 2 stretch.
- **Tokio's `current-thread` runtime as an option.** Multi-threaded tokio is overkill on a 4-core Pi 4 with the agent + lens + LoRa stack also running. Expose runtime-mode as a feature flag.
- **Reticulum-rs transport, real LoRa radio.** This is the production path. The Phase 2.3 `peer-replicate` feature must work against an actual LoRa hat (RAK4631 or similar), not just a TCP loopback.
- **Memory budget: ≤256 MB resident** for the persist crate's portion. Bounded queue capacity, journal compaction, no unbounded vec growth. Tested under sustained load in CI.
- **Power-cycle resilience.** The redb journal must survive an `init 6` mid-batch. A standard test in CI: kill the process during ingest, restart, verify no data loss + no duplication.

### 3.4 MCU no_std — the smallest sovereign node

**Phase 3 stretch.** Not committed; sketched here so the architecture doesn't preclude it.

**The robustness commitments — to keep the door open:**

- **`schema/` and `verify/` modules compile `no_std + alloc`.** No `std::` in those modules. CI gate: a `cargo build --no-default-features --features no_std --target thumbv7em-none-eabihf` job.
- **No backend on MCU.** A Cortex-M4F can validate a trace's signature and store the signed bytes as opaque flash, but it doesn't run SQLite. The Backend trait is `cfg(feature = "std")`-gated; MCU builds get verify-only.
- **Reticulum no_std support is upstream concern.** Reticulum-rs's no_std story is pending; track in the watchlist.
- **Code size budget: 64KB for `verify/`** including ed25519-dalek + sha2. Both crates support `no_std`; their MCU footprint is well-characterized.

The point of this target is not to ship today. It's to **not architect ourselves out of it.** Layer 1 of §2 is the load-bearing commitment.

### 3.5 Python — the lens path of least resistance

**Phase 1 baseline.** PyO3 0.28, abi3-py311 wheel, one wheel per `(os, arch)` pair: `linux-x86_64`, `linux-aarch64`, `darwin-arm64`. Build via `maturin`.

**The robustness commitments:**

- **`abi3-py311`.** One wheel works for Python 3.11, 3.12, 3.13, future. We don't ship six wheels per OS.
- **`manylinux_2_28` baseline.** Cover every realistic Linux deployment without per-distro wheels.
- **No `numpy` or `pandas` interop in this crate.** The persist crate's PyO3 surface is pure-types: bytes in, JSON-serializable summary out. Keeps the wheel slim.
- **GIL-aware async surface.** PyO3 calls run on the FastAPI threadpool's threads (FSD §7 open question 2 resolved: synchronous from Python's view, internally async). The Rust side spawns a tokio runtime once at first call and reuses it; never inside the async-vs-sync trap.
- **Stub package for type checking.** Generate `.pyi` stubs alongside the wheel so `mypy` / `pyright` work. PyO3 has tooling for this as of 0.27.

### 3.6 Web — types only, runtime never

**The browser does not run `ciris-persist`.** It calls the lens's HTTP API and renders the results.

**The robustness commitment is on the schema side:** every API-shape Rust struct that crosses the lens HTTP boundary derives `ts_rs::TS`, and a build script writes `bindings/typescript/*.d.ts` files. The web client imports those types via npm package linkage to the bindings directory.

This means: **the same trait struct in `schema/runtime.rs` produces the Pydantic model the agent uses, the OpenAPI shape the lens serves, the TypeScript type the web client imports, and the Swift type the iOS client uses.** One source. No drift.

### 3.7 WASM — the explicit not-yet

**Open question; flag in the watchlist.**

The lens's browser path could grow a "live trace verification" pane that runs Ed25519 verify in WASM, against a stream of events served by the lens — eliminating a server roundtrip per event. That's compelling but speculative.

The Backend trait can grow a `wasm-opfs` variant (sqlite via the Origin Private File System) when needed; redb has wasm support today. Layer 1 already compiles for `wasm32-unknown-unknown` because it's `no_std`-clean.

**Decision:** ship TypeScript types now (which the browser uses), defer the WASM runtime question to Phase 3 unless lens UX surfaces a concrete need.

---

## 4. CI matrix — what "robustly supported" means in practice

Per PR, every PR:

| Job | Target | What it runs |
|---|---|---|
| `linux-x86_64-test` | `x86_64-unknown-linux-gnu` | `cargo test --features postgres,sqlite,server,pyo3` |
| `linux-aarch64-build` | `aarch64-unknown-linux-gnu` | `cargo build --features postgres,sqlite,server,pyo3` (cross-compile) |
| `darwin-aarch64-test` | `aarch64-apple-darwin` | `cargo test --features sqlite,pyo3` (no Postgres on Mac CI) |
| `ios-device-build` | `aarch64-apple-ios` | `cargo build --features sqlite,c-abi --no-default-features` |
| `ios-sim-test` | `aarch64-apple-ios-sim` | XCTest against generated Swift package |
| `android-aarch64-build` | `aarch64-linux-android` | `cargo build --features sqlite,c-abi` (Phase 2.5+) |
| `mcu-no_std-build` | `thumbv7em-none-eabihf` | `cargo build --no-default-features --features no_std` (Layer 1 only) |
| `pyo3-wheel-build` | each of linux-x86_64, linux-aarch64, darwin-arm64 | `maturin build --release --strip` |
| `python-binding-test` | linux-x86_64 | install wheel + run Python test suite against PyO3 surface |
| `swift-package-test` | darwin-arm64 | `swift test` against generated Swift package |
| `canonical-bytes-parity` | linux-x86_64 | corpus of recorded `python-json-canonical` outputs vs Rust impl, byte-exact compare |
| `journal-resilience` | linux-x86_64 | kill -9 mid-ingest, restart, verify no loss / no dupe |
| `lint` | linux-x86_64 | `cargo clippy --all-features -- -D warnings`, `cargo fmt --check` |
| `audit` | linux-x86_64 | `cargo audit` for dep CVEs, `cargo deny` for license drift |

Per release (tag push):

| Job | Output |
|---|---|
| `release-pypi` | publish abi3-py311 wheels to PyPI |
| `release-crates-io` | publish `ciris-persist` to crates.io |
| `release-swift-package` | tag the swift-bridge–generated package |
| `release-aar` | publish AAR to a maven coord (Phase 2.5+) |
| `release-typescript` | publish `@ciris/persist-types` to npm |

That's ~15 jobs per PR, ~5 jobs per release. Boring is good. The win is that **a regression on iOS surfaces in CI before it hits the iOS Resources directory in the agent repo.**

---

## 5. Future-proofness commitments — the trait shapes to seal early

These are the Phase-1-implementable trait shapes that future phases extend without modification. Locking these in correctly during Phase 1 is the difference between "Phase 3 took six months" and "Phase 3 was a sequence of one-week PRs."

### 5.1 `trait Backend` — sealed in Phase 1

```rust
#[async_trait]
pub trait Backend: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Phase 1 surface — append-only signed events.
    async fn insert_trace_events_batch(
        &self, events: &[TraceEventRow]
    ) -> Result<usize, Self::Error>;

    async fn insert_trace_llm_calls_batch(
        &self, calls: &[TraceLlmCallRow]
    ) -> Result<usize, Self::Error>;

    async fn lookup_public_key(
        &self, key_id: &str
    ) -> Result<Option<VerifyingKey>, Self::Error>;

    /// Phase 2 surface — agent audit log.
    async fn append_audit_entry(
        &self, entry: &AuditEntry
    ) -> Result<u64, Self::Error>;

    async fn record_correlation(
        &self, c: &ServiceCorrelation
    ) -> Result<(), Self::Error>;

    /// Phase 3 surface — runtime state + graph + governance.
    async fn upsert_task(&self, t: &Task) -> Result<(), Self::Error>;
    async fn try_claim_shared_task(
        &self, params: ClaimParams<'_>
    ) -> Result<(Task, bool), Self::Error>;
    async fn add_graph_node(&self, n: &GraphNode) -> Result<(), Self::Error>;
    // … etc — added in Phase 3 cutovers, but the trait shape is fixed Phase 1.

    /// Migration management.
    async fn run_migrations(&self) -> Result<(), Self::Error>;
}
```

Phase 1's `postgres.rs` impl satisfies the Phase-1 methods and `unimplemented!()`'s the Phase-2/3 ones; Phase 2's expanded impl fills in audit + correlation; Phase 3 finishes runtime state. **The trait surface itself is Phase 1 work** — that's the lock-in that prevents bifurcation.

### 5.2 `trait Canonicalizer` — sealed in Phase 1, two impls

```rust
pub trait Canonicalizer {
    fn canonicalize<T: Serialize>(&self, value: &T) -> Result<Vec<u8>, CanonError>;
}

pub struct PythonJsonDumpsCanonicalizer;  // Phase 1 — byte-exact with agent
pub struct RFC8785Canonicalizer;          // Future — when agent flips to JCS
```

The Phase 1 verify path takes `&dyn Canonicalizer` (or generics) so swapping is a configuration change, not a code change. See `CRATE_RECOMMENDATIONS.md` §5.1 for why this matters.

### 5.3 `trait Transport` — sealed in Phase 2

```rust
#[async_trait]
pub trait Transport: Send + Sync {
    async fn announce(&self, identity: &Identity) -> Result<(), TransportError>;
    async fn send_resource(&self, dest: Destination, bytes: Bytes)
        -> Result<(), TransportError>;
    fn subscribe_resources(&self) -> ResourceStream;
}
```

`reticulum-rs` and `leviculum` impls live behind feature flags; an in-memory test impl ships in tests. Switching transports is a Cargo feature flip — see `CRATE_RECOMMENDATIONS.md` §5.3.

### 5.4 `trait Scrubber` — already a passthrough Phase 1

The PII scrubber already lives in `cirislens-core`. The crate exposes a `Scrubber` trait and Phase 1 ships a `CirisLensCoreScrubber` impl that delegates. New scrubbers (Presidio-style, regex-based, locale-specific) become trait impls without changing the persist crate.

### 5.5 The schema-version contract

`SUPPORTED_VERSIONS: &[&str]` is a constant in `schema/version.rs`. Bumping it is a one-line change *plus* writing a migrator from the old schema to the new. The migrator lives in `schema/version/v_2_7_0_to_v_2_8_0.rs`. Old payloads validate against the old version forever; the lens applies on-ingest mapping when needed.

This is the FSD §10's "no flag-day at any phase" promise made concrete.

---

## 6. Open architectural questions surfaced

These either need a Phase 1 decision before code lands, or a tracked spike that gates a later phase.

1. **Canonicalizer-trait pluggability vs single Phase-1 impl.** This document leans toward shipping the trait + one impl in Phase 1, so the agent-flips-to-JCS path is cheap. Alternative: ship a concrete `python_json_canonicalize` function in Phase 1 and refactor to a trait when JCS lands. Lean: ship the trait. Cost ≈ same; future flexibility ≠ same.
2. **iOS swift-bridge vs uniffi (revisited from CRATE_RECOMMENDATIONS §3.2).** This document leans swift-bridge for iOS and uniffi for Android; CRATE_RECOMMENDATIONS leans cbindgen+swift-bridge for both. **Decision to make:** is the Android Kotlin path a hard requirement, or is "C ABI + JNI" enough? Lean: hard requirement, because Phase 3's iOS Python removal implies Android parity is the next ask. Plan the FFI shape for it now — pull uniffi in for Android specifically when Phase 2.5 lands.
3. **WASM browser runtime.** Is the lens going to grow an in-browser verify pane? If yes, the WASM target needs Phase 2 attention (Backend variant for OPFS, async runtime story for browser). If no, defer indefinitely. Lean: defer. Surface only when lens UX has a concrete need.
4. **Reticulum-rs no_std reach.** The MCU sovereign node target depends on Reticulum-rs (or Leviculum) gaining no_std support upstream. Track in CRATE_RECOMMENDATIONS watchlist. We don't ship MCU support until that lands; we don't architect ourselves out of it either.
5. **Tokio runtime mode for embedded.** Multi-thread tokio isn't right for a 4-core Pi running the agent + lens + LoRa stack. Expose `runtime-current-thread` as a feature flag *during Phase 1*, not later. The cost of doing it later is a tokio version bump that breaks runtime selection mid-rollout.
6. **Migration tooling target.** `refinery` runs against `tokio-postgres` and `rusqlite`. Does it run on iOS? On Android? Verify before Phase 2 commits — or write a tiny in-tree migrator that only depends on `Backend::run_migrations`.
7. **Schema codegen ownership.** Does `ciris-persist` own the codegen step (so it ships generated `.d.ts` / `.pyi` / `Package.swift`), or does the consumer repo (CIRISLens, CIRISAgent, web client) run codegen itself? Lean: this crate owns the build script that emits codegen artifacts, consumers vendor or symlink. Same model as `swift-protobuf`.
8. **Per-platform release cadence.** Linux + Python wheels can release weekly; iOS + Android release on the consumer's app-store cadence (every 2-4 weeks). Decide whether the crate version moves with Linux speed or app-store speed. Lean: crate moves at Linux speed; the iOS / Android app projects pin to a specific crate version and bump deliberately.

---

## 7. Phasing

This document doesn't change the FSD's three-phase shape. It refines what each phase has to land:

| Phase | Platform-architecture work |
|---|---|
| **1** | Layer 1 + Layer 2 traits (Backend, Canonicalizer) sealed. Layer 3 public Rust API. PyO3 FFI shell. Linux x86_64 + arm64 + macOS dev CI green. TypeScript codegen. Pydantic codegen. Canonical-bytes parity test. |
| **2** | sqlite Backend impl. iOS swift-bridge FFI + xcframework + XCTest CI. Android uniffi FFI + AAR + KGP test CI. Pi-class embedded Linux + power-cycle resilience CI. Reticulum-rs transport feature behind `peer-replicate`. |
| **2.5** | Android device shipping. Per-event chain extension if PoB §4.5 calls for it. |
| **3** | Phase 3 table cutovers per FSD §5. MCU no_std verify-only target if Reticulum-rs no_std support has landed. WASM Backend variant if lens browser pane has surfaced. |

Phase 1 is committing the architecture; later phases are filling it in. The cost of getting Phase 1's trait shapes right is what makes Phase 2 and 3 cheap.

---

## 8. Closing note

The FSD already says "the crate's API surface is designed in Phase 1 to support all of Phases 2 and 3 without future rewrites." This document operationalizes that promise across **platforms** as well as phases. The two are the same problem viewed from different axes:

- *Phasing* asks: "which tables and which agents are migrated when?"
- *Portability* asks: "which targets and which language consumers are reached when?"

Both answers fall out of the same architectural commitment — **substrate decoupled from surface, single source of truth in Rust, no_std-clean at the bottom, codegen-driven at the top.** Get that right in Phase 1, and every later platform target is a CI job and a build script away, not an architectural negotiation.
