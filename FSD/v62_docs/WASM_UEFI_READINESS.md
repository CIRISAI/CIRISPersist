# Persist v61.4.1: WASM and UEFI readiness (static pass)

Branch `wasm-uefi-probe`, cut from tag `v61.4.1` (`32e19ede`). Written 2026-11-15.
Design under test: CIRISServer `FSD/WASM_NODE.md` (the FSD), measured against persist v59.1.2.

**This is a static pass. Nothing was compiled.** At the start of the session the disk had 14 GB free,
below the 25 GB floor, and the coordinator approved a static-only pass: source reading, `grep`,
`cargo tree --offline` (resolves the graph and builds nothing), and the original probe sources. At the
end of the session the disk showed 224 GB free, so a build pass is now possible (§15).

Marks used on every claim:

- **[static]**: from source, manifests or `cargo tree --offline`, all at v61.4.1 in this worktree.
- **[read]**: read from another repo or document (the FSD, Verify, Kernel, Ossicle, the probe scratch).
- **[unverified, needs a build]**: an inference that only a compile or a run settles.

Tools added on this branch: `tools/wasm_audit/prod_sites.py` counts the wasm-hostile primitives in
**production** code. It strips comments and strings, and drops items and files gated `cfg(test)`,
`cfg(all(test, …))` and `test-anchor`. It splits the counts into node code, `src/ffi/` and `src/bin/`.

---

## 0. Verdict

| Target | Builds today? | Top blockers |
|---|---|---|
| Browser, `wasm32-unknown-unknown` (and the EFI module, which is the same bytes, §3) | **No.** [static; the compile errors are inferred from the graph and match the v59 probe log] | (1) `ciris-verify-core` default (host) features pull tokio `full`, which brings mio and socket2, plus reqwest, hickory, rustls, x509, zip and goblin; (2) `ciris-keyring` defaults pull libloading, keyring 3 and dirs; (3) `fs4` (rustix/errno) has no sys module off unix/windows; (4) `uuid` v4 hits a `compile_error!` without a randomness feature; (5) getrandom 0.2 has no backend on this target; (6) chrono/wasmbind, getrandom 0.3/0.4 `wasm_js` and time are already JS-shaped, which breaks the three-import rule even once it compiles; (7) refinery's runner calls `OffsetDateTime::now_utc()`, which panics at runtime on this target |
| `wasm32-wasip2` | **No** [static] | Everything above except wasmbind/JS, plus: rusqlite without `bundled` links the system `libsqlite3` through pkg-config (no sqlite-wasm-rs on `target_os = "wasi"`); fs4 fails (wasi is not `unix`); mio/socket2 on wasip2 are [unverified, needs a build]. Building persist as a wasip2 binary also contradicts FSD §4.1 rule 1 (no `wasi:*` imports), see §14 |
| `x86_64-unknown-uefi` (native) | **No, and it is not the path** [static/read] | The same graph plus `libsqlite3-sys` through pkg-config and tokio/mio on an incomplete `std`. The FSD's EFI node is the **wasm module run through wasm2c inside a host shim** (§3.1, §4.3). Persist never targets `*-unknown-uefi` directly. Readiness for UEFI therefore means readiness for `wasm32-unknown-unknown` under the three imports |

**Overall: partial.** The storage stack has landed: rusqlite 0.41.1 selects sqlite-wasm-rs 0.6.2 on its own on
`wasm32-unknown-unknown`, and the `links` conflict is gone. What blocks wasm is mostly dependency
configuration (Verify, keyring, tokio, uuid, getrandom, fs4, redb), not persist's logic. The logic-side work
is countable and small:

- 30 `Instant::now` sites;
- 4 `SystemTime` sites;
- 401 `Utc::now()` sites;
- 7 `tokio::spawn` sites;
- 10 tokio timer sites;
- 16 raw `spawn_blocking` sites on the sqlite path;
- 14 production `block_on` sites in `audit/merkle_store.rs`;
- 5 target-`cfg` sites;
- one PRAGMA block;
- one reader default.

---

## 1. A finding about the v59 probe that the FSD does not state

The probe sources survive at
`<local scratch>` (read only) [read]:

- **The Engine probe** (`sql-probes/engine-probe/`) ran the real `ciris_persist::Engine` in a Worker. **It used
  `wasm-bindgen`, `wasm-bindgen-futures`, `js-sys`, `getrandom` 0.2 `js`, 0.3 and 0.4 `wasm_js`, `uuid/js`,
  `time/wasm-bindgen` and `chrono/wasmbind`** (`engine-probe/Cargo.toml`). Persist itself was patched: it
  dropped fs4, set tokio to `rt, sync, macros, time`, set keyring to `default-features=false`, and rewrote
  `std::time` to `web-time` with `webtime.py` (`persist-Cargo.diff`).
- **The three-import payload** (`efi-probes/pay/`) is the module behind FSD §1 claim 2 and the OVMF table in
  §3.3. **It does not contain persist.** It is rusqlite + sqlite-wasm-rs + ml-dsa + ed25519-dalek + sha2, and
  it applies persist's migration **SQL text** (`mod mig`) with `execute_batch`, with no refinery, no Engine and no tokio.

So the FSD's claim "a module with SQLite, ML-DSA-65, Ed25519 and all 182 persist migrations needs exactly three
imports" holds for the migrations and the crypto. **An Engine under the three-import rule has never been
built** [read]. The browser Engine result (§1 claim 1) stands, but it ran on JS shims. Everything in §2 below is the
distance between those two probes.

---

## 2. Q1: `wasm32-unknown-unknown`, blockers in order

Command [static]:

```
CARGO_GUARD_MAX_GB=4 scripts/cargo_guard.sh cargo tree --offline --target wasm32-unknown-unknown \
  --no-default-features --features sqlite -e normal,build [-i <crate>] [-e features]
```

It resolved offline: 894 lines, and the smallest Engine feature set is just `sqlite`.

| # | Blocker | Path (`cargo tree -i`) | Site | Kind |
|---|---|---|---|---|
| 1 | **tokio `full`** → `mio` 1.2.2 (`net, os-poll`), `socket2`, `signal-hook-registry`, `process`, `fs` | `tokio feature "full"` ← `ciris-verify-core` v22.2.0 (workspace `tokio = { features = ["full"] }`, `~/.cargo/git/checkouts/cirisverify-…/7146fa4/Cargo.toml:23`); also h2, hickory, tokio-rustls | persist asks only `rt-multi-thread, sync, macros, signal, time` at `Cargo.toml:777` | compile error: "This wasm target is unsupported by mio" (v59 log `persist0-wasm32-unknown-unknown.log`) [read]; still in the v61 graph [static] |
| 2 | **verify-core host half**: reqwest 0.12, hickory-resolver 0.25, rustls 0.23 with ring `SystemRandom`, x509-parser, zip 9, goblin | `ciris-verify-core feature "default"` ← `ciris-persist` (`Cargo.toml:581`, default features on) | the dependency | v59 log: 5× `SystemRandom: SecureRandom not satisfied`, 7× `UnixTime::now` [read] |
| 3 | **ciris-keyring defaults** `software, keyring-storage, tpm-plugin` → libloading 0.8.9, keyring 3.6.3, dirs-sys | `ciris-keyring feature "default"` ← persist (`Cargo.toml:580`) and verify-core | the dependency | v59 log: `unresolved imports libloading::Library` [read] |
| 4 | **fs4 0.13.1** → rustix 1.1.4 → errno ("target OS is unknown … unsupported by errno") | ← persist `Cargo.toml:595` | `src/federation/replication/disk_pressure.rs:348` (`fs4::available_space`), `src/ffi/pyo3.rs:35028` | fs4 has `#[cfg(unix)] mod unix` / `#[cfg(windows)]` only (`fs4-0.13.1/src/lib.rs:125-134`) [static] |
| 5 | **redb 4.1.0** | ← persist `Cargo.toml:774` | `src/journal.rs:23`, declared unconditionally at `src/lib.rs:96`; used only by `queue::spawn_persister` (the lens server path), never by the Engine | redb has a `not(any(windows, unix, wasi))` fallback backend (`redb-4.1.0/src/tree_store/page_store/file_backend/mod.rs:6`), so it probably compiles, but it is file-shaped and off the node path [unverified, needs a build] |
| 6 | **uuid 1.23.5 `v4`** | ← persist `Cargo.toml:651`; moka ← hickory | 247 production `Uuid::new_v4()` in 24 files | `compile_error!("to use uuid on wasm32-unknown-unknown, specify … js, rng-getrandom, or rng-rand")` (`uuid-1.23.5/src/rng.rs:104`) [static] |
| 7 | **getrandom 0.2.17** with no backend | ← persist direct `Cargo.toml:549` (used once, `src/ffi/pyo3.rs:2178`); ← rand_core 0.6 (ed25519-dalek `rand_core`, ciris-crypto `std`) | | compile error without `js` or `custom` [static] |
| 8 | **getrandom 0.3.4 / 0.4.3 `wasm_js` already ON** | 0.3 `wasm_js` ← `jsonschema` 0.46 and `referencing` (even with `default-features=false`, `Cargo.toml:664`); 0.4 `wasm_js` ← `zip` (verify host) | | compiles, but the default backend is then **JS** (`getrandom-0.3.4/src/backends.rs:188-192`). That breaks the three imports unless `--cfg getrandom_backend="custom"` is set (§10) [static] |
| 9 | **chrono `wasmbind`** → wasm-bindgen 0.2.126, js-sys | ← `rusqlite` `chrono` feature on wasm-unknown (`rusqlite-0.41.1/Cargo.toml:316-320`), ← persist `chrono` default features (`Cargo.toml:635`), ← verify-core | 401 production `Utc::now()` (§5) | compiles; every `Utc::now()` becomes a JS `Date` import [static; import list unverified, needs a build] |
| 10 | **time 0.3.53** without `wasm-bindgen` | ← `refinery-core` 0.10.1, ← x509-parser | `refinery-core-0.10.1/src/runner.rs:130`: `applied_on = Some(OffsetDateTime::now_utc())` | compiles; **panics at the first migration**, because `SystemTime::now` is unsupported on this target. The probe passed only because it enabled `time/wasm-bindgen` (JS) [static/read] |
| 11 | **`std::time::Instant` / `SystemTime`** in persist | n/a | 30 `Instant` in 11 files, 4 `SystemTime` in 3 files (production, §5) | compiles; panics when reached [static] |
| 12 | **`cfg(unix)` / `cfg(windows)` code** | n/a | `src/queue.rs:205`, `:221` (`shutdown_signal`: neither arm exists on wasm, so the `pub use` at `src/lib.rs:246` fails to resolve); `src/store/sqlite_conn_model.rs:92`, `:117` (cgroup memory limit; the `not(linux)` arm returns `None`, harmless); `src/store/postgres.rs:6332` (not on the sqlite path); `src/ffi/pyo3.rs:2197` | `shutdown_signal` is a compile error [static] |
| 13 | **The `links = "sqlite3"` conflict** | `cargo tree -i libsqlite3-sys --target wasm32-unknown-unknown` → "nothing to print" | n/a | **Gone.** On this target rusqlite 0.41.1 selects `sqlite-wasm-rs` 0.6.2 through its default `ffi-sqlite-wasm-rs` feature (`rusqlite-0.41.1/Cargo.toml:109,113,328-334`), and sqlite-wasm-rs declares `links = "wsqlite3"` (`sqlite-wasm-rs-0.6.2/Cargo.toml:19`). Verify v22.2.0 also pins rusqlite 0.41 (workspace `Cargo.toml:74`) [static] |
| 14 | **ring 0.17.14** | ← `ciris-crypto` `aes-gcm` (implied by persist's `key-grant` and `hybrid-kex`, `Cargo.toml:587`), ← rustls-webpki | ring `aead` only, in `ciris-crypto/src/aes_gcm.rs:59`, `hpke.rs:44` | needs a C toolchain for wasm32 (clang or zig). ring's `SystemRandom` has no impl on wasm-unknown without `wasm32_unknown_unknown_js` (`ring-0.17.14/src/rand.rs:124-158`), but aead does not use it [unverified, needs a build] |

Blockers 1–3 vanish when persist takes **Verify 23** with `default-features = false, features = ["std", "pqc"]` and keyring with
`default-features = false, features = ["software", "pqc-ml-dsa"]` (§9). Blockers 4–12 are persist's own.

---

## 3. Q2: `wasm32-wasip2` and `x86_64-unknown-uefi`

Same command with `--target wasm32-wasip2` (443 crates) and `--target x86_64-unknown-uefi` (449 crates) [static]:

- **SQLite.** On both targets the graph carries `libsqlite3-sys v0.39.1 default,min_sqlite_version_3_45_3,pkg-config,vcpkg`. That is
  the system library, because persist enables `bundled` only on Android (`Cargo.toml:885`). sqlite-wasm-rs is gated to
  `target_os = "unknown"`. wasip2 would need `bundled` + `wasm32-wasi-vfs` and a wasi-sdk C compiler (FSD §3.1 [read]).
  UEFI has no libc for SQLite's C at all.
- **tokio `full`, mio, socket2 0.6.5, fs4/rustix/errno, redb, keyring 3.6.3, dirs-sys, ring**: present on both.
  fs4 fails on both (neither is `unix`) [static]. mio/socket2 on wasip2 [unverified, needs a build].
- **JS**: chrono still carries `wasmbind`, but on these targets that code is cfg'd off. getrandom 0.3/0.4 use WASI random
  on wasip2 and `efi_rng` on UEFI [static, from getrandom's backend tables].
- **UEFI native is not the FSD's path** (§4.3: wasm → wasm2c → PE in a host shim) [read]. The UEFI work for persist
  is the same as for the browser: one `wasm32-unknown-unknown` module with three imports, then the host's Block I/O VFS (§6.3).

**Recommendation for the CI middle lane:** run the **same `wasm32-unknown-unknown` module** under wasmtime with a
small host that implements `ciris.*` from WASI, rather than building persist for `wasm32-wasip2`. Building for
wasip2 adds a second SQLite build (bundled + wasi-vfs), puts `wasi:*` imports in the module (against FSD §4.1 rule 1), and
tests different bytes from the ones the browser and EFI run.

---

## 4. Q3: the FSD §10.3 table, item by item, at v61.4.1

| §10.3 change | Status at v61.4.1 | Site / evidence |
|---|---|---|
| tokio → `rt, sync, macros, time`; no `signal`, `rt-multi-thread` | **Still needed, and not sufficient alone.** Persist still asks for `rt-multi-thread, signal` (`Cargo.toml:777`), and verify-core v22 forces `full` anyway. Fix both sides | [static] |
| `shutdown_signal` on `cfg(unix)` | **Still needed.** `src/queue.rs:205` / `:221`; re-exported at `src/lib.rs:246`. Move it to the lifecycle event, or gate the queue module off the node | [static] |
| `fs4::available_space` → `storage.free-bytes` | **Still needed, and easier than the FSD says.** A `FreeBytesSource` trait already exists (`src/federation/replication/disk_pressure.rs:334-336`), with `StatvfsFreeBytes` at `:344-349` and a stub at `:356`. Add a host-backed impl and make fs4 optional | [static] |
| `std::time` → `web-time` | **Changed.** Production: 30 `Instant::now` / `std::time::Instant` in 11 files, plus 4 `SystemTime` in 3 files (§5). Raw counts including tests: 118 / 15. The FSD's "93 lines, 40 files" counted verify too. **New, larger item:** 401 production `chrono::Utc::now()` in 76 files plus 26 in ffi, which the FSD does not list. Under the three-import rule these need a clock seam, not `web-time`. `web-time` itself imports JS `performance.now` | [static] |
| `time/wasm-bindgen`, getrandom backends, `uuid/js` | **Still needed, and changed shape.** No JS (settled, §10): getrandom 0.2 `custom` + `register_custom_getrandom!`; getrandom 0.3/0.4 `--cfg getrandom_backend="custom"`, which defines one `__getrandom_v03_custom` symbol used by both 0.3 and 0.4 (`getrandom-0.4.3/src/backends/custom.rs:10`); uuid `rng-getrandom`. **time:** refinery's `now_utc()` (`runner.rs:130`) must not run. Persist applies the embedded migrations itself (§13 P6), or refinery is patched | [static] |
| PRAGMA order, exclusive first | **Still needed, and the site moved.** `src/store/sqlite.rs:1157-1163` (`apply_connection_settings`, fn at `:1142`; the FSD's `:1064` is stale): `foreign_keys, journal_mode=WAL, synchronous, busy_timeout, wal_autocheckpoint, journal_size_limit`. Also `apply_tuning` (`sqlite.rs:1105`) and `PRAGMA optimize` (`:615-618`) run later. `locking_mode=EXCLUSIVE` must be the first statement, chosen by a runtime capability (host says "single process"), not a `cfg` | [static] |
| `readers=0` | **Still needed; the door exists.** `open_with_readers` at `src/store/sqlite.rs:1095`; `readers == 0` skips both `materialize_wal` and the pool (`:1112-1121`). But `Engine::with_signer` → `src/engine.rs:11701` → `SqliteBackend::open`, which uses `default_reader_count()` (`sqlite_conn_model.rs:170-181`): env var, else `available_parallelism()`, which fails on wasm, so `unwrap_or(2).clamp(2,8)` = **2 readers**. That matches "the probe ran with 2 readers". Fix: the reader count comes from the host capability (single-thread host → 0) and is threaded through the DSN or the Engine builder | [static] |
| `redb` journal | **Still needed; simple.** `src/journal.rs` is used only by `queue.rs` / `server/` (`spawn_persister`), never by the Engine. Gate `journal` + `queue` (and `server`) behind a feature that the node build leaves off | [static] |
| `Backend` / `FederationDirectory` migration | **None, unchanged.** `async_trait` + `Send` futures, synchronous closures | [static] |
| Self-key re-registration conflict on reboot | **Fixed natively in v61 (#1146).** See §8 | [static/read] |

New sites since v59 that the table does not list [static]:

| New item | Site |
|---|---|
| `Condvar` in the read pool (blocks a single thread forever if a second guard is wanted) | `src/store/sqlite_conn_model.rs:24,194,241,297,317` (`ReadPool::acquire`). Moot with 0 readers, but `acquire` must never be reached on a single thread |
| `Condvar` + thread teardown gauge (`ciris-persist-teardown`) | `src/engine.rs:147-200` (`teardown` mod, `thread::Builder::spawn` at `:204`) → inline drop on wasm |
| `dispatch_blocking` | **moved** to `src/store/sqlite_conn_model.rs:378-391` (the FSD's `:194` is stale). It is correct only if no tokio runtime is current: with a tokio runtime on the thread it calls `spawn_blocking`, which needs threads |
| raw `tokio::task::spawn_blocking`, bypassing `dispatch_blocking`, on the sqlite path | `src/audit/sqlite.rs` (12), `src/secrets/sqlite.rs` (2), `src/encrypted_kv.rs:738` (1), `src/federation/at_rest_cascade.rs` (1) |
| `tokio::runtime::Handle::current()` (panics with no tokio runtime) | `src/audit/sqlite.rs` (4), `src/audit/merkle_store.rs:1101,1390,1465`, `src/queue.rs` (1) |
| sync-over-async `runtime.block_on` (production) | `src/audit/merkle_store.rs:409,465,496,…` (14 production of 33 raw); `src/queue.rs:288`; `src/federation/genesis/scratch.rs:95` (thread + current-thread runtime, `release_blocking` `:89-98`, called from `Drop`) |
| 196 SQLite migrations (FSD: 182) | `migrations/sqlite/lens/` (196 files) |

---

## 5. Architecture rules: production site counts (v62 work items)

`python3 -I tools/wasm_audit/prod_sites.py src` (433 production files, 142 test-only files dropped) [static].
"Node" excludes `src/ffi/` and `src/bin/`. Counts are an **upper bound**: several `pub mod` witness modules
compiled into the lib (`federation/bootstrap_admission.rs`, `at_rest_cascade.rs`, `chunk_dag_cascade.rs`,
`tier_ingest.rs`) are test drivers that are not `cfg`-gated, and they hold about 180 of the `Uuid::new_v4` and about 80 of the `Utc::now` hits.

| Rule (FSD / coordinator) | Primitive | Node hits / files | ffi | Work item |
|---|---|---|---|---|
| **No `cfg(target_*)` in node crates** (§4.1.2) | `cfg(unix|windows|target_os…)` | 5 sites / 3 files: `queue.rs:205,221`; `store/sqlite_conn_model.rs:92,117`; `store/postgres.rs:6332` | 1 (`pyo3.rs:2197`) | `shutdown_signal` → lifecycle event; cgroup limit → host capability; postgres stays host-only. Plus `Cargo.toml:874-886` target tables (linux/ios/android keyring, android `bundled`). Those are manifest `cfg`, which the lint should allow for host-only deps |
| **One thread, `ciris-rt` executor** (§5) | `tokio::spawn` | 7 / 4: `engine.rs:2098,2205,11451` (background loops), `queue.rs:264`, `disk_pressure.rs:576`, `store/postgres.rs` (2, host) | 4 | → `ciris_rt::spawn`; the 3 engine loops → Cadence slots |
| | `tokio::time::{sleep,interval,timeout}` | 10 / 5 (engine 3, queue 2, disk_pressure 1, postgres 4) | 0 | → `ciris_rt::time` |
| | `Handle::current` / `try_current` | 15 / 6 (audit/sqlite 4, audit/postgres 4, postgres_runtime_connect 4, queue 1, postgres 1, sqlite_conn_model 1) | 0 | remove on the sqlite path; `dispatch_blocking`'s `try_current` becomes `ciris_rt::blocking` |
| | `Runtime::new` / `Builder` | 2 / 2 (`genesis/scratch.rs`, `store/test_backend.rs`) | 1 | `scratch` release → `.await` in an async release; `test_backend` → cfg(test) |
| | `std::thread::spawn` / `Builder` | 2 / 2 (`engine.rs:204` teardown, `genesis/scratch.rs:90`) | 0 | inline drop; async release |
| | `Condvar` | 8 / 2 (`sqlite_conn_model.rs` ReadPool, `engine.rs` teardown) | 0 | 0 readers; inline teardown |
| **`spawn_blocking` runs inline** | `spawn_blocking` (raw tokio) | 25 / 8; **16 on the sqlite path** (audit/sqlite 12, secrets/sqlite 2, encrypted_kv 1, at_rest_cascade 1); 8 postgres (host); 1 inside `dispatch_blocking` | 0 | route all 16 through `dispatch_blocking`, then make `dispatch_blocking` = `ciris_rt::blocking` (inline). **S**, mechanical |
| | `dispatch_blocking` | 6 / 3 (already right) | | keep |
| **`block_in_place` removed by `.await`** | `block_in_place` | **0** in all of `src/`, tests included | 0 | none. Edge's "126 block_in_place" is `block_on`; see §12 item 5 |
| | `.block_on(` (sync-over-async) | 17 / 4: `audit/merkle_store.rs` 14, `queue.rs` 1, `genesis/scratch.rs` 1, `store/test_backend.rs` 1 | 854 (`ffi/pyo3.rs`, the PyO3 bridge, host-only) | `SqliteMerkleStore`'s sync `TransparencyStore` impl → async trait or a synchronous body (it is SQLite, so synchronous is natural). **M** |
| Clock is an import (§4.4 `clock`) | `Instant::now` | 30 / 11 (replication/admission 7, cache 4, postgres 3, key_grant 3, maintenance 6, migration_timing 2, cache/admission 2, secrets 2, vocabulary 1) | 0 | → one `Clock` seam (monotonic) |
| | `SystemTime` | 4 / 3 (`store/migration_timing.rs`, `debug/mod.rs`, postgres) | 0 | → `Clock::wall` |
| | `chrono::Utc::now()` | **401 / 76** (upper bound) | 26 | → `Clock::wall`; most sit in door code (`store/sqlite.rs` 52, `engine.rs` 36, `admission.rs` 17). **M–L**, mechanical; much of it is "stamp first-held" |
| Randomness is an import (§4.4 `random`) | `Uuid::new_v4()` | 247 / 24 (upper bound) | 0 | uuid `rng-getrandom` + the custom backend: no source change |
| No ambient authority (§4.1.3) | `std::fs` | 10 / 8 (journal, sqlite_conn_model cgroup, migration_timing, signing/mod, debug, 3 scrub model loaders) | 7 | gate the scrub-ner loaders and `debug`; `signing/mod.rs` key file → host `seal`/`storage` |
| | `std::env::var` | 33 / 19 | 8 | env knobs (`CIRIS_PERSIST_SQLITE_READERS`, mmap, cache…) → host config. On wasm-unknown `env::var` returns `NotPresent` (harmless but silent) |
| | `fs4`, `redb`, `tokio::signal`, `libc` | 1, 1, 2, 3 | | §4 |

---

## 6. Q4: the module's import list and size

**Not measured: no build was run** [unverified, needs a build]. `wasm-tools` and `wasm-objdump` were not checked or
installed. Expected from §2, once the compile blockers are cleared but before the clock and RNG seams exist: imports from `__wbindgen_placeholder__`
for chrono's `Date` (every `Utc::now`), and for getrandom 0.3/0.4 `wasm_js` unless the custom cfg is set. Those break
the three-import rule. With the seams in place, plus the custom getrandom backend and the `sqlite-wasm-rs` host hooks mapped as in the payload
probe (`efi-probes/pay/lib.rs:12-19` [read]), the import set should be `ciris.now_us`, `ciris.random`, `ciris.log`
[unverified, needs a build]. The payload probe without persist measured 2.4 MB raw [read]. Persist adds the Engine, about 700k
lines of source in total (`find src -name '*.rs' | xargs cat | wc -l` = 705,753, including tests), so expect a much larger module; R8 applies.

---

## 7. Q5: migrations and SQL features under sqlite-wasm-rs

[static] counts over `migrations/sqlite/lens/*.sql` (196 files):

| Feature | Count | Needs a change on sqlite-wasm-rs? |
|---|---|---|
| `CREATE TRIGGER` | 25 | No (plain SQL) |
| `GENERATED ALWAYS` columns | 6 | No (SQLite ≥ 3.31; the build is 3.53.4) |
| JSON functions (`json_extract`, `->>` …) | 137 | No; JSON is built in since 3.38 |
| `subsec` modifier | 44 | No (≥ 3.42) |
| `'now'` in date functions | 73 | No source change. SQLite asks the VFS for the time (`xCurrentTimeInt64`), which sqlite-wasm-rs routes to `rust_sqlite_wasm_host_epoch_timestamp_in_ms`, i.e. `ciris.now_us` (payload probe `pay/lib.rs:15` [read]) |
| `localtime`, `random()`, FTS, virtual tables, `STRICT`, `WITHOUT ROWID` | 0 | n/a |
| Rust-registered `ciris_sha256_ed25519_raw` | 1 function | No. Pure Rust (sha2 + base64), registered at open (`src/federation/key_digest.rs:96-111`, called at `src/store/sqlite.rs:1198`); queries only, never in a migration (`key_digest.rs:87-88`). Needs rusqlite's `functions` feature, which is portable |

The v59 payload applied all 182 migrations with 0 failures on V8, wasmi and PE [read]. The 14 added since then (V183–V196) use
the same constructs [static]. **[unverified, needs a build]**: a re-run of the 196 under sqlite-wasm-rs in memory. The
probe's harness (`execute_batch` over the SQL text) can be reused as is. The **runner**, not the SQL, is the blocker: refinery's
`now_utc()` (§2 #10).

---

## 8. Q6: the self-key re-registration conflict on reboot

**Native showed it, and v61 fixed it.**

- The probe's second boot logged `conflicts with existing row: key_id wasm-probe-gcl6fxxczn already exists with different content`
  (`sql-probes/res-e7.jsonl`, `res-e9.jsonl`) against persist v59 [read].
- v61 added #1146: `register_self_federation_key` returns early, writing nothing, when the held row states the same pubkeys,
  identity, roles and expiry (`src/engine.rs` in `register_self_federation_key`, the `self_registration_unchanged` check;
  predicate at `src/federation/register.rs:1824`; CHANGELOG line 382) [static].
- The witness `i1146_restart_is_a_no_op_sqlite` opens **a file store twice** (`src/federation/self_registration_restart_invariants.rs:271-276`,
  body `:52`) [static]. **Not run here** [unverified, needs a build]. Run it with
  `scripts/cargo_guard.sh cargo nextest run --features sqlite -E 'test(i1146_restart_is_a_no_op_sqlite)'`.

It was a native defect, not probe-only. The cause was a fresh `valid_from` and a re-signed envelope on every boot. On wasm it disappears with
v61. Close the FSD's open item.

---

## 9. Verify 23: what persist must pass it, and where

Local checkout `<checkout CIRISVerify>` on `release/23.0.0` (`f7471bf`), read only [read].

**The shape.** Verify 23 has no host-value interface. Its pure tier takes **values as parameters**:

- `ciris-crypto` and `ciris-verify-core` have default-on `std`; core also has default-on `host`
  (`src/ciris-verify-core/Cargo.toml` features `std` / `host`; `CLAUDE.md:110`).
- Without `std`, both crates are `#![no_std]` + `alloc` (`ciris-crypto/src/lib.rs:30`, `ciris-verify-core/src/lib.rs:40`).
  They are checked on `wasm32-unknown-unknown`, `x86_64-unknown-uefi` and `aarch64-unknown-uefi` at MSRV 1.89 in CI (`pure-half`).
- Pure tier: "reads no clock, draws no randomness and does no I/O: `now` is a parameter and keys come from caller seeds."
- `std` adds `rand`, `ciris-crypto/random` (OsRng), `kdf`, `aes-gcm` (ring), `x509-parser`, `chrono/clock`.
- `host` adds keyring, tokio, reqwest, rustls, rusqlite, zip, goblin, libc.

**What persist uses, by Verify 23 tier.** Built from `grep -rhoE "ciris_verify_core::[a-z_]+" src` [static] and
`src/ciris-verify-core/src/lib.rs` cfgs [read]:

| Tier | Modules persist uses |
|---|---|
| pure | `accord_genesis` (81), `accord_live_quorum` (54), `substrate` (51), `transport_binding` (46), `jcs` (33), `genesis_bundle`, `classification`, `derive_symmetric_key`, `redactable`, `provenance`, `ceg_outbox`, `reconsider_dos`, `operational_admit`, `federation_self_record`, `produce_self_key_record`, plus ungated `transparency` (106), `threshold` (79), `self_at_login`, `fedcode`, `federation_provenance`, `locale_merkle`, `subject_binding`, `skill_import`, `test_anchor` |
| `std` | `security` (4), `trust_anchor_store` (2) |
| **`host`** | **`accord_custody_attestation` (17)**, **`device_attestation` (2)** |

**What persist must supply, and where:**

| Value | Verify 23 form | Persist site that supplies it |
|---|---|---|
| Wall time | `now: DateTime<Utc>` / `now_ms: u64` / `now_epoch_secs` parameters (e.g. `accord_genesis.rs:1042`, `transparency.rs:357`, `reconsider_dos.rs:185`, `trust_anchor_store.rs:1175`) | the new persist `Clock` seam (§13 P3), fed by `ciris.now_us`; today these callers pass `Utc::now()` |
| Key seeds | `from_seed` constructors (`MlDsa65SoftwareSigner::from_seed_bytes`, `ed25519_dalek::SigningKey::from_bytes`) | persist's identity mint (`src/ffi/pyo3.rs:2178` today draws with `getrandom::getrandom`; the Engine takes a built `LocalSigner`). Seeds come from `ciris.random` through the custom getrandom backend, or are handed in by the host `seal` |
| Randomness for `std`-tier draws | `rand_core::OsRng` → getrandom (`ciris-crypto/src/random.rs:39,65,83`, `x25519.rs:76,125`, `ed25519.rs:55`, `ml_dsa.rs:70`), behind the SP 800-90B startup health latch (`rng_health.rs:242`) | **not persist.** The final link (the node cdylib, best `ciris-host-abi`) defines `__getrandom_v03_custom` and registers the getrandom 0.2 custom fn, both calling `ciris.random`. Persist only enables uuid `rng-getrandom` and must not define the symbol |
| Feature selection | `ciris-verify-core = { default-features = false, features = ["std", "pqc"] }`, `ciris-crypto` features as today | `Cargo.toml:581`, `:587` |

**Verify asks** (Verify's work, not persist's): (a) `accord_custody_attestation`'s **verifier** half
(X.509 / attestation chain checking against the pinned roots) moves from `host` to `std`. Persist's canonical-admission
FIPS floor calls it, and a SoftwareOnly browser node still has to verify peers' custody. (b) `ciris-keyring` gets
a no-host profile: `default-features = false, features = ["software", "pqc-ml-dsa"]` still carries `dirs` 6, `rand` 0.8,
`std::fs` in `src/software.rs` (29 sites) and `storage/mod.rs` (34) (`ciris-keyring/Cargo.toml` deps, read).
Persist uses only `MlDsa65SoftwareSigner`, `Ed25519SoftwareSigner`, `PqcSigner` / `HardwareSigner` traits and
`KeyringError` on the node path; `get_platform_signer`, `create_platform_storage` and `SecureBlobStorage` are host-side.
(c) Verify 23 is itself a BREAKING edition-2 cut (composite ML-DSA-65-Ed25519, CBOR/COSE), and persist pins v22.2.0. Adopting 23
belongs to v62 whatever the wasm plan.

---

## 10. Randomness: settled as getrandom `custom` (no JS); Ossicle does not fit

**Settled (coordinator, FSD §4.1):** no getrandom `js`. One module serves browser and EFI. The wiring [static, from the registry sources]:

| Crate | Mechanism | Who enables it |
|---|---|---|
| getrandom 0.2.17 | feature `custom` + `getrandom::register_custom_getrandom!(f)` | persist (direct, `Cargo.toml:549`), or drop the direct dep (one ffi use) and let the node crate add `custom` |
| getrandom 0.3.4 and 0.4.3 | `RUSTFLAGS=--cfg getrandom_backend="custom"` (target section of `.cargo/config.toml`); one `extern "Rust" fn __getrandom_v03_custom(*mut u8, usize) -> Result<(), Error>` serves both (`getrandom-0.3.4/src/backends/custom.rs:10`, `0.4.3/…/custom.rs:10`). The custom branch is checked **before** the `wasm_js` default (`backends.rs:11` vs `:188`), so jsonschema's and zip's `wasm_js` feature stops mattering | the node build's config, not persist's Cargo.toml |
| uuid | feature `rng-getrandom` (`uuid-1.23.5/Cargo.toml:115`) | persist `Cargo.toml:651` |
| sqlite-wasm-rs | five link-time hooks `rust_sqlite_wasm_host_{sleep,random,epoch_timestamp_in_ms,fill_entropy,localtime}` | the node crate (as in `pay/lib.rs:12-17` [read]) |

The payload probe already defined `__getrandom_v03_custom` over `ciris.random` (`pay/lib.rs:19`) [read]. [unverified, needs a build]:
whether wasm-bindgen still contributes any import when `wasm_js` is on but unused. Removing the feature at its source (jsonschema
`default-features=false` still enables `wasm_js` on `referencing`) is the clean fix, as an upstream ask or a feature patch.

**CIRISOssicle** (`<checkout CIRISOssicle>`, `1bc2f09`) [read]:

- It is a Python + CuPy (CUDA) GPU timing "strain gauge" (`src/strain_gauge.py:505` `generate_trng`, `src/trng_generate.py`).
- Its TRNG output is raw timing LSBs ("lower 4 bits, 6/6 NIST"), with no conditioner and no DRBG.
- It is licensed **BSL 1.1**, not AGPL.

It does **not** fit `ciris.random`: there is no GPU in a Worker or in firmware, and it is not Rust. Unconditioned bits also violate "CSPRNG or trap; there is no weak fallback" (§4.4).
At most it could be one extra entropy input that a host mixes into its own DRBG on a native GPU host. It belongs to neither persist nor the
node module. Use `crypto.getRandomValues` (browser), `EFI_RNG_PROTOCOL` (EFI) and `wasi:random` (wasmtime), as the FSD already says.

---

## 11. The kernel crate: what it shrinks, and what it does not

CIRISKernel `crates/ciris-kernel` on branch `kernel-crate`, fetched through `gh api …/contents/…?ref=kernel-crate` [read]:

- **`#![no_std]`, `#![forbid(unsafe_code)]`, `extern crate alloc`, and zero dependencies** (`src/lib.rs:26-29`;
  `Cargo.toml` `[dependencies]` is empty; `rust-version = "1.89"`). No tokio, no clock, no crypto, no I/O. Only
  `alloc::collections::{BTreeMap, BTreeSet}`, `Vec` and `String` (grep over all 13 modules). It builds for any target persist targets
  [read; unverified for wasm, needs a build, but nothing in it can fail].
- Instants are generic ordered types (`window::WindowRow::T`, `key_end::KeyEndRow::T`), and `now` is passed in (`ADOPTING.md`, "Instants").

**The surface it shrinks.** ADOPTING.md maps these persist decisions onto kernel functions:

- `plan_put_attestation`, `owner_of`;
- `consensus::{evaluate, eligible, counted}`;
- `trust_root_valid`, `check_federation`;
- `check_delegation_cycle_admission`;
- `is_roster_key_at`, `check_roster_act_fresh`;
- `self_roster`/`cosign::execute_due`;
- `held_head_verdict`, `stamp_entitles`;
- `purge_finalize`;
- key liveness.

Those decisions live in 10 files: `attestation_admit`, `admission`, `consensus`, `trust_root`, `replication/admission`,
`self_roster`, `cosign`, `group_supersede_admit`, `precedence`, `steward_purge`. Together they are **53,725 production lines** [static]. Their wasm-hostile content:

| Primitive | In the kernel-replaced files | Persist node total |
|---|---|---|
| `tokio::spawn`, `spawn_blocking`, `block_on`, threads, `Condvar`, tokio timers, `Handle::current`, `std::fs`, target `cfg` | **0** | 7 + 25 + 17 + 2 + 8 + 10 + 15 + 10 + 5 |
| `Instant::now` | 7 (all `replication/admission.rs`, the rate limiter, which persist keeps) | 30 |
| `chrono::Utc::now()` | 31 (admission 17, attestation_admit 7, trust_root 5, cosign 1, steward_purge 1) | 401 |
| `Uuid::new_v4` | 1 | 247 |

**Assessment.** The kernel makes the node **smaller and easier to reason about**, not much more compilable:

- **What it does.** About 54k lines of decision code become calls into a zero-dependency `no_std` crate. A
  wasm build compiles and audits less persist code. The 31 `Utc::now()` reads in door code become one `now` argument at the
  kernel call, and the `execute_due` sweeps become "an answer read at `now`" (`window::outcome`). That is exactly the shape a tick-driven
  single-thread node wants: no timer task per sweep. The kernel also pins the `rust-version = 1.89` floor that Verify's pure half uses.
- **What it does not do.** Every blocker in §2 and nearly every site in §5 sit in what ADOPTING.md says persist **keeps**:
  bytes at rest, migrations, SQL and paging, the effect executor, replication, first-held stamping and the local operational store
  (`store/sqlite.rs`, `engine.rs`, `audit/`, `secrets/`, `queue`, `disk_pressure`, `cache`), plus the dependency graph (Verify, keyring,
  tokio, uuid, getrandom, fs4). The kernel touches none of them.

So "MUCH more viable" holds for **size and determinism**; the **porting** work below is independent of it and can run in parallel.

---

## 12. Edge's census of persist, checked

| # | Edge's claim | Finding [static unless marked] | Lands in v62 |
|---|---|---|---|
| 1 | tokio asks `rt-multi-thread` and `signal`; gate per target (wasm: sync/macros/rt/time) | **Partly right.** `Cargo.toml:777` is as stated, but **verify-core v22's workspace `tokio = full`** also forces `full`, `net` and mio regardless. A per-target table is a `cfg(target_*)` in the manifest; the FSD lints source `cfg`, not manifests. Better: persist depends on `tokio = { features = ["sync", "macros"] }` only, and `rt`/`time` come from `ciris-rt` or a host feature. Verify 23 non-host drops tokio | yes, S (persist) + Verify 23 adoption |
| 2 | getrandom 0.2 without `js`, direct and via rand_core 0.6 (dalek, x25519) and ring; add `js` on wasm | **Paths right; remedy withdrawn and settled: `custom`** (§10). Ring does not use getrandom on wasm-unknown without its own `wasm32_unknown_unknown_js` feature, and persist's ring use is aead only. Also missed: getrandom **0.3 and 0.4 already have `wasm_js` on** (jsonschema/referencing, zip), and **uuid** needs `rng-getrandom` | yes, S |
| 3 | Unconditional file-backed pieces: redb journal, fs4, 151 `std::fs` in 60 files | journal (`src/journal.rs`, `lib.rs:96`) and fs4 (`disk_pressure.rs:348`) confirmed. **151/60 is raw, tests included; production is 10 node sites in 8 files + 7 ffi + 3 bin** (§5). The journal is not on the Engine path, and `disk_pressure` already has a `FreeBytesSource` seam | yes, S |
| 4 | OPFS sahpool: no WAL, no shm, skip `materialize_wal`, 0 readers, non-WAL journal | **Withdrawn, settled for the FSD.** sahpool **does** accept `SQLITE_OPEN_WAL` files (`sqlite-wasm-vfs-0.3.0/src/sahpool.rs:78`) and has no `xShmMap` ("Shared-memory WAL is not supported", `:7`; `rsqlite-vfs-0.2.0/src/lib.rs:1213`), so WAL works **only** with `locking_mode=EXCLUSIVE` first (heap wal-index), as FSD §6.2 measured. Edge is right on: no shm, 0 readers, one connection per database (`sahpool.rs:5-6`). `materialize_wal` is already skipped when readers = 0 (`sqlite.rs:1112-1118`) | yes, S (PRAGMA order + reader capability) |
| 5 | ~126 non-FFI `block_in_place` calls that panic outside a multi-thread runtime (merkle_store 33) | **Mislabelled: there are 0 `block_in_place` anywhere in `src/`.** 126 = raw non-`ffi/pyo3.rs`, non-`ffi/directory_capsule.rs` **`block_on`**, tests included; merkle_store has 33 raw `block_on`. Production: **17 `.block_on(` in 4 files**: `audit/merkle_store.rs` 14 (sync `TransparencyStore` over `runtime.block_on` + `Handle::current` at `:1101,1390,1465`), `queue.rs:288`, `genesis/scratch.rs:95`, `store/test_backend.rs`. They panic inside any runtime (re-entrant `block_on`) and with no tokio runtime (`Handle::current`), not only outside multi-thread | yes, M |
| 6 | keyring `default-features=false`, dropping libloading / keyring3 / dirs | **Right for libloading and keyring 3; dirs stays.** Verify 23's keyring has `dirs = "6"` and `rand = "0.8"` as non-optional deps, and `std::fs` in `software.rs`/`storage/mod.rs`. Needs a keyring no-host profile (Verify ask, §9) | yes, S persist / M Verify |
| ask | encrypted-kv as home for Edge's transit-KEX and onion hop-key seeds (0600 files today) | **Yes, with three changes** (next) | yes, S–M |

**encrypted-kv on wasm** (`src/encrypted_kv.rs`, feature `encrypted-kv = ["sqlite", "ciris-crypto/kdf", "/hmac", "/xchacha", "/random"]`) [static].
Note that it is **not** the `secrets` feature: `secrets` adds `aes-gcm`, which means ring.

- **Works as is:** it is app-layer XChaCha20-Poly1305 + HKDF/HMAC-SHA3 over an ordinary rusqlite connection (no SQLCipher, no PRAGMA of its
  own). The crypto is pure Rust.
- **Change 1, its own database file.** `EncryptedKVStore::open(path, …)` opens a **second connection** (`encrypted_kv.rs:462-463`). On sahpool,
  two connections to one database "do not coordinate locks" (`sahpool.rs:5-6`), and the Engine writer holds `locking_mode=EXCLUSIVE`. So the
  KV must be its own sahpool file (a second slot), or ride the Engine writer. A separate file is simpler and keeps the
  "opaque file" property.
- **Change 2, `spawn_blocking`.** `encrypted_kv.rs:738` calls raw `tokio::task::spawn_blocking` → route it through `dispatch_blocking`.
- **Change 3, nonces.** `ciris_crypto::random::bytes` (`encrypted_kv.rs:434`) → OsRng → getrandom 0.2, which the custom backend (§10) covers; no source change.
- **The passphrase.** The root key is HKDF over a passphrase. On a SoftwareOnly browser node that passphrase must come from the host `seal`
  (WebAuthn PRF where present) or carry the software-key warning, per Eric's custody ruling.

---

## 13. v62 plan, sized

S = days, M = about a week or two, L = several weeks. "Native+" means native nodes benefit too.

### Persist

| # | Change | Site | Size | Depends on | Native+ |
|---|---|---|---|---|---|
| P1 | **Adopt Verify 23** non-host: `ciris-verify-core` `default-features=false, ["std","pqc"]`; keyring `default-features=false, ["software","pqc-ml-dsa"]` on the node build; move the `accord_custody_attestation` / `device_attestation` calls behind a host trait | `Cargo.toml:580-587,875-886`; the 19 host-module call sites | **L** (edition-2 cut is breaking; the feature trim itself is S) | Verify 23.x, V1 | yes (edition 2) |
| P2 | **Feature split `node` vs host**: gate `journal`, `queue`, `server`, `debug`, `pipeline/scrub` model loaders, `fs4`, `redb`, `libc`, the direct `getrandom` and `ffi` off the node set; tokio → `sync, macros` + `ciris-rt` | `Cargo.toml:549,595,596,774,777`; `src/lib.rs:96,111,246` | S | none | build hygiene |
| P3 | **`Clock` seam** (monotonic + wall), passed to the Engine; replace 30 `Instant`, 4 `SystemTime`, 401 `Utc::now()`; feeds Verify's `now` parameters and the kernel's `now` | 76 node files (§5) | M–L (mechanical, wide) | none | yes: deterministic tests, replay (FSD §5.1) |
| P4 | **Randomness via the custom backend**: uuid `rng-getrandom`; no persist-defined symbol; document the node-crate contract | `Cargo.toml:651` | S | H1 | none |
| P5 | **Single-thread executor seam**: 7 `tokio::spawn` + 10 timers → `ciris_rt`; the 3 engine loops (`engine.rs:2098,2205,11451`) → Cadence slots; 16 raw `spawn_blocking` → `dispatch_blocking`; `dispatch_blocking` → `ciris_rt::blocking`; `Handle::current` off the sqlite path | §5 rows | M | H2 (`ciris-rt`) | the `dispatch_blocking` routing fixes runtime-mismatch bugs natively (`foreign_runtime_1231`) |
| P6 | **Own migration runner over refinery's embedded list** (or patch refinery to take `applied_on`): kills `time::now_utc()` | `src/store/sqlite.rs:87,1639`; `store/migration_timing.rs` | S–M (must keep the `refinery_schema_history` rows and checksums byte-identical: a shipped migration is immutable as BYTES) | P3 | removes the `time` dep |
| P7 | **SQLite open profile as a host capability**: `locking_mode=EXCLUSIVE` first, WAL, `readers=0`, no mmap/cgroup tuning, no env knobs | `src/store/sqlite.rs:1095-1163`; `sqlite_conn_model.rs:92-181`; `engine.rs:11686-11701` (DSN → open) | S | H1 (capability answer) | a single-process profile helps mobile |
| P8 | **`audit/merkle_store` without sync-over-async**: synchronous SQLite body or async trait | `src/audit/merkle_store.rs` (14 `block_on`, 3 `Handle::current`), `audit/sqlite.rs` | M | Verify `TransparencyStore` trait shape | yes: removes the re-entrant `block_on` panic class |
| P9 | `shutdown_signal` → lifecycle event; teardown thread → inline drop; `genesis/scratch` release → async | `queue.rs:205-232`; `engine.rs:147-210`; `genesis/scratch.rs:89-110` | S | P5 | yes (teardown simplification) |
| P10 | **§6.4 query shape**: two-phase key-then-row read; covering index `… asserted_at DESC`; counters for full scans; keyset cursors | the 18 `ORDER BY … asserted_at` reads in `src/store/sqlite.rs` (e.g. `:4349,4435,5016,5067`); a new migration | M | none (**can start now**) | **yes, the canonical first** |
| P11 | encrypted-kv: own file, `dispatch_blocking`, passphrase from `seal` | `src/encrypted_kv.rs:462,738` | S | P5, H1 | no |
| P12 | **CI gates**: a `wasm32-unknown-unknown` build lane of the node feature set; import-allowlist check (`ciris.*` only); source target-`cfg` lint (extend `prod_sites.py`'s `cfg_target` row into a gate); 196 migrations under sqlite-wasm-rs in memory | new workflow, `tools/wasm_audit/` | S–M | P1–P7 | stops native regressions from reaching wasm |
| P13 | Gate the witness modules compiled into the lib (`bootstrap_admission.rs`, `at_rest_cascade.rs`, `chunk_dag_cascade.rs`, `tier_ingest.rs` …) behind `cfg(any(test, feature = "test-anchor"))` | `src/federation/mod.rs` | S | none | smaller production lib; honest counts |
| P14 | Kernel adoption (CIRISKernel PR #1) | ADOPTING.md table | **L** (the v62 refactor itself) | kernel tag | yes |

### Not persist

| Owner | Work | Size |
|---|---|---|
| **Verify** | V1: `accord_custody_attestation` verifier to `std`; V2: keyring no-host profile (`dirs`, `rand` optional; no `std::fs` without `host`); V3: tag 23.x with the edition-2 ceremony set | M |
| **Host ABI / rt** (D12, new repo) | H1: `ciris-host-abi`: WIT, the custom getrandom symbol over `ciris.random`, the five sqlite-wasm-rs hooks, the import gate, capability answers (single-process, readers, free-bytes); H2: `ciris-rt` (executor, timers, `blocking` inline, replay) | S + M |
| **Edge** | `Transport` over `net`; its own tokio/timer migration; move its transit-KEX / onion seeds into encrypted-kv | L |
| **Host (browser / EFI / wasmtime)** | sahpool install and leader election (browser); Block I/O slot VFS, RNG, TSC clock, wasm2c (EFI); WASI adapter for the CI lane (wasmtime) | M / L / S |
| **Upstream (optional)** | jsonschema/referencing: stop enabling getrandom `wasm_js` by default; refinery: injectable `applied_on` | S |

**What the kernel covers or eases** (§11): P14 retires about 54k lines of door code from the wasm audit; P3 is cheaper because door-code `now`
becomes one kernel argument; the sweep loops (`execute_due`) drop out of P5's spawn list. P1, P2, P4–P13 are untouched by it.

**Suggested order:**

1. Start at once, in parallel with the kernel work: P10, P2, P4, P7, P13. These are small, and P10 helps native now.
2. Then P5, P6, P8, P9, and P12 as the gate.
3. P1 with Verify 23.x.
4. P3 alongside P14.
5. P11 when Edge moves its seeds.

---

## 14. Where this contradicts or corrects the FSD

1. **§1 claim 2 is about a payload without persist** (§1 here). "All 182 persist migrations under three imports" ran as SQL text through
   rusqlite, not through persist. The Engine probe (claim 1) used wasm-bindgen, getrandom/uuid/time/chrono JS backends and a patched
   persist [read].
2. **§10.3 "PRAGMA order: `sqlite.rs:1064`"** is now `src/store/sqlite.rs:1157-1163` (fn `:1142`); **`dispatch_blocking` `sqlite_conn_model.rs:194`** is now
   `:378` [static].
3. **§10.3 omits `chrono::Utc::now()`**: 401 production sites, the largest clock item. `web-time` is not a three-import answer either: it imports
   JS `performance` [static].
4. **§10.3 omits refinery's `time::OffsetDateTime::now_utc()`** (`refinery-core-0.10.1/src/runner.rs:130`). The probe passed only with
   `time/wasm-bindgen` (JS) [static/read].
5. **§10.3 omits uuid** (247 sites; `compile_error!` without a feature) and the already-on `wasm_js` features of getrandom 0.3/0.4 [static].
6. **§10.3 "tokio features" alone does not work**: verify-core v22 forces tokio `full` [static].
7. **§5.2 "persist `block_in_place` 0"** is right [static]. Edge's "126 block_in_place" is a mislabel for `block_on`.
8. **§6.1 "`links = sqlite3` conflicts across targets"** no longer applies: on wasm-unknown, rusqlite 0.41 uses sqlite-wasm-rs (`links = "wsqlite3"`),
   and verify and persist both pin rusqlite 0.41 [static].
9. **§6.1 "182 migrations"** is now 196 [static].
10. **The open item on self-key re-registration** was a native defect, fixed by #1146 in v61 [static/read].
11. **§3.1 wasip2 "rusqlite bundled + wasm32-wasi-vfs builds"** vs **§4.1 rule 1** ("no `wasi:*`"): building persist for wasip2 puts `wasi:*` imports in the module.
    Prefer the wasm32-unknown-unknown module under wasmtime with a WASI-backed `ciris.*` host (§3) [static/inference].
12. **§10.3 "`fs4` → `storage.free-bytes`: 1 site"** is right, and the seam (`FreeBytesSource`) already exists [static].

---

## 15. Commands run, and what remains for a build pass

Run (all `cargo` through `scripts/cargo_guard.sh`, all `--offline`, none compiling):

```
cargo tree --offline --target wasm32-unknown-unknown --no-default-features --features sqlite -e normal,build --prefix depth --format '{p} {f}'
cargo tree … -i {tokio,mio,fs4,redb,getrandom@0.2.17,getrandom@0.3.4,getrandom@0.4.3,uuid,time,wasm-bindgen,js-sys,libsqlite3-sys,sqlite-wasm-rs,chrono,libc,web-time,parking_lot} --depth 3
cargo tree … -e features -i {tokio,ciris-keyring,ciris-verify-core,chrono,getrandom@0.3.4,getrandom@0.4.3,uuid,ring,libloading,errno} --depth 2
cargo tree --offline --target {wasm32-wasip2,x86_64-unknown-uefi} --no-default-features --features sqlite -e normal --prefix none
python3 -I tools/wasm_audit/prod_sites.py src [--files <pattern>]
grep over src/, migrations/sqlite/lens/, ~/.cargo/registry/src/… (rusqlite 0.41.1, libsqlite3-sys 0.39.1, sqlite-wasm-rs 0.6.2,
  sqlite-wasm-vfs 0.3.0, rsqlite-vfs 0.2.0, getrandom 0.2.17/0.3.4/0.4.3, uuid 1.23.5, ring 0.17.14, fs4 0.13.1, redb 4.1.0, refinery-core 0.10.1)
gh api repos/CIRISAI/CIRISKernel/contents/crates/ciris-kernel/{ADOPTING.md,Cargo.toml,src/*.rs}?ref=kernel-crate
```

Not run (each [unverified, needs a build]); the disk is now at 224 GB free, so these can go next:

1. `cargo check --target wasm32-unknown-unknown --no-default-features --features sqlite` on v61.4.1 as is, to record the real error list.
2. The same with a probe patch: P2 + P4 + Verify v22 `default-features=false`, plus a node cdylib defining the custom getrandom symbol and sqlite hooks.
   Then `wasm-tools print | grep import` for the import list, plus raw and gzip sizes. `wasm-tools` is not installed; `cargo install wasm-tools` would be needed.
3. 196 migrations under sqlite-wasm-rs in memory (reuse `efi-probes/pay`).
4. `i1146_restart_is_a_no_op_sqlite` natively.
