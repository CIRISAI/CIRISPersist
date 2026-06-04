# Debugging harness — cohabitation races, migration timing, hangs, and background-thread panics

When a cohabitation symptom is "subprocess sometimes returns fast, sometimes
hangs with empty stderr," the source is usually a tokio background thread
panicking silently (default panic hook: print stderr, drop thread, continue
process) and leaving its subsystem half-initialized for the next call to race
into. This directory has the toolchain to find these:

- A Rust panic hook in `src/debug/mod.rs` that captures every background-thread
  panic with a symbol-resolved backtrace, opt-in via env var
- A migration-timing diagnostic in `src/store/migration_timing.rs` that
  quantifies how many microseconds each refinery `run()` adds to first-
  Engine-open (always compiled; env-var-armed)
- A Cargo profile `panic-debug` (in root `Cargo.toml`) that keeps full DWARF
  symbols so backtraces resolve
- A Python harness `race_repro.py` that drives a scenario over N subprocess
  rounds, classifies each outcome (fast / hung / panicked / other), and
  surfaces every signal we can capture
- A gdb wrapper `debug_attach.sh` for the case where you want a live snapshot
  of every thread's call stack in a hung process

The harness mirrors the CIRISEdge `tools/` shape — same `race_repro.py`
classifier, same panic-hook architecture, same `panic-debug` profile name.
That's intentional: the cohab race that motivated this harness
(CIRISPersist#156 / CIRISEdge#58) spans both layers, and being able to run
the same shape of repro on both sides while comparing manifests is the
point.

The panic-hook is **two-layer opt-in** with strict security posture:

1. **`debug-tools` Cargo feature** (default OFF) — `src/debug/` is not
   compiled at all. The `panic_count` and `install_panic_logger`
   pyfunctions don't exist on the module. The `CIRIS_PERSIST_PANIC_LOG`
   string isn't even *present* in the binary — there's no env var to
   inject. Release wheels published to PyPI build without this feature
   and carry **zero diagnostic surface**.
2. **`CIRIS_PERSIST_PANIC_LOG` env var** (only consulted when the feature
   is ON) — the panic hook installs only when this is set. So even a
   developer panic-debug wheel is silent at runtime unless the env var
   is explicitly exported.

The migration-timing diagnostic is **always-compiled** but env-var-armed
(`CIRIS_PERSIST_MIGRATION_TIMING_LOG`). The cost without the env var is
one `std::env::var` lookup per Engine open — cheap enough that gating
behind the feature flag is pure ceremony. Operators can also use this
in production to monitor migration-apply latency across releases.

Verification:

```bash
# Production wheel (no debug-tools):
nm ciris_persist.abi3.so | grep -c panic_count          # → 0
nm ciris_persist.abi3.so | grep -c install_panic_logger # → 0
strings ciris_persist.abi3.so | grep -c CIRIS_PERSIST_PANIC_LOG  # → 0

# Migration-timing IS in any wheel (always-compiled):
strings ciris_persist.abi3.so | grep -c CIRIS_PERSIST_MIGRATION_TIMING_LOG  # → ≥1
```

## Quick start — reproduce CIRISPersist#156 (sqlite cohab regression)

```bash
# 1. Build a panic-debug wheel (~80s build; large .so — debug info is
#    huge but the wheel is dev-only). The `--strip false` override is
#    REQUIRED — pyproject.toml's [tool.maturin] sets strip=true for
#    release wheels, which would otherwise drop the debug info maturin
#    is meant to preserve under panic-debug. The `debug-tools` feature
#    enables the in-process panic hook + dladdr resolution.
maturin build --profile panic-debug \
  --features "pyo3 extension-module sqlite postgres cirisaudit debug-tools" \
  --skip-auditwheel \
  --strip false \
  --include-debuginfo

# 2. Install into a clean venv
python3 -m venv /tmp/persist-debug && source /tmp/persist-debug/bin/activate
pip install --force-reinstall \
  target/wheels/ciris_persist-*-linux_x86_64.whl \
  ciris-edge==1.1.7 \
  ciris-verify==4.8.0

# 3. Run the harness with panic capture + migration timing armed
python3 tools/race_repro.py \
  --scenario tools/scenarios/sqlite_inmemory_cohab.py \
  --rounds 40 \
  --timeout 8 \
  --panic-log /tmp/persist-panic.log \
  --migration-timing-log /tmp/persist-migration-timing.log \
  --out /tmp/persist-race-manifest.json
```

The harness prints a one-line summary per round and a structured summary at
the end. Every panic captured by the in-process hook is written to
`/tmp/persist-panic.log.{pid}` per subprocess — fully symbolicated under the
panic-debug profile. Migration timing lands in
`/tmp/persist-migration-timing.log.{pid}` as JSON-Lines, one row per
`run_migrations()` call.

## What the harness captures (and when)

| Signal | Captured by | Wheel build | Notes |
|---|---|---|---|
| Subprocess returncode + stdout + stderr | `race_repro.py` | any | Default; always on. |
| `panicked at <file>:<line>` first line | `race_repro.py` (stderr classifier) | any | What tokio's default hook prints. |
| Resolved-symbol backtrace for every panic | `src/debug/mod.rs` panic hook | **panic-debug** for symbols | `CIRIS_PERSIST_PANIC_LOG=…` arms; release-strip wheel gives addresses. |
| Per-migration apply time | `src/store/migration_timing.rs` | **any** | `CIRIS_PERSIST_MIGRATION_TIMING_LOG=…` arms. Always-compiled. |
| Live all-thread call stacks at hang time | `tools/debug_attach.sh` | **panic-debug** for symbols | Needs `--gdb-on-hang` + ptrace permission. |

## When to use which

- **First-time triage of a race or hang.** Start with `race_repro.py` against
  a scenario script. The classifier tells you fast/hung/panicked counts; the
  manifest JSON gives you per-round outcomes for later analysis.
- **"Did v3.X.x add boot-time delay?"** Run the harness with
  `--migration-timing-log` against two pinned persist versions (e.g.
  v3.11.0 vs v3.12.1) and compare the `total_wall_us` distributions. This
  is what motivated the diagnostic: CIRISPersist#156 needed quantified
  proof that V058+V059 shifted the boot timing window.
- **"Why does this background thread panic?"** Build a panic-debug wheel and
  set `CIRIS_PERSIST_PANIC_LOG`. Every panic gets a resolved backtrace
  pointing at the call site that constructed a timer outside a runtime
  context (the most common shape for our cohabitation panics).
- **"Why does this subprocess hang with no panic?"** Use `--gdb-on-hang` so
  the harness invokes `debug_attach.sh` automatically on every hung
  subprocess. The all-thread backtrace tells you what every worker is parked
  on — usually a futex with one thread in `ep_poll` (IO driver) and the rest
  waiting for a wakeup that isn't coming. Cross-reference with the panic log:
  if a panic preceded the hang, the dead thread is usually the wakeup source.

## ptrace permission

Linux distros default to `kernel.yama.ptrace_scope=1`, which means only the
direct parent of a process can ptrace it. `race_repro.py` IS the direct
parent of every scenario subprocess, so it can attach without sudo:

```bash
# By default
python3 tools/race_repro.py … --gdb-on-hang
```

If you're attaching from outside the harness (e.g. by hand to a running
process), you need either:

- `sudo sysctl kernel.yama.ptrace_scope=0` (system-wide; persists until reboot
  or until you set it back to 1)
- `sudo` on the gdb invocation
- The target opted in via `prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)` (you'd
  add `import prctl; prctl.set_ptracer(prctl.SET_PTRACER_ANY)` to the
  scenario script's preamble)

## Filtering tokio noise

Backtraces through tokio's runtime are long — a single `.await` adds 10+
scheduler frames. Two filters are wired in:

- `RUST_BACKTRACE=short,exclude=tokio::*` (Rust 1.80+) — drops tokio internal
  frames from the panic backtrace
- `CIRIS_GDB_FILTER_TOKIO=1` env var for `debug_attach.sh` — drops
  tokio-internal lines from the gdb dump

Both default off. Turn them on once you've confirmed the noise is in fact
tokio internals and not load-bearing application code in the trace.

## Architecture, briefly

```
race_repro.py ─┐
               ├─ subprocess (clean venv, env vars set)
               │     │
               │     └── ciris_persist wheel
               │              │
               │              ├── #[cfg(feature = "debug-tools")] code path
               │              │   (compiled OUT of release wheels — zero surface)
               │              │
               │              ├── on `import ciris_persist`:
               │              │   reads CIRIS_PERSIST_PANIC_LOG (only if feature on)
               │              │     └── debug::install_panic_logger()
               │              │         └── std::panic::set_hook(…)
               │              │             └── per panic:
               │              │                 ├── PANIC_COUNT++ (atomic, lock-free)
               │              │                 ├── backtrace::trace() raw IPs
               │              │                 ├── libc::dladdr() → <basename>+<offset>
               │              │                 └── append entry → /tmp/persist-panic.log.{pid}
               │              │
               │              └── on cp.Engine(...) → run_migrations:
               │                  (always compiled; env-var-armed)
               │                  reads CIRIS_PERSIST_MIGRATION_TIMING_LOG
               │                    └── one JSON-Lines entry appended:
               │                        {"unix_ms": …, "backend": "sqlite",
               │                         "total_wall_us": …, "applied_count": N,
               │                         "applied_versions": "58,59"}
               │
               └─ debug_attach.sh on hang (rust-gdb -batch -ex 't a a bt')
```

Symbol resolution flow (post-mortem, deterministic):

```
panic-log entry: "  3: ip=0x7a4e…  ciris_persist.abi3.so+0x1a78"
                                                          ─┬──
                                                           └── offset within the .so
                                                               (computed at capture via dladdr)
                                                               ↓
addr2line --exe <wheel>/ciris_persist/ciris_persist.abi3.so 0x1a78
  → ciris_persist::debug::install_panic_logger::{{closure}} at src/debug/mod.rs:184
```

The wheel's runtime overhead from this machinery is **zero** in the
default (no-feature) build for the panic hook — none of that code is in
the binary. The migration-timing diagnostic is always compiled but no-ops
silently without its env var (one env-var lookup per Engine open).

## Persist-specific scenarios

| Scenario | Reproduces |
|---|---|
| `sqlite_inmemory_cohab.py` | CIRISPersist#156 — sqlite::memory: cohab with edge `init_edge_runtime` |
| `engine_construction_timing.py` | Pure Engine constructor timing (no edge); useful for v3.11.0 vs v3.12.1 comparison |
| `concurrent_boot_advisory_lock.py` | AV-26 — N parallel postgres Engine opens; verifies the advisory lock holds (sibling of `qa_harness::av26_concurrent_boot_advisory_lock`) |

## References

- [Agoda Engineering — Debugging a Rust Service Deadlock with GDB](https://medium.com/agoda-engineering/when-the-profiler-becomes-the-problem-debugging-a-rust-service-deadlock-with-gdb-95fc186b6aca)
  — the `[profile.release] debug = true` pattern + `rust-gdb -p PID -batch -ex 't a a bt'`
  workflow this harness builds on.
- [wg-async — Async Stack Traces design doc](https://rust-lang.github.io/wg-async/design_docs/async_stack_traces.html)
  — why tokio doesn't yet have first-class goroutine-style backtraces;
  why panic hooks + tracing-spans remain the canonical tool for now.
- [`std::panic::set_hook`](https://doc.rust-lang.org/std/panic/fn.set_hook.html)
  — the API our hook wraps.
- CIRISEdge `tools/README.md` — the sibling harness on the edge side; same
  shape, same scenarios pattern, same panic-hook architecture.
- CIRISPersist#156 / CIRISEdge#58 / CIRISPersist#139 — the use-cases this
  harness was designed to crack.
