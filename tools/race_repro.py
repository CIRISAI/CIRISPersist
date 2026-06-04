#!/usr/bin/env python3
"""
CIRISPersist race / hang / migration-timing diagnostic harness.

Drives a user-supplied scenario script in N fresh Python subprocesses,
detects races (mixed pass/fail/timeout outcomes), hangs (>timeout),
and migration-apply timing skew, and surfaces every signal we can
capture without flaky guesswork:

  - Subprocess returncode + stdout + stderr
  - Background-thread panic backtraces (via the in-process panic hook
    if CIRIS_PERSIST_PANIC_LOG is exported and the wheel was built with
    `panic-debug` profile so symbols resolve)
  - Optional: rust-gdb batch-mode all-thread backtrace on hung
    subprocesses (--gdb-on-hang; needs kernel.yama.ptrace_scope=0 or
    sudo)
  - Migration-apply timing (per-run JSON-Lines) when
    --migration-timing-log is provided

Mirrors the CIRISEdge `tools/race_repro.py` shape; the two harnesses
can run in parallel against the same cohab scenario for two-sided
correlation. The persist-side addition is the migration-timing log:
when triage suspects a boot-time scheduling shift, comparing
total_wall_us across pinned persist versions is the discriminator.

Typical use (CIRISPersist#156):

    # Build a panic-debug wheel + install in a clean venv first
    # (see tools/README.md for the maturin invocation).

    python3 tools/race_repro.py \\
      --scenario tools/scenarios/sqlite_inmemory_cohab.py \\
      --rounds 40 --timeout 8 \\
      --panic-log /tmp/persist-panic.log \\
      --migration-timing-log /tmp/persist-migration-timing.log

The harness writes a per-run summary + dumps every captured panic +
saves a JSON manifest of all rounds for later analysis.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Round:
    index: int
    returncode: int | None
    wall_ms: float
    stdout: str
    stderr: str
    timed_out: bool
    panic_log_delta: str = ""  # appended panic-log entries this round
    migration_timing_delta: str = ""  # appended migration-timing entries this round
    gdb_dump: str = ""  # rust-gdb dump if --gdb-on-hang triggered


@dataclass
class Summary:
    fast: int = 0
    hung: int = 0
    panicked: int = 0
    other_failures: int = 0
    timings_ms: list[float] = field(default_factory=list)
    migration_us: list[int] = field(default_factory=list)
    rounds: list[Round] = field(default_factory=list)


def find_rust_gdb() -> str | None:
    return shutil.which("rust-gdb") or shutil.which("gdb")


def gdb_dump(pid: int, gdb_path: str) -> str:
    """Batch-mode 'thread apply all bt' against pid.

    Returns the captured stdout/stderr. Requires either
    `kernel.yama.ptrace_scope=0` or the harness running as root /
    with CAP_SYS_PTRACE.
    """
    try:
        proc = subprocess.run(
            [
                gdb_path,
                "-batch",
                "-quiet",
                "-ex", "set pagination off",
                "-ex", "set print thread-events off",
                "-ex", f"attach {pid}",
                "-ex", "info threads",
                "-ex", "thread apply all bt 80",
                "-ex", "detach",
                "-ex", "quit",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return f"--- gdb stdout ---\n{proc.stdout}\n--- gdb stderr ---\n{proc.stderr}"
    except subprocess.TimeoutExpired:
        return "[gdb timed out after 30s]"
    except FileNotFoundError:
        return f"[gdb not found at {gdb_path}]"


def read_sibling_pid_log(path: Path, pid: int) -> str:
    """Read the per-pid sibling file at `path.{pid}` if present."""
    sibling = path.with_name(path.name + f".{pid}")
    if not sibling.exists():
        return ""
    try:
        return sibling.read_text()
    except OSError as e:
        return f"[read failed: {e}]"


def extract_migration_us(text: str) -> list[int]:
    """Pull `total_wall_us` values from JSON-Lines migration timing text."""
    out: list[int] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
            if "total_wall_us" in row:
                out.append(int(row["total_wall_us"]))
        except json.JSONDecodeError:
            continue
    return out


def run_one_round(
    args: argparse.Namespace,
    index: int,
    gdb_path: str | None,
) -> Round:
    env = dict(os.environ)
    if args.panic_log is not None:
        env["CIRIS_PERSIST_PANIC_LOG"] = str(args.panic_log)
    if args.migration_timing_log is not None:
        env["CIRIS_PERSIST_MIGRATION_TIMING_LOG"] = str(args.migration_timing_log)
    env["RUST_BACKTRACE"] = args.backtrace

    started = time.perf_counter()
    proc = subprocess.Popen(
        [sys.executable, str(args.scenario)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )

    try:
        stdout, stderr = proc.communicate(timeout=args.timeout)
        wall_ms = (time.perf_counter() - started) * 1000
        panic_delta = (
            read_sibling_pid_log(args.panic_log, proc.pid)
            if args.panic_log is not None
            else ""
        )
        migration_delta = (
            read_sibling_pid_log(args.migration_timing_log, proc.pid)
            if args.migration_timing_log is not None
            else ""
        )
        return Round(
            index=index,
            returncode=proc.returncode,
            wall_ms=wall_ms,
            stdout=stdout,
            stderr=stderr,
            timed_out=False,
            panic_log_delta=panic_delta,
            migration_timing_delta=migration_delta,
        )
    except subprocess.TimeoutExpired:
        wall_ms = (time.perf_counter() - started) * 1000
        gdb_text = ""
        if args.gdb_on_hang and gdb_path is not None:
            gdb_text = gdb_dump(proc.pid, gdb_path)

        proc.kill()
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            stdout, stderr = "", "[stderr unreadable after kill]"

        panic_delta = (
            read_sibling_pid_log(args.panic_log, proc.pid)
            if args.panic_log is not None
            else ""
        )
        migration_delta = (
            read_sibling_pid_log(args.migration_timing_log, proc.pid)
            if args.migration_timing_log is not None
            else ""
        )

        return Round(
            index=index,
            returncode=None,
            wall_ms=wall_ms,
            stdout=stdout,
            stderr=stderr,
            timed_out=True,
            panic_log_delta=panic_delta,
            migration_timing_delta=migration_delta,
            gdb_dump=gdb_text,
        )


def classify(r: Round) -> str:
    if r.timed_out:
        return "hung"
    if r.returncode == 0 and (r.stdout or "").strip():
        return "fast"
    if "panicked" in (r.stderr or "") or "no reactor running" in (r.stderr or ""):
        return "panicked"
    return "other_failure"


def quantiles(xs: list[float]) -> tuple[float, float, float, float]:
    if not xs:
        return (0.0, 0.0, 0.0, 0.0)
    s = sorted(xs)
    n = len(s)
    return (s[0], s[n // 2], s[int(n * 0.95)], s[-1])


def main() -> int:
    parser = argparse.ArgumentParser(
        description="CIRISPersist race/hang/migration-timing diagnostic harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--scenario", required=True, type=Path,
                        help="path to a scenario script (single-shot subprocess)")
    parser.add_argument("--rounds", type=int, default=30,
                        help="number of subprocess rounds (default 30)")
    parser.add_argument("--timeout", type=float, default=8.0,
                        help="per-round subprocess timeout in seconds (default 8)")
    parser.add_argument("--panic-log", type=Path, default=None,
                        help="parent path for CIRIS_PERSIST_PANIC_LOG; .{pid} suffix added per subprocess")
    parser.add_argument("--migration-timing-log", type=Path, default=None,
                        help="parent path for CIRIS_PERSIST_MIGRATION_TIMING_LOG; .{pid} suffix added per subprocess")
    parser.add_argument("--backtrace", default="1",
                        choices=["0", "1", "full", "short"],
                        help="RUST_BACKTRACE value (default 1)")
    parser.add_argument("--gdb-on-hang", action="store_true",
                        help="rust-gdb attach + 'thread apply all bt' on every hung subprocess")
    parser.add_argument("--out", type=Path, default=None,
                        help="optional JSON manifest output path")
    args = parser.parse_args()

    if not args.scenario.exists():
        print(f"scenario not found: {args.scenario}", file=sys.stderr)
        return 2

    gdb_path = find_rust_gdb() if args.gdb_on_hang else None
    if args.gdb_on_hang and gdb_path is None:
        print("warning: --gdb-on-hang requested but rust-gdb / gdb not found in PATH",
              file=sys.stderr)

    summary = Summary()

    print(f"running {args.rounds} rounds; timeout={args.timeout}s; scenario={args.scenario}")
    if args.panic_log:
        print(f"panic log parent: {args.panic_log} (per-pid suffix added by Rust hook)")
    if args.migration_timing_log:
        print(f"migration timing log parent: {args.migration_timing_log} (per-pid suffix)")
    if args.gdb_on_hang:
        print(f"gdb-on-hang armed via {gdb_path}")
    print()

    for i in range(args.rounds):
        r = run_one_round(args, i, gdb_path)
        klass = classify(r)
        if klass == "fast":
            summary.fast += 1
            summary.timings_ms.append(r.wall_ms)
        elif klass == "hung":
            summary.hung += 1
        elif klass == "panicked":
            summary.panicked += 1
        else:
            summary.other_failures += 1

        # Migration-us extraction (regardless of outcome — every
        # subprocess that opened an engine emits at least one entry).
        if r.migration_timing_delta:
            summary.migration_us.extend(extract_migration_us(r.migration_timing_delta))

        summary.rounds.append(r)

        # Per-round line.
        suffix = ""
        if r.migration_timing_delta:
            us_list = extract_migration_us(r.migration_timing_delta)
            if us_list:
                suffix = f"  mig_us={','.join(map(str, us_list))}"
        if klass == "fast":
            print(f"  [{i:02d}] OK     ({r.wall_ms:>6.0f}ms){suffix}")
        elif klass == "hung":
            print(f"  [{i:02d}] HANG   ({r.wall_ms:>6.0f}ms){suffix}")
        elif klass == "panicked":
            last_panic = (r.stderr.strip().splitlines() or [""])[-1][:120]
            print(f"  [{i:02d}] PANIC  ({r.wall_ms:>6.0f}ms){suffix}  {last_panic}")
        else:
            tail = (r.stderr.strip().splitlines() or [""])[-1][:120]
            print(f"  [{i:02d}] FAIL   rc={r.returncode}{suffix}  {tail}")

    print()
    print("=== summary ===")
    print(f"  fast    : {summary.fast}")
    print(f"  hung    : {summary.hung}")
    print(f"  panic   : {summary.panicked}")
    print(f"  other   : {summary.other_failures}")
    if summary.timings_ms:
        lo, p50, p95, hi = quantiles(summary.timings_ms)
        print(f"  wall    : min={lo:.0f}ms p50={p50:.0f}ms p95={p95:.0f}ms max={hi:.0f}ms")
    if summary.migration_us:
        lo, p50, p95, hi = quantiles([float(x) for x in summary.migration_us])
        print(f"  mig_us  : min={lo:.0f}us p50={p50:.0f}us p95={p95:.0f}us max={hi:.0f}us "
              f"(samples={len(summary.migration_us)})")

    # Surface the first panic / hang with full context.
    first_panic = next(
        (r for r in summary.rounds if r.panic_log_delta or "panicked" in (r.stderr or "")),
        None,
    )
    if first_panic:
        print()
        print(f"=== first panic-bearing round ({first_panic.index}) ===")
        if first_panic.panic_log_delta:
            print("--- panic log entry (symbol-resolved if panic-debug wheel) ---")
            print(first_panic.panic_log_delta)
        if "panicked" in (first_panic.stderr or ""):
            print("--- stderr panic lines ---")
            print(
                "\n".join(
                    line for line in first_panic.stderr.splitlines()
                    if "panic" in line.lower() or "reactor" in line.lower()
                )[:4000]
            )

    first_hang = next((r for r in summary.rounds if r.timed_out), None)
    if first_hang:
        print()
        print(f"=== first hang ({first_hang.index}) ===")
        print(f"stderr len={len(first_hang.stderr)}; stdout len={len(first_hang.stdout)}")
        if first_hang.gdb_dump:
            print("--- gdb 'thread apply all bt' ---")
            print(first_hang.gdb_dump[:8000])
        elif first_hang.stderr:
            print("--- last 20 stderr lines ---")
            print("\n".join(first_hang.stderr.splitlines()[-20:]))

    if args.out:
        data = {
            "scenario": str(args.scenario),
            "rounds_total": args.rounds,
            "timeout_s": args.timeout,
            "fast": summary.fast,
            "hung": summary.hung,
            "panicked": summary.panicked,
            "other_failures": summary.other_failures,
            "migration_us_samples": summary.migration_us,
            "rounds": [
                {
                    "index": r.index,
                    "returncode": r.returncode,
                    "wall_ms": r.wall_ms,
                    "timed_out": r.timed_out,
                    "stdout_len": len(r.stdout),
                    "stderr_len": len(r.stderr),
                    "stderr_tail": "\n".join(r.stderr.splitlines()[-10:]),
                    "panic_log_present": bool(r.panic_log_delta),
                    "migration_timing_present": bool(r.migration_timing_delta),
                    "migration_us": extract_migration_us(r.migration_timing_delta),
                    "gdb_dump_present": bool(r.gdb_dump),
                }
                for r in summary.rounds
            ],
        }
        args.out.write_text(json.dumps(data, indent=2))
        print(f"\nmanifest written to {args.out}")

    return 0 if summary.hung == 0 and summary.panicked == 0 and summary.other_failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
