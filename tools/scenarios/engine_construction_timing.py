"""Scenario: pure Engine constructor timing (no edge, no I/O work).

Times `cp.Engine('sqlite::memory:', ...)` end-to-end and exits. No
edge dependency. Useful for quantifying the v3.11.0 vs v3.12.x
boot-time delta in isolation — when triage for CIRISPersist#156
needs proof of "how much did migration count growth shift the
window," run this scenario against both pinned wheels via
race_repro.py with --migration-timing-log and compare the
distributions.

Output (JSON on stdout):
    {
      "engine_wall_us": 4521,        # the constructor's wall clock
      "panic_count": 0,               # if debug-tools enabled
      "persist_version": "3.12.1"
    }

The migration-timing entries (one per migration-apply call) land in
the file pointed to by CIRIS_PERSIST_MIGRATION_TIMING_LOG (with
.{pid} appended) — the harness collects them per-round.
"""
import json
import os
import secrets
import sys
import tempfile
import time


def main() -> None:
    import ciris_persist as cp

    d = tempfile.mkdtemp()
    seed_path = os.path.join(d, "s")
    open(seed_path, "wb").write(secrets.token_bytes(32))

    cp.reset_engine()
    key_id = "d-" + secrets.token_hex(8)

    t0 = time.perf_counter()
    engine = cp.Engine(
        "sqlite::memory:",
        key_id,
        local_key_id=key_id,
        local_key_path=seed_path,
    )
    engine_wall_us = int((time.perf_counter() - t0) * 1_000_000)

    payload = {
        "engine_wall_us": engine_wall_us,
        "persist_version": getattr(cp, "__version__", "unknown"),
    }
    if hasattr(cp, "panic_count"):
        payload["panic_count"] = cp.panic_count()

    print(json.dumps(payload))
    sys.stdout.flush()
    # Touch `engine` to defeat any "unused variable" optimizer (no-op
    # in CPython but makes the intent obvious).
    del engine
    os._exit(0)


if __name__ == "__main__":
    main()
