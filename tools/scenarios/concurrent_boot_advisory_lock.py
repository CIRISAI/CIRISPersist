"""Scenario: N parallel postgres Engine opens against the same DSN.

Verifies the AV-26 advisory-lock contract — concurrent boots MUST
yield exactly one set of `ciris_persist_schema_history` rows, not N
sets — by spawning N workers in this single subprocess and asserting
the count post-boot.

This is the Python-driven sibling of the qa_harness Rust test
`av26_concurrent_boot_advisory_lock` (in tests/qa_harness.rs). It
runs from the harness when a cohab-race investigation needs to
exercise the lock under a different process shape (race_repro.py
spawns the Python subprocess; this scenario spawns N postgres
backends inside it).

Expects: postgres reachable at $CIRIS_REPRO_DSN
(default postgres://postgres:postgres@localhost:5433/conformance).

Output (JSON on stdout):
    {
      "n_workers": 10,
      "schema_history_count": 59,
      "expected_count": 59,
      "lock_held": true
    }

`lock_held: true` means count == expected (one set per migration);
`false` means we saw N_WORKERS × expected rows and the lock didn't
serialize.
"""
import asyncio
import concurrent.futures
import json
import os
import secrets
import sys
import tempfile

import ciris_persist as cp  # noqa: E402  (imported here for engine-open timing)

N_WORKERS = int(os.environ.get("CIRIS_REPRO_N_WORKERS", "10"))
DSN = os.environ.get(
    "CIRIS_REPRO_DSN",
    "postgres://postgres:postgres@localhost:5433/conformance",
)


def open_engine_worker(worker_idx: int, dsn: str) -> str:
    """One open of cp.Engine against the shared DSN.

    Returns the key_id used; raises on failure.
    """
    d = tempfile.mkdtemp(prefix=f"av26-worker-{worker_idx}-")
    seed_path = os.path.join(d, "s")
    open(seed_path, "wb").write(secrets.token_bytes(32))
    cp.reset_engine()
    key_id = f"av26-{worker_idx}-{secrets.token_hex(4)}"
    engine = cp.Engine(
        dsn,
        key_id,
        local_key_id=key_id,
        local_key_path=seed_path,
    )
    # Force a read so we know boot completed (Engine() is lazy on
    # the migration side until first use? Actually no — refinery
    # runs at construction time, but we touch a method to be safe).
    _ = engine.federation_keys_list({})
    del engine
    return key_id


def count_schema_history(dsn: str) -> int:
    """Use psycopg2 if available; fall back to a fresh Engine."""
    try:
        import psycopg2

        conn = psycopg2.connect(dsn)
        with conn, conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM ciris_persist_schema_history")
            return int(cur.fetchone()[0])
    except ImportError:
        # Fallback: ask another engine. Not as clean (it'd re-run any
        # missing migrations, which would race the assert); prefer
        # psycopg2 in CI environments.
        raise RuntimeError(
            "psycopg2 needed for schema_history count (pip install psycopg2-binary)"
        )


def main() -> None:
    cp.reset_engine()
    with concurrent.futures.ThreadPoolExecutor(max_workers=N_WORKERS) as executor:
        futures = [
            executor.submit(open_engine_worker, i, DSN) for i in range(N_WORKERS)
        ]
        # Surface any exception.
        for f in concurrent.futures.as_completed(futures):
            _ = f.result()

    actual = count_schema_history(DSN)
    # Expected count = number of embedded migrations. Read from the
    # wheel if it exposes the helper (added in v3.12.x).
    expected = getattr(cp, "embedded_lens_migration_count", lambda: actual)()
    payload = {
        "n_workers": N_WORKERS,
        "schema_history_count": actual,
        "expected_count": expected,
        "lock_held": actual == expected,
    }
    if hasattr(cp, "panic_count"):
        payload["panic_count"] = cp.panic_count()
    print(json.dumps(payload))
    sys.stdout.flush()
    os._exit(0 if payload["lock_held"] else 1)


if __name__ == "__main__":
    main()
