"""Scenario: cp.Engine('sqlite::memory:') + edge init_edge_runtime cohab race.

Reproduces CIRISPersist#156 — persist v3.12.x + edge v1.1.7 hangs on
linux × sqlite at the `init_edge_runtime` / first `send` boundary.
Postgres-backed Engine constructions don't hit this race (the extra ms
of socket/pool setup absorbs the timing window).

Designed to be driven by tools/race_repro.py with --migration-timing-log
so the per-run migration-apply latency can be correlated with the
fast/hung classification.

The scenario is "Engine + init_edge_runtime + send_durable_inline_text"
— end-to-end the same path edge's conformance test exercises, just
inlined here so the harness can run it as a fresh subprocess each round.

Phase stamps go to stderr so a hang can be localized to a step:
  python_start → import_persist → import_edge → pre_engine →
  post_engine → post_register_key → post_init_edge_runtime →
  post_send_durable

Expects: no postgres. Pure sqlite::memory: + edge.
"""
import json
import os
import secrets
import sys
import tempfile
import time


def stamp(phase: str) -> None:
    """Emit a phase marker so the harness can localize a hang to a step."""
    print(f"PHASE {time.perf_counter() * 1000:.1f}ms {phase}", file=sys.stderr, flush=True)


def main() -> None:
    stamp("python_start")
    import ciris_persist as cp
    stamp("import_persist")

    try:
        from ciris_edge.ciris_edge import init_edge_runtime  # type: ignore
    except ImportError as e:
        # Scenario is opt-in on edge being installed; surface the
        # error clearly so the harness's classifier reports it.
        print(json.dumps({"error": f"ciris_edge not installed: {e}"}))
        sys.exit(2)
    stamp("import_edge")

    d = tempfile.mkdtemp()
    seed_path = os.path.join(d, "s")
    open(seed_path, "wb").write(secrets.token_bytes(32))
    idp = os.path.join(d, "t.id")
    open(idp, "wb").write(b"\x00" * 64)

    cp.reset_engine()
    key_id = "d-" + secrets.token_hex(8)

    stamp("pre_engine")
    engine = cp.Engine(
        "sqlite::memory:",
        key_id,
        local_key_id=key_id,
        local_key_path=seed_path,
    )
    stamp("post_engine")

    kid = engine.register_self_federation_key("agent", "ref", None, None, None)
    stamp("post_register_key")

    edge = init_edge_runtime(engine, idp, listen_addr="127.0.0.1:0")
    stamp("post_init_edge_runtime")

    handle = edge.send_durable_inline_text(kid, "race-probe")
    stamp("post_send_durable")

    payload = {
        "durable_returned": type(handle).__name__,
    }
    # Capture the wheel's panic count if the build exposes it
    # (debug-tools feature on).
    if hasattr(cp, "panic_count"):
        payload["panic_count"] = cp.panic_count()

    print(json.dumps(payload))
    sys.stdout.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
